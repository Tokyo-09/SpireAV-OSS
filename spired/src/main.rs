use av_core::core::{config::Config as SpireConfig, db::ThreatDatabase};
use clap::Parser;
use env_logger::Builder;
use log::{LevelFilter, debug, error, info};
use reqwest::Client;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;

// use nix::unistd::Uid;

use crate::{commands::Cli, monitor::monitor_directory, utils::load_config};

pub mod commands;
pub mod monitor;
pub mod telemetry;
pub mod utils;

#[derive(Deserialize)]
pub struct Config {
    excluded_paths: Vec<PathBuf>,
    excluded_extensions: Vec<String>,
    excluded_files: Vec<String>,
    telemetry: bool,
    // _excluded_processes: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    /*
    #[cfg(target_os = "linux")]
    if !Uid::effective().is_root() {
        anyhow::bail!("You must run this executable with root permissions");
    }
    */

    let config = load_config()?;

    if config.telemetry {
        info!("Telemetry enabled. Collecting and sending data...");

        let telemetry_data = json!({
            "app_version": "1.0.0",
            "user_id": "example_user",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "metrics": {
                "cpu_usage": 42.5,
                "memory_usage": 128
            }
        });

        let client = Client::new();
        let response = client
            .post("https://127.0.0.1/api/collect")
            .json(&telemetry_data)
            .send()
            .await?;

        if response.status().is_success() {
            info!("Telemetry sent successfully.");
        } else {
            error!("Failed to send telemetry: {}", response.status());
        }
    } else {
        info!("Telemetry disabled. No data will be collected or sent.");
    }

    let ip = String::from("http://127.0.0.1:8080");

    let cfg = SpireConfig::load()?;
    let spire_dir = cfg.spire_dir();
    let db_path = spire_dir.join(cfg.db_path());
    let yara_db_path = spire_dir.join(cfg.yara_rules_path());

    debug!("spire_dir: {}", spire_dir.display());
    debug!("db_path: {}", db_path.display());
    debug!("yara_db_path: {}", yara_db_path.display());

    if !spire_dir.exists() {
        std::fs::DirBuilder::new().create(&spire_dir)?;
        log::debug!("Created directory: {}", spire_dir.display());
    }

    if !db_path.exists() || !yara_db_path.exists() {
        debug!("Database or YARA rules not found, downloading...");
        ThreatDatabase::install(&ip, &spire_dir, &db_path, &yara_db_path)?;
    }

    let conn = Connection::open(&db_path)?;

    let args = Cli::parse();

    let log_level = match args.verbose {
        0 => LevelFilter::Off,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    Builder::new().filter_level(log_level).init();

    info!("Logging initialized to with level {:?}", log_level);
    log::debug!("Apps run in: {:?} mode", log_level);

    monitor_directory(&conn, config)?;

    Ok(())
}
