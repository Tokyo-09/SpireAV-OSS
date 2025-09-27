use av_core::{
    SpireAvScanner,
    core::{config::Config as SpireConfig, db::ThreatDatabase},
};
use clap::Parser;
use env_logger::Builder;
use log::{LevelFilter, debug, error, info};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use rusqlite::Connection;
use serde::Deserialize;
use std::{path::PathBuf, sync::mpsc::channel, time::Duration};

// use nix::unistd::Uid;

use crate::{
    commands::Cli,
    utils::{load_config, should_monitor_path},
};

pub mod commands;
pub mod utils;

#[derive(Deserialize)]
pub struct Config {
    excluded_paths: Vec<PathBuf>,
    excluded_extensions: Vec<String>,
    excluded_files: Vec<String>,
    // _excluded_processes: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    /*
    #[cfg(target_os = "linux")]
    if !Uid::effective().is_root() {
        anyhow::bail!("You must run this executable with root permissions");
    }
    */

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

    monitor_directory(&conn)?;

    Ok(())
}

fn monitor_directory(conn: &Connection) -> anyhow::Result<()> {
    let config = load_config("./config.toml")?;

    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            debug!("Received filesystem event: {:?}", res);
            let _ = tx.send(res);
        },
        NotifyConfig::default().with_poll_interval(Duration::from_secs(1)),
    )?;

    let directories = vec![
        dirs::home_dir(),
        dirs::audio_dir(),
        dirs::cache_dir(),
        dirs::data_dir(),
        dirs::config_local_dir(),
        dirs::config_dir(),
        dirs::document_dir(),
        dirs::download_dir(),
        dirs::executable_dir(),
        dirs::picture_dir(),
        dirs::preference_dir(),
        dirs::public_dir(),
        dirs::state_dir(),
        dirs::template_dir(),
        dirs::video_dir(),
    ];

    debug!("monitoring: {:?}", directories);

    for dir in directories {
        match dir {
            Some(path) => {
                if path.exists() {
                    match watcher.watch(&path, RecursiveMode::Recursive) {
                        Ok(_) => info!("Monitoring directory: {}", path.display()),
                        Err(e) => error!(
                            "Failed to watch directory {}: {} (continuing without it)",
                            path.display(),
                            e
                        ),
                    }
                } else {
                    debug!("Directory does not exist, skipping: {}", path.display());
                }
            }
            None => {
                debug!("Directory not found, skipping");
            }
        }
    }

    info!("Starting event loop");
    for res in rx {
        debug!("Processing event: {:?}", res);
        match res {
            Ok(event) => {
                debug!("Event kind: {:?}", event.kind);
                if event.kind.is_create() || event.kind.is_modify() {
                    for file_path in event.paths {
                        debug!("Checking path: {}", file_path.display());
                        if file_path.is_file() {
                            let parent = file_path.parent().unwrap_or(&file_path);
                            if should_monitor_path(parent, &config)
                                && should_monitor_path(&file_path, &config)
                            {
                                info!("Detected change in file: {:?}", file_path);
                                if let Err(e) = SpireAvScanner::scan_single_file(conn, file_path) {
                                    error!("Error scanning file  {}", e)
                                }
                            } else {
                                debug!(
                                    "Skipping file in unmonitored directory: {}",
                                    file_path.display()
                                );
                            }
                        }
                    }
                } else {
                    debug!("Ignoring event kind: {:?}", event.kind);
                }
            }
            Err(e) => {
                error!("Filesystem watch error: {}", e);
            }
        }
    }

    Ok(())
}
