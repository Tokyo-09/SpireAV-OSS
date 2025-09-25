use av_engine::AvEngine;
use clap::Parser;
use env_logger::Builder;
use indicatif::MultiProgress;
// use sysinfo::System;

use cli::commands::{Cli, Command};
use log::LevelFilter;

mod cli;
// mod generated;

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let log_level = match args.verbose {
        0 => LevelFilter::Info,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Debug,
    };

    Builder::new().filter_level(log_level).init();

    log::debug!("Apps run in: {:?} mode", log_level);

    let engine = AvEngine::new()?;
    let m = MultiProgress::new();

    match args.command {
        Command::Scan { scan_type } => engine.scan(scan_type, &m)?,
        Command::Config { action } => {
            dbg!(action);
            unimplemented!("Not yet working");
        }
        Command::Quarantine { action } => engine.quarantine(action)?,
        Command::UpdateDB { ip } => {
            m.println(format!("Database update not implemented: ip={ip:?}"))?;
            unimplemented!("Database update is not yet implemented");
        }
    }

    Ok(())
}
