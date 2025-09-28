use clap::{Parser, Subcommand};
use std::net::Ipv4Addr;

use av_core::types::{OnDemaindScanModes, QuarantineAction};

#[derive(Parser, Debug)]
#[command(
    version = "0.2.0",
    name = "Rust Sentinel",
    about = "Simple rust AntiVirus"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[clap(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Scan {
        #[clap(subcommand)]
        scan_type: OnDemaindScanModes,
    },
    Quarantine {
        #[clap(subcommand)]
        action: QuarantineAction,
    },
    Config {
        #[clap(subcommand)]
        action: QuarantineAction,
    },
    UpdateDB {
        // Server ip address
        ip: Option<Ipv4Addr>,
    },
    PasswordManager {
        #[clap(subcommand)]
        action: PasswordManagerAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum PasswordManagerAction {
    List,
    Add,
    Remove { id: String },
}
