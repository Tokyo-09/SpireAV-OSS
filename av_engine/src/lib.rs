use av_core::{
    SpireAvScanner,
    core::{config::Config as SpireConfig, db::ThreatDatabase, quarantine::Quarantine},
    types::QuarantineAction,
};
use chrono::{DateTime, FixedOffset, Utc};
use indicatif::MultiProgress;

use log::debug;
use rusqlite::Connection;
use std::path::PathBuf;

use utils::generate_html_report;

pub mod utils;

#[allow(dead_code)]
pub struct AvEngine {
    spire_dir: PathBuf,
    db_path: PathBuf,
    yara_db_path: PathBuf,
    conn: Connection,
}

impl AvEngine {
    pub fn new() -> anyhow::Result<Self> {
        let cfg = SpireConfig::load()?;
        let spire_dir = cfg.spire_dir();
        let db_path = spire_dir.join(cfg.db_path());
        let yara_db_path = spire_dir.join(cfg.yara_rules_path());

        // TODO! Shloud take value from args
        let ip = String::from("http://127.0.0.1:8080");

        if !spire_dir.exists() {
            std::fs::DirBuilder::new().create(&spire_dir)?;
            log::debug!("Created directory: {}", spire_dir.display());
        }

        if !db_path.exists() || !yara_db_path.exists() {
            debug!("Database or YARA rules not found, downloading...");
            ThreatDatabase::install(&ip, &spire_dir, &db_path, &yara_db_path)?;
        }

        let conn = Connection::open(&db_path)?;

        Ok(AvEngine {
            spire_dir,
            db_path,
            yara_db_path,
            conn,
        })
    }
    pub fn scan(
        &self,
        scan_type: av_core::types::OnDemaindScanModes,
        m: &MultiProgress,
    ) -> anyhow::Result<()> {
        match scan_type {
            av_core::types::OnDemaindScanModes::Fast { path, report } => {
                let results = SpireAvScanner::scan_path(&self.conn, &path)?;
                if let Some(report_path) = report {
                    generate_html_report(&results, &report_path, None)?;
                    m.println(format!("Report generated at: {}", report_path.display()))?;
                }
            }
            av_core::types::OnDemaindScanModes::Full {
                rules,
                path,
                report,
            } => {
                let rules_path = rules.unwrap_or_else(|| self.yara_db_path.clone());
                if !rules_path.exists() {
                    anyhow::bail!("Yara rules path does not exist: {}", rules_path.display());
                }
                let results = SpireAvScanner::scan_yara(&self.conn, &rules_path, &path)?;
                if let Some(report_path) = report {
                    generate_html_report(&results, &report_path, None)?;
                    m.println(format!("Report generated at: {}", report_path.display()))?;
                }
            }
            av_core::types::OnDemaindScanModes::YaraScan {
                rules,
                path,
                report,
            } => {
                let rules_path = rules.unwrap_or_else(|| self.yara_db_path.clone());
                if !rules_path.exists() {
                    anyhow::bail!("Yara rules path does not exist: {}", rules_path.display());
                }
                let results = SpireAvScanner::scan_yara(&self.conn, &rules_path, &path)?;
                if let Some(report_path) = report {
                    generate_html_report(&results, &report_path, None)?;
                    m.println(format!("Report generated at: {}", report_path.display()))?;
                }
            }
            av_core::types::OnDemaindScanModes::ProcessScan {} => {
                unimplemented!("Not yet working!")
            }
        }
        Ok(())
    }
    pub fn quarantine(&self, quarantine_action: QuarantineAction) -> anyhow::Result<()> {
        match quarantine_action {
            QuarantineAction::List {} => {
                let items = Quarantine::list_quarantined(&self.conn)?;
                let _: () = for (id, original_path, malware_name, timestamp) in items {
                    let datetime = DateTime::<Utc>::from_timestamp(timestamp, 0)
                        .ok_or_else(|| anyhow::anyhow!("Invalid timestamp: {}", timestamp))?;
                    let cest_offset =
                        FixedOffset::east_opt(2 * 3600).expect("Invalid timezone offset");
                    let datetime_cest = datetime.with_timezone(&cest_offset);
                    println!(
                        "ID: {:<4} | Path: {} | Malware: {} | Quarantined: {}",
                        id,
                        original_path,
                        malware_name,
                        datetime_cest.format("%Y-%m-%d %H:%M:%S %Z")
                    );
                };
                Ok(())
            }
            QuarantineAction::Restore { id } => {
                Quarantine::restore_quarantined(&self.conn, id)?;
                println!("Restored item with ID: {id}");
                Ok(())
            }
            QuarantineAction::Delete { id } => {
                Quarantine::delete_quarantined(&self.conn, id)?;
                println!("Deleted item with ID: {id}");
                Ok(())
            }
        }
    }
}
