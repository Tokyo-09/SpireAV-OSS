use crate::core::db::ThreatDatabase;

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum ScanResult {
    Clean(PathBuf),
    Threat {
        path: PathBuf,
        malware: ThreatDatabase,
    },
    YaraThreat {
        path: PathBuf,
        matching_rules: Vec<String>,
    },
    Error {
        path: PathBuf,
        error: String,
    },
}
