use anyhow::{Result, bail};
use chrono::Utc;
use dirs;
use rusqlite::Connection;
use std::fs::{self, remove_file};
use std::path::PathBuf;

use crate::core::models::ScanResult;

#[allow(dead_code)]
pub struct Quarantine {
    conn: Connection,
    result: ScanResult,
    id: i64,
}

impl Quarantine {
    pub fn quarantine_file(conn: &Connection, result: &ScanResult) -> Result<()> {
        let (path, malware_name) = match result {
            ScanResult::Threat { path, malware } => (path.clone(), malware.name.clone()),
            ScanResult::YaraThreat {
                path,
                matching_rules,
            } => (
                path.clone(),
                format!("YARA Threat: {}", matching_rules.join(", ")),
            ),
            _ => bail!("Cannot quarantine non-threat result"),
        };

        let quarantine_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("./.spire"))
            .join("spire_quarantine");
        fs::create_dir_all(&quarantine_dir)?;

        let timestamp = Utc::now().timestamp();
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let dest = quarantine_dir.join(format!("{file_name}_{timestamp}"));

        fs::rename(&path, &dest)?;

        conn.execute(
            "INSERT INTO quarantine (original_path, malware_name, quarantined_path, timestamp)
         VALUES (?1, ?2, ?3, ?4)",
            [
                path.display().to_string(),
                malware_name,
                dest.display().to_string(),
                timestamp.to_string(),
            ],
        )?;

        Ok(())
    }

    pub fn list_quarantined(conn: &Connection) -> Result<Vec<(i64, String, String, i64)>> {
        let mut stmt = conn.prepare(
            "SELECT id, original_path, malware_name, timestamp FROM quarantine ORDER BY timestamp DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;

        // Collect iterator of Result into Result<Vec>
        let items: Result<Vec<(i64, String, String, i64)>, rusqlite::Error> = rows.collect();
        items.map_err(|e| anyhow::anyhow!("Failed to collect quarantine items: {}", e))
    }

    pub fn restore_quarantined(conn: &Connection, id: i64) -> Result<()> {
        let (quarantined_path, original_path): (String, String) = conn.query_row(
            "SELECT quarantined_path, original_path FROM quarantine WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        fs::rename(&quarantined_path, &original_path)?;

        conn.execute("DELETE FROM quarantine WHERE id = ?1", [id])?;

        Ok(())
    }

    pub fn delete_quarantined(conn: &Connection, id: i64) -> Result<()> {
        let quarantined_path: String = conn.query_row(
            "SELECT quarantined_path FROM quarantine WHERE id = ?1",
            [id],
            |row| row.get(0),
        )?;

        remove_file(&quarantined_path)?;

        conn.execute("DELETE FROM quarantine WHERE id = ?1", [id])?;

        Ok(())
    }
}
