use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use rusqlite::{Connection, Statement};

use anyhow::{Context, Ok};
use log::debug;
use reqwest::blocking::Client;
use zip::ZipArchive;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ThreatDatabase {
    pub name: String,
    pub md5hash: String,
    pub sha256hash: String,
}

impl ThreatDatabase {
    pub fn query_db(conn: &Connection) -> anyhow::Result<()> {
        let statement = conn.prepare("SELECT * FROM default_db")?;
        let mut stmt: Statement = statement;
        let ioc_iter = stmt.query_map([], |row| {
            let value = ThreatDatabase {
                name: row.get(1)?,
                md5hash: row.get(0)?,
                sha256hash: row.get(3)?,
            };
            Result::Ok(value)
        })?;

        for ioc in ioc_iter {
            println!("{:?}", ioc?);
        }
        Ok(())
    }

    pub fn install(
        ip: &str,
        spire_dir: &Path,
        db_path: &PathBuf,
        yara_rules_path: &PathBuf,
    ) -> anyhow::Result<()> {
        // Initialize HTTP client with a timeout
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        // Validate and construct URLs
        let base_url = ip.trim_end_matches('/');
        let db_url = format!("{}/database.db", base_url);
        let yara_url = format!("{}/yara.zip", base_url);

        // Ensure parent directories exist
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create parent directory '{}'", parent.display())
            })?;
        }

        fs::create_dir_all(yara_rules_path).with_context(|| {
            format!(
                "Failed to create YARA rules directory '{}'",
                yara_rules_path.display()
            )
        })?;

        // Download database.db
        let response = client
            .get(&db_url)
            .send()
            .with_context(|| format!("Failed to send GET request to {}", db_url))?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("Unexpected HTTP status {} when fetching {}", status, db_url);
        }

        // Read database bytes
        let db_bytes = response
            .bytes()
            .with_context(|| format!("Failed to read response body from {}", db_url))?;

        // Write database to temp file then rename atomically
        let db_tmp_path = db_path.with_extension("part");
        {
            let mut tmp_file = File::create(&db_tmp_path).with_context(|| {
                format!(
                    "Failed to create temporary file '{}'",
                    db_tmp_path.display()
                )
            })?;
            tmp_file.write_all(&db_bytes).with_context(|| {
                format!(
                    "Failed to write to temporary file '{}'",
                    db_tmp_path.display()
                )
            })?;
            tmp_file
                .flush()
                .context("Failed to flush temporary database file")?;
        }

        fs::rename(&db_tmp_path, db_path).with_context(|| {
            format!(
                "Failed to rename '{}' -> '{}'",
                db_tmp_path.display(),
                db_path.display()
            )
        })?;

        debug!("Database downloaded successfully to: {}", db_path.display());

        // Download yara.zip
        let yara_response = client
            .get(&yara_url)
            .send()
            .with_context(|| format!("Failed to send GET request to {}", yara_url))?;

        let yara_status = yara_response.status();
        if !yara_status.is_success() {
            anyhow::bail!(
                "Unexpected HTTP status {} when fetching {}",
                yara_status,
                yara_url
            );
        }

        // Read yara.zip bytes
        let yara_bytes = yara_response
            .bytes()
            .with_context(|| format!("Failed to read response body from {}", yara_url))?;

        // Write yara.zip to temp file
        let yara_tmp_path = spire_dir.join("yara.zip.part");
        {
            let mut yara_tmp_file = File::create(&yara_tmp_path).with_context(|| {
                format!(
                    "Failed to create temporary file '{}'",
                    yara_tmp_path.display()
                )
            })?;
            yara_tmp_file.write_all(&yara_bytes).with_context(|| {
                format!(
                    "Failed to write to temporary file '{}'",
                    yara_tmp_path.display()
                )
            })?;
            yara_tmp_file
                .flush()
                .context("Failed to flush temporary YARA file")?;
        }

        // Extract yara.zip to yara_rules directory
        let yara_file = File::open(&yara_tmp_path).with_context(|| {
            format!(
                "Failed to open temporary YARA file '{}'",
                yara_tmp_path.display()
            )
        })?;
        let mut archive = ZipArchive::new(yara_file).with_context(|| {
            format!(
                "Failed to read ZIP archive from '{}'",
                yara_tmp_path.display()
            )
        })?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .with_context(|| format!("Failed to read file {} from ZIP archive", i))?;
            let file_path = file
                .enclosed_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid file path in ZIP archive"))?;

            // Sanitize file path to prevent directory traversal
            if file_path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                continue;
            }

            // Only extract .yara or .yar files
            if file_path
                .extension()
                .map(|ext| ext == "yara" || ext == "yar")
                .unwrap_or(false)
            {
                let dest_path = yara_rules_path.join(file_path);
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("Failed to create parent directory '{}'", parent.display())
                    })?;
                }

                let mut dest_file = File::create(&dest_path)
                    .with_context(|| format!("Failed to create file '{}'", dest_path.display()))?;
                std::io::copy(&mut file, &mut dest_file)
                    .with_context(|| format!("Failed to extract file '{}'", dest_path.display()))?;
                dest_file
                    .flush()
                    .context("Failed to flush extracted YARA file")?;
            }
        }

        fs::remove_file(&yara_tmp_path).with_context(|| {
            format!(
                "Failed to remove temporary file '{}'",
                yara_tmp_path.display()
            )
        })?;

        debug!(
            "YARA rules extracted successfully to: {}",
            yara_rules_path.display()
        );
        Ok(())
    }

    pub fn update_db(
        ip: &str,
        spire_dir: &Path,
        db_path: &PathBuf,
        yara_rules_path: &PathBuf,
    ) -> anyhow::Result<()> {
        Self::install(ip, spire_dir, db_path, yara_rules_path)?;
        Ok(())
    }
}
