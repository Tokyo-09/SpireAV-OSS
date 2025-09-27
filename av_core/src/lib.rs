use crate::{
    core::{
        config::Config as SpireConfig, db::ThreatDatabase, hashes::Hasher, models::ScanResult,
        quarantine::Quarantine, scanner::entropy::calculate_entropy,
    },
    modules::heuristic_scanner::SpireHeuristicEngine,
    types::{FileContainer, FileData, FileType, HeuristicResult},
    utils::{
        heuristic_analyze::{extract_ascii_strings, parse_file},
        scanner::create_progress_bar,
        yara::compile_yara_rules,
    },
};

use std::{
    fs,
    path::{Path, PathBuf},
    sync::mpsc::channel,
    time::Duration,
};

use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use notify_rust::{Notification, Timeout};
use rusqlite::Connection;
use walkdir::WalkDir;
use yara_x::Scanner as yara_Scanner;

pub mod core;
pub mod modules;
pub mod types;
pub mod utils;

#[allow(dead_code)]
pub struct SpireAvScanner {
    rules: SpireHeuristicEngine,
    conn: Connection,
    path: PathBuf,
    md5hash: String,
    sha256hash: String,
    config: SpireConfig,
}

impl SpireAvScanner {
    pub fn check_file(
        conn: &Connection,
        md5hash: String,
        sha256hash: String,
    ) -> Result<Option<ThreatDatabase>, anyhow::Error> {
        let mut stmt = conn.prepare("SELECT md5hash, sha256hash, name FROM default_db WHERE md5hash = ?1 OR sha256hash = ?2")?;
        let mut malware_iter = stmt.query_map([md5hash, sha256hash], |row| {
            let md5hash: String = row.get(0)?;
            let sha256hash: String = row.get(1)?;
            let name: String = row.get(2)?;
            Ok(ThreatDatabase {
                name,
                md5hash,
                sha256hash,
            })
        })?;

        if let Some(malware) = malware_iter.next() {
            let malware = malware?;
            return Ok(Some(malware));
        }
        Ok(None)
    }
    pub fn scan_single_file(conn: &Connection, file_path: PathBuf) -> anyhow::Result<ScanResult> {
        let path_display = file_path.canonicalize();

        info!("Scanning: {path_display:?}");

        let (md5hash, sha256hash) = Hasher::calculate_hashes(file_path.clone())?;
        let entropy = calculate_entropy(file_path.clone())?;

        match Self::check_file(conn, md5hash.clone(), sha256hash.clone()) {
            Ok(Some(malware)) => {
                info!(
                    "Threat detected in {:?}: {} (MD5: {}, SHA256: {}, entropy: {})",
                    path_display, malware.name, malware.md5hash, malware.sha256hash, entropy
                );
                Quarantine::quarantine_file(
                    conn,
                    &ScanResult::Threat {
                        path: file_path.clone(),
                        malware: malware.clone(),
                    },
                )?;
                info!(
                    "Quarantined file {} (MD5: {}, SHA256: {}, entropy: {})",
                    malware.name, malware.md5hash, malware.sha256hash, entropy
                );

                Notification::new()
                .summary("Spire AV: Threat Detected")  // Заголовок
                .body(&format!(
                    "File: {:?}\nMalware: {}\nMD5: {}\nSHA256: {}\nEntropy: {}\nQuarantined successfully.",
                    path_display, malware.name, malware.md5hash, malware.sha256hash, entropy
                ))
                .icon("dialog-warning")  
                .appname("Spire AV") 
                .timeout(Timeout::Milliseconds(10000))
                .show()?;

                Ok(ScanResult::Threat {
                    path: file_path,
                    malware,
                })
            }
            Ok(None) => {
                info!("File clean: {path_display:?}");
                Ok(ScanResult::Clean(file_path))
            }
            Err(e) => {
                info!("Error scanning {path_display:?}: {e}");
                error!("Error scanning {path_display:?}: {e}");
                Ok(ScanResult::Error {
                    path: file_path,
                    error: e.to_string(),
                })
            }
        }
    }
    pub fn scan_path(conn: &Connection, path: &PathBuf) -> anyhow::Result<Vec<ScanResult>> {
        let mut results: Vec<ScanResult> = Vec::new();

        if path.is_file() {
            if !path.exists() {
                anyhow::bail!("File does not exist: {}", path.display());
            }

            let pb = create_progress_bar(1, &format!("Scanning file: {}", path.display()))?;

            let result = Self::scan_single_file(conn, path.to_path_buf());
            results.push(result?);
            pb.inc(1);
            pb.finish_with_message("File scan completed.");
        } else if path.is_dir() {
            let total_files: u64 = WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .count() as u64;

            let pb = create_progress_bar(
                total_files,
                &format!("Scanning directory: {}", path.display()),
            )?;

            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let path_display = entry.path();
                    pb.set_message(format!("Scanning: {path_display:?}"));

                    let (md5hash, sha256hash) =
                        Hasher::calculate_hashes(path_display.to_path_buf())?;
                    let entropy = calculate_entropy(entry.path().to_path_buf())?;

                    match Self::check_file(conn, md5hash.clone(), sha256hash.clone()) {
                        Ok(Some(malware)) => {
                            pb.println(format!(
                                "Threat detected in {:?}: {} (MD5: {}, SHA256: {}, entropy: {})",
                                path_display,
                                malware.name,
                                malware.md5hash,
                                malware.sha256hash,
                                entropy
                            ));
                            Quarantine::quarantine_file(
                                conn,
                                &ScanResult::Threat {
                                    path: entry.path().to_path_buf(),
                                    malware: malware.clone(),
                                },
                            )?;
                            pb.println(format!(
                                "Quarantined file {} (MD5: {}, SHA256: {}, entropy: {})",
                                malware.name, malware.md5hash, malware.sha256hash, entropy
                            ));
                            Notification::new().summary("Spire AV: Threat Detected")  // Заголовок
                            .body(&format!(
                    "File: {:?}\nMalware: {}\nMD5: {}\nSHA256: {}\nEntropy: {}\nQuarantined successfully.",
                    path_display, malware.name, malware.md5hash, malware.sha256hash, entropy
                ))
                .icon("dialog-warning")  
                .appname("Spire AV") 
                .timeout(Timeout::Milliseconds(10000))
                .show()?;
                            results.push(ScanResult::Threat {
                                path: entry.path().to_path_buf(),
                                malware,
                            });
                        }
                        Ok(None) => {
                            pb.println(format!("File clean: {path_display:?}"));
                            results.push(ScanResult::Clean(entry.path().to_path_buf()));
                        }
                        Err(e) => {
                            pb.println(format!("Error scanning {path_display:?}: {e}"));
                            error!("Error: {e}");
                            results.push(ScanResult::Error {
                                path: entry.path().to_path_buf(),
                                error: e.to_string(),
                            });
                        }
                    }
                    pb.inc(1);
                }
            }
            pb.finish_with_message("Directory scan completed.");
        } else {
            anyhow::bail!("Path is neither a file nor a directory: {}", path.display());
        }

        Ok(results)
    }
    pub fn scan_yara(
        conn: &Connection,
        rules_path: &PathBuf,
        target_path: &PathBuf,
    ) -> anyhow::Result<Vec<ScanResult>> {
        let compiled_rules = compile_yara_rules(rules_path)?;

        let mut scanner = yara_Scanner::new(&compiled_rules);

        let mut results: Vec<ScanResult> = Vec::new();

        if target_path.is_file() {
            match fs::read(target_path) {
                Ok(data) => match scanner.scan(&data) {
                    Ok(scan_results) => {
                        let matching = scan_results.matching_rules();
                        let matching_rules: Vec<String> =
                            matching.map(|rule| rule.identifier().to_string()).collect();
                        if !matching_rules.is_empty() {
                            results.push(ScanResult::YaraThreat {
                                path: target_path.clone(),
                                matching_rules,
                            });
                        } else {
                            results.push(ScanResult::Clean(target_path.clone()));
                        }
                    }
                    Err(e) => {
                        results.push(ScanResult::Error {
                            path: target_path.clone(),
                            error: e.to_string(),
                        });
                    }
                },
                Err(e) => {
                    results.push(ScanResult::Error {
                        path: target_path.clone(),
                        error: format!("Failed to read file: {e}"),
                    });
                }
            }
        } else if target_path.is_dir() {
            let total_files: u64 = WalkDir::new(target_path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .count() as u64;

            let pb = ProgressBar::new(total_files);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
                    .progress_chars("#>-"),
            );
            pb.set_message(format!(
                "YARA scanning directory: {}",
                target_path.display()
            ));

            for entry in WalkDir::new(target_path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let path_display = entry.path().display();
                    pb.set_message(format!("Scanning: {path_display}"));

                    match fs::read(entry.path()) {
                        Ok(data) => match scanner.scan(&data) {
                            Ok(scan_results) => {
                                let matching = scan_results.matching_rules();
                                let matching_rules: Vec<String> =
                                    matching.map(|rule| rule.identifier().to_string()).collect();
                                if !matching_rules.is_empty() {
                                    pb.println(format!(
                                        "Threat detected in {}: YARA matches - {}",
                                        path_display,
                                        matching_rules.join(", ")
                                    ));
                                    Quarantine::quarantine_file(
                                        conn,
                                        &ScanResult::YaraThreat {
                                            path: entry.path().to_path_buf(),
                                            matching_rules: matching_rules.clone(),
                                        },
                                    )?;
                                    pb.println(format!(
                                        "Quarantined file {}: YARA matches - {}",
                                        path_display,
                                        matching_rules.join(", ")
                                    ));
                                    Notification::new()
                .summary("Spire AV: Threat Detected")  // Заголовок
                .body(&format!(
                    "File: {:?}\nMalware: {:?}\nMD5: \nQuarantined successfully.",
                    path_display, matching_rules
                ))
                .icon("dialog-warning")  
                .appname("Spire AV") 
                .timeout(Timeout::Milliseconds(10000))
                .show()?;
                                    results.push(ScanResult::YaraThreat {
                                        path: entry.path().to_path_buf(),
                                        matching_rules,
                                    });
                                } else {
                                    pb.println(format!("File clean: {path_display}"));
                                    results.push(ScanResult::Clean(entry.path().to_path_buf()));
                                }
                            }
                            Err(e) => {
                                pb.println(format!("Error scanning {path_display}: {e}"));
                                error!("Error: {e}");
                                results.push(ScanResult::Error {
                                    path: entry.path().to_path_buf(),
                                    error: e.to_string(),
                                });
                            }
                        },
                        Err(e) => {
                            pb.println(format!("Error reading {path_display}: {e}"));
                            error!("Error: {e}");
                            results.push(ScanResult::Error {
                                path: entry.path().to_path_buf(),
                                error: format!("Failed to read file: {e}"),
                            });
                        }
                    }
                    pb.inc(1);
                }
            }

            pb.finish_with_message("YARA directory scan completed.");
        } else {
            anyhow::bail!(
                "Target path is neither a file nor a directory: {}",
                target_path.display()
            );
        }

        Ok(results)
    }
    pub fn heuristic_scan(path: &PathBuf) -> anyhow::Result<()> {
        let engine = SpireHeuristicEngine::new();

        let file_path = path;
        let bytes = std::fs::read(file_path).expect("unable read file");

        // Parse the file
        let file_data = match parse_file(&bytes) {
            Ok(data) => data,
            Err(_) => {
                let strings = extract_ascii_strings(&bytes, 4);
                FileData {
                    bytes,
                    file_type: FileType::Unknown,
                    strings,
                    container: FileContainer::None,
                }
            }
        };

        match engine.scan(&file_data) {
            HeuristicResult::Safe => {
                debug!("✅ Safe");
                Ok(())
            }
            HeuristicResult::Suspicious { score, reason } => {
                debug!("⚠️ Suspicious (score: {})", score);
                debug!("   Reason: {}", reason);
                Ok(())
            }
            HeuristicResult::Malicious { score, reason } => {
                debug!("❌ Malicious (score: {})", score);
                debug!("   Reason: {}", reason);
                Ok(())
            }
        }
    }
    pub fn monitor_directory(conn: &Connection, path: &Path) -> anyhow::Result<()> {
        let (tx, rx) = channel();
        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                let _ = tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_secs(1)),
        )?;

        watcher.watch(path, RecursiveMode::Recursive)?;
        info!("Monitoring directory: {}", path.display());

        for res in rx {
            match res {
                Ok(event) => {
                    if event.kind.is_create() || event.kind.is_modify() {
                        for file_path in event.paths {
                            if file_path.is_file() {
                                info!("Detected change in file: {}", file_path.display());
                                Self::scan_single_file(conn, file_path)?;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Filesystem watch error: {}", e);
                }
            }
        }

        Ok(())
    }
}
