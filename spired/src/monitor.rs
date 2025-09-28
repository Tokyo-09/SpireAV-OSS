use std::{sync::mpsc::channel, time::Duration};

use av_core::SpireAvScanner;
use log::{debug, error, info};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use rusqlite::Connection;

use crate::{Config, utils::should_monitor_path};

pub fn monitor_directory(conn: &Connection, config: Config) -> anyhow::Result<()> {
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
