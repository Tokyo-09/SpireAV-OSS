use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "windows")]
use std::os::windows::fs::MetadataExt;

use crate::Config;

pub fn get_filesystem_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if cfg!(target_os = "linux") {
        let _roots = dirs::home_dir();
    } else if cfg!(target_os = "windows") {
        for drive in b'A'..=b'Z' {
            let drive_path = PathBuf::from(format!("{}:\\", drive as char));
            if drive_path.exists() {
                roots.push(drive_path);
            }
        }
    }
    roots
}

pub fn should_monitor_path(path: &Path, config: &Config) -> bool {
    for excluded_path in &config.excluded_paths {
        if path.starts_with(excluded_path) {
            return false;
        }
    }

    if let Some(extension) = path.extension().and_then(|ext| ext.to_str())
        && config
            .excluded_extensions
            .contains(&extension.to_lowercase())
    {
        return false;
    }

    if let Some(file_name) = path.file_name().and_then(|name| name.to_str())
        && config.excluded_files.contains(&file_name.to_string())
    {
        return false;
    }

    true
}

pub fn load_config(path: &str) -> anyhow::Result<Config> {
    let config_content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&config_content)?;
    Ok(config)
}
