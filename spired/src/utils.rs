use std::{fs, path::Path};

#[cfg(target_os = "windows")]
use std::os::windows::fs::MetadataExt;

use crate::Config;

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

pub fn load_config() -> anyhow::Result<Config> {
    let mut config_path =
        dirs::config_dir().ok_or_else(|| anyhow::anyhow!("Unable to get config directory"))?;
    config_path.push("spire");
    config_path.push("Config.toml");

    // Проверяем, существует ли файл
    if !Path::new(&config_path).exists() {
        // Создаем директорию, если она не существует
        let config_dir = config_path.parent().unwrap();
        fs::create_dir_all(config_dir)?;

        // Содержимое по умолчанию
        let default_content = r#"
spire_dir = ["~/.spire"]

spire_db_path =  ["data/database.db"]

yara_rules_path = ["yara_rules/yara"]

# Исключённые пути
excluded_paths = ["/root/.local/share/fish/", "/root/.spire", "/root/.spire/data/", "/root/.local/share/spire_quarantine/"]

# Исключённые расширения файлов
excluded_extensions = ["log", "tmp", "bak", "db"]

# Исключённые имена файлов
excluded_files = ["secret.txt", ".gitignore", "fish_history", ".bash_history"]

excluded_processes = ["firefox", "chrome", "systemd"]

telemetry = false
"#;

        fs::write(&config_path, default_content)?;
    }

    let config_content = fs::read_to_string(&config_path)?;

    let config: Config = toml::from_str(&config_content)?;

    Ok(config)
}
