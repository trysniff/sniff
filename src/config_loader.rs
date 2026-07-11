use crate::config::ResolvedConfig;
use crate::env_value;
use std::fs;
use std::path::{Path, PathBuf};

fn find_config_path(cwd: &Path) -> Option<PathBuf> {
    let mut current_dir = cwd.to_path_buf();
    loop {
        let potential = current_dir.join("sniff.config.toml");
        if potential.is_file() {
            return Some(potential);
        }
        if !current_dir.pop() {
            break;
        }
    }
    None
}

pub fn resolve_config(cwd: &Path) -> Result<ResolvedConfig, String> {
    let mut config = ResolvedConfig::default();

    if let Some(config_path) = find_config_path(cwd) {
        let content = fs::read_to_string(&config_path)
            .map_err(|err| format!("failed to read config {}: {}", config_path.display(), err))?;
        config = toml::from_str::<ResolvedConfig>(&content)
            .map_err(|err| format!("failed to parse config {}: {}", config_path.display(), err))?;
    }

    if let Some(model) = env_value::read("SNIFF_MODEL") {
        config.model = model;
    }

    if let Some(endpoint) = env_value::read("SNIFF_ENDPOINT") {
        config.llm.endpoint = endpoint;
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::resolve_config;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn invalid_config_fails_instead_of_using_defaults() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-invalid-config-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("sniff.config.toml"), "[thresholds\ninvalid").unwrap();

        let err = resolve_config(&root).expect_err("invalid config should fail explicitly");
        assert!(err.contains("failed to parse config"), "{err}");

        let _ = fs::remove_dir_all(&root);
    }
}
