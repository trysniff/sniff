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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProofCommands {
    pub test_command: Option<Vec<String>>,
    pub differential_command: Option<Vec<String>>,
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

/// Read the optional shell-free repository test argv without widening the
/// main runtime configuration contract. Sniff never guesses a test runner.
pub fn resolve_proof_test_command(cwd: &Path) -> Result<Option<Vec<String>>, String> {
    Ok(resolve_proof_commands(cwd)?.test_command)
}

pub fn resolve_proof_commands(cwd: &Path) -> Result<ProofCommands, String> {
    let Some(config_path) = find_config_path(cwd) else {
        return Ok(ProofCommands::default());
    };
    let content = fs::read_to_string(&config_path)
        .map_err(|err| format!("failed to read config {}: {err}", config_path.display()))?;
    let value = toml::from_str::<toml::Value>(&content)
        .map_err(|err| format!("failed to parse config {}: {err}", config_path.display()))?;
    let proof = value.get("proof");
    let test_command = parse_proof_command(proof, "test_command", &config_path)?;
    let differential_command = parse_proof_command(proof, "differential_command", &config_path)?;
    Ok(ProofCommands {
        test_command,
        differential_command,
    })
}

fn parse_proof_command(
    proof: Option<&toml::Value>,
    field: &str,
    config_path: &Path,
) -> Result<Option<Vec<String>>, String> {
    let Some(command) = proof.and_then(|proof| proof.get(field)) else {
        return Ok(None);
    };
    let values = command.as_array().ok_or_else(|| {
        format!(
            "proof.{field} in {} must be an argv array",
            config_path.display()
        )
    })?;
    let mut argv = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let argument = value.as_str().ok_or_else(|| {
            format!(
                "proof.{field} argument {index} in {} must be a string",
                config_path.display()
            )
        })?;
        if argument.is_empty() || argument.contains('\0') {
            return Err(format!(
                "proof.{field} argument {index} in {} is empty or contains NUL",
                config_path.display()
            ));
        }
        argv.push(argument.to_string());
    }
    if argv.is_empty() {
        return Err(format!(
            "proof.{field} in {} cannot be empty",
            config_path.display()
        ));
    }
    Ok(Some(argv))
}

#[cfg(test)]
mod tests {
    use super::{resolve_config, resolve_proof_commands, resolve_proof_test_command};
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

    #[test]
    fn proof_test_command_is_explicit_argv_not_shell_text() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-proof-config-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("sniff.config.toml"),
            "[proof]\ntest_command = [\"python\", \"-m\", \"pytest\", \"tests\"]\n",
        )
        .unwrap();

        let command = resolve_proof_test_command(&root).unwrap();
        assert_eq!(
            command,
            Some(vec![
                "python".to_string(),
                "-m".to_string(),
                "pytest".to_string(),
                "tests".to_string(),
            ])
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn proof_differential_command_is_loaded_separately() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-diff-proof-config-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("sniff.config.toml"),
            "[proof]\ndifferential_command = [\"python\", \"scripts\", \"probe.py\"]\n",
        )
        .unwrap();

        let commands = resolve_proof_commands(&root).unwrap();
        assert_eq!(commands.test_command, None);
        assert_eq!(
            commands.differential_command,
            Some(vec![
                "python".to_string(),
                "scripts".to_string(),
                "probe.py".to_string(),
            ])
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_proof_test_command_fails_closed() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-empty-proof-config-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("sniff.config.toml"),
            "[proof]\ntest_command = []\n",
        )
        .unwrap();

        let error = resolve_proof_test_command(&root).unwrap_err();
        assert!(error.contains("cannot be empty"));
        let _ = fs::remove_dir_all(&root);
    }
}
