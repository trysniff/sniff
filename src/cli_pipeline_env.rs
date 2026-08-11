use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn find_target_env_path(path: &Path) -> Option<PathBuf> {
    let mut current = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    };

    loop {
        let env_path = current.join(".env");
        if env_path.is_file() {
            return Some(env_path);
        }

        if !current.pop() {
            break;
        }
    }

    None
}

fn load_env_from_dir(path: &Path, skip_dotenv: bool) -> Result<(), String> {
    if skip_dotenv
        || env::var("SNIFF_SKIP_DOTENV")
            .ok()
            .map(|value| {
                !value.trim().is_empty() && value != "0" && value.to_lowercase() != "false"
            })
            .unwrap_or(false)
    {
        return Ok(());
    }

    if let Some(env_path) = find_target_env_path(path) {
        load_env_file_with_policy(&env_path, false)
            .map_err(|err| format!("failed to load env file {}: {err}", env_path.display()))?;
    }

    Ok(())
}

pub(super) fn load_working_dir_env(skip_dotenv: bool) -> Result<(), String> {
    let cwd =
        env::current_dir().map_err(|err| format!("failed to read current directory: {err}"))?;
    load_env_from_dir(&cwd, skip_dotenv)
}

pub(super) fn load_target_env(path: &Path, skip_dotenv: bool) -> Result<(), String> {
    load_env_from_dir(path, skip_dotenv)
}

fn load_env_file_with_policy(
    path: &Path,
    allow_execution_controls: bool,
) -> Result<(), std::io::Error> {
    let content = fs::read_to_string(path)?;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };

        let key = raw_key.trim();
        if key.is_empty() {
            continue;
        }
        if !allow_execution_controls && is_execution_control_key(key) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "target .env cannot configure execution control {key}; set it in the trusted working-directory environment instead"
                ),
            ));
        }

        let mut value = raw_value.trim().to_string();
        if value.len() >= 2 {
            let bytes = value.as_bytes();
            let first = bytes[0];
            let last = bytes[bytes.len() - 1];
            if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
                value = value[1..value.len() - 1].to_string();
            }
        }

        // Make the repo-local .env authoritative so Sniff behaves consistently
        // when the shell already has stale AI settings.
        unsafe {
            env::set_var(key, value);
        }
    }

    Ok(())
}

fn is_execution_control_key(key: &str) -> bool {
    matches!(
        key,
        "SNIFF_SANDBOX_RUNNER"
            | "SNIFF_INTERNAL_GRADLE_LAUNCHER"
            | "SNIFF_GRADLE_LAUNCHER_JAR"
            | "SNIFF_GRADLE_MAIN_CLASS"
            | "SNIFF_GRADLE_PROJECT"
            | "PATH"
            | "HOME"
            | "USERPROFILE"
            | "TEMP"
            | "TMP"
            | "LOCALAPPDATA"
            | "XDG_CACHE_HOME"
            | "SNIFF_CACHE_DIR"
            | "CARGO_HOME"
            | "RUSTUP_HOME"
            | "JAVA_HOME"
            | "GRADLE_USER_HOME"
            | "NODE_PATH"
            | "PYTHONPATH"
            | "PYTHONHOME"
            | "GOPATH"
            | "GOMODCACHE"
            | "GOCACHE"
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "ALL_PROXY"
            | "NO_PROXY"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        find_target_env_path, load_env_file_with_policy, load_target_env, load_working_dir_env,
    };
    use std::env;
    use std::fs;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_test_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn find_target_env_path_walks_up_from_file_scans() {
        let _lock = env_test_lock();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-env-test-{unique}"));
        let nested = root.join("src").join("pkg");
        fs::create_dir_all(&nested).unwrap();
        fs::write(root.join(".env"), "SNIFF_API_KEY=test-key\n").unwrap();
        let file_path = nested.join("module.py");
        fs::write(&file_path, "print('hello')\n").unwrap();

        let found = find_target_env_path(&file_path).expect("expected env path");
        assert_eq!(found, root.join(".env"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn load_env_file_overrides_existing_values() {
        let _lock = env_test_lock();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-env-override-test-{unique}"));
        fs::create_dir_all(&root).unwrap();
        let env_path = root.join(".env");
        fs::write(
            &env_path,
            "SNIFF_ENDPOINT=https://example.invalid/anthropic\n",
        )
        .unwrap();

        unsafe {
            env::set_var("SNIFF_ENDPOINT", "https://old.invalid/openai");
        }

        load_env_file_with_policy(&env_path, true).unwrap();
        assert_eq!(
            env::var("SNIFF_ENDPOINT").unwrap(),
            "https://example.invalid/anthropic"
        );

        unsafe {
            env::remove_var("SNIFF_ENDPOINT");
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn load_working_dir_env_reads_dotenv_from_current_directory() {
        let _lock = env_test_lock();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-env-cwd-test-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(".env"),
            "SNIFF_API_KEY=cwd-key\nSNIFF_ENDPOINT=https://cwd.example/api\n",
        )
        .unwrap();

        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(&root).unwrap();

        unsafe {
            env::remove_var("SNIFF_API_KEY");
            env::remove_var("SNIFF_ENDPOINT");
        }

        load_working_dir_env(false).expect("working directory env should load");

        assert_eq!(env::var("SNIFF_API_KEY").unwrap(), "cwd-key");
        assert_eq!(
            env::var("SNIFF_ENDPOINT").unwrap(),
            "https://cwd.example/api"
        );

        env::set_current_dir(original_dir).unwrap();
        unsafe {
            env::remove_var("SNIFF_API_KEY");
            env::remove_var("SNIFF_ENDPOINT");
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn target_env_overrides_working_dir_env() {
        let _lock = env_test_lock();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let cwd_root = std::env::temp_dir().join(format!("sniff-env-cwd-precedence-{unique}"));
        let target_root =
            std::env::temp_dir().join(format!("sniff-env-target-precedence-{unique}"));
        fs::create_dir_all(&cwd_root).unwrap();
        fs::create_dir_all(&target_root).unwrap();
        fs::write(
            cwd_root.join(".env"),
            "SNIFF_ENDPOINT=https://cwd.example/api\n",
        )
        .unwrap();
        fs::write(
            target_root.join(".env"),
            "SNIFF_ENDPOINT=https://target.example/api\n",
        )
        .unwrap();

        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(&cwd_root).unwrap();

        unsafe {
            env::remove_var("SNIFF_ENDPOINT");
        }

        load_working_dir_env(false).expect("working directory env should load");
        assert_eq!(
            env::var("SNIFF_ENDPOINT").unwrap(),
            "https://cwd.example/api"
        );

        load_target_env(&target_root, false).expect("target env should load");
        assert_eq!(
            env::var("SNIFF_ENDPOINT").unwrap(),
            "https://target.example/api"
        );

        env::set_current_dir(original_dir).unwrap();
        unsafe {
            env::remove_var("SNIFF_ENDPOINT");
        }
        let _ = fs::remove_dir_all(&cwd_root);
        let _ = fs::remove_dir_all(&target_root);
    }

    #[test]
    fn skip_dotenv_flag_prevents_loading_env_files() {
        let _lock = env_test_lock();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-env-skip-test-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(".env"),
            "SNIFF_ENDPOINT=https://skip.example/api\n",
        )
        .unwrap();

        unsafe {
            env::remove_var("SNIFF_ENDPOINT");
        }

        load_target_env(&root, true).expect("skipped dotenv should not fail");
        assert!(env::var("SNIFF_ENDPOINT").is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn target_dotenv_rejects_execution_control_variables() {
        let _lock = env_test_lock();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-env-target-control-test-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(".env"),
            "SNIFF_SANDBOX_RUNNER=C:/malicious/runner.exe\nSNIFF_ENDPOINT=https://provider.example/api\n",
        )
        .unwrap();

        unsafe {
            env::remove_var("SNIFF_SANDBOX_RUNNER");
            env::remove_var("SNIFF_ENDPOINT");
        }

        let error =
            load_target_env(&root, false).expect_err("target execution controls must fail closed");
        assert!(error.contains("SNIFF_SANDBOX_RUNNER"));
        assert!(env::var("SNIFF_SANDBOX_RUNNER").is_err());
        assert!(env::var("SNIFF_ENDPOINT").is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn target_dotenv_rejects_process_path_controls() {
        let _lock = env_test_lock();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-env-target-path-test-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".env"), "PATH=C:/malicious/bin\n").unwrap();

        let original_path = env::var_os("PATH");
        let error = load_target_env(&root, false).expect_err("target PATH must fail closed");
        assert!(error.contains("PATH"));
        assert_eq!(env::var_os("PATH"), original_path);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn working_directory_dotenv_also_rejects_execution_controls() {
        let _lock = env_test_lock();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sniff-env-cwd-control-test-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(".env"),
            "SNIFF_SANDBOX_RUNNER=C:/malicious/runner.exe\n",
        )
        .unwrap();

        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(&root).unwrap();
        unsafe {
            env::remove_var("SNIFF_SANDBOX_RUNNER");
        }

        let error = load_working_dir_env(false)
            .expect_err("working-directory dotenv controls must fail closed");
        assert!(error.contains("SNIFF_SANDBOX_RUNNER"));
        assert!(env::var("SNIFF_SANDBOX_RUNNER").is_err());

        env::set_current_dir(original_dir).unwrap();
        let _ = fs::remove_dir_all(&root);
    }
}
