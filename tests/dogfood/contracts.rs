use super::*;

#[test]
fn bumpkin_github_integration_subtree_matches_current_report_contract() {
    let root = unique_root("sniff-dogfood-bumpkin-github-integration");
    fs::create_dir_all(&root).unwrap();
    let (endpoint, mut child) = spawn_bumpkin_github_integration_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    let github_root = root.join("src/bumpkin/integrations/github");
    fs::create_dir_all(&github_root).unwrap();
    write_file(&root, ".env", "");
    for name in [
        "contracts.py",
        "ingress.py",
        "reactions.py",
        "recommendations.py",
        "webhook.py",
        "webhook_commands.py",
        "webhook_service.py",
        "persistence_sqlite.py",
        "github_auth.py",
    ] {
        let source = if name == "github_auth.py" {
            "def normalize_auth_header(value):\n    if value:\n        return value.strip()\n    return None\n"
                .to_string()
        } else {
            python_slop_module(name.trim_end_matches(".py"))
        };
        write_file(
            &root,
            &format!("src/bumpkin/integrations/github/{name}"),
            &source,
        );
    }

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&github_root)
        .arg("--skip-dotenv")
        .env("SNIFF_API_KEY", "test-key")
        .env("SNIFF_ENDPOINT", &endpoint)
        .env("SNIFF_MODEL", "test-model")
        .env("SNIFF_LLM_MAX_CONCURRENCY", "1")
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(report.contains("AI response coverage:**"));
    assert!(report.contains("Trusted method verdicts:**"));

    child.kill();
    child.wait();
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn brandset_background_core_subtree_matches_current_report_contract() {
    let root = unique_root("sniff-dogfood-brandset-background-core");
    fs::create_dir_all(&root).unwrap();
    let expected = [
        "domain-gateway.ts",
        "drop-payload-staging.ts",
        "frame-sync.ts",
        "registry-sync.ts",
        "runtime-wireup.ts",
    ];
    let (endpoint, _hits, _prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    let background_root = root.join("ui/background/core");
    fs::create_dir_all(&background_root).unwrap();
    write_file(&root, ".env", "");
    for name in expected {
        write_file(
            &root,
            &format!("ui/background/core/{name}"),
            &ts_slop_module(name.trim_end_matches(".ts")),
        );
    }

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&background_root)
        .arg("--skip-dotenv")
        .env("SNIFF_API_KEY", "test-key")
        .env("SNIFF_ENDPOINT", &endpoint)
        .env("SNIFF_MODEL", "test-model")
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(report.contains("AI response coverage:**"));
    assert!(report.contains("Trusted method verdicts:**"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn data_catalog_modules_stay_out_of_the_report_end_to_end() {
    let root = unique_root("sniff-dogfood-data-catalog");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    populate_data_catalog_repo(&root);

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(
        report.contains("sloppy.py"),
        "expected the real slop file to appear in the report:\n{}",
        report
    );
    assert!(
        !report.contains("platforms.ts"),
        "data catalog glue should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        !prompt_text.contains("File path: platforms.ts"),
        "methodless data catalog glue should not consume a method review:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn pure_contract_type_modules_stay_out_of_the_report_end_to_end() {
    let root = unique_root("sniff-dogfood-contract-types");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    populate_contract_type_repo(&root);

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(
        report.contains("sloppy.py"),
        "expected the real slop file to appear in the report:\n{}",
        report
    );
    assert!(
        !report.contains("session-runtime-contracts.ts"),
        "contract-only type files should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        !prompt_text.contains("File path: session-runtime-contracts.ts"),
        "methodless contract-only type files should not consume a method review:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn small_python_package_with_generated_downloads_stays_clean_end_to_end() {
    let root = unique_root("sniff-python-package-downloads");
    let src_dir = root.join("src").join("python_test");
    let downloads_dir = root.join("downloads");
    let generated_dir = root.join("generated");
    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(&downloads_dir).unwrap();
    fs::create_dir_all(&generated_dir).unwrap();

    write_file(
        &root,
        "src/python_test/__init__.py",
        "from .api import ApiClient\n",
    );
    write_file(
        &root,
        "src/python_test/api.py",
        "def build_client(name):\n    return {\"name\": name}\n",
    );
    write_file(
        &root,
        "src/python_test/catalog.py",
        "def list_catalog_items(items):\n    return [item.strip() for item in items]\n",
    );
    write_file(
        &root,
        "src/python_test/formal.py",
        "def format_record(record):\n    return f'{record}'.strip()\n",
    );
    write_file(
        &root,
        "generated/auto_generated.py",
        "# auto-generated\n\ndef generated_helper():\n    return 1\n",
    );
    fs::write(downloads_dir.join("release-notes.zip"), b"PK\x03\x04").unwrap();
    fs::write(downloads_dir.join("release-notes.md"), "# notes\n").unwrap();
    fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"python-test\"\nversion = \"0.0.0\"\n",
    )
    .unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);
    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "expected a clean scan to exit successfully:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(
        report.contains("Scanned:** 4 files"),
        "expected the tiny Python package to scan only the supported source files:\n{}",
        report
    );
    assert!(
        report.contains("AI response coverage:** 3 of 3 review records emitted, 0 missing")
            && report
                .contains("Trusted method verdicts:** 3 of 3 resolved, 0 unresolved, 0 missing"),
        "expected all three eligible methods to complete:\n{}",
        report
    );
    assert!(
        report.contains("Slop findings:** 0 slop | 0 kinda slop"),
        "expected the package to stay clean:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        !prompt_text.contains("File path: __init__.py")
            && prompt_text.contains("File path: ")
            && prompt_text.contains("api.py")
            && prompt_text.contains("catalog.py")
            && prompt_text.contains("formal.py"),
        "expected only the three files with eligible methods to be reviewed:\n{}",
        prompt_text
    );
    assert!(
        !prompt_text.contains("generated/auto_generated.py"),
        "generated files should stay out of the review path:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn skillmatch_backend_hotspots_match_the_current_report_contract() {
    let root = unique_root("sniff-dogfood-skillmatch-backend");
    fs::create_dir_all(&root).unwrap();
    write_file(&root, ".env", "");

    for name in [
        "applicationController.js",
        "jobController.js",
        "postsController.js",
        "userController.js",
    ] {
        let source = format!(
            "{}{}",
            js_slop_bundle(name.trim_end_matches(".js")),
            js_branchy_helpers(name.trim_end_matches(".js"), 18)
        );
        write_file(&root, &format!("src/{name}"), &source);
    }

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .arg("--skip-dotenv")
        .env("SNIFF_API_KEY", "test-key")
        .env("SNIFF_ENDPOINT", &endpoint)
        .env("SNIFF_MODEL", "test-model")
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(report.contains("applicationController.js"));
    assert!(report.contains("jobController.js"));
    assert!(report.contains("postsController.js"));
    assert!(report.contains("userController.js"));
    assert!(report.contains("AI response coverage:** 84 of 84 review records emitted, 0 missing"));
    assert!(
        report.contains("Trusted method verdicts:** 84 of 84 resolved, 0 unresolved, 0 missing")
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("File path: ")
            && prompt_text.contains("applicationController.js")
            && prompt_text.contains("jobController.js")
            && prompt_text.contains("userController.js"),
        "expected the backend hotspots to be reviewed by the mock provider:\n{}",
        prompt_text
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn console_summary_does_not_leak_report_findings() {
    let root = unique_root("sniff-dogfood-console-filter");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(&root, "src/sloppy.py", &python_slop_module("sloppy"));
    write_file(
        &root,
        "src/borderline.py",
        "def borderline(value):\n    if value:\n        return value\n    return 1\n",
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Report written to"));
    assert!(stdout.contains("Findings:"));
    assert!(!stdout.contains("Affected files:"));
    assert!(!stdout.contains("sloppy.py"));
    assert!(
        !stdout.contains("Top reasons") && !stdout.contains("Evidence:"),
        "console output should not leak report details:\n{}",
        stdout
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("sloppy.py"),
        "expected the slop file to be reviewed by the mock provider"
    );

    let _ = fs::remove_dir_all(&root);
}
