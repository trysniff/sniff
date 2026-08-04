use super::*;

#[test]
fn unresolved_method_is_reported_and_exits_non_successfully() {
    let root = unique_root("sniff-unresolved-method");
    fs::create_dir_all(&root).unwrap();
    write_file(
        &root,
        "src/boundary.py",
        "def external_boundary(value):\n    return external_package.transform(value)\n",
    );
    let endpoint = format!("{}/chat/completions", spawn_unresolved_method_server());
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

    assert_eq!(
        output.status.code(),
        Some(1),
        "Unresolved must be a visible non-success result.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = fs::read_to_string(root.join("sniff-report.md")).unwrap();
    assert!(report.contains("## Unresolved Reviews"));
    assert!(report.contains("`external_boundary`"));
    assert!(report.contains("Missing evidence: external package implementation and consumers"));
    assert!(report.contains("Do not edit from these entries"));
    assert!(!report.contains("Recommended action"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn failed_ai_setup_preserves_last_completed_report() {
    let root = unique_root("sniff-dogfood-stale-report");
    fs::create_dir_all(&root).unwrap();
    write_file(&root, "src/sample.py", "def sample():\n    return 1\n");
    write_file(
        &root,
        "sniff-report.md",
        "stale report from an earlier run\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
        .arg("--skip-dotenv")
        .env_remove("SNIFF_API_KEY")
        .env_remove("SNIFF_ENDPOINT")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("AI config is missing") || stderr.contains("AI model is missing"),
        "expected explicit AI setup failure:\n{}",
        stderr
    );
    assert_eq!(
        fs::read_to_string(root.join("sniff-report.md")).unwrap(),
        "stale report from an earlier run\n",
        "a failed scan must not destroy the last completed report"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_style_repo_scan_finishes_without_stack_overflow() {
    let root = unique_root("sniff-dogfood-regression");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits) = spawn_openai_style_server();
    let endpoint = format!("{}/chat/completions", endpoint);
    populate_bumpkin_like_repo(&root);

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("src").join("bumpkin"))
        .arg("--only-files")
        .output()
        .unwrap();

    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "unexpected exit status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("overflowed its stack"),
        "scan still overflowed the stack:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(root.join("sniff-report.md").exists());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn deprecated_only_files_alias_adds_file_reviews_without_skipping_methods() {
    let root = unique_root("sniff-dogfood-signature-hotspot");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    let mut source = String::from("from __future__ import annotations\n\n");
    for idx in 0..20 {
        source.push_str(&format!(
            "def helper_{idx}(value):\n    return value\n\n",
            idx = idx
        ));
    }
    source.push_str("def extract_python_signatures(items):\n    total = 0\n");
    for idx in 0..52 {
        source.push_str(&format!(
            "    if items:\n        total += {idx}\n",
            idx = idx
        ));
    }
    source.push_str("    return total\n");

    write_file(
        &root,
        "src/bumpkin/analysis/finding_python_signatures.py",
        &source,
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("src"))
        .arg("--only-files")
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
        report.contains("finding_python_signatures.py"),
        "signature hotspot should surface in only-files mode:\n{}",
        report
    );
    assert!(
        report.contains("Slop"),
        "signature hotspot should still be slop in only-files mode:\n{}",
        report
    );
    assert!(
        prompts
            .lock()
            .unwrap()
            .iter()
            .any(|prompt| prompt.contains("Filename: finding_python_signatures.py")),
        "expected the hotspot file to be reviewed by the mock provider"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn support_facades_are_reviewed_and_real_slop_still_surfaces_end_to_end() {
    let root = unique_root("sniff-dogfood-slf");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/orchestrator/explanation_facts.py",
        "from bumpkin.analysis.explanation_facts import *  # noqa: F403\n",
    );
    write_file(
        &root,
        "src/bumpkin/orchestrator/base_classification.py",
        "def determine_base_classification():\n    return None\n",
    );
    write_file(
        &root,
        "src/bumpkin/orchestrator/analysis_stage.py",
        "def apply_analysis_stage():\n    return None\n",
    );
    write_file(
        &root,
        "src/bumpkin/orchestrator/explainability.py",
        "def build_explainability_rows():\n    return []\n",
    );
    write_file(
        &root,
        "src/bumpkin/orchestrator/explanation_polish.py",
        "def should_run_explanation_polish():\n    return False\n",
    );
    write_file(
        &root,
        "src/bumpkin/orchestrator/postprocess.py",
        "def build_semantic_trace_artifacts():\n    return None\n",
    );
    write_file(
        &root,
        "src/bumpkin/orchestrator/court_output.py",
        "def apply_docs_only_policy():\n    return None\n",
    );
    write_file(
        &root,
        "src/bumpkin/orchestrator/court_payload.py",
        "def extract_json_payload():\n    return None\n",
    );
    write_file(
        &root,
        "src/bumpkin/orchestrator/court_setup.py",
        "def prepare_court_setup():\n    return None\n",
    );
    write_file(
        &root,
        "src/bumpkin/integrations/github/guards.py",
        "def evaluate_publish_guard():\n    return True\n",
    );
    write_file(
        &root,
        "src/bumpkin/policies/guards.py",
        "def apply_analysis_coverage_guard():\n    return True\n",
    );
    write_file(
        &root,
        "src/bumpkin/core/sloppy.py",
        "def sloppy(a, b, c, d, e, f):\n    total = 0\n    if a:\n        total += a\n    if b:\n        total += b\n    if c:\n        total += c\n    if d:\n        total += d\n    if e:\n        total += e\n    if f:\n        total += f\n    for i in range(10):\n        total += i\n    return total\n",
    );
    write_file(
        &root,
        "src/bumpkin/core/app.ts",
        "export function buildApp() {\n  return null;\n}\n",
    );
    write_file(&root, "src/bumpkin/core/lib.rs", "pub fn run() {}\n");
    write_file(
        &root,
        "src/bumpkin/core/server.go",
        "package core\n\nfunc Run() {}\n",
    );
    write_file(
        &root,
        "src/bumpkin/core/Helper.kt",
        "fun helper(): Int = 1\n",
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("src"))
        .arg("--only-files")
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
        !report.contains("app.ts"),
        "clean surfaces should stay out of the default report:\n{}",
        report
    );
    assert!(
        !report.contains("lib.rs"),
        "clean surfaces should stay out of the default report:\n{}",
        report
    );
    assert!(
        !report.contains("server.go"),
        "clean surfaces should stay out of the default report:\n{}",
        report
    );
    assert!(
        !report.contains("Helper.kt"),
        "clean surfaces should stay out of the default report:\n{}",
        report
    );
    assert!(
        report.contains("Slop"),
        "expected the real slop file to be surfaced as slop:\n{}",
        report
    );
    assert!(
        !report.contains("explanation_facts.py"),
        "support facade should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("base_classification.py"),
        "support plumbing should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("analysis_stage.py"),
        "support plumbing should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("explainability.py"),
        "support plumbing should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("explanation_polish.py"),
        "support plumbing should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("postprocess.py"),
        "support plumbing should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("court_output.py"),
        "support plumbing should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("court_payload.py"),
        "support plumbing should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("court_setup.py"),
        "support plumbing should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("integrations/github/guards.py"),
        "support plumbing should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("policies/guards.py"),
        "support plumbing should stay out of the report:\n{}",
        report
    );

    let prompts = prompts.lock().unwrap();
    assert!(
        prompts.iter().any(|prompt| prompt.contains("sloppy.py")),
        "expected the slop file to be reviewed by the mock provider"
    );
    assert!(
        prompts
            .iter()
            .any(|prompt| prompt.contains("Filename: explanation_facts.py")),
        "support re-export shims should be reviewed as files"
    );
    assert!(
        prompts
            .iter()
            .any(|prompt| prompt.contains("Filename: postprocess.py")),
        "expected the support orchestration file to be reviewed as a file"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn react_main_entrypoints_stay_out_of_the_report_but_are_reviewed_end_to_end() {
    let root = unique_root("sniff-dogfood-react-entrypoint");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    populate_react_entrypoint_repo(&root);

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(&root)
        .arg("--only-files")
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
        !report.contains("main.tsx"),
        "React entrypoints should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("Filename: main.tsx"),
        "main.tsx should be reviewed by the AI before its intentional-surface verdict is normalized:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn methodless_compatibility_shims_stay_out_of_the_report_without_ai_spend() {
    let root = unique_root("sniff-dogfood-compat-shim");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/MedicationDetailsContract.kt",
        "@file:Suppress(\"unused\")\n\npackage com.onpill.shared.uicontract\n\n// Compatibility shim: declarations were decomposed into:\n// - MedicationDetailsModels.kt\n// - MedicationDetailsFieldOptions.kt\n// - MedicationDetailsActions.kt\n",
    );
    write_file(
        &root,
        "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/RemindersCabinetContract.kt",
        "@file:Suppress(\"unused\")\n\npackage com.onpill.shared.uicontract\n\n// Compatibility shim: declarations were decomposed into:\n// - RemindersCabinetModels.kt\n// - RemindersCabinetActions.kt\n// - RemindersCabinetReducer.kt\n",
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("shared"))
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
        report.contains("0 slop | 0 kinda slop"),
        "compatibility shims should stay out of the report:\n{}",
        report
    );
    assert!(
        !report.contains("MedicationDetailsContract.kt"),
        "compatibility shim filenames should not be surfaced as slop:\n{}",
        report
    );
    assert!(
        !report.contains("RemindersCabinetContract.kt"),
        "compatibility shim filenames should not be surfaced as slop:\n{}",
        report
    );
    assert!(report.contains("AI coverage:** 0 of 0 expected reviews completed, 0 missed"));

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.is_empty(),
        "files with no methods should not buy method or file reviews:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}
