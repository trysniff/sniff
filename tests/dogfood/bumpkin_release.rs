use super::*;

#[test]
fn brandset_runtime_wireup_surfaces_real_slop_while_supporting_neighbors_stay_clean() {
    let root = unique_root("sniff-dogfood-brandset-runtime-wireup");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "ui/background/core/runtime-wireup.ts",
        &ts_slop_bundle("runtimeWireup", "registerRuntimeWireup"),
    );
    write_file(
        &root,
        "ui/background/core/ops-handlers.ts",
        &ts_clean_module("createOpsHandlers"),
    );
    write_file(
        &root,
        "ui/background/core/session-init-payload.ts",
        &ts_clean_module("buildSessionInitPayload"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("ui").join("background").join("core"))
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
        report.contains("runtime-wireup.ts"),
        "runtime-wireup should be surfaced as slop:\n{}",
        report
    );
    for clean_name in ["ops-handlers.ts", "session-init-payload.ts"] {
        assert!(
            !report.contains(clean_name),
            "{clean_name} should stay out of the report:\n{}",
            report
        );
    }

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("runtime-wireup")
            && prompt_text.contains("ops-handlers")
            && prompt_text.contains("session-init-payload"),
        "expected the runtime boundary surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn brandset_frame_sync_surfaces_real_slop_while_progress_runtime_stays_clean() {
    let root = unique_root("sniff-dogfood-brandset-frame-sync");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "ui/background/core/frame-sync.ts",
        &ts_slop_bundle("frameSync", "createFrameSyncCoordinator"),
    );
    write_file(
        &root,
        "ui/background/core/session-progress-runtime.ts",
        &ts_clean_module("createSessionProgressRuntime"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(root.join("ui").join("background").join("core"))
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
        report.contains("frame-sync.ts"),
        "frame-sync should be surfaced as slop:\n{}",
        report
    );
    assert!(
        !report.contains("session-progress-runtime.ts"),
        "session-progress-runtime should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("frame-sync.ts")
            && prompt_text.contains("session-progress-runtime.ts"),
        "expected the frame sync surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_release_orchestration_surfaces_real_slop_while_analysis_stays_clean() {
    let root = unique_root("sniff-dogfood-bumpkin-release-orchestration");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/orchestrator/pipeline.py",
        &python_slop_bundle("pipeline", "run_pipeline"),
    );
    write_file(
        &root,
        "src/bumpkin/release/planning.py",
        &python_slop_bundle("planning", "prepare_release_plan"),
    );
    write_file(
        &root,
        "src/bumpkin/release/analysis.py",
        &python_clean_module("review_release_analysis"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
        report.contains("pipeline.py"),
        "pipeline.py should be surfaced as slop:\n{}",
        report
    );
    assert!(
        report.contains("planning.py"),
        "planning.py should be surfaced as slop:\n{}",
        report
    );
    assert!(
        !report.contains("release/analysis.py"),
        "release analysis helpers should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("pipeline.py")
            && prompt_text.contains("planning.py")
            && prompt_text.contains("analysis.py"),
        "expected the release orchestration surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_repository_client_surfaces_real_slop_while_release_helpers_stay_clean() {
    let root = unique_root("sniff-dogfood-bumpkin-repository-client");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/release/repository_client.py",
        &python_slop_bundle("repositoryClient", "get_pull_request"),
    );
    write_file(
        &root,
        "src/bumpkin/release/candidate.py",
        &python_clean_module("build_candidate"),
    );
    write_file(
        &root,
        "src/bumpkin/release/output_writers.py",
        &python_clean_module("write_release_output"),
    );
    write_file(
        &root,
        "src/bumpkin/release/analysis.py",
        &python_clean_module("review_release_analysis"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
        report.contains("repository_client.py"),
        "repository_client.py should be surfaced as slop:\n{}",
        report
    );
    for clean_name in ["candidate.py", "output_writers.py", "analysis.py"] {
        assert!(
            !report.contains(clean_name),
            "{clean_name} should stay out of the report:\n{}",
            report
        );
    }

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("repository_client.py")
            && prompt_text.contains("candidate.py")
            && prompt_text.contains("output_writers.py")
            && prompt_text.contains("analysis.py"),
        "expected the release client surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_release_rationale_surfaces_real_slop_while_publish_stays_clean() {
    let root = unique_root("sniff-dogfood-bumpkin-release-rationale");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/release/rationale.py",
        &python_slop_bundle("releaseRationale", "build_release_why"),
    );
    write_file(
        &root,
        "src/bumpkin/release/publish.py",
        &python_clean_module("publish_release"),
    );
    write_file(
        &root,
        "src/bumpkin/release/analysis.py",
        &python_clean_module("review_release_analysis"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
        report.contains("rationale.py"),
        "rationale.py should be surfaced as slop:\n{}",
        report
    );
    for clean_name in ["publish.py", "analysis.py"] {
        assert!(
            !report.contains(clean_name),
            "{clean_name} should stay out of the report:\n{}",
            report
        );
    }

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("rationale.py")
            && prompt_text.contains("publish.py")
            && prompt_text.contains("analysis.py"),
        "expected the release rationale surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_release_comments_surfaces_real_slop_while_tokens_stays_clean() {
    let root = unique_root("sniff-dogfood-bumpkin-release-comments");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/io/comments.py",
        &python_slop_bundle("commentMetadata", "build_comment_metadata"),
    );
    write_file(
        &root,
        "src/bumpkin/io/tokens.py",
        &python_clean_module("count_tokens"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
        report.contains("comments.py"),
        "comments.py should be surfaced as slop:\n{}",
        report
    );
    assert!(
        !report.contains("tokens.py"),
        "tokens.py should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("comments.py") && prompt_text.contains("tokens.py"),
        "expected the io comment surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bumpkin_policy_engine_surfaces_real_slop_while_guards_stays_clean() {
    let root = unique_root("sniff-dogfood-bumpkin-policy-engine");
    fs::create_dir_all(&root).unwrap();

    let (endpoint, _hits, prompts) = spawn_prompt_logging_server();
    let endpoint = format!("{}/chat/completions", endpoint);

    write_file(
        &root,
        "src/bumpkin/policies/engine.py",
        &python_slop_bundle("policyEngine", "apply_impact_threshold"),
    );
    write_file(
        &root,
        "src/bumpkin/policies/guards.py",
        &python_clean_module("check_release_guards"),
    );

    fs::write(
        root.join(".env"),
        format!("SNIFF_API_KEY=test-key\nSNIFF_ENDPOINT={endpoint}\nSNIFF_MODEL=test-model\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sniff"))
        .current_dir(&root)
        .arg(".")
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
        report.contains("engine.py"),
        "engine.py should be surfaced as slop:\n{}",
        report
    );
    assert!(
        !report.contains("guards.py"),
        "guards.py should stay out of the report:\n{}",
        report
    );

    let prompt_text = prompts.lock().unwrap().join("\n");
    assert!(
        prompt_text.contains("engine.py") && prompt_text.contains("guards.py"),
        "expected the policy engine surfaces to be reviewed by the mock provider:\n{}",
        prompt_text
    );

    let _ = fs::remove_dir_all(&root);
}
