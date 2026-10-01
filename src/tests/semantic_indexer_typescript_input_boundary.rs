use super::*;
use crate::sandbox::SandboxOutput;
use tempfile::TempDir;

fn spec() -> PinnedIndexer {
    pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap()
}

fn evidence() -> SemanticIndexerProcessEvidence {
    let stdout = "provider output\n".to_string();
    let stderr = "compiler diagnostic\n".to_string();
    process_evidence(SandboxOutput {
        status_code: Some(0),
        stdout_sha256: format!("{:x}", Sha256::digest(stdout.as_bytes())),
        stderr_sha256: format!("{:x}", Sha256::digest(stderr.as_bytes())),
        stdout,
        stderr,
        timed_out: false,
        memory_limit_exceeded: false,
        process_limit_exceeded: false,
    })
}

#[test]
fn post_index_input_failure_retains_actual_process_but_never_invents_one_for_cache_reuse() {
    for process in [None, Some(evidence())] {
        let guard = typescript_inputs::input_failure(spec(), "runtime changed");
        let failure = finish_variant(Ok((42, process.clone())), Err(guard)).unwrap_err();
        assert_eq!(failure.process.as_deref(), process.as_ref());
        assert_eq!(
            failure.phase,
            SemanticIndexerRunPhase::IntegrityVerification
        );
    }
    assert_eq!(finish_variant(Ok((42, None)), Ok(())).unwrap(), (42, None));
}

#[test]
fn failed_index_and_later_input_guard_retain_diagnostics_and_primary_evidence() {
    let process = evidence();
    let mut run = typescript_inputs::input_failure(spec(), "invalid SCIP output");
    run.process = Some(Box::new(process.clone()));
    let guard = typescript_inputs::input_failure(spec(), "installation changed");
    let failure = finish_variant::<i32>(Err(run), Err(guard)).unwrap_err();
    assert_eq!(failure.process.as_deref(), Some(&process));
    assert_eq!(
        failure.detail,
        "invalid SCIP output; additionally, installation changed"
    );
    let mut guard = typescript_inputs::input_failure(spec(), "primary guard");
    let mut own = process.clone();
    own.stdout = "guard evidence".into();
    own.stdout_sha256 = format!("{:x}", Sha256::digest(own.stdout.as_bytes()));
    guard.process = Some(Box::new(own.clone()));
    let failure = finish_variant(Ok((42, Some(process))), Err(guard)).unwrap_err();
    assert_eq!(failure.process.as_deref(), Some(&own));
}

#[tokio::test]
#[ignore = "requires checksum-pinned TypeScript, Node.js and native sandbox"]
async fn normal_scan_rejects_stale_or_removed_census_inputs_before_worker_or_progress_reuse() {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("tsconfig.json"),
        r#"{"files":["index.ts"]}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("index.ts"),
        "export function value() { return 1; }\n",
    )
    .unwrap();
    let files = [
        crate::parser::parse_file_checked(root.path().join("index.ts").to_str().unwrap()).unwrap(),
    ];
    let before = repository_snapshot::repository_content_digest(root.path()).unwrap();
    let store = SemanticIndexerStore::for_user().unwrap();
    let installed = store.verify(spec()).unwrap();
    let recovery = recovery::SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
    let progress_root = root.path().join(".sniff/semantic-progress");
    fs::create_dir_all(&progress_root).unwrap();
    let context = RequiredIndexerRunContext {
        root: root.path(),
        files: &files,
        required_documents: &files,
        store: &store,
        recovery: &recovery,
        repository_content_sha256: &before,
        progress_root: Some(&progress_root),
    };
    let plans = super::super::typescript_model::discover(&context)
        .await
        .unwrap();
    assert!(!root.path().join(INDEXER_TEMP_DIR).exists());
    typescript_inputs::observe(&context, spec(), &installed).unwrap();
    assert!(
        !root.path().join(INDEXER_TEMP_DIR).exists(),
        "input probes must not stage a runtime in the source repository"
    );
    for (key, missing) in [
        ("compiler_runtime_sha256", false),
        ("compiler_installation_sha256", false),
        ("compiler_runtime_sha256", true),
    ] {
        let mut changed = plans.clone();
        if missing {
            changed[0].dimensions.remove(key);
        } else {
            changed[0].dimensions.insert(key.into(), "f".repeat(64));
        }
        let failure = run_typescript_variants(&context, spec(), &installed, &changed)
            .await
            .unwrap_err();
        assert_eq!(
            failure.phase,
            SemanticIndexerRunPhase::IntegrityVerification
        );
        assert!(
            failure.process.is_none(),
            "no graph worker must start: {failure:?}"
        );
        assert!(!root.path().join("index.scip").exists());
        let family = progress_root.join("typescript");
        assert!(
            !family.exists() || fs::read_dir(&family).unwrap().next().is_none(),
            "must not publish progress before input guard"
        );
    }
    run_typescript_variants(&context, spec(), &installed, &plans)
        .await
        .unwrap()
        .validate()
        .unwrap();
    let plan = &plans[0];
    let unit = progress_unit(spec(), plan).unwrap();
    let identity = prepare_progress_identity(&context, spec(), &installed).unwrap();
    let progress =
        open_variant_progress(&progress_root, spec(), &installed, plan, &unit, &identity).unwrap();
    let selected = files_for_plan(context.root, context.files, plan).unwrap();
    let (_, process) = run_or_resume_variant(
        &context,
        spec(),
        &installed,
        plan,
        &selected,
        Some(&progress),
        &unit,
    )
    .await
    .unwrap();
    assert!(
        process.is_none(),
        "warm checkpoint must not launch a graph worker"
    );
    assert!(!root.path().join(INDEXER_TEMP_DIR).exists());
    run_typescript_variants(&context, spec(), &installed, &plans)
        .await
        .unwrap();
    assert!(!root.path().join(INDEXER_TEMP_DIR).exists());

    let execution_root = recovery.prepare_indexer_run().unwrap();
    repository_snapshot::stage_repository_snapshot(context.root, &execution_root).unwrap();
    fs::create_dir(execution_root.join(INDEXER_TEMP_DIR)).unwrap();
    let mut prepared = build_indexer_sandbox_command(
        spec(),
        &execution_root,
        &installed,
        variant_arguments(spec(), plan).unwrap(),
        None,
    )
    .unwrap();
    // Alter only the private prepared image, never the machine's Node runtime.
    let changed_image = execution_root
        .join(INDEXER_TEMP_DIR)
        .join("changed-node-image");
    fs::write(&changed_image, b"different prepared worker image").unwrap();
    prepared.command.program = changed_image.to_string_lossy().into_owned();
    prepared.runtime_files = vec![changed_image];
    let failure = typescript_inputs::run_worker(prepared, spec(), &installed, plan)
        .await
        .unwrap_err();
    assert_eq!(
        failure.phase,
        SemanticIndexerRunPhase::IntegrityVerification
    );
    assert!(failure.detail.contains("execution inputs differ"));
    assert!(
        failure.process.is_none(),
        "mismatched prepared image must never start"
    );
    recovery.finish_indexer_run().unwrap();
    assert!(!root.path().join("index.scip").exists());
    fs::write(
        root.path().join("tsconfig.json"),
        r#"{"compilerOptions":{"strict":true},"files":["index.ts"]}"#,
    )
    .unwrap();
    let failure = run_typescript_variants(&context, spec(), &installed, &plans)
        .await
        .unwrap_err();
    assert!(failure.detail.contains("repository changed"));
    assert!(failure.process.is_none());
    fs::write(
        root.path().join("tsconfig.json"),
        r#"{"files":["index.ts"]}"#,
    )
    .unwrap();
    assert_eq!(
        repository_snapshot::repository_content_digest(root.path()).unwrap(),
        before
    );
    recovery.finish().unwrap();
    assert!(!root.path().join(".sniff-indexer-recovery.json").exists());
}
