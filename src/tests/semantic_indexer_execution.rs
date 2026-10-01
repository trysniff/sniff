use super::*;
use tempfile::TempDir;

fn spec() -> PinnedIndexer {
    pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap()
}

fn output(status: Option<i32>) -> SandboxOutput {
    let stdout = "worker stdout\n".to_string();
    let stderr = "worker stderr\n".to_string();
    SandboxOutput {
        status_code: status,
        stdout_sha256: format!("{:x}", Sha256::digest(stdout.as_bytes())),
        stderr_sha256: format!("{:x}", Sha256::digest(stderr.as_bytes())),
        stdout,
        stderr,
        timed_out: false,
        memory_limit_exceeded: false,
        process_limit_exceeded: false,
    }
}

struct Fixture {
    root: TempDir,
    recovery: SemanticIndexerRecoveryGuard,
    execution_root: PathBuf,
    files: Vec<FileRecord>,
    digest: String,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        fs::write(
            root.path().join("index.ts"),
            "export function value() { return 1; }\n",
        )
        .unwrap();
        fs::write(
            root.path().join("tsconfig.json"),
            r#"{"files":["index.ts"]}"#,
        )
        .unwrap();
        let files = vec![
            crate::parser::parse_file_checked(root.path().join("index.ts").to_str().unwrap())
                .unwrap(),
        ];
        let recovery = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        let execution_root = recovery.prepare_indexer_run().unwrap();
        repository_snapshot::stage_repository_snapshot(root.path(), &execution_root).unwrap();
        let digest = source_integrity_digest_at(root.path(), &execution_root, &files).unwrap();
        Self {
            root,
            recovery,
            execution_root,
            files,
            digest,
        }
    }

    fn completion(&self) -> Completion<'_> {
        Completion {
            spec: spec(),
            root: self.root.path(),
            execution_root: &self.execution_root,
            files: &self.files,
            recovery: &self.recovery,
            typescript_plan: None,
            source_digest_before: &self.digest,
        }
    }

    fn finish(self) {
        self.recovery.finish().unwrap();
    }
}

#[test]
fn cleanup_and_source_faults_keep_actual_evidence_and_attempt_remaining_cleanup() {
    for status in [Some(0), Some(2), None] {
        let fixture = Fixture::new();
        let cache = fixture.execution_root.join(INDEXER_CACHE_DIR);
        fs::create_dir(&cache).unwrap();
        let missing_project = fixture
            .execution_root
            .join(INDEXER_TEMP_DIR)
            .join("missing.json");
        fs::write(fixture.execution_root.join("index.ts"), "changed source").unwrap();
        let raw = output(status);
        let expected = process_evidence(raw.clone());
        let failure = fixture
            .completion()
            .finish(Ok(raw), Some(missing_project), None, Some(cache.clone()))
            .unwrap_err();
        assert_eq!(failure.process.as_deref(), Some(&expected));
        assert_eq!(
            failure.phase,
            SemanticIndexerRunPhase::IntegrityVerification
        );
        assert!(failure.detail.contains("project cleanup failed"));
        assert!(
            failure
                .detail
                .contains("differs from parsed source snapshot")
        );
        assert!(
            !cache.exists(),
            "cleanup must continue after an earlier guard error"
        );
        assert!(!fixture.root.path().join("index.scip").exists());
        fixture.finish();
    }
}

#[test]
fn startup_failure_and_multiple_guards_keep_diagnostics_without_inventing_a_process() {
    let fixture = Fixture::new();
    let missing = fixture.execution_root.join("missing.json");
    fs::remove_file(fixture.execution_root.join("index.ts")).unwrap();
    let failure = fixture
        .completion()
        .finish(
            Err(execution_failure(
                spec(),
                SemanticIndexerRunPhase::Execution,
                "sandbox did not start",
            )),
            Some(missing),
            None,
            None,
        )
        .unwrap_err();
    assert!(failure.process.is_none());
    assert!(failure.detail.contains("sandbox did not start"));
    assert!(failure.detail.contains("project cleanup failed"));
    assert!(failure.detail.contains("failed to hash eligible source"));
    fixture.finish();
}

#[test]
fn publication_collision_and_missing_index_retain_worker_evidence() {
    for collision in [false, true] {
        let fixture = Fixture::new();
        if collision {
            fs::write(fixture.execution_root.join("index.scip"), b"index fixture").unwrap();
            fs::write(fixture.root.path().join("index.scip"), b"occupied slot").unwrap();
        }
        let raw = output(Some(0));
        let expected = process_evidence(raw.clone());
        let failure = fixture
            .completion()
            .finish(Ok(raw), None, None, None)
            .unwrap_err();
        assert_eq!(failure.phase, SemanticIndexerRunPhase::OutputValidation);
        assert_eq!(failure.process.as_deref(), Some(&expected));
        if collision {
            assert!(failure.detail.contains("refusing to overwrite"));
            assert_eq!(
                fs::read(fixture.root.path().join("index.scip")).unwrap(),
                b"occupied slot"
            );
        } else {
            assert_eq!(
                failure.kind,
                SemanticIndexerRunFailureKind::IncompleteOutput
            );
        }
        fixture.finish();
    }
}

#[test]
fn rejected_or_resource_limited_workers_never_publish_an_index() {
    for (status, timed_out, memory, processes) in [
        (Some(2), false, false, false),
        (None, false, false, false),
        (Some(0), true, false, false),
        (Some(0), false, true, false),
        (Some(0), false, false, true),
    ] {
        let fixture = Fixture::new();
        fs::write(
            fixture.execution_root.join("index.scip"),
            b"must not publish",
        )
        .unwrap();
        let mut raw = output(status);
        raw.timed_out = timed_out;
        raw.memory_limit_exceeded = memory;
        raw.process_limit_exceeded = processes;
        let expected = process_evidence(raw.clone());
        let failure = fixture
            .completion()
            .finish(Ok(raw), None, None, None)
            .unwrap_err();
        assert_eq!(failure.phase, SemanticIndexerRunPhase::Execution);
        assert_eq!(failure.process.as_deref(), Some(&expected));
        assert!(!fixture.root.path().join("index.scip").exists());
        fixture.finish();
    }
}

#[tokio::test]
#[ignore = "requires checksum-pinned TypeScript, Node.js and native sandbox"]
async fn native_typescript_completion_rejects_cleanup_source_and_publication_faults_with_actual_worker_evidence()
 {
    let fixture = Fixture::new();
    fixture.recovery.finish_indexer_run().unwrap();
    let before = repository_snapshot::repository_content_digest(fixture.root.path()).unwrap();
    let store = SemanticIndexerStore::for_user().unwrap();
    let installed = store.verify(spec()).unwrap();
    let context = RequiredIndexerRunContext {
        root: fixture.root.path(),
        files: &fixture.files,
        required_documents: &fixture.files,
        store: &store,
        recovery: &fixture.recovery,
        repository_content_sha256: &before,
        progress_root: None,
    };
    let plans = super::super::typescript_model::discover(&context)
        .await
        .unwrap();
    for fault in ["cleanup", "source", "publication"] {
        let root = fixture.recovery.prepare_indexer_run().unwrap();
        repository_snapshot::stage_repository_snapshot(fixture.root.path(), &root).unwrap();
        fs::create_dir(root.join(INDEXER_TEMP_DIR)).unwrap();
        let digest =
            source_integrity_digest_at(fixture.root.path(), &root, &fixture.files).unwrap();
        let prepared = build_indexer_sandbox_command(
            spec(),
            &root,
            &installed,
            typescript_variant_arguments(spec(), &plans[0]).unwrap(),
            None,
        )
        .unwrap();
        let raw =
            super::super::typescript_inputs::run_worker(prepared, spec(), &installed, &plans[0])
                .await
                .unwrap();
        assert_eq!(
            raw.status_code,
            Some(0),
            "real compiler must succeed before fault injection: {raw:?}"
        );
        assert!(!raw.timed_out && !raw.memory_limit_exceeded && !raw.process_limit_exceeded);
        assert!(root.join("index.scip").is_file());
        let expected = process_evidence(raw.clone());
        let mut temporary_project = None;
        match fault {
            "cleanup" => {
                let blocked = root.join(INDEXER_TEMP_DIR).join("blocked-project.json");
                fs::create_dir(&blocked).unwrap();
                temporary_project = Some(blocked);
            }
            "source" => fs::write(root.join("index.ts"), "changed compiler input").unwrap(),
            "publication" => {
                fs::write(fixture.root.path().join("index.scip"), b"occupied slot").unwrap()
            }
            _ => unreachable!(),
        }
        let completion = Completion {
            spec: spec(),
            root: fixture.root.path(),
            execution_root: &root,
            files: &fixture.files,
            recovery: &fixture.recovery,
            typescript_plan: Some(&plans[0]),
            source_digest_before: &digest,
        };
        let failure = completion
            .finish(Ok(raw), temporary_project, None, None)
            .unwrap_err();
        assert_eq!(failure.process.as_deref(), Some(&expected), "{fault}");
        assert_eq!(
            failure.phase,
            match fault {
                "cleanup" => SemanticIndexerRunPhase::Cleanup,
                "source" => SemanticIndexerRunPhase::IntegrityVerification,
                _ => SemanticIndexerRunPhase::OutputValidation,
            }
        );
        if fault == "publication" {
            assert_eq!(
                fs::read(fixture.root.path().join("index.scip")).unwrap(),
                b"occupied slot"
            );
            fs::remove_file(fixture.root.path().join("index.scip")).unwrap();
        } else {
            assert!(!fixture.root.path().join("index.scip").exists());
        }
        fixture.recovery.finish_indexer_run().unwrap();
        assert!(!root.exists());
        assert_eq!(
            repository_snapshot::repository_content_digest(fixture.root.path()).unwrap(),
            before
        );
    }
    fixture.finish();
}
