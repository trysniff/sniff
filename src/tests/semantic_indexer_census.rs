use super::*;
use crate::sandbox::SandboxOutput;
use crate::semantic_index::{SemanticIndexerCompilerQuery, SemanticVariantId};
use tempfile::TempDir;

fn journal(root: &Path, kind: SemanticIndexerKind) -> Journal {
    let spec = pinned_indexer(kind).unwrap();
    let store = SemanticIndexerStore::at(root.join("unused-installation"));
    let recovery = recovery::SemanticIndexerRecoveryGuard::begin(root).unwrap();
    let context = RequiredIndexerRunContext {
        root,
        files: &[],
        required_documents: &[],
        store: &store,
        recovery: &recovery,
        repository_content_sha256: &"a".repeat(64),
        progress_root: None,
    };
    // Journal fixtures exercise persistence, not installation qualification.
    let installed = InstalledIndexer {
        root: root.to_path_buf(),
        entrypoint: root.join("unused"),
        tree_sha256: "b".repeat(64),
    };
    let journal = Journal::open(&context, spec, &installed).unwrap();
    recovery.finish().unwrap();
    journal
}

fn bind(journal: &Journal) {
    journal
        .bind_inputs(Inputs::Go {
            executable_sha256: "c".repeat(64),
            sdk_sha256: "d".repeat(64),
            dependencies_sha256: "e".repeat(64),
        })
        .unwrap();
}

fn request(role: Role) -> Request {
    Request {
        role,
        arguments: vec!["tool".into(), "dist".into(), "list".into(), "-json".into()],
        environment: BTreeMap::from([("GOTOOLCHAIN".into(), "local".into())]),
    }
}

fn output(stdout: &str) -> SandboxOutput {
    let stderr = "diagnostic\n".to_string();
    SandboxOutput {
        status_code: Some(0),
        stdout: stdout.to_string(),
        stdout_sha256: format!("{:x}", Sha256::digest(stdout.as_bytes())),
        stderr_sha256: format!("{:x}", Sha256::digest(stderr.as_bytes())),
        stderr,
        timed_out: false,
        memory_limit_exceeded: false,
        process_limit_exceeded: false,
    }
}

fn plan() -> SemanticIndexerVariantPlan {
    SemanticIndexerVariantPlan {
        identity: SemanticVariantId("fixture-world".into()),
        dimensions: BTreeMap::from([("source_snapshot_sha256".into(), "a".repeat(64))]),
        environment: BTreeMap::new(),
        compiler_query: SemanticIndexerCompilerQuery::ProjectPackages,
        compiler_project: Some(RepositoryPath("go.mod".into())),
        selected_documents: BTreeSet::from([RepositoryPath("main.go".into())]),
        ignored_documents: BTreeSet::new(),
    }
}

fn complete_command(journal: &Journal) {
    journal
        .record_command(request(Role::GoPlatforms), Ok(output("[]")))
        .unwrap();
    journal
        .record_model(ModelPart::GoPlatforms("[]".into()))
        .unwrap();
}

fn terminal(journal: &Journal) -> TerminalReceipt {
    let path = journal.root.join("terminal.json");
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    receipt_io::read(&path, value["sha256"].as_str().unwrap()).unwrap()
}

#[test]
fn successful_terminal_preserves_ordered_commands_and_typed_models_without_reuse_authority() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    bind(&journal);
    complete_command(&journal);
    journal
        .record_command(request(Role::GoEnvironment), Ok(output("{}")))
        .unwrap();
    journal
        .record_model(ModelPart::GoEnvironment(BTreeMap::new()))
        .unwrap();
    assert_eq!(journal.finish(Ok(vec![plan()])).unwrap(), vec![plan()]);
    let saved = terminal(&journal);
    assert!(!saved.input_closure_proven);
    assert!(matches!(saved.result, TerminalOutcome::Accepted { .. }));
    assert_eq!(saved.commands.len(), 2);
    for sequence in 0..2 {
        let command: CommandReceipt = receipt_io::read(
            &journal.root.join(command_name(sequence)),
            &saved.commands[sequence],
        )
        .unwrap();
        assert_eq!(command.sequence, sequence);
        assert_eq!(
            command.preceding_sha256.as_ref(),
            sequence
                .checked_sub(1)
                .map(|previous| &saved.commands[previous])
        );
        let model: ModelReceipt = receipt_io::read(
            &journal.root.join(model_name(sequence)),
            saved.models[sequence].as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(model.command_sha256, saved.commands[sequence]);
        assert_eq!(model.model.role(), command.request.role);
    }
    assert!(journal.finish(Ok(vec![plan()])).is_err());
    assert!(
        journal
            .record_command(request(Role::GoPlatforms), Ok(output("[]")))
            .is_err()
    );
}

#[test]
fn missing_model_failed_command_and_incomplete_stdout_cannot_publish_success() {
    for case in 0..4 {
        let root = TempDir::new().unwrap();
        let journal = journal(root.path(), SemanticIndexerKind::Go);
        bind(&journal);
        let mut captured = output("[]");
        match case {
            1 => captured.status_code = Some(2),
            2 => captured.stdout_sha256 = "f".repeat(64),
            3 => captured.timed_out = true,
            _ => (),
        }
        let expected = process_evidence(captured.clone());
        journal
            .record_command(request(Role::GoPlatforms), Ok(captured))
            .unwrap();
        if case != 0 {
            journal
                .record_model(ModelPart::GoPlatforms("[]".into()))
                .unwrap();
        }
        let failure = journal.finish(Ok(vec![plan()])).unwrap_err();
        assert_eq!(failure.process.as_deref(), Some(&expected));
        assert!(matches!(
            terminal(&journal).result,
            TerminalOutcome::Failed { .. }
        ));
    }
}

#[test]
fn failed_startup_never_borrows_preceding_process_and_rejects_model_publication() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    bind(&journal);
    complete_command(&journal);
    let failure = persistence_failure(journal.spec, "worker did not start");
    let failure = journal
        .record_command(request(Role::GoModule), Err(failure))
        .unwrap_err();
    assert!(failure.process.is_none());
    let model = ModelPart::GoModule(super::super::go_model_output::ModuleIdentity {
        path: "example.test/model".into(),
        project: RepositoryPath("go.mod".into()),
    });
    assert!(journal.record_model(model).unwrap_err().process.is_none());
    let failure = journal.finish(Err(failure)).unwrap_err();
    assert!(failure.process.is_none());
    let saved = terminal(&journal);
    assert!(saved.models[0].is_some());
    assert!(saved.models[1].is_none());
    let last: CommandReceipt =
        receipt_io::read(&journal.root.join(command_name(1)), &saved.commands[1]).unwrap();
    assert!(last.result.process().is_none());
}

#[test]
fn worker_and_cleanup_failures_keep_actual_raw_commitments_and_diagnostics() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    bind(&journal);
    let mut captured = output("partial output");
    captured.stdout_sha256 = "f".repeat(64);
    captured.timed_out = true;
    let expected = process_evidence(captured.clone());
    let failure = indexer_process_failure(
        journal.spec,
        SemanticIndexerRunFailureKind::RepositoryRejected,
        SemanticIndexerRunPhase::Execution,
        "timed out",
        captured,
    );
    let failure = journal
        .record_command(request(Role::GoPlatforms), Err(failure))
        .unwrap_err();
    let cleanup = persistence_failure(journal.spec, "cleanup failed");
    let result = combine_typed_run_and_integrity::<Vec<SemanticIndexerVariantPlan>>(
        Err(failure),
        Err(cleanup),
    );
    let failure = journal.finish(result).unwrap_err();
    assert_eq!(failure.process.as_deref(), Some(&expected));
    assert!(failure.detail.contains("timed out") && failure.detail.contains("cleanup failed"));
    let TerminalOutcome::Failed { failure: saved } = terminal(&journal).result else {
        panic!("failure became accepted")
    };
    assert_eq!(saved, failure);
}

#[test]
fn post_census_guard_failure_and_no_worker_failure_are_durable_not_accepted() {
    for started in [false, true] {
        let root = TempDir::new().unwrap();
        let journal = journal(root.path(), SemanticIndexerKind::Go);
        let mut failure = persistence_failure(journal.spec, "integrity changed");
        if started {
            bind(&journal);
            complete_command(&journal);
            failure.process = Some(Box::new(process_evidence(output("[]"))));
        }
        let expected = failure.clone();
        assert_eq!(journal.finish(Err(failure)).unwrap_err(), expected);
        let TerminalOutcome::Failed { failure } = terminal(&journal).result else {
            panic!("guard failure became accepted")
        };
        assert_eq!(failure, expected);
    }
}

#[test]
fn changed_missing_and_unknown_receipt_content_fails_closed() {
    for case in 0..3 {
        let root = TempDir::new().unwrap();
        let journal = journal(root.path(), SemanticIndexerKind::Go);
        bind(&journal);
        complete_command(&journal);
        let path = journal.root.join(command_name(0));
        if case == 0 {
            fs::remove_file(&path).unwrap();
        } else {
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            if case == 1 {
                value["value"]["sequence"] = 1.into();
            } else {
                value["value"]["unexpected"] = true.into();
            }
            fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        }
        assert!(journal.finish(Ok(vec![plan()])).is_err());
        assert!(matches!(
            terminal(&journal).result,
            TerminalOutcome::Failed { .. }
        ));
    }
}

#[test]
fn cross_provider_repeated_inputs_wrong_models_and_changed_plan_scope_are_rejected() {
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    assert!(
        journal
            .bind_inputs(Inputs::TypeScript {
                runtime_sha256: "c".repeat(64)
            })
            .is_err()
    );
    bind(&journal);
    assert!(
        journal
            .bind_inputs(Inputs::Go {
                executable_sha256: "c".repeat(64),
                sdk_sha256: "d".repeat(64),
                dependencies_sha256: "e".repeat(64)
            })
            .is_err()
    );
    assert!(
        journal
            .record_command(request(Role::TypeScriptProject), Ok(output("[]")))
            .is_err()
    );
    journal
        .record_command(request(Role::GoPlatforms), Ok(output("[]")))
        .unwrap();
    assert!(
        journal
            .record_model(ModelPart::GoEnvironment(BTreeMap::new()))
            .is_err()
    );
    journal
        .record_model(ModelPart::GoPlatforms("[]".into()))
        .unwrap();
    assert!(
        journal
            .record_model(ModelPart::GoPlatforms("[]".into()))
            .is_err()
    );
    let mut changed = plan();
    changed
        .dimensions
        .insert("source_snapshot_sha256".into(), "f".repeat(64));
    assert!(journal.finish(Ok(vec![changed])).is_err());
}

#[test]
fn receipt_publication_does_not_overwrite_and_new_attempt_preserves_previous_attempt() {
    let root = TempDir::new().unwrap();
    let first = journal(root.path(), SemanticIndexerKind::Go);
    let before = fs::read(first.root.join("scope.json")).unwrap();
    assert!(receipt_io::write(&first.root, "scope.json", &"replacement").is_err());
    let second = journal(root.path(), SemanticIndexerKind::Go);
    assert_ne!(first.root, second.root);
    assert_eq!(fs::read(first.root.join("scope.json")).unwrap(), before);
}

#[test]
fn census_storage_rejects_non_directory_and_redirected_entries() {
    let root = TempDir::new().unwrap();
    let target = TempDir::new().unwrap();
    let plain_file = root.path().join("not-a-directory");
    fs::write(&plain_file, "keep").unwrap();
    assert!(receipt_io::ensure_plain_directory(&plain_file).is_err());
    let link = root.path().join("redirected");
    #[cfg(unix)]
    std::os::unix::fs::symlink(target.path(), &link).unwrap();
    #[cfg(windows)]
    {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target.path())
            .output()
            .unwrap();
        assert!(status.status.success(), "{status:?}");
    }
    assert!(receipt_io::ensure_plain_directory(&link).is_err());
    assert!(receipt_io::write(&link, "receipt.json", &"untrusted").is_err());
    assert!(!target.path().join("receipt.json").exists());
    assert_eq!(fs::read_to_string(&plain_file).unwrap(), "keep");
}

#[test]
fn rejected_go_world_roundtrips_as_rejected_with_context_and_diagnostics() {
    use super::super::go_model_output::{CompilerWorld, ContextOutcome, ModuleIdentity};
    use crate::compiler_go_model::{GoCompilerArchitecture, GoCompilerContext, GoCompilerQuery};
    let root = TempDir::new().unwrap();
    let journal = journal(root.path(), SemanticIndexerKind::Go);
    bind(&journal);
    journal
        .record_command(request(Role::GoWorld), Ok(output("{}")))
        .unwrap();
    journal
        .record_model(ModelPart::GoWorld(Box::new(CompilerWorld {
            module: ModuleIdentity {
                path: "example.test/model".into(),
                project: RepositoryPath("go.mod".into()),
            },
            context: GoCompilerContext {
                goos: "linux".into(),
                goarch: "amd64".into(),
                cgo_enabled: false,
                build_tags: vec!["feature".into()],
                architecture: GoCompilerArchitecture::Default,
                query: GoCompilerQuery::ModulePackages,
            },
            environment: BTreeMap::from([("GOOS".into(), "linux".into())]),
            outcome: ContextOutcome::Rejected {
                diagnostics: vec!["no selected Go files".into()],
            },
        })))
        .unwrap();
    let state = journal.state.lock().unwrap();
    let receipt: ModelReceipt = receipt_io::read(
        &journal.root.join(model_name(0)),
        state.models[0].as_ref().unwrap(),
    )
    .unwrap();
    let ModelPart::GoWorld(world) = receipt.model else {
        panic!("world changed kind")
    };
    let ContextOutcome::Rejected { diagnostics } = world.outcome else {
        panic!("rejected world became accepted")
    };
    assert_eq!(diagnostics, vec!["no selected Go files"]);
    assert_eq!(world.context.build_tags, vec!["feature"]);
}

pub(in super::super) fn assert_native_terminal(
    root: &Path,
    kind: SemanticIndexerKind,
    accepted: bool,
    commands: usize,
) {
    let family = if kind == SemanticIndexerKind::Go {
        "go"
    } else {
        "typescript"
    };
    let digest = repository_snapshot::repository_content_digest(root).unwrap();
    let attempts = fs::read_dir(
        root.join(".sniff/compiler-census")
            .join(digest)
            .join(family),
    )
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert_eq!(attempts.len(), 1);
    let path = attempts[0].path().join("terminal.json");
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let terminal: TerminalReceipt =
        receipt_io::read(&path, value["sha256"].as_str().unwrap()).unwrap();
    assert!(!terminal.input_closure_proven);
    assert_eq!(terminal.commands.len(), commands);
    assert_eq!(
        matches!(terminal.result, TerminalOutcome::Accepted { .. }),
        accepted
    );
    let scope: Scope = receipt_io::read(
        &attempts[0].path().join("scope.json"),
        &terminal.scope_sha256,
    )
    .unwrap();
    assert_eq!(scope.indexer, kind);
    for (sequence, digest) in terminal.commands.iter().enumerate() {
        let command: CommandReceipt =
            receipt_io::read(&attempts[0].path().join(command_name(sequence)), digest).unwrap();
        assert!(command.result.process().is_some());
        if let Some(model_digest) = &terminal.models[sequence] {
            let model: ModelReceipt =
                receipt_io::read(&attempts[0].path().join(model_name(sequence)), model_digest)
                    .unwrap();
            assert_eq!(model.command_sha256, *digest);
            assert_eq!(model.model.role(), command.request.role);
        }
    }
}
