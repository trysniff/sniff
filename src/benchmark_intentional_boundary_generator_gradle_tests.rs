use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryManifestDeclaration, IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryManifestProvider, IntentionalBoundaryManifestTarget,
    IntentionalBoundaryProjectModelExecution, IntentionalBoundaryProjectModelTargetStatus,
    IntentionalBoundarySemanticRange, census_intentional_boundary_gradle_project_models,
    census_intentional_boundary_repository, inventory_intentional_boundary_repository,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn fixture() -> (
    TempDir,
    IntentionalBoundaryRepositoryInventory,
    IntentionalBoundaryProjectModelCensus,
) {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    git(root.path(), &["config", "user.name", "SniffBench"]);
    git(
        root.path(),
        &["config", "user.email", "bench@example.invalid"],
    );
    git(
        root.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example/gradle-generator.git",
        ],
    );
    for (path, source) in [
        ("settings.gradle.kts", "rootProject.name = \"fixture\"\n"),
        ("build.gradle.kts", "plugins { application }\n"),
        ("gradle.lockfile", "empty=empty\n"),
        (
            "gradle/verification-metadata.xml",
            "<verification-metadata/>\n",
        ),
        (
            "src/main/kotlin/Generated.kt",
            "// @generated\npackage fixture\nfun generated() = 1\n",
        ),
    ] {
        let target = root.path().join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, source).unwrap();
    }
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = inventory_intentional_boundary_repository(
        "github.com/example/gradle-generator",
        &revision,
        root.path(),
    )
    .unwrap();
    let task = IntentionalBoundaryProjectModelProducerTask {
        task_path: ":writeGenerated".to_string(),
        task_type: "org.gradle.api.DefaultTask".to_string(),
        output_repository_paths: vec![
            "build/generator-state".to_string(),
            "src/main/kotlin/Generated.kt".to_string(),
        ],
        source_repository_paths: vec!["src/main/kotlin/Generated.kt".to_string()],
    };
    let execution_id = "gradle-execution".to_string();
    let target = IntentionalBoundaryProjectModelTarget {
        target_id: "gradle-target".to_string(),
        execution_id: execution_id.clone(),
        provider: IntentionalBoundaryProjectModelProvider::GradleToolingApi,
        manifest_repository_path: "build.gradle.kts".to_string(),
        manifest_object_id: "a".repeat(40),
        package_name: "gradle::".to_string(),
        package_version: "git:test".to_string(),
        target_name: ":".to_string(),
        provider_kinds: vec!["application".to_string()],
        provider_output_types: vec!["jvm_application".to_string()],
        source_repository_paths: vec!["src/main/kotlin/Generated.kt".to_string()],
        producer_tasks: vec![task],
        required_features: Vec::new(),
        target_status: IntentionalBoundaryProjectModelTargetStatus::Boundary {
            declaration_kind: IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint,
            target: IntentionalBoundaryManifestTarget::RepositoryPaths {
                repository_paths: vec!["src/main/kotlin/Generated.kt".to_string()],
            },
        },
    };
    let census = IntentionalBoundaryProjectModelCensus {
        schema_version: 3,
        project_model_contract: "fixture".to_string(),
        repository: inventory.repository.clone(),
        revision,
        inventory_sha256: inventory.inventory_sha256.clone(),
        executions: vec![IntentionalBoundaryProjectModelExecution {
            execution_id,
            provider: IntentionalBoundaryProjectModelProvider::GradleToolingApi,
            invocation_anchor_repository_path: "settings.gradle.kts".to_string(),
            invocation_anchor_object_id: "b".repeat(40),
            toolchain_identity_sha256: "c".repeat(64),
            command_contract: "fixture".to_string(),
            normalized_model_sha256: "d".repeat(64),
            covered_manifest_repository_paths: vec![
                "build.gradle.kts".to_string(),
                "settings.gradle.kts".to_string(),
            ],
            target_count: 1,
        }],
        targets: vec![target],
        execution_count_by_provider: BTreeMap::new(),
        target_count_by_status: BTreeMap::new(),
        project_model_census_sha256: "e".repeat(64),
    };
    (root, inventory, census)
}

#[test]
fn plans_only_the_exact_committed_gradle_producer() {
    let (_root, inventory, census) = fixture();
    let target = &census.targets[0];
    let task = &target.producer_tasks[0];

    let GradleGeneratorCommandPlan::Planned(command) =
        gradle_generator_command_plan(&inventory, &census, target, task)
    else {
        panic!("expected exact Gradle generator command");
    };

    let preparation = command.preparation.unwrap();
    assert_eq!(preparation.last(), Some(&task.task_path));
    assert!(!preparation.iter().any(|argument| argument == "--offline"));
    assert_eq!(command.execution.last(), Some(&task.task_path));
    assert!(
        command
            .execution
            .iter()
            .any(|argument| argument == "--offline")
    );
    assert!(
        command
            .execution
            .iter()
            .any(|argument| argument == "--rerun-tasks")
    );
    let expected_environment = BTreeMap::from([(
        "JAVA_TOOL_OPTIONS".to_string(),
        "-Djava.net.preferIPv4Stack=true".to_string(),
    )]);
    assert_eq!(command.preparation_environment, expected_environment);
    assert_eq!(command.execution_environment, expected_environment);
    assert_eq!(command.cleanup_paths, ["build/generator-state"]);
}

#[test]
fn missing_gradle_verification_or_lock_state_is_typed_unresolved() {
    let (_root, inventory, census) = fixture();
    let target = &census.targets[0];
    let task = &target.producer_tasks[0];
    for missing in ["gradle/verification-metadata.xml", "gradle.lockfile"] {
        let mut changed = inventory.clone();
        changed
            .tracked_entries
            .retain(|entry| entry.repository_path != missing);
        let GradleGeneratorCommandPlan::Unresolved { reason, .. } =
            gradle_generator_command_plan(&changed, &census, target, task)
        else {
            panic!("missing Gradle lock evidence was accepted");
        };
        assert_eq!(
            reason,
            IntentionalBoundaryGeneratorUnresolvedReason::MissingConfiguration
        );
    }
}

#[test]
fn nested_gradle_producers_require_their_project_scoped_lock() {
    let (_root, mut inventory, mut census) = fixture();
    let lock = inventory
        .tracked_entries
        .iter_mut()
        .find(|entry| entry.repository_path == "gradle.lockfile")
        .unwrap();
    lock.repository_path = "module/gradle.lockfile".to_string();
    let target = &mut census.targets[0];
    target.manifest_repository_path = "module/build.gradle.kts".to_string();
    target.producer_tasks[0].task_path = ":module:writeGenerated".to_string();
    let task = target.producer_tasks[0].clone();

    assert!(matches!(
        gradle_generator_command_plan(&inventory, &census, &census.targets[0], &task),
        GradleGeneratorCommandPlan::Planned(_)
    ));
    inventory
        .tracked_entries
        .iter_mut()
        .find(|entry| entry.repository_path == "module/gradle.lockfile")
        .unwrap()
        .repository_path = "gradle.lockfile".to_string();
    assert!(matches!(
        gradle_generator_command_plan(&inventory, &census, &census.targets[0], &task),
        GradleGeneratorCommandPlan::Unresolved {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::MissingConfiguration,
            ..
        }
    ));
}

#[test]
fn an_uncommitted_gradle_task_is_never_executed() {
    let (_root, inventory, census) = fixture();
    let target = &census.targets[0];
    let mut invented = target.producer_tasks[0].clone();
    invented.task_path = ":generateEverything".to_string();

    let GradleGeneratorCommandPlan::Unresolved { reason, .. } =
        gradle_generator_command_plan(&inventory, &census, target, &invented)
    else {
        panic!("invented Gradle task was accepted");
    };
    assert_eq!(
        reason,
        IntentionalBoundaryGeneratorUnresolvedReason::UnsupportedConfiguration
    );
}

#[test]
fn exact_gradle_ownership_precedes_manifest_proximity_and_preserves_ambiguity() {
    let (_root, _inventory, mut census) = fixture();
    let declaration = IntentionalBoundaryManifestDeclaration {
        declaration_id: "nearby-manifest-generator".to_string(),
        provider: IntentionalBoundaryManifestProvider::CargoManifest,
        manifest_repository_path: "build.rs".to_string(),
        manifest_object_id: "f".repeat(40),
        declaration_kind: IntentionalBoundaryManifestDeclarationKind::BuildScript,
        declaration_location: IntentionalBoundarySemanticRange {
            repository_path: "build.rs".to_string(),
            start_line_zero_based: 0,
            start_character_zero_based: 0,
            end_line_zero_based: 0,
            end_character_zero_based: 1,
        },
        target: IntentionalBoundaryManifestTarget::RepositoryPath {
            repository_path: "src/main/kotlin/Generated.kt".to_string(),
        },
    };
    let declarations = [declaration];
    let configurations =
        super::super::configuration::configurations(&declarations, &census).unwrap();
    let ids = super::super::configuration::candidate_configuration_ids(
        "src/main/kotlin/Generated.kt",
        &configurations,
    );
    assert_eq!(ids.len(), 1);
    assert!(ids[0].starts_with("ibgc-gradle-v1:"));

    let mut second = census.targets[0].clone();
    second.target_id = "second-gradle-target".to_string();
    second.producer_tasks[0].task_path = ":writeGeneratedAgain".to_string();
    census.targets.push(second);
    let configurations = super::super::configuration::configurations(&[], &census).unwrap();
    let ids = super::super::configuration::candidate_configuration_ids(
        "src/main/kotlin/Generated.kt",
        &configurations,
    );
    assert_eq!(ids.len(), 2);
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    let by_id = super::super::configuration::configurations_by_id(&configurations);
    let candidates = super::super::configuration::sorted_candidates(&ids, &by_id).unwrap();
    assert!(super::super::configuration::has_ambiguous_exact_gradle(
        &candidates
    ));
    assert!(matches!(
        candidates[0].evidence_proof(),
        super::super::configuration::GeneratorConfigurationEvidenceProof::ProjectModel(
            crate::benchmark::release::IntentionalBoundaryProjectModelProofKind::GeneratorConfiguration
        )
    ));
}

fn runtime_fixture() -> (TempDir, IntentionalBoundaryRepositoryInventory) {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    git(root.path(), &["config", "user.name", "SniffBench"]);
    git(
        root.path(),
        &["config", "user.email", "bench@example.invalid"],
    );
    git(
        root.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example/gradle-generator-runtime.git",
        ],
    );
    for (path, source) in [
        (
            "settings.gradle",
            "rootProject.name = 'gradle-generator-runtime'\n",
        ),
        (
            "build.gradle",
            concat!(
                "plugins { id 'application' }\n",
                "sourceSets.main.java {\n",
                "  srcDir 'src/main/kotlin'\n",
                "  include '**/*.java', '**/*.kt'\n",
                "}\n",
                "tasks.register('prepareGenerator') {\n",
                "  outputs.file(layout.buildDirectory.file('generator/prepared.txt'))\n",
                "  doLast {\n",
                "    file('build/generator').mkdirs()\n",
                "    file('build/generator/prepared.txt').text = 'prepared\\n'\n",
                "  }\n",
                "}\n",
                "tasks.register('writeGenerated') {\n",
                "  dependsOn tasks.named('prepareGenerator')\n",
                "  outputs.file(layout.projectDirectory.file('src/main/kotlin/example/Generated.kt'))\n",
                "  doLast {\n",
                "    file('src/main/kotlin/example/Generated.kt').text = ",
                "'// @generated\\npackage example\\nfun generatedValue(): Int = 7\\n'\n",
                "  }\n",
                "}\n",
            ),
        ),
        (
            "gradle.lockfile",
            concat!(
                "# This is a Gradle generated file for dependency locking.\n",
                "# Manual edits can break the build and are not advised.\n",
                "empty=empty\n",
            ),
        ),
        (
            "gradle/verification-metadata.xml",
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                "<verification-metadata>\n",
                "  <configuration>\n",
                "    <verify-metadata>true</verify-metadata>\n",
                "    <verify-signatures>false</verify-signatures>\n",
                "  </configuration>\n",
                "  <components/>\n",
                "</verification-metadata>\n",
            ),
        ),
        (
            "src/main/kotlin/example/Generated.kt",
            concat!(
                "// @generated\n",
                "package example\n",
                "fun generatedValue(): Int = 7\n",
            ),
        ),
    ] {
        let target = root.path().join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, source).unwrap();
    }
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = inventory_intentional_boundary_repository(
        "github.com/example/gradle-generator-runtime",
        &revision,
        root.path(),
    )
    .unwrap();
    (root, inventory)
}

#[test]
fn real_gradle_generator_reproduces_the_compiler_owned_output_twice_offline() {
    let (root, inventory) = runtime_fixture();
    let source = census_intentional_boundary_repository(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
    )
    .unwrap();
    assert!(source.source_files.iter().any(|file| {
        file.repository_path == "src/main/kotlin/example/Generated.kt" && file.language == "kotlin"
    }));
    let gradle_available = Command::new("gradle")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    let models = census_intentional_boundary_gradle_project_models(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
    );
    if !gradle_available {
        assert!(models.unwrap_err().contains("runtime is unavailable"));
        return;
    }
    let models = models.unwrap();
    let target = models
        .targets
        .iter()
        .find(|target| !target.producer_tasks.is_empty())
        .expect("Tooling API omitted the exact producer task");
    let task = &target.producer_tasks[0];
    assert_eq!(task.task_path, ":writeGenerated");
    assert_eq!(
        task.source_repository_paths,
        ["src/main/kotlin/example/Generated.kt"]
    );
    assert!(
        task.output_repository_paths
            .iter()
            .any(|path| path == "build/generator/prepared.txt")
    );
    let GradleGeneratorCommandPlan::Planned(command) =
        gradle_generator_command_plan(&inventory, &models, target, task)
    else {
        panic!("real Gradle producer was not plannable");
    };
    let expected =
        super::super::expected_output(&inventory, &source, "src/main/kotlin/example/Generated.kt")
            .unwrap();
    let replay = super::super::runtime::execute_generator_replay(
        root.path(),
        &inventory.revision,
        &command,
        &[expected],
    );
    match replay {
        Ok(success) => {
            assert_eq!(success.preparations.len(), 2);
            assert_eq!(success.executions.len(), 2);
            assert_eq!(success.outputs.len(), 1);
            assert_eq!(
                success.outputs[0].first_run_sha256,
                success.outputs[0].committed_sha256
            );
            assert_eq!(
                success.outputs[0].second_run_sha256,
                success.outputs[0].committed_sha256
            );
        }
        Err(failure) if cfg!(windows) => assert_eq!(
            failure.reason,
            IntentionalBoundaryGeneratorUnresolvedReason::SandboxUnavailable,
            "unexpected Windows Gradle replay failure: {}",
            failure.detail
        ),
        Err(failure) => panic!("Gradle replay failed: {}", failure.detail),
    }
}
