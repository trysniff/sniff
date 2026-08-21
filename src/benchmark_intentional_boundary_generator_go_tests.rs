use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryIndexerKind, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryProjectModelExecution, IntentionalBoundaryProjectModelTarget,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticVisibility, bind_intentional_boundary_manifests,
    census_intentional_boundary_go_ast, census_intentional_boundary_manifests,
    census_intentional_boundary_repository, extract_intentional_boundary_compiler_and_ast_evidence,
    inventory_intentional_boundary_repository, parse_intentional_boundary_go_list,
};
use std::fs;
use std::path::Path;
use std::process::Command;

fn directive(path: &str, line: u32, source_text: &str) -> IntentionalBoundaryGoGenerateDirective {
    IntentionalBoundaryGoGenerateDirective {
        location: IntentionalBoundarySemanticRange {
            repository_path: path.to_string(),
            start_line_zero_based: line,
            start_character_zero_based: 0,
            end_line_zero_based: line,
            end_character_zero_based: source_text.len() as u32,
        },
        source_text: source_text.to_string(),
    }
}

fn declaration(
    module: Option<&str>,
    package: &str,
    directives: Vec<IntentionalBoundaryGoGenerateDirective>,
) -> IntentionalBoundaryManifestDeclaration {
    IntentionalBoundaryManifestDeclaration {
        declaration_id: "go-generator".to_string(),
        provider: IntentionalBoundaryManifestProvider::GoGenerateSource,
        manifest_repository_path: directives[0].location.repository_path.clone(),
        manifest_object_id: "a".repeat(40),
        declaration_kind: IntentionalBoundaryManifestDeclarationKind::GeneratorCommand,
        declaration_location: directives[0].location.clone(),
        target: IntentionalBoundaryManifestTarget::GoGeneratePackage {
            module_manifest_repository_path: module.map(str::to_string),
            package_repository_path: package.to_string(),
            directives,
        },
    }
}

fn project_models(module: &str, sources: &[&str]) -> IntentionalBoundaryProjectModelCensus {
    let execution_id = "go-list-execution".to_string();
    let source_repository_paths = sources
        .iter()
        .map(|path| (*path).to_string())
        .collect::<Vec<_>>();
    IntentionalBoundaryProjectModelCensus {
        schema_version: 2,
        project_model_contract: "test".to_string(),
        repository: "owner/repository".to_string(),
        revision: "1".repeat(40),
        inventory_sha256: "2".repeat(64),
        executions: vec![IntentionalBoundaryProjectModelExecution {
            execution_id: execution_id.clone(),
            provider: Provider::GoList,
            invocation_anchor_repository_path: module.to_string(),
            invocation_anchor_object_id: "3".repeat(40),
            toolchain_identity_sha256: "4".repeat(64),
            command_contract: "test".to_string(),
            normalized_model_sha256: "5".repeat(64),
            covered_manifest_repository_paths: vec![module.to_string()],
            target_count: 1,
        }],
        targets: vec![IntentionalBoundaryProjectModelTarget {
            target_id: "go-list-target".to_string(),
            execution_id,
            provider: Provider::GoList,
            manifest_repository_path: module.to_string(),
            manifest_object_id: "3".repeat(40),
            package_name: "example.com/project".to_string(),
            package_version: "git:test".to_string(),
            target_name: "example.com/project/tools".to_string(),
            provider_kinds: vec!["package".to_string()],
            provider_output_types: vec!["package_archive".to_string()],
            source_repository_paths: source_repository_paths.clone(),
            required_features: Vec::new(),
            target_status: IntentionalBoundaryProjectModelTargetStatus::Boundary {
                declaration_kind: IntentionalBoundaryManifestDeclarationKind::PublishedModule,
                target: IntentionalBoundaryManifestTarget::RepositoryPaths {
                    repository_paths: source_repository_paths,
                },
            },
        }],
        execution_count_by_provider: BTreeMap::new(),
        target_count_by_status: BTreeMap::new(),
        project_model_census_sha256: "6".repeat(64),
    }
}

#[test]
fn compiler_owned_go_directive_has_exact_locked_two_phase_command() {
    let declaration = declaration(
        Some("go.mod"),
        "tools",
        vec![directive(
            "tools/gen.go",
            2,
            "//go:generate go run ./cmd/gen",
        )],
    );
    let models = project_models("go.mod", &["tools/gen.go", "tools/helper.go"]);

    let command = go_generator_command(&models, &declaration).unwrap();

    assert_eq!(
        command.preparation.unwrap(),
        ["go", "-C", ".", "mod", "download", "all"]
    );
    assert_eq!(
        command.execution,
        [
            "go",
            "-C",
            "tools",
            "generate",
            "-mod=readonly",
            "-buildvcs=false",
            "gen.go",
        ]
    );
    assert_eq!(command.preparation_environment, go_environment(false));
    assert_eq!(command.execution_environment, go_environment(true));
    assert_eq!(
        command
            .execution_environment
            .get("GOPROXY")
            .map(String::as_str),
        Some("off")
    );
    assert_eq!(
        command
            .execution_environment
            .get("GOFLAGS")
            .map(String::as_str),
        Some("-mod=readonly -buildvcs=false")
    );
}

#[test]
fn file_local_alias_directly_expanding_to_go_is_supported() {
    let declaration = declaration(
        Some("go.mod"),
        "tools",
        vec![
            directive(
                "tools/gen.go",
                2,
                "//go:generate -command generate go run ./cmd/gen",
            ),
            directive(
                "tools/gen.go",
                3,
                "//go:generate generate -output result.go",
            ),
        ],
    );
    let models = project_models("go.mod", &["tools/gen.go"]);

    assert!(go_generator_command(&models, &declaration).is_some());
}

#[test]
fn aliases_do_not_leak_between_go_source_files() {
    let declaration = declaration(
        Some("go.mod"),
        "tools",
        vec![
            directive(
                "tools/a.go",
                2,
                "//go:generate -command generate go run ./cmd/gen",
            ),
            directive("tools/b.go", 2, "//go:generate generate"),
        ],
    );
    let models = project_models("go.mod", &["tools/a.go", "tools/b.go"]);

    assert!(go_generator_command(&models, &declaration).is_none());
}

#[test]
fn arbitrary_direct_and_aliased_executables_are_rejected() {
    let models = project_models("go.mod", &["tools/gen.go"]);
    let direct = declaration(
        Some("go.mod"),
        "tools",
        vec![directive("tools/gen.go", 2, "//go:generate python gen.py")],
    );
    let aliased = declaration(
        Some("go.mod"),
        "tools",
        vec![
            directive(
                "tools/gen.go",
                2,
                "//go:generate -command generate python gen.py",
            ),
            directive("tools/gen.go", 3, "//go:generate generate"),
        ],
    );

    assert!(go_generator_command(&models, &direct).is_none());
    assert!(go_generator_command(&models, &aliased).is_none());
    assert!(matches!(
        go_generator_command_plan(&models, &direct),
        GoGeneratorCommandPlan::Unresolved {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::UnsupportedConfiguration,
            ..
        }
    ));
}

#[test]
fn quoted_or_variable_executable_words_are_rejected_without_guessing() {
    let models = project_models("go.mod", &["tools/gen.go"]);
    for source in [
        "//go:generate \"go\" run ./cmd/gen",
        "//go:generate $GENERATOR run ./cmd/gen",
    ] {
        let declaration = declaration(
            Some("go.mod"),
            "tools",
            vec![directive("tools/gen.go", 2, source)],
        );
        assert!(go_generator_command(&models, &declaration).is_none());
    }
}

#[test]
fn missing_module_or_compiler_source_ownership_is_rejected() {
    let directive = directive("tools/gen.go", 2, "//go:generate go run ./cmd/gen");
    let moduleless = declaration(None, "tools", vec![directive.clone()]);
    let unowned = declaration(Some("go.mod"), "tools", vec![directive]);
    let models = project_models("go.mod", &["tools/other.go"]);

    assert!(go_generator_command(&models, &moduleless).is_none());
    assert!(go_generator_command(&models, &unowned).is_none());
    assert!(matches!(
        go_generator_command_plan(&models, &moduleless),
        GoGeneratorCommandPlan::Unresolved {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::MissingConfiguration,
            ..
        }
    ));
}

#[test]
fn ambiguous_compiler_package_ownership_is_rejected() {
    let declaration = declaration(
        Some("go.mod"),
        "tools",
        vec![directive(
            "tools/gen.go",
            2,
            "//go:generate go run ./cmd/gen",
        )],
    );
    let mut models = project_models("go.mod", &["tools/gen.go"]);
    let mut duplicate = models.targets[0].clone();
    duplicate.target_id = "second-go-list-target".to_string();
    models.targets.push(duplicate);

    assert!(go_generator_command(&models, &declaration).is_none());
    assert!(matches!(
        go_generator_command_plan(&models, &declaration),
        GoGeneratorCommandPlan::Unresolved {
            reason: IntentionalBoundaryGeneratorUnresolvedReason::AmbiguousConfiguration,
            ..
        }
    ));
}

#[test]
fn nested_module_and_multiple_source_files_use_exact_package_relative_names() {
    let declaration = declaration(
        Some("modules/tool/go.mod"),
        "modules/tool/internal/gen",
        vec![
            directive(
                "modules/tool/internal/gen/a.go",
                1,
                "//go:generate go run ./cmd",
            ),
            directive(
                "modules/tool/internal/gen/b.go",
                1,
                "//go:generate go run ./cmd",
            ),
        ],
    );
    let models = project_models(
        "modules/tool/go.mod",
        &[
            "modules/tool/internal/gen/a.go",
            "modules/tool/internal/gen/b.go",
        ],
    );

    let command = go_generator_command(&models, &declaration).unwrap();

    assert_eq!(
        command.preparation.unwrap(),
        ["go", "-C", "modules/tool", "mod", "download", "all"]
    );
    assert_eq!(
        &command.execution[0..6],
        [
            "go",
            "-C",
            "modules/tool/internal/gen",
            "generate",
            "-mod=readonly",
            "-buildvcs=false",
        ]
    );
    assert_eq!(&command.execution[6..], ["a.go", "b.go"]);
}

#[test]
fn alias_declarations_without_an_executable_directive_are_not_replayed() {
    let declaration = declaration(
        Some("go.mod"),
        "tools",
        vec![directive(
            "tools/gen.go",
            2,
            "//go:generate -command generate go run ./cmd/gen",
        )],
    );
    let models = project_models("go.mod", &["tools/gen.go"]);

    assert!(go_generator_command(&models, &declaration).is_none());
}

#[test]
fn real_go_generator_reproduces_compiler_owned_output_twice_offline() {
    let fixture = real_fixture();
    let go_available = Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success());

    let census = super::super::census_intentional_boundary_generators(
        &fixture.repository,
        &fixture.revision,
        fixture.root.path(),
        &fixture.inventory,
        &fixture.source,
        &fixture.semantic,
        &fixture.project_models,
        &fixture.manifests,
        &fixture.bindings,
        &fixture.evidence,
    )
    .unwrap();

    let outcome = &census.replays[0].outcome;
    match outcome {
        crate::benchmark::release::IntentionalBoundaryGeneratorReplayOutcome::Reproduced {
            preparations,
            outputs,
            executions,
            ..
        } => {
            assert!(go_available, "Go replay succeeded without a visible Go runtime");
            assert_eq!(preparations.len(), 2);
            assert_eq!(outputs.len(), 1);
            assert_eq!(executions.len(), 2);
            assert!(preparations.iter().all(|execution| execution.network_enabled));
            assert!(executions.iter().all(|execution| {
                !execution.network_enabled
                    && execution.environment.get("GOPROXY").map(String::as_str) == Some("off")
            }));
        }
        crate::benchmark::release::IntentionalBoundaryGeneratorReplayOutcome::Unresolved {
            reason:
                crate::benchmark::release::IntentionalBoundaryGeneratorUnresolvedReason::RuntimeUnavailable,
            ..
        } if !go_available => {}
        crate::benchmark::release::IntentionalBoundaryGeneratorReplayOutcome::Unresolved {
            reason:
                crate::benchmark::release::IntentionalBoundaryGeneratorUnresolvedReason::SandboxUnavailable,
            ..
        } if cfg!(windows) => {}
        _ => panic!("real Go generator did not reproduce its committed output: {outcome:#?}"),
    }
}

struct RealFixture {
    root: tempfile::TempDir,
    repository: String,
    revision: String,
    inventory: crate::benchmark::release::IntentionalBoundaryRepositoryInventory,
    source: crate::benchmark::release::IntentionalBoundarySourceCensus,
    semantic: IntentionalBoundarySemanticCensus,
    project_models: IntentionalBoundaryProjectModelCensus,
    manifests: crate::benchmark::release::IntentionalBoundaryManifestCensus,
    bindings: crate::benchmark::release::IntentionalBoundaryManifestBindingCensus,
    evidence: crate::benchmark::release::IntentionalBoundaryEvidenceCensus,
}

fn real_fixture() -> RealFixture {
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
            "https://github.com/example/go-generator-fixture.git",
        ],
    );
    fs::create_dir_all(root.path().join("tools/cmd/generate")).unwrap();
    fs::write(
        root.path().join("go.mod"),
        "module example.com/sniff-go-generator\n\ngo 1.22\n",
    )
    .unwrap();
    fs::write(
        root.path().join("tools/gen.go"),
        concat!(
            "package tools\n\n",
            "//go:generate go run ./cmd/generate\n",
            "func Keep() int { return 1 }\n",
        ),
    )
    .unwrap();
    let generated = concat!(
        "// Code generated by go generate; DO NOT EDIT.\n\n",
        "package tools\n\n",
        "func GeneratedValue() int { return 7 }\n",
    );
    fs::write(root.path().join("tools/generated.go"), generated).unwrap();
    fs::write(
        root.path().join("tools/cmd/generate/main.go"),
        format!(
            "package main\n\nimport \"os\"\n\nfunc main() {{\n\tif err := os.WriteFile(\"generated.go\", []byte({generated:?}), 0o644); err != nil {{\n\t\tpanic(err)\n\t}}\n}}\n"
        ),
    )
    .unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let repository = "github.com/example/go-generator-fixture".to_string();
    let inventory =
        inventory_intentional_boundary_repository(&repository, &revision, root.path()).unwrap();
    let source =
        census_intentional_boundary_repository(&repository, &revision, root.path(), &inventory)
            .unwrap();
    let semantic = semantic_fixture(&source);
    let ast = census_intentional_boundary_go_ast(
        &repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
    )
    .unwrap();
    let evidence = extract_intentional_boundary_compiler_and_ast_evidence(
        &repository,
        &revision,
        root.path(),
        &inventory,
        &source,
        &semantic,
        &[ast],
    )
    .unwrap();
    let manifests =
        census_intentional_boundary_manifests(&repository, &revision, root.path(), &inventory)
            .unwrap();
    let bindings = bind_intentional_boundary_manifests(&source, &semantic, &manifests).unwrap();
    let project_models = parse_intentional_boundary_go_list(
        root.path(),
        &inventory,
        "go.mod",
        &"7".repeat(64),
        go_list_output(root.path()).as_bytes(),
    )
    .unwrap();
    RealFixture {
        root,
        repository,
        revision,
        inventory,
        source,
        semantic,
        project_models,
        manifests,
        bindings,
        evidence,
    }
}

fn go_list_output(root: &Path) -> String {
    let root = fs::canonicalize(root).unwrap();
    let module = serde_json::json!({
        "Path": "example.com/sniff-go-generator",
        "Version": "",
        "Dir": root,
        "GoMod": root.join("go.mod"),
        "Main": true,
    });
    [
        serde_json::json!({
            "Dir": root.join("tools"),
            "ImportPath": "example.com/sniff-go-generator/tools",
            "Name": "tools",
            "GoFiles": ["gen.go", "generated.go"],
            "Module": module,
        }),
        serde_json::json!({
            "Dir": root.join("tools/cmd/generate"),
            "ImportPath": "example.com/sniff-go-generator/tools/cmd/generate",
            "Name": "main",
            "GoFiles": ["main.go"],
            "Module": module,
        }),
    ]
    .into_iter()
    .map(|value| serde_json::to_string(&value).unwrap())
    .collect()
}

fn semantic_fixture(
    source: &crate::benchmark::release::IntentionalBoundarySourceCensus,
) -> IntentionalBoundarySemanticCensus {
    let methods = source
        .source_files
        .iter()
        .flat_map(|file| {
            file.methods.iter().map(move |method| {
                let symbol_id = format!(
                    "scip-go generator-fixture {}/{}().",
                    file.repository_path, method.symbol_name
                );
                let definition = IntentionalBoundarySemanticRange {
                    repository_path: file.repository_path.clone(),
                    start_line_zero_based: method.start_line.saturating_sub(1) as u32,
                    start_character_zero_based: 0,
                    end_line_zero_based: method.end_line.saturating_sub(1) as u32,
                    end_character_zero_based: 1,
                };
                IntentionalBoundarySemanticMethod {
                    parser_unit_id: method.parser_unit_id.clone(),
                    repository_path: file.repository_path.clone(),
                    symbol_name: method.symbol_name.clone(),
                    start_line: method.start_line,
                    end_line: method.end_line,
                    indexer: IntentionalBoundaryIndexerKind::Go,
                    status: IntentionalBoundarySemanticMethodStatus::Resolved {
                        symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                            symbol_id: symbol_id.clone(),
                            provider_identity: symbol_id,
                            display_name: Some(method.symbol_name.clone()),
                            category: IntentionalBoundarySemanticSymbolCategory::Callable,
                            provider_kind: "function".to_string(),
                            documentation: Vec::new(),
                            signature: None,
                            signature_referenced_symbols: Vec::new(),
                            owner: None,
                            definitions: vec![definition.clone()],
                            visibility: IntentionalBoundarySemanticVisibility::Public,
                            surfaces: Vec::new(),
                            origin: IntentionalBoundarySemanticOrigin::Repository,
                            ambiguity_notes: Vec::new(),
                        }),
                        joined_definition: Some(definition),
                    },
                    occurrences: Vec::new(),
                    calls: Vec::new(),
                    relationships: Vec::new(),
                    imports: Vec::new(),
                    test_relationships: Vec::new(),
                }
            })
        })
        .collect::<Vec<_>>();
    let mut semantic = IntentionalBoundarySemanticCensus {
        schema_version:
            crate::benchmark::release::INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract:
            crate::benchmark::release::intentional_boundary_semantic::SEMANTIC_CENSUS_CONTRACT
                .to_string(),
        repository: source.repository.clone(),
        revision: source.revision.clone(),
        source_census_sha256: source.census_sha256.clone(),
        indexers: vec![IntentionalBoundarySemanticIndexerCensus {
            indexer: IntentionalBoundaryIndexerKind::Go,
            tool_name: "scip-go".to_string(),
            tool_version: Some("fixture".to_string()),
            semantic_facts_sha256: "8".repeat(64),
            diagnostic_count: 0,
            diagnostics_sha256: "9".repeat(64),
            document_count: source.source_files.len(),
            symbol_count: methods.len(),
            relationship_count: 0,
            import_count: 0,
            call_count: 0,
            test_relationship_count: 0,
            unresolved_edge_count: 0,
        }],
        resolved_method_count: methods.len(),
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        methods,
        semantic_census_sha256: String::new(),
    };
    semantic.semantic_census_sha256 =
        crate::benchmark::release::intentional_boundary_semantic::compute_semantic_census_sha256(
            &semantic,
        )
        .unwrap();
    semantic
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}
