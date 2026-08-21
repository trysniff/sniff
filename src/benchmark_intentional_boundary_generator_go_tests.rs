use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelExecution,
    IntentionalBoundaryProjectModelTarget, IntentionalBoundarySemanticRange,
};

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
