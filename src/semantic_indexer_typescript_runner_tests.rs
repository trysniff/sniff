use super::*;
use std::process::Command;

fn plan(project: Option<&str>) -> SemanticIndexerVariantPlan {
    SemanticIndexerVariantPlan {
        identity: crate::semantic_index::SemanticVariantId("typescript-world".to_string()),
        dimensions: BTreeMap::from([
            ("compiler_version".to_string(), "5.6.2".to_string()),
            (
                "root_config".to_string(),
                project.unwrap_or("<inferred>").to_string(),
            ),
        ]),
        environment: BTreeMap::new(),
        compiler_query: match project {
            Some(_) => crate::semantic_index::SemanticIndexerCompilerQuery::ProjectPackages,
            None => crate::semantic_index::SemanticIndexerCompilerQuery::ExactSources {
                source_documents: BTreeSet::from([RepositoryPath("src/index.ts".to_string())]),
            },
        },
        compiler_project: project.map(|path| RepositoryPath(path.to_string())),
        selected_documents: BTreeSet::from([RepositoryPath("src/index.ts".to_string())]),
        ignored_documents: BTreeSet::new(),
    }
}

#[test]
fn explicit_project_uses_the_exact_compiler_config() {
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();

    assert_eq!(
        variant_arguments(spec, &plan(Some("packages/api/tsconfig.build.json"))).unwrap(),
        ["index", "packages/api/tsconfig.build.json"]
    );
}

#[test]
fn loose_project_uses_an_exact_generated_compiler_config() {
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    let root = tempfile::tempdir().unwrap();
    let project = plan(None);
    let config = prepare_loose_project(spec, root.path(), &project)
        .unwrap()
        .unwrap();

    assert_eq!(
        variant_arguments(spec, &project).unwrap(),
        ["index", ".sniff-typescript-loose-project.json"]
    );
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    assert_eq!(
        value["compilerOptions"],
        serde_json::json!({"noEmit": true})
    );
    assert_eq!(value["files"], serde_json::json!(["src/index.ts"]));
}

#[test]
fn loose_mixed_project_enables_only_the_required_compiler_modes() {
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut project = plan(None);
    let roots = BTreeSet::from([
        RepositoryPath("rollup.config.js".to_string()),
        RepositoryPath("src/view.tsx".to_string()),
    ]);
    project.compiler_query = crate::semantic_index::SemanticIndexerCompilerQuery::ExactSources {
        source_documents: roots.clone(),
    };
    project.selected_documents = roots;

    let config = prepare_loose_project(spec, root.path(), &project)
        .unwrap()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();

    assert_eq!(
        value["compilerOptions"],
        serde_json::json!({
            "allowJs": true,
            "checkJs": false,
            "jsx": "preserve",
            "noEmit": true
        })
    );
    assert_eq!(
        value["files"],
        serde_json::json!(["rollup.config.js", "src/view.tsx"])
    );
}

#[test]
fn failed_variant_run_removes_a_partial_repository_output() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("index.scip"), b"partial").unwrap();
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript).unwrap();
    let failure = indexer_failure(
        spec,
        SemanticIndexerRunFailureKind::RepositoryRejected,
        SemanticIndexerRunPhase::Execution,
        "provider failed",
    );

    let returned = clean_after_failed_run(root.path(), spec, failure);

    assert_eq!(returned.phase, SemanticIndexerRunPhase::Execution);
    assert!(!root.path().join("index.scip").exists());
}

#[tokio::test]
#[ignore = "requires installed pinned scip-typescript runtime, Node.js, and native sandbox"]
async fn live_project_reference_world_is_indexed_as_one_qualified_variant() {
    let root = tempfile::tempdir().unwrap();
    let progress = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    git(root.path(), &["config", "user.name", "Sniff"]);
    git(
        root.path(),
        &["config", "user.email", "sniff@example.invalid"],
    );
    let files = vec![
        write_file(
            root.path(),
            "src/index.ts",
            "import { core } from '../packages/core/src/core';\nexport function main(): string { return core(); }\n",
        ),
        write_file(
            root.path(),
            "packages/core/src/core.ts",
            "export function core(): string { return 'core'; }\n",
        ),
    ];
    write_text(
        root.path(),
        "tsconfig.json",
        r#"{"files":["src/index.ts"],"references":[{"path":"packages/core"}]}"#,
    );
    write_text(
        root.path(),
        "packages/core/tsconfig.json",
        r#"{"compilerOptions":{"composite":true},"files":["src/core.ts"]}"#,
    );
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let plan = SemanticIndexerVariantPlan {
        identity: crate::semantic_index::SemanticVariantId("typescript-world".to_string()),
        dimensions: BTreeMap::from([
            ("compiler_version".to_string(), "5.6.2".to_string()),
            ("root_config".to_string(), "tsconfig.json".to_string()),
        ]),
        environment: BTreeMap::new(),
        compiler_query: crate::semantic_index::SemanticIndexerCompilerQuery::ProjectPackages,
        compiler_project: Some(RepositoryPath("tsconfig.json".to_string())),
        selected_documents: BTreeSet::from([
            RepositoryPath("packages/core/src/core.ts".to_string()),
            RepositoryPath("src/index.ts".to_string()),
        ]),
        ignored_documents: BTreeSet::new(),
    };
    let variant_plans = BTreeMap::from([(SemanticIndexerKind::TypeScriptJavaScript, vec![plan])]);
    let outcome = run_required_indexers_exhaustive_typed_scoped_resumable_with_variants(
        root.path(),
        &files,
        &files,
        progress.path(),
        &variant_plans,
    )
    .await
    .unwrap();
    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    let SemanticIndexSet::Qualified {
        variants: qualified_variants,
    } = &outcome.indexes[&SemanticIndexerKind::TypeScriptJavaScript]
    else {
        panic!("expected a qualified TypeScript semantic index");
    };
    let index = &qualified_variants
        [&crate::semantic_index::SemanticVariantId("typescript-world".to_string())]
        .index;
    assert!(
        index
            .documents
            .contains_key(&RepositoryPath("src/index.ts".to_string()))
    );
    assert!(
        index
            .documents
            .contains_key(&RepositoryPath("packages/core/src/core.ts".to_string()))
    );
    let resumed = run_required_indexers_exhaustive_typed_scoped_resumable_with_variants(
        root.path(),
        &files,
        &files,
        progress.path(),
        &variant_plans,
    )
    .await
    .unwrap();
    assert!(resumed.failures.is_empty(), "{:?}", resumed.failures);
    assert_eq!(resumed.indexes, outcome.indexes);
}

#[tokio::test]
#[ignore = "requires installed pinned scip-typescript runtime, Node.js, and native sandbox"]
async fn live_configured_and_loose_worlds_cover_every_exact_source() {
    let root = tempfile::tempdir().unwrap();
    let progress = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    git(root.path(), &["config", "user.name", "Sniff"]);
    git(
        root.path(),
        &["config", "user.email", "sniff@example.invalid"],
    );
    let files = vec![
        write_file(root.path(), "src/index.ts", "export const value = 1;\n"),
        write_file(
            root.path(),
            "src/index.test.ts",
            "export const expected = 1;\n",
        ),
        write_file_language(
            root.path(),
            "rollup.config.js",
            "export default {};\n",
            "javascript",
        ),
    ];
    write_text(
        root.path(),
        "tsconfig.json",
        r#"{"files":["src/index.ts"]}"#,
    );
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let configured = SemanticIndexerVariantPlan {
        identity: crate::semantic_index::SemanticVariantId("configured-world".to_string()),
        dimensions: BTreeMap::from([
            ("compiler_version".to_string(), "5.6.2".to_string()),
            ("root_config".to_string(), "tsconfig.json".to_string()),
        ]),
        environment: BTreeMap::new(),
        compiler_query: crate::semantic_index::SemanticIndexerCompilerQuery::ProjectPackages,
        compiler_project: Some(RepositoryPath("tsconfig.json".to_string())),
        selected_documents: BTreeSet::from([RepositoryPath("src/index.ts".to_string())]),
        ignored_documents: BTreeSet::from([
            RepositoryPath("rollup.config.js".to_string()),
            RepositoryPath("src/index.test.ts".to_string()),
        ]),
    };
    let loose_roots = BTreeSet::from([
        RepositoryPath("rollup.config.js".to_string()),
        RepositoryPath("src/index.test.ts".to_string()),
    ]);
    let loose = SemanticIndexerVariantPlan {
        identity: crate::semantic_index::SemanticVariantId("loose-world".to_string()),
        dimensions: BTreeMap::from([
            ("compiler_version".to_string(), "5.6.2".to_string()),
            ("root_config".to_string(), "<inferred>".to_string()),
        ]),
        environment: BTreeMap::new(),
        compiler_query: crate::semantic_index::SemanticIndexerCompilerQuery::ExactSources {
            source_documents: loose_roots.clone(),
        },
        compiler_project: None,
        selected_documents: loose_roots,
        ignored_documents: BTreeSet::from([RepositoryPath("src/index.ts".to_string())]),
    };
    let variant_plans = BTreeMap::from([(
        SemanticIndexerKind::TypeScriptJavaScript,
        vec![configured, loose],
    )]);

    let outcome = run_required_indexers_exhaustive_typed_scoped_resumable_with_variants(
        root.path(),
        &files,
        &files,
        progress.path(),
        &variant_plans,
    )
    .await
    .unwrap();

    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    let SemanticIndexSet::Qualified { variants } =
        &outcome.indexes[&SemanticIndexerKind::TypeScriptJavaScript]
    else {
        panic!("expected qualified TypeScript semantic variants");
    };
    assert_eq!(variants.len(), 2);
    let loose =
        &variants[&crate::semantic_index::SemanticVariantId("loose-world".to_string())].index;
    assert!(
        loose
            .documents
            .contains_key(&RepositoryPath("rollup.config.js".to_string()))
    );
    let module_anchor = crate::semantic_index::SemanticLocation {
        document: RepositoryPath("rollup.config.js".to_string()),
        range: crate::semantic_index::SemanticSourceRange {
            start: crate::semantic_index::SemanticPosition {
                line: 0,
                character: 0,
            },
            end: crate::semantic_index::SemanticPosition {
                line: 0,
                character: 0,
            },
        },
    };
    let module_symbols = loose
        .symbols
        .values()
        .filter(|symbol| {
            symbol.origin == crate::semantic_index::SemanticSymbolOrigin::Repository
                && symbol.kind.category == crate::semantic_index::SemanticSymbolCategory::Module
                && symbol.definitions.contains(&module_anchor)
        })
        .collect::<Vec<_>>();
    assert_eq!(module_symbols.len(), 1);
    assert!(
        loose
            .documents
            .contains_key(&RepositoryPath("src/index.test.ts".to_string()))
    );
}

fn write_file(root: &Path, relative: &str, source: &str) -> FileRecord {
    write_file_language(root, relative, source, "typescript")
}

fn write_file_language(root: &Path, relative: &str, source: &str, language: &str) -> FileRecord {
    write_text(root, relative, source);
    FileRecord {
        file_path: root.join(relative).to_string_lossy().into_owned(),
        source: source.to_string(),
        language: language.to_string(),
        methods: Vec::new(),
    }
}

fn write_text(root: &Path, relative: &str, source: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
}

fn git(root: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}
