use super::*;
use crate::benchmark::BoundaryGitEntryKind;

#[test]
fn selects_each_language_native_recipe_family() {
    let node = vec![
        fact(
            "package.json",
            HistoricalV3RecipeInputInterpretation::NodePackage {
                has_test_script: true,
            },
        ),
        fact(
            "package-lock.json",
            HistoricalV3RecipeInputInterpretation::Opaque,
        ),
    ];
    let (pairs, inputs) = pairs_and_inputs(&node);
    assert_eq!(
        node_recipe(&pairs, inputs).unwrap().selector,
        HistoricalV3TestRecipeSelector::NodePackage
    );

    let cargo = opaque_facts(&["Cargo.toml", "Cargo.lock"]);
    let (pairs, inputs) = pairs_and_inputs(&cargo);
    assert_eq!(
        cargo_recipe(&pairs, inputs).unwrap().selector,
        HistoricalV3TestRecipeSelector::Cargo
    );

    let go = opaque_facts(&["go.mod", "go.sum"]);
    let (pairs, inputs) = pairs_and_inputs(&go);
    assert_eq!(
        go_recipe(&pairs, inputs).unwrap().selector,
        HistoricalV3TestRecipeSelector::GoModule
    );

    let python = vec![
        fact(
            "pyproject.toml",
            HistoricalV3RecipeInputInterpretation::PythonProject {
                has_pytest_configuration: true,
            },
        ),
        fact("uv.lock", HistoricalV3RecipeInputInterpretation::Opaque),
    ];
    let (pairs, inputs) = pairs_and_inputs(&python);
    assert_eq!(
        python_recipe(&pairs, false, inputs).unwrap().selector,
        HistoricalV3TestRecipeSelector::PythonUv
    );

    for (lock, expected) in [
        ("poetry.lock", HistoricalV3TestRecipeSelector::PythonPoetry),
        ("pdm.lock", HistoricalV3TestRecipeSelector::PythonPdm),
    ] {
        let python = vec![
            fact(
                "pyproject.toml",
                HistoricalV3RecipeInputInterpretation::PythonProject {
                    has_pytest_configuration: true,
                },
            ),
            fact(lock, HistoricalV3RecipeInputInterpretation::Opaque),
        ];
        let (pairs, inputs) = pairs_and_inputs(&python);
        assert_eq!(
            python_recipe(&pairs, false, inputs).unwrap().selector,
            expected
        );
    }

    let requirements = vec![fact(
        "requirements.txt",
        HistoricalV3RecipeInputInterpretation::PythonRequirements {
            hash_locked: true,
            contains_pytest: true,
        },
    )];
    let (pairs, inputs) = pairs_and_inputs(&requirements);
    assert_eq!(
        python_recipe(&pairs, true, inputs).unwrap().selector,
        HistoricalV3TestRecipeSelector::PythonHashedRequirements
    );

    let gradle = vec![
        fact("gradlew", HistoricalV3RecipeInputInterpretation::Opaque),
        fact(
            "gradle/wrapper/gradle-wrapper.jar",
            HistoricalV3RecipeInputInterpretation::Opaque,
        ),
        fact(
            "gradle/wrapper/gradle-wrapper.properties",
            HistoricalV3RecipeInputInterpretation::GradleWrapperProperties {
                distribution_sha256: Some("d".repeat(64)),
            },
        ),
        fact(
            "build.gradle.kts",
            HistoricalV3RecipeInputInterpretation::Opaque,
        ),
        fact(
            "gradle/verification-metadata.xml",
            HistoricalV3RecipeInputInterpretation::Opaque,
        ),
    ];
    let (pairs, inputs) = pairs_and_inputs(&gradle);
    assert_eq!(
        gradle_recipe(&pairs, inputs).unwrap().selector,
        HistoricalV3TestRecipeSelector::GradleWrapper
    );
}

#[test]
fn rejects_ambiguous_node_locks_and_unhashed_python_requirements() {
    let node = vec![
        fact(
            "package.json",
            HistoricalV3RecipeInputInterpretation::NodePackage {
                has_test_script: true,
            },
        ),
        fact(
            "package-lock.json",
            HistoricalV3RecipeInputInterpretation::Opaque,
        ),
        fact(
            "pnpm-lock.yaml",
            HistoricalV3RecipeInputInterpretation::Opaque,
        ),
    ];
    let (pairs, inputs) = pairs_and_inputs(&node);
    assert_eq!(
        node_recipe(&pairs, inputs).unwrap_err(),
        HistoricalV3TestRecipeExclusionReason::AmbiguousRecipeInputs
    );

    let python = vec![fact(
        "requirements.txt",
        HistoricalV3RecipeInputInterpretation::PythonRequirements {
            hash_locked: false,
            contains_pytest: true,
        },
    )];
    let (pairs, inputs) = pairs_and_inputs(&python);
    assert_eq!(
        python_recipe(&pairs, true, inputs).unwrap_err(),
        HistoricalV3TestRecipeExclusionReason::UnreproducibleDependencies
    );
}

#[test]
fn berry_recipe_disables_network_without_using_the_classic_flag() {
    let node = vec![
        fact(
            "package.json",
            HistoricalV3RecipeInputInterpretation::NodePackage {
                has_test_script: true,
            },
        ),
        fact(
            "yarn.lock",
            HistoricalV3RecipeInputInterpretation::YarnLock {
                generation: HistoricalV3YarnLockGeneration::Berry,
            },
        ),
    ];
    let (pairs, inputs) = pairs_and_inputs(&node);
    let plan = node_recipe(&pairs, inputs).unwrap();
    assert_eq!(
        plan.preparation_commands[0].argv,
        argv(&["yarn", "install", "--immutable", "--immutable-cache"])
    );
    assert_eq!(
        plan.preparation_commands[0]
            .environment
            .get("YARN_ENABLE_NETWORK")
            .map(String::as_str),
        Some("0")
    );
}

fn pairs_and_inputs(
    facts: &[HistoricalV3RecipeInputFact],
) -> (InputPairs<'_>, Vec<HistoricalV3TestRecipeInputBinding>) {
    let pairs = InputPairs::new(facts, facts).unwrap();
    let inputs = pairs.bindings().unwrap();
    (pairs, inputs)
}

fn opaque_facts(paths: &[&str]) -> Vec<HistoricalV3RecipeInputFact> {
    paths
        .iter()
        .map(|path| fact(path, HistoricalV3RecipeInputInterpretation::Opaque))
        .collect()
}

fn fact(
    path: &str,
    interpretation: HistoricalV3RecipeInputInterpretation,
) -> HistoricalV3RecipeInputFact {
    HistoricalV3RecipeInputFact {
        repository_path: path.to_string(),
        mode: "100644".to_string(),
        entry_kind: BoundaryGitEntryKind::RegularBlob,
        object_id: "a".repeat(40),
        byte_length: Some(1),
        input_status: HistoricalV3RecipeInputStatus::Committed {
            content_sha256: "b".repeat(64),
            interpretation,
        },
    }
}
