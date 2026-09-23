use super::super::{
    HistoricalV3Language, HistoricalV3RecipeCommand, HistoricalV3RecipeInputFact,
    HistoricalV3RecipeInputInterpretation, HistoricalV3RecipeInputStatus,
    HistoricalV3SourceSnapshot, HistoricalV3TestRecipeExclusionReason,
    HistoricalV3TestRecipeInputBinding, HistoricalV3TestRecipeSelector,
    HistoricalV3YarnLockGeneration,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub(super) struct RecipePlan {
    pub selector: HistoricalV3TestRecipeSelector,
    pub preparation_commands: Vec<HistoricalV3RecipeCommand>,
    pub test_command: HistoricalV3RecipeCommand,
    pub runtime_program: String,
    pub inputs: Vec<HistoricalV3TestRecipeInputBinding>,
}

pub(super) fn select_recipe(
    language: HistoricalV3Language,
    base: &HistoricalV3SourceSnapshot,
    merge: &HistoricalV3SourceSnapshot,
) -> Result<RecipePlan, HistoricalV3TestRecipeExclusionReason> {
    let pairs = InputPairs::new(&base.recipe_input_facts, &merge.recipe_input_facts)?;
    let inputs = pairs.bindings()?;
    match language {
        HistoricalV3Language::JavaScript | HistoricalV3Language::TypeScript => {
            node_recipe(&pairs, inputs)
        }
        HistoricalV3Language::Rust => cargo_recipe(&pairs, inputs),
        HistoricalV3Language::Go => go_recipe(&pairs, inputs),
        HistoricalV3Language::Python => {
            python_recipe(&pairs, has_python_test_source(base, merge), inputs)
        }
        HistoricalV3Language::Kotlin => gradle_recipe(&pairs, inputs),
    }
}

fn has_python_test_source(
    base: &HistoricalV3SourceSnapshot,
    merge: &HistoricalV3SourceSnapshot,
) -> bool {
    [base, merge].into_iter().all(|snapshot| {
        snapshot.source_file_facts.iter().any(|file| {
            file.repository_path
                .split('/')
                .any(|segment| matches!(segment, "test" | "tests"))
                && file.repository_path.ends_with(".py")
        })
    })
}

struct InputPairs<'a> {
    base: BTreeMap<&'a str, &'a HistoricalV3RecipeInputFact>,
    merge: BTreeMap<&'a str, &'a HistoricalV3RecipeInputFact>,
}

impl<'a> InputPairs<'a> {
    fn new(
        base: &'a [HistoricalV3RecipeInputFact],
        merge: &'a [HistoricalV3RecipeInputFact],
    ) -> Result<Self, HistoricalV3TestRecipeExclusionReason> {
        let base = fact_map(base)?;
        let merge = fact_map(merge)?;
        for fact in base.values().chain(merge.values()) {
            match fact.input_status {
                HistoricalV3RecipeInputStatus::Committed { .. } => {}
                HistoricalV3RecipeInputStatus::InvalidContent { .. } => {
                    return Err(HistoricalV3TestRecipeExclusionReason::InvalidRecipeInput);
                }
                HistoricalV3RecipeInputStatus::FileTooLarge => {
                    return Err(HistoricalV3TestRecipeExclusionReason::InputFileTooLarge);
                }
                HistoricalV3RecipeInputStatus::TotalLimitExceeded => {
                    return Err(HistoricalV3TestRecipeExclusionReason::InputTotalTooLarge);
                }
                HistoricalV3RecipeInputStatus::UnsupportedEntryKind => {
                    return Err(HistoricalV3TestRecipeExclusionReason::UnsupportedInputKind);
                }
            }
        }
        let paths = base
            .keys()
            .chain(merge.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for path in paths {
            let (Some(base), Some(merge)) = (base.get(path), merge.get(path)) else {
                return Err(HistoricalV3TestRecipeExclusionReason::ChangedRecipeInputs);
            };
            if !same_input(base, merge) {
                return Err(HistoricalV3TestRecipeExclusionReason::ChangedRecipeInputs);
            }
        }
        Ok(Self { base, merge })
    }

    fn fact(&self, path: &str) -> Option<&'a HistoricalV3RecipeInputFact> {
        self.base.get(path).copied()
    }

    fn contains(&self, path: &str) -> bool {
        self.base.contains_key(path)
    }

    fn paths(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.base.keys().copied()
    }

    fn bindings(
        &self,
    ) -> Result<Vec<HistoricalV3TestRecipeInputBinding>, HistoricalV3TestRecipeExclusionReason>
    {
        self.base
            .iter()
            .map(|(path, base)| {
                let merge = self
                    .merge
                    .get(path)
                    .copied()
                    .ok_or(HistoricalV3TestRecipeExclusionReason::ChangedRecipeInputs)?;
                Ok(HistoricalV3TestRecipeInputBinding {
                    repository_path: (*path).to_string(),
                    base_object_id: base.object_id.clone(),
                    merge_object_id: merge.object_id.clone(),
                    content_sha256: content_sha256(base)?.to_string(),
                })
            })
            .collect()
    }
}

fn node_recipe(
    pairs: &InputPairs<'_>,
    inputs: Vec<HistoricalV3TestRecipeInputBinding>,
) -> Result<RecipePlan, HistoricalV3TestRecipeExclusionReason> {
    let package = pairs
        .fact("package.json")
        .ok_or(HistoricalV3TestRecipeExclusionReason::MissingRecipeInputs)?;
    if !matches!(
        interpretation(package)?,
        HistoricalV3RecipeInputInterpretation::NodePackage {
            has_test_script: true
        }
    ) {
        return Err(HistoricalV3TestRecipeExclusionReason::NoTestsDeclared);
    }
    let lockfiles = [
        ("package-lock.json", "npm"),
        ("npm-shrinkwrap.json", "npm"),
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("bun.lock", "bun"),
        ("bun.lockb", "bun"),
    ]
    .into_iter()
    .filter(|(path, _)| pairs.contains(path))
    .collect::<Vec<_>>();
    if lockfiles.len() > 1 {
        return Err(HistoricalV3TestRecipeExclusionReason::AmbiguousRecipeInputs);
    }
    let Some((_, manager)) = lockfiles.first().copied() else {
        return Err(HistoricalV3TestRecipeExclusionReason::UnreproducibleDependencies);
    };
    let (preparation, preparation_environment, test) = match manager {
        "npm" => (
            argv(&["npm", "ci", "--offline"]),
            vec![("CI", "true")],
            argv(&["npm", "test"]),
        ),
        "pnpm" => (
            argv(&["pnpm", "install", "--offline", "--frozen-lockfile"]),
            vec![("CI", "true")],
            argv(&["pnpm", "test"]),
        ),
        "yarn" => {
            let generation = match interpretation(
                pairs
                    .fact("yarn.lock")
                    .ok_or(HistoricalV3TestRecipeExclusionReason::MissingRecipeInputs)?,
            )? {
                HistoricalV3RecipeInputInterpretation::YarnLock { generation } => *generation,
                _ => return Err(HistoricalV3TestRecipeExclusionReason::InvalidRecipeInput),
            };
            match generation {
                HistoricalV3YarnLockGeneration::Classic => (
                    argv(&["yarn", "install", "--offline", "--frozen-lockfile"]),
                    vec![("CI", "true")],
                    argv(&["yarn", "test"]),
                ),
                HistoricalV3YarnLockGeneration::Berry => (
                    argv(&["yarn", "install", "--immutable", "--immutable-cache"]),
                    vec![("CI", "true"), ("YARN_ENABLE_NETWORK", "0")],
                    argv(&["yarn", "test"]),
                ),
            }
        }
        "bun" => (
            argv(&["bun", "install", "--offline", "--frozen-lockfile"]),
            vec![("CI", "true")],
            argv(&["bun", "run", "test"]),
        ),
        _ => return Err(HistoricalV3TestRecipeExclusionReason::InvalidRecipeInput),
    };
    Ok(plan(
        HistoricalV3TestRecipeSelector::NodePackage,
        vec![command(preparation, preparation_environment)],
        command(test, [("CI", "true")]),
        manager,
        inputs,
    ))
}

fn cargo_recipe(
    pairs: &InputPairs<'_>,
    inputs: Vec<HistoricalV3TestRecipeInputBinding>,
) -> Result<RecipePlan, HistoricalV3TestRecipeExclusionReason> {
    require_paths(pairs, &["Cargo.toml", "Cargo.lock"])?;
    Ok(plan(
        HistoricalV3TestRecipeSelector::Cargo,
        vec![command(
            argv(&["cargo", "fetch", "--locked", "--offline"]),
            [("CARGO_NET_OFFLINE", "true")],
        )],
        command(
            argv(&[
                "cargo",
                "test",
                "--workspace",
                "--all-targets",
                "--locked",
                "--offline",
            ]),
            [("CARGO_NET_OFFLINE", "true")],
        ),
        "cargo",
        inputs,
    ))
}

fn go_recipe(
    pairs: &InputPairs<'_>,
    inputs: Vec<HistoricalV3TestRecipeInputBinding>,
) -> Result<RecipePlan, HistoricalV3TestRecipeExclusionReason> {
    require_paths(pairs, &["go.mod", "go.sum"])?;
    Ok(plan(
        HistoricalV3TestRecipeSelector::GoModule,
        vec![command(
            argv(&["go", "mod", "download"]),
            [("GOPROXY", "off")],
        )],
        command(argv(&["go", "test", "./..."]), [("GOPROXY", "off")]),
        "go",
        inputs,
    ))
}

fn python_recipe(
    pairs: &InputPairs<'_>,
    has_test_source: bool,
    inputs: Vec<HistoricalV3TestRecipeInputBinding>,
) -> Result<RecipePlan, HistoricalV3TestRecipeExclusionReason> {
    let pyproject_has_test = pairs
        .fact("pyproject.toml")
        .map(interpretation)
        .transpose()?
        .is_some_and(|value| {
            matches!(
                value,
                HistoricalV3RecipeInputInterpretation::PythonProject {
                    has_pytest_configuration: true
                }
            )
        });
    let has_pytest_config = pyproject_has_test
        || ["pytest.ini", "tox.ini", "setup.cfg"]
            .into_iter()
            .any(|path| pairs.contains(path));
    let manager_locks = ["uv.lock", "poetry.lock", "pdm.lock"]
        .into_iter()
        .filter(|path| pairs.contains(path))
        .collect::<Vec<_>>();
    let requirements = pairs
        .paths()
        .filter(|path| {
            path.starts_with("requirements") && path.ends_with(".txt")
                || path.starts_with("requirements") && path.ends_with(".lock")
        })
        .collect::<Vec<_>>();
    if manager_locks.len() + usize::from(!requirements.is_empty()) > 1 {
        return Err(HistoricalV3TestRecipeExclusionReason::AmbiguousRecipeInputs);
    }
    if !has_test_source && !has_pytest_config {
        return Err(HistoricalV3TestRecipeExclusionReason::NoTestsDeclared);
    }
    if let Some(lock) = manager_locks.first().copied() {
        require_paths(pairs, &["pyproject.toml", lock])?;
        return Ok(match lock {
            "uv.lock" => plan(
                HistoricalV3TestRecipeSelector::PythonUv,
                vec![command(
                    argv(&["uv", "sync", "--locked", "--offline", "--no-progress"]),
                    [("UV_OFFLINE", "1")],
                )],
                command(
                    argv(&["uv", "run", "--locked", "--offline", "pytest"]),
                    [("UV_OFFLINE", "1")],
                ),
                "uv",
                inputs,
            ),
            "poetry.lock" => plan(
                HistoricalV3TestRecipeSelector::PythonPoetry,
                vec![command(
                    argv(&["poetry", "sync", "--no-interaction", "--no-ansi"]),
                    [("PIP_NO_INDEX", "1"), ("POETRY_NO_INTERACTION", "1")],
                )],
                command(argv(&["poetry", "run", "pytest"]), [("PIP_NO_INDEX", "1")]),
                "poetry",
                inputs,
            ),
            "pdm.lock" => plan(
                HistoricalV3TestRecipeSelector::PythonPdm,
                vec![command(
                    argv(&["pdm", "sync", "--clean", "--no-editable"]),
                    [("PIP_NO_INDEX", "1")],
                )],
                command(argv(&["pdm", "run", "pytest"]), [("PIP_NO_INDEX", "1")]),
                "pdm",
                inputs,
            ),
            _ => return Err(HistoricalV3TestRecipeExclusionReason::InvalidRecipeInput),
        });
    }
    if requirements.is_empty() {
        return Err(HistoricalV3TestRecipeExclusionReason::UnreproducibleDependencies);
    }
    let mut contains_pytest = false;
    for path in &requirements {
        match interpretation(
            pairs
                .fact(path)
                .ok_or(HistoricalV3TestRecipeExclusionReason::MissingRecipeInputs)?,
        )? {
            HistoricalV3RecipeInputInterpretation::PythonRequirements {
                hash_locked: true,
                contains_pytest: found,
            } => contains_pytest |= *found,
            _ => return Err(HistoricalV3TestRecipeExclusionReason::UnreproducibleDependencies),
        }
    }
    if !contains_pytest {
        return Err(HistoricalV3TestRecipeExclusionReason::NoTestsDeclared);
    }
    let mut preparation = vec!["python".to_string(), "-m".to_string(), "pip".to_string()];
    preparation.extend(["install".to_string(), "--require-hashes".to_string()]);
    for path in requirements {
        preparation.extend(["-r".to_string(), path.to_string()]);
    }
    Ok(plan(
        HistoricalV3TestRecipeSelector::PythonHashedRequirements,
        vec![command(preparation, [("PIP_NO_INDEX", "1")])],
        command(argv(&["python", "-m", "pytest"]), [("PIP_NO_INDEX", "1")]),
        "python",
        inputs,
    ))
}

fn gradle_recipe(
    pairs: &InputPairs<'_>,
    inputs: Vec<HistoricalV3TestRecipeInputBinding>,
) -> Result<RecipePlan, HistoricalV3TestRecipeExclusionReason> {
    require_paths(
        pairs,
        &[
            "gradlew",
            "gradle/wrapper/gradle-wrapper.jar",
            "gradle/wrapper/gradle-wrapper.properties",
        ],
    )?;
    let properties = pairs
        .fact("gradle/wrapper/gradle-wrapper.properties")
        .ok_or(HistoricalV3TestRecipeExclusionReason::MissingRecipeInputs)?;
    if !matches!(
        interpretation(properties)?,
        HistoricalV3RecipeInputInterpretation::GradleWrapperProperties {
            distribution_sha256: Some(_)
        }
    ) {
        return Err(HistoricalV3TestRecipeExclusionReason::UnreproducibleDependencies);
    }
    let has_build = pairs.paths().any(|path| {
        matches!(
            path.rsplit('/').next(),
            Some("settings.gradle" | "settings.gradle.kts" | "build.gradle" | "build.gradle.kts")
        )
    });
    let has_dependency_lock = pairs.paths().any(|path| {
        path.ends_with("gradle.lockfile")
            || path.contains("/gradle/dependency-locks/")
            || path == "gradle/verification-metadata.xml"
    });
    if !has_build {
        return Err(HistoricalV3TestRecipeExclusionReason::MissingRecipeInputs);
    }
    if !has_dependency_lock {
        return Err(HistoricalV3TestRecipeExclusionReason::UnreproducibleDependencies);
    }
    let common = [
        "--offline",
        "--no-daemon",
        "--no-build-cache",
        "--console=plain",
    ];
    let mut preparation = vec!["./gradlew".to_string(), "testClasses".to_string()];
    preparation.extend(common.iter().map(|value| value.to_string()));
    let mut test = vec!["./gradlew".to_string(), "test".to_string()];
    test.extend(common.iter().map(|value| value.to_string()));
    Ok(plan(
        HistoricalV3TestRecipeSelector::GradleWrapper,
        vec![command(preparation, std::iter::empty::<(&str, &str)>())],
        command(test, std::iter::empty::<(&str, &str)>()),
        "./gradlew",
        inputs,
    ))
}

fn fact_map(
    facts: &[HistoricalV3RecipeInputFact],
) -> Result<BTreeMap<&str, &HistoricalV3RecipeInputFact>, HistoricalV3TestRecipeExclusionReason> {
    let map = facts
        .iter()
        .map(|fact| (fact.repository_path.as_str(), fact))
        .collect::<BTreeMap<_, _>>();
    if map.len() != facts.len() {
        return Err(HistoricalV3TestRecipeExclusionReason::InvalidRecipeInput);
    }
    Ok(map)
}

fn same_input(base: &HistoricalV3RecipeInputFact, merge: &HistoricalV3RecipeInputFact) -> bool {
    base.repository_path == merge.repository_path
        && base.mode == merge.mode
        && base.entry_kind == merge.entry_kind
        && base.object_id == merge.object_id
        && base.byte_length == merge.byte_length
        && content_sha256(base).ok() == content_sha256(merge).ok()
}

fn content_sha256(
    fact: &HistoricalV3RecipeInputFact,
) -> Result<&str, HistoricalV3TestRecipeExclusionReason> {
    match &fact.input_status {
        HistoricalV3RecipeInputStatus::Committed { content_sha256, .. } => Ok(content_sha256),
        _ => Err(HistoricalV3TestRecipeExclusionReason::InvalidRecipeInput),
    }
}

fn interpretation(
    fact: &HistoricalV3RecipeInputFact,
) -> Result<&HistoricalV3RecipeInputInterpretation, HistoricalV3TestRecipeExclusionReason> {
    match &fact.input_status {
        HistoricalV3RecipeInputStatus::Committed { interpretation, .. } => Ok(interpretation),
        _ => Err(HistoricalV3TestRecipeExclusionReason::InvalidRecipeInput),
    }
}

fn require_paths(
    pairs: &InputPairs<'_>,
    paths: &[&str],
) -> Result<(), HistoricalV3TestRecipeExclusionReason> {
    if paths.iter().all(|path| pairs.contains(path)) {
        Ok(())
    } else {
        Err(HistoricalV3TestRecipeExclusionReason::MissingRecipeInputs)
    }
}

fn plan(
    selector: HistoricalV3TestRecipeSelector,
    preparation_commands: Vec<HistoricalV3RecipeCommand>,
    test_command: HistoricalV3RecipeCommand,
    runtime_program: &str,
    inputs: Vec<HistoricalV3TestRecipeInputBinding>,
) -> RecipePlan {
    RecipePlan {
        selector,
        preparation_commands,
        test_command,
        runtime_program: runtime_program.to_string(),
        inputs,
    }
}

fn argv(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn command<'a>(
    argv: Vec<String>,
    environment: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> HistoricalV3RecipeCommand {
    HistoricalV3RecipeCommand {
        argv,
        environment: environment
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
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
}
