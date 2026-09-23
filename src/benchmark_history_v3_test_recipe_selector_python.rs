use super::*;

pub(super) fn python_recipe(
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
            path.starts_with("requirements") && (path.ends_with(".txt") || path.ends_with(".lock"))
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
        return managed_recipe(lock, inputs);
    }
    requirements_recipe(pairs, requirements, inputs)
}

fn managed_recipe(
    lock: &str,
    inputs: Vec<HistoricalV3TestRecipeInputBinding>,
) -> Result<RecipePlan, HistoricalV3TestRecipeExclusionReason> {
    Ok(match lock {
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
    })
}

fn requirements_recipe(
    pairs: &InputPairs<'_>,
    requirements: Vec<&str>,
    inputs: Vec<HistoricalV3TestRecipeInputBinding>,
) -> Result<RecipePlan, HistoricalV3TestRecipeExclusionReason> {
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
