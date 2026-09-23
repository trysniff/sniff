use super::*;

pub(super) fn node_recipe(
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
        "yarn" => yarn_commands(pairs)?,
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

type NodeCommands = (Vec<String>, Vec<(&'static str, &'static str)>, Vec<String>);

fn yarn_commands(
    pairs: &InputPairs<'_>,
) -> Result<NodeCommands, HistoricalV3TestRecipeExclusionReason> {
    let generation = match interpretation(
        pairs
            .fact("yarn.lock")
            .ok_or(HistoricalV3TestRecipeExclusionReason::MissingRecipeInputs)?,
    )? {
        HistoricalV3RecipeInputInterpretation::YarnLock { generation } => *generation,
        _ => return Err(HistoricalV3TestRecipeExclusionReason::InvalidRecipeInput),
    };
    Ok(match generation {
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
    })
}
