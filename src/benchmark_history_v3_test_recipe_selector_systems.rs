use super::*;

pub(super) fn cargo_recipe(
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

pub(super) fn go_recipe(
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

pub(super) fn gradle_recipe(
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
