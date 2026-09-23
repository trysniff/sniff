use super::super::{
    HistoricalV3Language, HistoricalV3RecipeCommand, HistoricalV3RecipeInputFact,
    HistoricalV3RecipeInputInterpretation, HistoricalV3RecipeInputStatus,
    HistoricalV3SourceSnapshot, HistoricalV3TestRecipeExclusionReason,
    HistoricalV3TestRecipeInputBinding, HistoricalV3TestRecipeSelector,
    HistoricalV3YarnLockGeneration,
};
use std::collections::{BTreeMap, BTreeSet};

#[path = "benchmark_history_v3_test_recipe_selector_node.rs"]
mod node;
#[path = "benchmark_history_v3_test_recipe_selector_python.rs"]
mod python;
#[path = "benchmark_history_v3_test_recipe_selector_systems.rs"]
mod systems;

use node::node_recipe;
use python::python_recipe;
use systems::{cargo_recipe, go_recipe, gradle_recipe};

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
#[path = "benchmark_history_v3_test_recipe_selector_tests.rs"]
mod tests;
