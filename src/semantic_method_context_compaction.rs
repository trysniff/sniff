use super::CompilerMethodWorld;
use crate::semantic_index::{SemanticIndexVariant, SemanticVariantId};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, PartialEq, Eq)]
struct CompactContext {
    common_dimensions: BTreeMap<String, String>,
    worlds: Vec<ContextWorld>,
    fact_groups: BTreeMap<Vec<String>, Vec<usize>>,
}

#[derive(Debug, PartialEq, Eq)]
struct ContextWorld {
    identity: Option<SemanticVariantId>,
    additional_dimensions: BTreeMap<String, String>,
}

pub(super) fn render(worlds: &[CompilerMethodWorld]) -> Result<String, String> {
    let compact = compact(worlds)?;
    let mut lines = vec![
        format!("observed compiler worlds: {}", worlds.len()),
        "Facts apply only to their listed observed worlds; omitted, rejected or unresolved contexts are not proven by agreement here.".to_string(),
    ];
    if !compact.common_dimensions.is_empty() {
        lines.push(format!(
            "common dimensions for every listed qualified world: {:?}",
            compact.common_dimensions
        ));
    }
    for (ordinal, world) in compact.worlds.iter().enumerate() {
        let header = match &world.identity {
            None => {
                "compiler variant: unqualified; not proof of all build configurations".to_string()
            }
            Some(identity) => {
                format!(
                    "compiler variant: qualified {:?}; additional dimensions: {:?}",
                    identity.0, world.additional_dimensions
                )
            }
        };
        lines.push(format!("W{}: {header}", ordinal + 1));
    }
    for (facts, members) in &compact.fact_groups {
        lines.push(format!(
            "\nfacts in observed worlds {}:",
            membership(members)
        ));
        lines.extend(facts.iter().cloned());
    }
    Ok(lines.join("\n"))
}

fn compact(worlds: &[CompilerMethodWorld]) -> Result<CompactContext, String> {
    let first = worlds
        .first()
        .ok_or_else(|| "compiler context has no observed worlds".to_string())?;
    let mut identities = BTreeSet::new();
    let mut common_dimensions = match &first.variant {
        SemanticIndexVariant::Unqualified => BTreeMap::new(),
        SemanticIndexVariant::Qualified { dimensions, .. } => dimensions.clone(),
    };
    for world in worlds {
        world.variant.validate()?;
        if world.lines.is_empty() {
            return Err("compiler context world omitted its facts".to_string());
        }
        match &world.variant {
            SemanticIndexVariant::Unqualified => {
                common_dimensions.clear();
                if !identities.insert(None) {
                    return Err("compiler context repeats an unqualified world".to_string());
                }
            }
            SemanticIndexVariant::Qualified {
                identity,
                dimensions,
            } => {
                if !identities.insert(Some(identity)) {
                    return Err("compiler context repeats a qualified world identity".to_string());
                }
                common_dimensions.retain(|key, value| dimensions.get(key) == Some(value));
            }
        }
    }
    let mut compact = CompactContext {
        common_dimensions,
        worlds: Vec::with_capacity(worlds.len()),
        fact_groups: BTreeMap::new(),
    };
    for (ordinal, world) in worlds.iter().enumerate() {
        let (identity, mut additional_dimensions) = match &world.variant {
            SemanticIndexVariant::Unqualified => (None, BTreeMap::new()),
            SemanticIndexVariant::Qualified {
                identity,
                dimensions,
            } => (Some(identity.clone()), dimensions.clone()),
        };
        additional_dimensions.retain(|key, _| !compact.common_dimensions.contains_key(key));
        compact.worlds.push(ContextWorld {
            identity,
            additional_dimensions,
        });
        compact
            .fact_groups
            .entry(world.lines.clone())
            .or_default()
            .push(ordinal);
    }
    Ok(compact)
}

fn membership(ordinals: &[usize]) -> String {
    let mut ranges = Vec::new();
    let mut position = 0;
    while position < ordinals.len() {
        let first = ordinals[position];
        let mut last = first;
        position += 1;
        while position < ordinals.len() && ordinals[position] == last + 1 {
            last = ordinals[position];
            position += 1;
        }
        ranges.push(if first == last {
            format!("W{}", first + 1)
        } else {
            format!("W{}-W{}", first + 1, last + 1)
        });
    }
    ranges.join(", ")
}

#[cfg(test)]
#[path = "tests/semantic_method_context_compaction.rs"]
mod tests;
