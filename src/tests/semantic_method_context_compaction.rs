use super::*;

fn world(identity: &str, target: &str, facts: &[&str]) -> CompilerMethodWorld {
    CompilerMethodWorld {
        variant: SemanticIndexVariant::Qualified {
            identity: SemanticVariantId(identity.to_string()),
            dimensions: BTreeMap::from([
                ("target".to_string(), target.to_string()),
                ("source_snapshot_sha256".to_string(), "a".repeat(64)),
                ("compiler_runtime_sha256".to_string(), "b".repeat(64)),
            ]),
        },
        lines: facts.iter().map(|fact| (*fact).to_string()).collect(),
    }
}

fn expand(context: &CompactContext) -> Vec<CompilerMethodWorld> {
    let mut facts = vec![None; context.worlds.len()];
    for (lines, members) in &context.fact_groups {
        for member in members {
            assert!(facts[*member].replace(lines.clone()).is_none());
        }
    }
    context
        .worlds
        .iter()
        .zip(facts)
        .map(|(world, lines)| {
            let variant = match &world.identity {
                None => {
                    assert!(context.common_dimensions.is_empty());
                    assert!(world.additional_dimensions.is_empty());
                    SemanticIndexVariant::Unqualified
                }
                Some(identity) => {
                    let mut dimensions = context.common_dimensions.clone();
                    for (key, value) in &world.additional_dimensions {
                        assert!(dimensions.insert(key.clone(), value.clone()).is_none());
                    }
                    SemanticIndexVariant::Qualified {
                        identity: identity.clone(),
                        dimensions,
                    }
                }
            };
            variant.validate().unwrap();
            CompilerMethodWorld {
                variant,
                lines: lines.unwrap(),
            }
        })
        .collect()
}

#[test]
fn equal_facts_compact_without_losing_worlds_dimensions_or_provenance() {
    let worlds = [
        world("linux-debug", "linux", &["same fact", "unknown tests"]),
        world("linux-release", "linux", &["same fact", "unknown tests"]),
        world("windows", "windows", &["same fact", "unknown tests"]),
    ];
    let compact = compact(&worlds).unwrap();
    assert_eq!(compact.worlds.len(), 3);
    assert_eq!(compact.fact_groups.len(), 1);
    assert_eq!(compact.common_dimensions.len(), 2);
    assert_eq!(expand(&compact), worlds);
    let rendered = render(&worlds).unwrap();
    assert_eq!(rendered.matches("same fact").count(), 1);
    assert_eq!(rendered.matches(&"a".repeat(64)).count(), 1);
    assert!(rendered.contains("W1-W3"));
    for identity in ["linux-debug", "linux-release", "windows"] {
        assert!(rendered.contains(identity));
    }
}

#[test]
fn conditional_exclusions_and_unknowns_do_not_become_cross_world_absence() {
    let worlds = [
        world(
            "linux",
            "linux",
            &["compiler symbol: resolved method", "tests: unknown"],
        ),
        world(
            "windows",
            "windows",
            &["compiler coverage: excluded", "tests: unknown"],
        ),
        world(
            "darwin",
            "darwin",
            &["compiler symbol: unresolved", "tests: unknown"],
        ),
        world(
            "linux-alias",
            "linux",
            &["compiler symbol: resolved method", "tests: unknown"],
        ),
    ];
    let compact = compact(&worlds).unwrap();
    assert_eq!(expand(&compact), worlds);
    assert_eq!(compact.fact_groups.len(), 3);
    assert_eq!(compact.fact_groups[&worlds[0].lines], [0, 3]);
    let rendered = render(&worlds).unwrap();
    assert!(rendered.contains("facts in observed worlds W1, W4:\ncompiler symbol: resolved"));
    assert!(rendered.contains("facts in observed worlds W2:\ncompiler coverage: excluded"));
    assert!(rendered.contains("facts in observed worlds W3:\ncompiler symbol: unresolved"));
    assert!(rendered.contains("omitted, rejected or unresolved contexts are not proven"));
}

#[test]
fn dimensions_missing_in_one_world_are_never_promoted_to_common() {
    let mut first = world("linux", "linux", &["facts"]);
    let mut second = world("windows", "linux", &["facts"]);
    let SemanticIndexVariant::Qualified { dimensions, .. } = &mut first.variant else {
        unreachable!()
    };
    dimensions.insert("extra".to_string(), "first only".to_string());
    let SemanticIndexVariant::Qualified { dimensions, .. } = &mut second.variant else {
        unreachable!()
    };
    dimensions.remove("compiler_runtime_sha256");
    let worlds = [first, second];
    let compact = compact(&worlds).unwrap();
    assert!(!compact.common_dimensions.contains_key("extra"));
    assert!(
        !compact
            .common_dimensions
            .contains_key("compiler_runtime_sha256")
    );
    assert_eq!(expand(&compact), worlds);
}

#[test]
fn unqualified_world_keeps_warning_and_prevents_common_qualified_dimensions() {
    let worlds = [
        CompilerMethodWorld {
            variant: SemanticIndexVariant::Unqualified,
            lines: vec!["facts".to_string()],
        },
        world("qualified", "linux", &["facts"]),
    ];
    let compact = compact(&worlds).unwrap();
    assert!(compact.common_dimensions.is_empty());
    assert_eq!(expand(&compact), worlds);
    assert!(
        render(&worlds)
            .unwrap()
            .contains("not proof of all build configurations")
    );
}

#[test]
fn malformed_empty_or_repeated_worlds_fail_instead_of_disappearing() {
    assert!(render(&[]).is_err());
    let one = world("one", "linux", &["facts"]);
    assert!(
        render(&[one.clone(), one.clone()])
            .unwrap_err()
            .contains("repeats")
    );
    let mut invalid = one.clone();
    invalid.lines.clear();
    assert!(render(&[invalid]).unwrap_err().contains("omitted"));
    let mut invalid = one;
    let SemanticIndexVariant::Qualified { dimensions, .. } = &mut invalid.variant else {
        unreachable!()
    };
    dimensions.clear();
    assert!(render(&[invalid]).is_err());
    let unknown = CompilerMethodWorld {
        variant: SemanticIndexVariant::Unqualified,
        lines: vec!["facts".to_string()],
    };
    assert!(render(&[unknown.clone(), unknown]).is_err());
}

#[test]
fn fact_line_boundaries_are_not_parsed_or_reclassified_during_grouping() {
    let worlds = [
        world("one", "linux", &["one\ntwo"]),
        world("two", "linux", &["one", "two"]),
    ];
    let compact = compact(&worlds).unwrap();
    assert_eq!(compact.fact_groups.len(), 2);
    assert_eq!(expand(&compact), worlds);
}

#[test]
fn hundred_world_fixture_reduces_bytes_without_dropping_a_world_or_fact() {
    let facts = (0..20)
        .map(|index| format!("compiler contract {index}: exact fact shared across observed worlds"))
        .collect::<Vec<_>>();
    let worlds = (0..100)
        .map(|index| {
            let mut world = world(
                &format!("{index:064x}"),
                &format!("target-{index}"),
                &["facts"],
            );
            world.lines = facts.clone();
            world
        })
        .collect::<Vec<_>>();
    let repeated = worlds
        .iter()
        .map(|world| format!("{:?}\n{}", world.variant, world.lines.join("\n")))
        .collect::<Vec<_>>()
        .join("\n\n");
    let compact = compact(&worlds).unwrap();
    assert_eq!(expand(&compact), worlds);
    let rendered = render(&worlds).unwrap();
    assert_eq!(rendered.matches("compiler variant: qualified").count(), 100);
    assert!(rendered.contains("facts in observed worlds W1-W100:"));
    assert!(
        rendered.len() * 4 < repeated.len(),
        "{} versus {} bytes",
        rendered.len(),
        repeated.len()
    );
}
