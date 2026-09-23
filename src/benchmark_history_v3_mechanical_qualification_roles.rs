use super::super::{
    HistoricalV3MechanicalPolicy, HistoricalV3NonProductionRole, HistoricalV3RoleEvidence,
    HistoricalV3SemanticSnapshot, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticOccurrenceRole,
};
use crate::semantic_index::SemanticOccurrenceRole;
use std::collections::BTreeSet;

pub(super) fn file_role_evidence(
    path: &str,
    policy: &HistoricalV3MechanicalPolicy,
    semantic: Option<&HistoricalV3SemanticSnapshot>,
) -> Vec<HistoricalV3RoleEvidence> {
    let mut evidence = path_role_evidence(path, policy);
    if let Some(semantic) = semantic {
        for compiler in &semantic.compiler_indexes {
            let Some(document) = compiler
                .index
                .documents
                .iter()
                .find(|(document, _)| document.0 == path)
                .map(|(_, document)| document)
            else {
                continue;
            };
            for occurrence in &document.occurrences {
                for role in &occurrence.roles {
                    match role {
                        SemanticOccurrenceRole::Generated => {
                            evidence
                                .insert(compiler_role(HistoricalV3NonProductionRole::Generated));
                        }
                        SemanticOccurrenceRole::Test => {}
                        _ => {}
                    }
                }
            }
        }
    }
    evidence.into_iter().collect()
}

pub(super) fn method_role_evidence(
    path: &str,
    policy: &HistoricalV3MechanicalPolicy,
    method: &IntentionalBoundarySemanticMethod,
) -> Vec<HistoricalV3RoleEvidence> {
    let mut evidence = path_role_evidence(path, policy);
    for occurrence in &method.occurrences {
        for role in &occurrence.roles {
            match role {
                IntentionalBoundarySemanticOccurrenceRole::Generated => {
                    evidence.insert(compiler_role(HistoricalV3NonProductionRole::Generated));
                }
                IntentionalBoundarySemanticOccurrenceRole::Test => {
                    evidence.insert(compiler_role(HistoricalV3NonProductionRole::Test));
                }
                _ => {}
            }
        }
    }
    if method
        .test_relationships
        .iter()
        .any(|relationship| relationship.test_symbol == resolved_symbol_id(method).unwrap_or(""))
    {
        evidence.insert(compiler_role(HistoricalV3NonProductionRole::Test));
    }
    evidence.into_iter().collect()
}

pub(super) fn roles(evidence: &[HistoricalV3RoleEvidence]) -> Vec<HistoricalV3NonProductionRole> {
    evidence
        .iter()
        .map(|evidence| match evidence {
            HistoricalV3RoleEvidence::CompilerOccurrence { role }
            | HistoricalV3RoleEvidence::PathSegment { role, .. }
            | HistoricalV3RoleEvidence::FileSuffix { role, .. } => *role,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn path_role_evidence(
    path: &str,
    policy: &HistoricalV3MechanicalPolicy,
) -> BTreeSet<HistoricalV3RoleEvidence> {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let segments = normalized.split('/').collect::<BTreeSet<_>>();
    let mut evidence = BTreeSet::new();
    add_segment_roles(
        &mut evidence,
        &segments,
        &policy.generated_path_segments,
        HistoricalV3NonProductionRole::Generated,
    );
    add_segment_roles(
        &mut evidence,
        &segments,
        &policy.vendored_path_segments,
        HistoricalV3NonProductionRole::Vendored,
    );
    add_segment_roles(
        &mut evidence,
        &segments,
        &policy.documentation_path_segments,
        HistoricalV3NonProductionRole::Documentation,
    );
    add_segment_roles(
        &mut evidence,
        &segments,
        &policy.fixture_path_segments,
        HistoricalV3NonProductionRole::Fixture,
    );
    add_segment_roles(
        &mut evidence,
        &segments,
        &policy.test_path_segments,
        HistoricalV3NonProductionRole::Test,
    );
    for suffix in &policy.test_file_suffixes {
        if normalized.ends_with(suffix) {
            evidence.insert(HistoricalV3RoleEvidence::FileSuffix {
                role: HistoricalV3NonProductionRole::Test,
                suffix: suffix.clone(),
            });
        }
    }
    evidence
}

fn add_segment_roles(
    evidence: &mut BTreeSet<HistoricalV3RoleEvidence>,
    segments: &BTreeSet<&str>,
    expected: &[String],
    role: HistoricalV3NonProductionRole,
) {
    for segment in expected {
        if segments.contains(segment.as_str()) {
            evidence.insert(HistoricalV3RoleEvidence::PathSegment {
                role,
                segment: segment.clone(),
            });
        }
    }
}

fn compiler_role(role: HistoricalV3NonProductionRole) -> HistoricalV3RoleEvidence {
    HistoricalV3RoleEvidence::CompilerOccurrence { role }
}

fn resolved_symbol_id(method: &IntentionalBoundarySemanticMethod) -> Option<&str> {
    match &method.status {
        super::super::IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } => {
            Some(&symbol.symbol_id)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::{
        IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticOccurrenceFacts,
        IntentionalBoundarySemanticRange,
    };

    #[test]
    fn compiler_test_role_is_method_scoped_inside_a_production_file() {
        let policy = HistoricalV3MechanicalPolicy {
            production_method_minimum: 1,
            production_method_maximum: 500,
            generated_path_segments: vec!["generated".to_string()],
            vendored_path_segments: vec!["vendor".to_string()],
            documentation_path_segments: vec!["docs".to_string()],
            fixture_path_segments: vec!["fixtures".to_string()],
            test_path_segments: vec!["tests".to_string()],
            test_file_suffixes: vec!["_test.rs".to_string()],
        };
        let production =
            method_with_roles(vec![IntentionalBoundarySemanticOccurrenceRole::Definition]);
        let test = method_with_roles(vec![
            IntentionalBoundarySemanticOccurrenceRole::Definition,
            IntentionalBoundarySemanticOccurrenceRole::Test,
        ]);

        assert!(roles(&method_role_evidence("src/lib.rs", &policy, &production)).is_empty());
        assert_eq!(
            roles(&method_role_evidence("src/lib.rs", &policy, &test)),
            vec![HistoricalV3NonProductionRole::Test]
        );
    }

    fn method_with_roles(
        occurrence_roles: Vec<IntentionalBoundarySemanticOccurrenceRole>,
    ) -> IntentionalBoundarySemanticMethod {
        IntentionalBoundarySemanticMethod {
            parser_unit_id: "src/lib.rs::method".to_string(),
            repository_path: "src/lib.rs".to_string(),
            symbol_name: "method".to_string(),
            start_line: 1,
            end_line: 1,
            indexer: super::super::super::IntentionalBoundaryIndexerKind::Rust,
            status: IntentionalBoundarySemanticMethodStatus::CompilerExcluded {
                reason: "not needed for role classification".to_string(),
            },
            occurrences: vec![IntentionalBoundarySemanticOccurrenceFacts {
                location: IntentionalBoundarySemanticRange {
                    repository_path: "src/lib.rs".to_string(),
                    start_line_zero_based: 0,
                    start_character_zero_based: 0,
                    end_line_zero_based: 0,
                    end_character_zero_based: 6,
                },
                roles: occurrence_roles,
                override_documentation: Vec::new(),
            }],
            calls: Vec::new(),
            relationships: Vec::new(),
            imports: Vec::new(),
            test_relationships: Vec::new(),
        }
    }
}
