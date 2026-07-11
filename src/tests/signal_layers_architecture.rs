use super::architecture_flags;
use crate::config::ResolvedConfig;
use crate::types::{FileRecord, MethodRecord, Reference};

#[test]
fn python_parameter_compat_helpers_are_treated_as_utility_surface() {
    let file = FileRecord {
        file_path: "src/bumpkin/analysis/finding_python_parameter_compat.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "is_optional_param".to_string(),
                file_path: "src/bumpkin/analysis/finding_python_parameter_compat.py".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 1,
                end_line: 2,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "normalize_python_annotation".to_string(),
                file_path: "src/bumpkin/analysis/finding_python_parameter_compat.py".to_string(),
                source: String::new(),
                loc: 6,
                param_count: 1,
                start_line: 3,
                end_line: 8,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "parse_python_parameter_specs".to_string(),
                file_path: "src/bumpkin/analysis/finding_python_parameter_compat.py".to_string(),
                source: String::new(),
                loc: 69,
                param_count: 1,
                start_line: 9,
                end_line: 78,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "same_python_parameter_surface".to_string(),
                file_path: "src/bumpkin/analysis/finding_python_parameter_compat.py".to_string(),
                source: String::new(),
                loc: 12,
                param_count: 2,
                start_line: 79,
                end_line: 90,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "has_compatible_python_parameter_surface".to_string(),
                file_path: "src/bumpkin/analysis/finding_python_parameter_compat.py".to_string(),
                source: String::new(),
                loc: 11,
                param_count: 2,
                start_line: 91,
                end_line: 101,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(flags.is_empty());
}

#[test]
fn python_surface_base_support_module_is_skipped() {
    let file = FileRecord {
        file_path: "src/bumpkin/analysis/finding_python_surface_base.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "collect_python_signature_source".to_string(),
                file_path: "src/bumpkin/analysis/finding_python_surface_base.py".to_string(),
                source: String::new(),
                loc: 26,
                param_count: 2,
                start_line: 1,
                end_line: 26,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "split_top_level_params".to_string(),
                file_path: "src/bumpkin/analysis/finding_python_surface_base.py".to_string(),
                source: String::new(),
                loc: 31,
                param_count: 1,
                start_line: 27,
                end_line: 57,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(flags.is_empty());
}

#[test]
fn persistence_record_parsing_helpers_are_skipped() {
    let file = FileRecord {
        file_path: "src/bumpkin/integrations/github/persistence_record_parsing.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "_optional_text".to_string(),
                file_path: "src/bumpkin/integrations/github/persistence_record_parsing.py"
                    .to_string(),
                source: String::new(),
                loc: 3,
                param_count: 2,
                start_line: 1,
                end_line: 3,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "build_stored_event_record".to_string(),
                file_path: "src/bumpkin/integrations/github/persistence_record_parsing.py"
                    .to_string(),
                source: String::new(),
                loc: 25,
                param_count: 1,
                start_line: 4,
                end_line: 28,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(flags.is_empty());
}

#[test]
fn diff_text_and_release_candidate_are_skipped() {
    let diff_text = FileRecord {
        file_path: "src/bumpkin/analysis/diff_text.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "_cap_diff_per_file".to_string(),
                file_path: "src/bumpkin/analysis/diff_text.py".to_string(),
                source: String::new(),
                loc: 24,
                param_count: 2,
                start_line: 1,
                end_line: 24,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_build_diff_text".to_string(),
                file_path: "src/bumpkin/analysis/diff_text.py".to_string(),
                source: String::new(),
                loc: 42,
                param_count: 4,
                start_line: 25,
                end_line: 66,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };
    let candidate = FileRecord {
        file_path: "src/bumpkin/release/candidate.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "_coerce_int".to_string(),
                file_path: "src/bumpkin/release/candidate.py".to_string(),
                source: String::new(),
                loc: 18,
                param_count: 1,
                start_line: 1,
                end_line: 18,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_deserialize_release_candidate".to_string(),
                file_path: "src/bumpkin/release/candidate.py".to_string(),
                source: String::new(),
                loc: 64,
                param_count: 1,
                start_line: 19,
                end_line: 82,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    let flags = architecture_flags(&[diff_text, candidate], &ResolvedConfig::default());
    assert!(flags.is_empty());
}

#[test]
fn finding_diff_module_is_skipped() {
    let file = FileRecord {
        file_path: "src/bumpkin/analysis/finding_diff.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "parse_diff_files".to_string(),
            file_path: "src/bumpkin/analysis/finding_diff.py".to_string(),
            source: String::new(),
            loc: 60,
            param_count: 1,
            start_line: 1,
            end_line: 2,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(flags.is_empty());
}

#[test]
fn eval_fixtures_module_is_skipped() {
    let file = FileRecord {
        file_path: "src/bumpkin/eval/fixtures.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "load_fixture_cases".to_string(),
            file_path: "src/bumpkin/eval/fixtures.py".to_string(),
            source: String::new(),
            loc: 60,
            param_count: 1,
            start_line: 1,
            end_line: 2,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(flags.is_empty());
}

#[test]
fn support_plumbing_orchestrator_modules_are_skipped_from_architecture_flags() {
    let file = FileRecord {
        file_path: "src/bumpkin/integrations/github/server.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "_json_wsgi_response".to_string(),
                file_path: "src/bumpkin/integrations/github/server.py".to_string(),
                source: String::new(),
                loc: 11,
                param_count: 4,
                start_line: 1,
                end_line: 11,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "run_self_host_server".to_string(),
                file_path: "src/bumpkin/integrations/github/server.py".to_string(),
                source: String::new(),
                loc: 10,
                param_count: 0,
                start_line: 12,
                end_line: 21,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(flags.is_empty());
}

#[test]
fn impl_facade_modules_do_not_trigger_fanout_noise_by_themselves() {
    let file = FileRecord {
        file_path: "src/llm_impl.rs".to_string(),
        source: String::new(),
        language: "rust".to_string(),
        methods: vec![
            MethodRecord {
                name: "new".to_string(),
                file_path: "src/llm_impl.rs".to_string(),
                source: String::new(),
                loc: 12,
                param_count: 2,
                start_line: 1,
                end_line: 12,
                is_exported: true,
                language: "rust".to_string(),
                nesting_depth: 0,
                references: vec![Reference {
                    file_path: "src/llm_call.rs".to_string(),
                    line: 1,
                    snippet: "mod llm_call".to_string(),
                }],
                real_ref_count: 1,
            },
            MethodRecord {
                name: "probe".to_string(),
                file_path: "src/llm_impl.rs".to_string(),
                source: String::new(),
                loc: 14,
                param_count: 0,
                start_line: 13,
                end_line: 26,
                is_exported: true,
                language: "rust".to_string(),
                nesting_depth: 0,
                references: vec![Reference {
                    file_path: "src/llm_json.rs".to_string(),
                    line: 1,
                    snippet: "mod llm_json".to_string(),
                }],
                real_ref_count: 1,
            },
            MethodRecord {
                name: "call".to_string(),
                file_path: "src/llm_impl.rs".to_string(),
                source: String::new(),
                loc: 18,
                param_count: 2,
                start_line: 27,
                end_line: 44,
                is_exported: true,
                language: "rust".to_string(),
                nesting_depth: 0,
                references: vec![
                    Reference {
                        file_path: "src/llm_retry.rs".to_string(),
                        line: 1,
                        snippet: "mod llm_retry".to_string(),
                    },
                    Reference {
                        file_path: "src/llm_transport.rs".to_string(),
                        line: 1,
                        snippet: "mod llm_transport".to_string(),
                    },
                    Reference {
                        file_path: "src/llm_payload.rs".to_string(),
                        line: 1,
                        snippet: "mod llm_payload".to_string(),
                    },
                    Reference {
                        file_path: "src/llm_schema.rs".to_string(),
                        line: 1,
                        snippet: "mod llm_schema".to_string(),
                    },
                    Reference {
                        file_path: "src/llm_usage.rs".to_string(),
                        line: 1,
                        snippet: "mod llm_usage".to_string(),
                    },
                ],
                real_ref_count: 5,
            },
        ],
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(
        flags.is_empty(),
        "implementation facade modules should not be flagged just for fan-out: {:?}",
        flags
    );
}

#[test]
fn protocol_surface_modules_are_skipped() {
    let file = FileRecord {
        file_path: "src/bumpkin/integrations/github/persistence_protocols.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "close".to_string(),
                file_path: "src/bumpkin/integrations/github/persistence_protocols.py".to_string(),
                source: String::new(),
                loc: 1,
                param_count: 0,
                start_line: 1,
                end_line: 1,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "delete_approvals".to_string(),
                file_path: "src/bumpkin/integrations/github/persistence_protocols.py".to_string(),
                source: String::new(),
                loc: 1,
                param_count: 2,
                start_line: 2,
                end_line: 2,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(flags.is_empty());
}

#[test]
fn support_plumbing_modules_are_skipped_from_architecture_flags() {
    let file = FileRecord {
        file_path: "src/bumpkin/orchestrator/explanation_facts.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: (0..10)
            .map(|index| MethodRecord {
                name: format!("helper_{index}"),
                file_path: "src/bumpkin/orchestrator/explanation_facts.py".to_string(),
                source: String::new(),
                loc: 4 + index * 5,
                param_count: 0,
                start_line: index + 1,
                end_line: index + 1,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            })
            .collect(),
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(flags.is_empty());
}

#[test]
fn data_catalog_modules_are_skipped_from_architecture_flags() {
    let file = FileRecord {
        file_path: "ui/src/data/platforms.ts".to_string(),
        source: "export type Platform = { id: string };\n\
                 const RAW_PLATFORMS: Record<string, Platform> = Object.fromEntries([]);\n\
                 export const PLATFORMS = RAW_PLATFORMS;\n"
            .to_string(),
        language: "typescript".to_string(),
        methods: (0..7)
            .map(|index| MethodRecord {
                name: format!("helper_{index}"),
                file_path: "ui/src/data/platforms.ts".to_string(),
                source: String::new(),
                loc: 3 + index,
                param_count: 1,
                start_line: index + 1,
                end_line: index + 1,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            })
            .collect(),
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(flags.is_empty());
}

#[test]
fn adapter_integration_single_oversized_method_is_not_silent() {
    let file = FileRecord {
        file_path: "src/bumpkin/integrations/github/webhook_service.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "process_merge_recommendation".to_string(),
            file_path: "src/bumpkin/integrations/github/webhook_service.py".to_string(),
            source: String::new(),
            loc: 137,
            param_count: 5,
            start_line: 1,
            end_line: 137,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(
        !flags.is_empty(),
        "a one-method adapter integration file with an oversized method should still be surfaced"
    );
}

#[test]
fn single_method_module_at_exactly_100_loc_is_not_flagged_as_oversized_by_itself() {
    let file = FileRecord {
        file_path: "src/bumpkin/background/session_claim_completion.py".to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "create_session_claim_completion".to_string(),
            file_path: "src/bumpkin/background/session_claim_completion.py".to_string(),
            source: String::new(),
            loc: 100,
            param_count: 3,
            start_line: 1,
            end_line: 100,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    let flags = architecture_flags(&[file], &ResolvedConfig::default());
    assert!(
        flags.is_empty(),
        "a single coherent method at exactly 100 LOC should not be called oversized slop"
    );
}
