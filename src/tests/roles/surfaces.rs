use super::*;

#[test]
fn provider_llm_facade_is_intentional_surface() {
    let file = FileRecord {
        file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm.py".to_string(),
        source: "from bumpkin.providers.chunking import split_diff_into_chunks as _split_diff_into_chunks_impl\n\
                 from bumpkin.providers.llm_payloads import validate_recommendation as _validate_recommendation_impl\n\
                 from bumpkin.providers.llm_transport import request_headers as _request_headers_impl\n\
                 from bumpkin.providers.semantic import manual_review_result as _manual_review_result_impl\n\
                 def _provider_mode_for_endpoint(endpoint): return _provider_mode_for_endpoint_impl(endpoint)\n\
                 def _normalize_request_endpoint(endpoint): return _normalize_request_endpoint_impl(endpoint)\n\
                 def _request_headers(token, endpoint): return _request_headers_impl(token, endpoint)\n\
                 def _manual_review_result(reasoning): return _manual_review_result_impl(reasoning=reasoning)\n"
            .to_string(),
        language: "python".to_string(),
        methods: vec![
            MethodRecord {
                name: "_provider_mode_for_endpoint".to_string(),
                file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm.py".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 1,
                end_line: 2,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_normalize_request_endpoint".to_string(),
                file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm.py".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 3,
                end_line: 4,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_request_headers".to_string(),
                file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm.py".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 2,
                start_line: 5,
                end_line: 6,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_manual_review_result".to_string(),
                file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm.py".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 7,
                end_line: 8,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "get_recommendation".to_string(),
                file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm.py".to_string(),
                source: String::new(),
                loc: 52,
                param_count: 12,
                start_line: 9,
                end_line: 60,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_split_diff_into_chunks".to_string(),
                file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm.py".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 3,
                start_line: 61,
                end_line: 62,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_aggregate_chunk_recommendations".to_string(),
                file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm.py".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 2,
                start_line: 63,
                end_line: 64,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "_build_messages".to_string(),
                file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm.py".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 4,
                start_line: 65,
                end_line: 66,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    assert!(is_provider_facade_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn utility_surface_modules_are_intentional_surfaces() {
    let file = FileRecord {
        file_path: "src/utils/helpers.ts".to_string(),
        source: String::new(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "stableStringify".to_string(),
                file_path: "src/utils/helpers.ts".to_string(),
                source: String::new(),
                loc: 12,
                param_count: 1,
                start_line: 1,
                end_line: 12,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "jsonResponse".to_string(),
                file_path: "src/utils/helpers.ts".to_string(),
                source: String::new(),
                loc: 16,
                param_count: 3,
                start_line: 13,
                end_line: 28,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "parseBooleanFlag".to_string(),
                file_path: "src/utils/helpers.ts".to_string(),
                source: String::new(),
                loc: 8,
                param_count: 2,
                start_line: 29,
                end_line: 36,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    assert!(is_utility_surface_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn domain_rules_modules_are_not_generic_utility_surfaces() {
    let file = FileRecord {
        file_path: "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/MedicationNumericRules.kt"
            .to_string(),
        source: String::new(),
        language: "kotlin".to_string(),
        methods: vec![
            MethodRecord {
                name: "sanitizeMedicationWholeNumberInput".to_string(),
                file_path: "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/MedicationNumericRules.kt"
                    .to_string(),
                source: String::new(),
                loc: 14,
                param_count: 0,
                start_line: 1,
                end_line: 14,
                is_exported: true,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "sanitizeMedicationDecimalInput".to_string(),
                file_path: "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/MedicationNumericRules.kt"
                    .to_string(),
                source: String::new(),
                loc: 21,
                param_count: 0,
                start_line: 16,
                end_line: 36,
                is_exported: true,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "sanitizeMedicationStrengthInput".to_string(),
                file_path: "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/MedicationNumericRules.kt"
                    .to_string(),
                source: String::new(),
                loc: 33,
                param_count: 0,
                start_line: 38,
                end_line: 71,
                is_exported: true,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    assert!(!is_utility_surface_module(&file));
}

#[test]
fn ui_support_helper_modules_are_intentional_surfaces() {
    let file = FileRecord {
        file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
        source: "function normalizeCode(value: unknown): string { return String(value || '').trim().toUpperCase(); }\n\
                 function normalizeFallback(fallback: string): string { return fallback || 'Something went wrong. Please retry.'; }\n\
                 function extractRawMessage(input: unknown): string { return ''; }\n\
                 function normalizeMessage(raw: string): string { return String(raw || '').trim().toLowerCase(); }\n\
                 function mapByMessagePattern(raw: string): string | null { return null; }\n\
                 function asFailureLike(input: unknown): { code?: unknown; message?: unknown } | null { return null; }\n\
                 export function getUserSafeToastMessage(input: unknown, fallback: string): string { return fallback; }\n"
            .to_string(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "normalizeCode".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 1,
                end_line: 1,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "normalizeFallback".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 2,
                end_line: 2,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "extractRawMessage".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 3,
                end_line: 3,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "normalizeMessage".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 4,
                end_line: 4,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "mapByMessagePattern".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 5,
                end_line: 5,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "asFailureLike".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 2,
                param_count: 1,
                start_line: 6,
                end_line: 6,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "getUserSafeToastMessage".to_string(),
                file_path: "ui/src/lib/user-safe-toast-message.ts".to_string(),
                source: String::new(),
                loc: 3,
                param_count: 2,
                start_line: 7,
                end_line: 7,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    assert!(is_support_plumbing_module(&file.file_path));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn analysis_finding_helper_modules_are_detected() {
    assert!(is_analysis_finding_helper_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\finding_python_parameter_compat.py"
    ));
    assert!(is_analysis_finding_helper_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\finding_python_reexports.py"
    ));
    assert!(!is_analysis_finding_helper_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\finding_python_signatures.py"
    ));
}

#[test]
fn analysis_finding_workspace_modules_are_detected() {
    assert!(is_analysis_finding_support_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\finding_workspace.py"
    ));
    assert!(is_analysis_finding_workspace_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\finding_workspace.py"
    ));
}

#[test]
fn analysis_explanation_support_is_reviewable_not_intentional_surface() {
    let file = FileRecord {
        file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\explanation_facts.py"
            .to_string(),
        source: "import re\n".to_string(),
        language: "python".to_string(),
        methods: vec![],
    };

    assert!(is_analysis_explanation_support_module(&file.file_path));
    assert!(!is_intentional_surface_record(&file));
}

#[test]
fn analysis_reexport_modules_are_treated_as_intentional_surfaces() {
    assert!(is_analysis_reexports_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\finding_python_reexports.py"
    ));
    assert!(is_intentional_surface_record(&FileRecord {
        file_path: "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\finding_python_reexports.py"
            .to_string(),
        source: "def extract_python_imported_names(statement_source, *, path):\n    return set()\n"
            .to_string(),
        language: "python".to_string(),
        methods: vec![],
    }));
}

#[test]
fn analysis_finding_diff_modules_are_detected() {
    assert!(is_analysis_finding_support_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\finding_diff.py"
    ));
}

#[test]
fn diff_text_and_release_candidate_are_parsing_helper_modules() {
    assert!(is_parsing_or_serialization_helper_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\diff_text.py"
    ));
    assert!(is_parsing_or_serialization_helper_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\release\\candidate.py"
    ));
}
