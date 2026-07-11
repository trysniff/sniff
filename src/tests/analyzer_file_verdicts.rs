use super::*;
use crate::report_types::LLMVerdict;
use crate::types::FindingTier;

#[test]
fn support_plumbing_duplicate_helper_noise_is_cleared() {
    let file = FileRecord {
        file_path: "src/llm_json.rs".to_string(),
        source: "fn demo() {}".to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };
    let mut verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file.file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::KindaSlop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "copy-pasted method body".to_string(),
        reason: "copy-pasted method body".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn support_plumbing_mixin_bridge_noise_is_cleared() {
    let file = FileRecord {
        file_path: "src/bumpkin/integrations/github/persistence_postgres_publish_decision_ops.py"
            .to_string(),
        source: "def record_publish_decision(self):\n    return 0\n".to_string(),
        language: "python".to_string(),
        methods: vec![],
    };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence: "record_publish_decision = record_publish_decision".to_string(),
            reason:
                "file contains a single function defined as a module-level function then assigned to a mixin class, mixing module-level and class-level patterns without clear purpose".to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn support_plumbing_state_bag_noise_is_cleared() {
    let file = FileRecord {
            file_path: "src/parser_impl/python_extractor_state.rs".to_string(),
            source: "pub(crate) struct PyExtractor<'a> {\n    pub source: &'a str,\n    pub line_index: LineIndex,\n    pub file_path: String,\n}\n".to_string(),
            language: "rust".to_string(),
            methods: vec![],
        };
    let mut verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file.file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::KindaSlop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "pub(crate) struct PyExtractor<'a> {".to_string(),
        reason: "struct holds too many unrelated fields and reads like a state bag".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn test_surface_generic_noise_is_cleared() {
    let file = FileRecord {
        file_path: "tests/PlatformServicesIntegrationServiceTest.kt".to_string(),
        source: "fun verifyHostSyncProtocolSupport() {}\n".to_string(),
        language: "kotlin".to_string(),
        methods: vec![],
    };
    let mut verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file.file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::KindaSlop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "module has sprawling helper surface".to_string(),
        reason: "module has sprawling helper surface (11 exported methods, 1-44 LOC spread)"
            .to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn small_wrapper_only_modules_are_cleared() {
    let file = FileRecord {
            file_path: "shared/core/src/commonMain/kotlin/com/pillit/shared/core/appstore/PillitRemindersCabinetReducer.kt"
                .to_string(),
            source: "internal object OnPillRemindersCabinetReducer {\n  internal fun reduce(state: Int): Int {\n    return RemindersCabinetReducer.reduce(state)\n  }\n  internal fun reduce(state: String): String {\n    return RemindersCabinetReducer.reduce(state)\n  }\n}\n"
                .to_string(),
            language: "kotlin".to_string(),
            methods: vec![
                crate::types::MethodRecord {
                    name: "reduce".to_string(),
                    file_path: "shared/core/src/commonMain/kotlin/com/pillit/shared/core/appstore/PillitRemindersCabinetReducer.kt"
                        .to_string(),
                    source: "internal fun reduce(state: Int): Int {\n  return RemindersCabinetReducer.reduce(state)\n}\n".to_string(),
                    loc: 3,
                    param_count: 1,
                    start_line: 2,
                    end_line: 4,
                    is_exported: false,
                    language: "kotlin".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                crate::types::MethodRecord {
                    name: "reduce".to_string(),
                    file_path: "shared/core/src/commonMain/kotlin/com/pillit/shared/core/appstore/PillitRemindersCabinetReducer.kt"
                        .to_string(),
                    source: "internal fun reduce(state: String): String {\n  return RemindersCabinetReducer.reduce(state)\n}\n".to_string(),
                    loc: 3,
                    param_count: 1,
                    start_line: 5,
                    end_line: 7,
                    is_exported: false,
                    language: "kotlin".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
            ],
        };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::Slop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence: "internal object OnPillRemindersCabinetReducer".to_string(),
            reason:
                "filename is inaccurate: the object is named OnPillRemindersCabinetReducer but the file is named PillitRemindersCabinetReducer.kt, and the file merely delegates to another reducer, making it a thin wrapper that hides its purpose."
                    .to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn appstore_hydration_support_noise_is_cleared() {
    let file = FileRecord {
            file_path:
                "shared/core/src/commonMain/kotlin/com/pillit/shared/core/appstore/PillitAppStoreMedicationDetailsHydration.kt"
                    .to_string(),
            source:
                "internal fun MedicationDetailsState.toScheduleDraft(): MedicationScheduleDraft = MedicationScheduleDraft(\n  frequency = if (isWeekly) MedicationScheduleFrequency.WEEKLY else MedicationScheduleFrequency.DAILY,\n  times = times.map { time -> MedicationScheduleTime(hour = time.hour, minute = time.minute, doseCount = time.doseCount) },\n  weekdays = selectedWeekdays,\n)\n"
                    .to_string(),
            language: "kotlin".to_string(),
            methods: vec![],
        };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence:
                "internal fun MedicationDetailsState.hydrateFromCabinetSelection(".to_string(),
            reason:
                "Filename mentions only hydration but file also contains unrelated toScheduleDraft and validationSummaryFor functions, mixing concerns"
                    .to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn core_planning_support_noise_is_cleared() {
    let file = FileRecord {
            file_path:
                "shared/core/src/commonMain/kotlin/com/pillit/shared/core/ReminderPresentationStatePlanner.kt"
                    .to_string(),
            source:
                "public object ReminderPresentationStatePlanner {\n  public fun isStaleActiveForegroundReminder(deliveryAtEpochMillis: Long, nowEpochMillis: Long): Boolean = deliveryAtEpochMillis > nowEpochMillis\n}\n"
                    .to_string(),
            language: "kotlin".to_string(),
            methods: vec![],
        };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence: "public object ReminderPresentationStatePlanner".to_string(),
            reason:
                "file mixes state planning with candidate filtering and staleness checks, and the name 'Planner' is vague for what is essentially a sanitization/validation utility"
                    .to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn appstore_row_helper_support_noise_is_cleared() {
    let file = FileRecord {
            file_path:
                "shared/core/src/commonMain/kotlin/com/pillit/shared/core/appstore/PillitMedicationDetailsCabinetRows.kt"
                    .to_string(),
            source:
                "internal fun List<CabinetItemState>.upsertCabinetRow() = this\ninternal fun List<ReminderItemState>.upsertReminderRow() = emptyList<ReminderItemState>()\ninternal fun List<*>.toSurfaceState(): UiSurfaceState = UiSurfaceState.SUCCESS\n"
                    .to_string(),
            language: "kotlin".to_string(),
            methods: vec![],
        };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence: "internal fun List<CabinetItemState>.upsertCabinetRow(".to_string(),
            reason:
                "file mixes cabinet row upsert, reminder row upsert, and surface state conversion; filename only mentions cabinet rows"
                    .to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn module_barrel_noise_is_cleared() {
    let file = FileRecord {
            file_path: "src/lib.rs".to_string(),
            source: "pub mod analyzer;\npub mod callgraph;\npub mod cli;\npub mod config;\npub mod config_loader;\npub mod env_value;\npub mod file_verdicts;\npub mod language_adapter;\npub mod languages;\npub mod llm;\npub mod parser;\npub mod report_types;\npub mod reporter;\npub mod roles;\npub mod scorer;\npub mod signal_layers;\npub mod symbol_graph;\npub mod types;\npub mod walker;\n"
                .to_string(),
            language: "rust".to_string(),
            methods: vec![],
        };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence: "pub mod analyzer;".to_string(),
            reason:
                "file is a barrel module that re-exports many unrelated modules and hides intent behind a vague filename"
                    .to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn compose_presentation_surface_noise_is_cleared() {
    let file = FileRecord {
            file_path:
                "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt"
                    .to_string(),
            source:
                "package com.onpill.shared.uicompose.components\n\n@Composable\npublic fun OnPillCard() {}\n@Composable\npublic fun OnPillButton() {}\npublic object OnPillSemanticColors { }\n"
                    .to_string(),
            language: "kotlin".to_string(),
            methods: vec![],
        };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence: "public object OnPillSemanticColors".to_string(),
            reason:
                "file mixes UI components with a color constants object, and the name 'PillitComponents' is vague for a file that also defines a semantic color palette"
                    .to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn compose_screen_surface_noise_is_cleared() {
    let file = FileRecord {
            file_path:
                "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                    .to_string(),
            source:
                "package com.onpill.shared.uicompose.screens\n\n@Composable\npublic fun OnPillMedicationDetailsScreen() {}\nprivate fun com.onpill.shared.uicontract.MedicationScheduleTimeUiState.label(): String = \"\"\n"
                    .to_string(),
            language: "kotlin".to_string(),
            methods: vec![],
        };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence:
                "private fun com.onpill.shared.uicontract.MedicationScheduleTimeUiState.label".to_string(),
            reason:
                "file mixes screen composables with unrelated private extension functions on UI contract types, causing mild cohesion problems"
                    .to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}

#[test]
fn design_tokens_noise_is_cleared() {
    let file = FileRecord {
            file_path:
                "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/design/PillitDesignTokens.kt"
                    .to_string(),
            source:
                "package com.onpill.shared.uicontract.design\n\npublic object OnPillStrings { public val appName: String = \"OnPill\" }\npublic object OnPillColors { public val primary: Long = 0xFFF27121L }\npublic object OnPillSpacing { public val m: Int = 16 }\npublic object OnPillTypography { public val body: Int = 16 }\n"
                    .to_string(),
            language: "kotlin".to_string(),
            methods: vec![],
        };
    let mut verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file.file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::KindaSlop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence: "public object OnPillStrings".to_string(),
            reason:
                "file mixes colors, spacing, strings, and typography into one token file; name suggests design tokens but includes app strings"
                    .to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

    normalize_file_verdict(
        &file,
        &LLMClient::new(
            crate::config::ResolvedConfig {
                thresholds: crate::config::ThresholdsConfig::default(),
                ignore: vec![],
                generic_names: vec![],
                generic_file_names: vec![],
                model: "mock".to_string(),
                llm: crate::config::LLMConfig {
                    system_context: String::new(),
                    endpoint: "http://127.0.0.1:9/anthropic".to_string(),
                },
            },
            None,
        ),
        &mut verdict,
    );

    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
}
