use super::*;

#[tokio::test]
async fn filename_vague_is_suppressed_for_normal_modules() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"llm.rs\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"filename is vague\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/llm.rs".to_string(),
        source: "pub struct LLMClient;".to_string(),
        language: "rust".to_string(),
        methods: vec![],
    };

    let (verdict, _, _) = analyzer.analyze_file(&file, &[]).await.unwrap();
    let verdict = verdict.expect("expected file verdict");
    assert_eq!(verdict.tier, FindingTier::Unresolved);
    assert!(!verdict.smelly);
    assert!(verdict.reason.contains("evidence"));
    assert_eq!(hits.load(Ordering::SeqCst), 4);
}

#[test]
fn detector_facade_modules_stay_clean_on_vague_filename_judgment() {
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(
            ResolvedConfig::default(),
            Some("test-key".to_string()),
        )),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
            file_path: "src/bumpkin/analysis/finding_python_detector.py".to_string(),
            source: "from bumpkin.analysis import finding_diff\n\ndef run_python_api_detection(diff_text: str, *, workspace_loader, build_finding):\n    return []\n".to_string(),
            language: "python".to_string(),
            methods: vec![MethodRecord {
                name: "run_python_api_detection".to_string(),
                file_path: "src/bumpkin/analysis/finding_python_detector.py".to_string(),
                source: "def run_python_api_detection(diff_text: str, *, workspace_loader, build_finding):\n    return []\n".to_string(),
                loc: 2,
                param_count: 3,
                start_line: 3,
                end_line: 4,
                is_exported: true,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            }],
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
        evidence: "filename is vague".to_string(),
        reason: "filename is vague".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
}

#[test]
fn anchor_method_strips_helper_filename_noise_on_mixed_file() {
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(
            ResolvedConfig::default(),
            Some("test-key".to_string()),
        )),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/background/core/session-safe-start.ts".to_string(),
        source: "export function randomIntInclusive(min: number, max: number): number {\n  return min;\n}\n\nexport function createSessionSafeStartRuntime() {\n  return {};\n}\n".to_string(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "randomIntInclusive".to_string(),
                file_path: "src/background/core/session-safe-start.ts".to_string(),
                source: "export function randomIntInclusive(min: number, max: number): number {\n  return min;\n}\n".to_string(),
                loc: 3,
                param_count: 2,
                start_line: 1,
                end_line: 3,
                is_exported: true,
                language: "typescript".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "createSessionSafeStartRuntime".to_string(),
                file_path: "src/background/core/session-safe-start.ts".to_string(),
                source: "export function createSessionSafeStartRuntime() {\n  return {};\n}\n".to_string(),
                loc: 3,
                param_count: 0,
                start_line: 5,
                end_line: 7,
                is_exported: true,
                language: "typescript".to_string(),
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
        evidence: "export function createSessionSafeStartRuntime".to_string(),
        reason: "createSessionSafeStartRuntime: duplicate error handling branches with identical return objects (if (!result || typeof result !== 'object')); function is too big (112 LOC > 100); branchy control flow (3 branches); file mixes a random utility function with session-safe-start logic, and the name 'session-safe-start' doesn't cover the random helper (export function randomIntInclusive(min: number, max: number): number {); functions vary widely in size (4-112 lines)".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::Slop);
    assert!(verdict.smelly);
    assert!(verdict.reason.contains("function is too big"));
    assert!(!verdict.reason.contains("random utility function"));
    assert!(verdict.evidence.contains("createSessionSafeStartRuntime"));
}

#[test]
fn kotlin_compose_surface_borderlines_are_cleared_by_runtime_normalizer() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":false,\"tier\":\"clean\",\"evidence\":\"\",\"cohesive\":true,\"name_accurate\":true,\"reason\":\"\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };

    let components = FileRecord {
        file_path:
            "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt"
                .to_string(),
        source: "package com.onpill.shared.uicompose.components\n\n@Composable\npublic fun OnPillCard() {}\n".to_string(),
        language: "kotlin".to_string(),
        methods: vec![
            MethodRecord {
                name: "OnPillCard".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt"
                        .to_string(),
                source: "@Composable\npublic fun OnPillCard() {}\n".to_string(),
                loc: 37,
                param_count: 0,
                start_line: 1,
                end_line: 37,
                is_exported: true,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "OnPillButton".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt"
                        .to_string(),
                source: "@Composable\npublic fun OnPillButton() {}\n".to_string(),
                loc: 31,
                param_count: 0,
                start_line: 38,
                end_line: 68,
                is_exported: true,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "OnPillHeader".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt"
                        .to_string(),
                source: "@Composable\npublic fun OnPillHeader() {}\n".to_string(),
                loc: 42,
                param_count: 0,
                start_line: 69,
                end_line: 110,
                is_exported: true,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "OnPillBackButton".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt"
                        .to_string(),
                source: "@Composable\npublic fun OnPillBackButton() {}\n".to_string(),
                loc: 28,
                param_count: 0,
                start_line: 111,
                end_line: 138,
                is_exported: true,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "GlassNavBar".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt"
                        .to_string(),
                source: "@Composable\npublic fun GlassNavBar() {}\n".to_string(),
                loc: 49,
                param_count: 0,
                start_line: 139,
                end_line: 187,
                is_exported: true,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "TabItem".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/components/PillitComponents.kt"
                        .to_string(),
                source: "@Composable\nprivate fun TabItem() {}\n".to_string(),
                loc: 18,
                param_count: 0,
                start_line: 188,
                end_line: 205,
                is_exported: false,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };
    let medication_details_screen = FileRecord {
        file_path:
            "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                .to_string(),
        source: "package com.onpill.shared.uicompose.screens\n\n@Composable\npublic fun OnPillMedicationDetailsScreen() {}\n".to_string(),
        language: "kotlin".to_string(),
        methods: vec![
            MethodRecord {
                name: "OnPillMedicationDetailsScreen".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                        .to_string(),
                source: "@Composable\npublic fun OnPillMedicationDetailsScreen() {}\n".to_string(),
                loc: 97,
                param_count: 0,
                start_line: 1,
                end_line: 97,
                is_exported: true,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "scheduleCard".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                        .to_string(),
                source: "@Composable\nprivate fun scheduleCard() {}\n".to_string(),
                loc: 28,
                param_count: 0,
                start_line: 98,
                end_line: 125,
                is_exported: false,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "recentHistoryCard".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                        .to_string(),
                source: "@Composable\nprivate fun recentHistoryCard() {}\n".to_string(),
                loc: 44,
                param_count: 0,
                start_line: 126,
                end_line: 169,
                is_exported: false,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "historyRow".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                        .to_string(),
                source: "@Composable\nprivate fun historyRow() {}\n".to_string(),
                loc: 19,
                param_count: 0,
                start_line: 170,
                end_line: 188,
                is_exported: false,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "localizedLabel".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                        .to_string(),
                source: "@Composable\nprivate fun ReminderStatus.localizedLabel() = \"\"\n".to_string(),
                loc: 12,
                param_count: 0,
                start_line: 189,
                end_line: 200,
                is_exported: false,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "localizedTitle".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                        .to_string(),
                source: "@Composable\nprivate fun MedicationPhotoStatus.localizedTitle() = \"\"\n".to_string(),
                loc: 10,
                param_count: 0,
                start_line: 201,
                end_line: 210,
                is_exported: false,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "label".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                        .to_string(),
                source: "private fun MedicationScheduleTimeUiState.label() = \"\"\n".to_string(),
                loc: 15,
                param_count: 0,
                start_line: 211,
                end_line: 225,
                is_exported: false,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "perReminderDoseLabel".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                        .to_string(),
                source: "private fun MedicationDetailsState.perReminderDoseLabel(fallbackCount: Int): String = \"\"\n".to_string(),
                loc: 12,
                param_count: 1,
                start_line: 226,
                end_line: 237,
                is_exported: false,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "twoDigits".to_string(),
                file_path:
                    "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/PillitMedicationDetailsScreen.kt"
                        .to_string(),
                source: "private fun Int.twoDigits(): String = toString().padStart(length = 2, padChar = '0')\n".to_string(),
                loc: 4,
                param_count: 0,
                start_line: 238,
                end_line: 241,
                is_exported: false,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    let mut components_verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: components.file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::KindaSlop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "PillitComponents".to_string(),
        reason: "file mixes UI components with a color constants object, and the name 'PillitComponents' is vague for a file that also defines a semantic color palette".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };
    normalize_file_verdict(&components, &analyzer.llm_client, &mut components_verdict);
    assert_eq!(components_verdict.tier, FindingTier::Clean);
    assert!(!components_verdict.smelly);
    assert!(components_verdict.reason.is_empty());
    assert!(components_verdict.evidence.is_empty());

    let mut screen_verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: medication_details_screen.file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::KindaSlop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "MedicationScheduleTimeUiState.label".to_string(),
        reason: "file mixes screen composables with unrelated private extension functions on UI contract types, causing mild cohesion problems (private fun com.onpill.shared.uicontract.MedicationScheduleTimeUiState.label)".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };
    normalize_file_verdict(
        &medication_details_screen,
        &analyzer.llm_client,
        &mut screen_verdict,
    );
    assert_eq!(screen_verdict.tier, FindingTier::Clean);
    assert!(!screen_verdict.smelly);
    assert!(screen_verdict.reason.is_empty());
    assert!(screen_verdict.evidence.is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn single_client_bootstrap_helpers_stay_clean() {
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(
            ResolvedConfig::default(),
            Some("test-key".to_string()),
        )),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/lib/supabase-client.ts".to_string(),
        source: "export function isDefinitiveInvalidTokenError(error: unknown): boolean { return false; }".to_string(),
        language: "typescript".to_string(),
        methods: vec![MethodRecord {
            name: "isDefinitiveInvalidTokenError".to_string(),
            file_path: "src/lib/supabase-client.ts".to_string(),
            source: "export function isDefinitiveInvalidTokenError(error: unknown): boolean { return false; }".to_string(),
            loc: 12,
            param_count: 1,
            start_line: 1,
            end_line: 12,
            is_exported: true,
            language: "typescript".to_string(),
            nesting_depth: 3,
            references: vec![],
            real_ref_count: 0,
        }],
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
        evidence: "client initialization".to_string(),
        reason: "file mixes client initialization, session verification, and auth-storage purging logic, doing too much for a single adapter integration".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::Clean);
    assert!(!verdict.smelly);
    assert!(verdict.reason.is_empty());
    assert!(verdict.evidence.is_empty());
}
