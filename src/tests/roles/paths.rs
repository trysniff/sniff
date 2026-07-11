use super::*;

#[test]
fn analysis_findings_facade_modules_are_detected() {
    assert!(is_analysis_findings_facade_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\findings.py"
    ));
    assert!(!is_analysis_findings_facade_module(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\analysis\\finding_python_reexports.py"
    ));
}

#[test]
fn root_llm_py_is_compatibility_shim() {
    assert!(is_compatibility_shim_path(
        "C:\\Users\\User\\bumpkin\\src\\llm.py"
    ));
    assert!(is_intentional_surface_record(&FileRecord {
        file_path: "C:\\Users\\User\\bumpkin\\src\\llm.py".to_string(),
        source: "# compatibility shim".to_string(),
        language: "python".to_string(),
        methods: vec![],
    }));
    assert!(!is_compatibility_shim_path(
        "C:\\Users\\User\\bumpkin\\src\\bumpkin\\providers\\llm.py"
    ));
}

#[test]
fn explicit_compatibility_shim_comments_are_intentional_surface() {
    let file = FileRecord {
        file_path: "C:\\Users\\User\\Pillit\\Pillit\\shared\\contract\\src\\commonMain\\kotlin\\com\\pillit\\shared\\uicontract\\MedicationDetailsContract.kt"
            .to_string(),
        source: "@file:Suppress(\"unused\")\n\npackage com.onpill.shared.uicontract\n\n// Compatibility shim: declarations were decomposed into:\n// - MedicationDetailsModels.kt\n// - MedicationDetailsFieldOptions.kt\n// - MedicationDetailsActions.kt\n"
            .to_string(),
        language: "kotlin".to_string(),
        methods: vec![],
    };

    assert!(is_compatibility_shim_record(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn src_root_library_files_stay_core_library_without_llm() {
    assert_eq!(
        classify_file_role("src/file_verdicts.rs"),
        FileRole::Library
    );
    assert_eq!(
        classify_file_role("C:\\Users\\User\\Sniff\\src\\file_verdicts.rs"),
        FileRole::Library
    );
    assert_eq!(file_role_label(FileRole::Library), "core_library");
}

#[test]
fn cli_suffix_files_are_treated_as_entrypoints() {
    assert_eq!(
        classify_file_role("src/corpus_cli.py"),
        FileRole::Entrypoint
    );
    assert_eq!(file_role_label(FileRole::Entrypoint), "cli_entrypoint");
}

#[test]
fn serverless_function_index_files_are_treated_as_entrypoints() {
    assert_eq!(
        classify_file_role("supabase/functions/create-polar-checkout-session/index.ts"),
        FileRole::Entrypoint
    );
    assert!(is_intentional_surface_record(&FileRecord {
        file_path: "supabase/functions/create-polar-checkout-session/index.ts".to_string(),
        source: "export default function handler() { return new Response('ok'); }".to_string(),
        language: "typescript".to_string(),
        methods: vec![],
    }));
}

#[test]
fn adapter_integration_modules_are_not_intentional_surfaces() {
    let file = FileRecord {
            file_path: "src/bumpkin/release/repository_client.py".to_string(),
            source: "from __future__ import annotations\n\nclass GitHubRepositoryClient:\n    def list_tags(self):\n        return []\n    def compare_commits(self, *, base_ref: str, head_ref: str):\n        return []\n".to_string(),
            language: "python".to_string(),
            methods: vec![],
        };

    assert_eq!(
        classify_file_role(&file.file_path),
        FileRole::AdapterIntegration
    );
    assert!(!is_intentional_surface_record(&file));
}

#[test]
fn hydration_hooks_are_treated_as_intentional_surfaces() {
    let file = FileRecord {
            file_path: "src/hooks/useHasMounted.ts".to_string(),
            source: "import { useState, useEffect } from 'react';\n\nexport const useHasMounted = () => {\n  const [hasMounted, setHasMounted] = useState(false);\n\n  useEffect(() => {\n    const timer = setTimeout(() => setHasMounted(true), 0);\n    return () => clearTimeout(timer);\n  }, []);\n\n  return hasMounted;\n};\n".to_string(),
            language: "tsx".to_string(),
            methods: vec![],
        };

    assert!(is_hydration_hook_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn next_route_pages_are_treated_as_intentional_surfaces() {
    let file = FileRecord {
        file_path: "src/app/privacy/page.tsx".to_string(),
        source: "export default function PrivacyPage() {\n  return <main>Privacy</main>;\n}\n"
            .to_string(),
        language: "tsx".to_string(),
        methods: vec![MethodRecord {
            name: "PrivacyPage".to_string(),
            file_path: "src/app/privacy/page.tsx".to_string(),
            source: "export default function PrivacyPage() {\n  return <main>Privacy</main>;\n}"
                .to_string(),
            loc: 3,
            param_count: 0,
            start_line: 1,
            end_line: 3,
            is_exported: true,
            language: "tsx".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    assert!(is_presentation_surface_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn jsx_component_surfaces_are_treated_as_intentional_surfaces() {
    let file = FileRecord {
        file_path: "src/components/sections/Hero.tsx".to_string(),
        source: "export function Hero() {\n  return <section><h1>Hero</h1></section>;\n}\n"
            .to_string(),
        language: "tsx".to_string(),
        methods: vec![MethodRecord {
            name: "Hero".to_string(),
            file_path: "src/components/sections/Hero.tsx".to_string(),
            source: "export function Hero() {\n  return <section><h1>Hero</h1></section>;\n}"
                .to_string(),
            loc: 3,
            param_count: 0,
            start_line: 1,
            end_line: 3,
            is_exported: true,
            language: "tsx".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    assert!(is_presentation_surface_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn small_root_app_shells_are_treated_as_intentional_surfaces() {
    let file = FileRecord {
        file_path: "src/App.tsx".to_string(),
        source: "export function App() {\n  return <main>Hello</main>;\n}\n".to_string(),
        language: "tsx".to_string(),
        methods: vec![MethodRecord {
            name: "App".to_string(),
            file_path: "src/App.tsx".to_string(),
            source: "export function App() {\n  return <main>Hello</main>;\n}".to_string(),
            loc: 3,
            param_count: 0,
            start_line: 1,
            end_line: 3,
            is_exported: true,
            language: "tsx".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }],
    };

    assert!(is_presentation_surface_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn small_kotlin_compose_widgets_are_treated_as_intentional_surfaces() {
    let file = FileRecord {
        file_path: "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/cabinet/WeeklyAdherenceCard.kt"
            .to_string(),
        source: "package com.onpill.shared.uicompose.screens.cabinet\n\nimport androidx.compose.runtime.Composable\n\n@Composable\npublic fun WeeklyAdherenceCard() {}\n"
            .to_string(),
        language: "kotlin".to_string(),
        methods: vec![
            MethodRecord {
                name: "WeeklyAdherenceCard".to_string(),
                file_path: "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/screens/cabinet/WeeklyAdherenceCard.kt"
                    .to_string(),
                source: "fun WeeklyAdherenceCard() {}".to_string(),
                loc: 47,
                param_count: 1,
                start_line: 1,
                end_line: 1,
                is_exported: true,
                language: "kotlin".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    };

    assert!(is_presentation_surface_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn kotlin_callback_contracts_are_treated_as_intentional_surfaces() {
    let file = FileRecord {
        file_path: "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/SettingsHistoryCallbacks.kt"
            .to_string(),
        source: "package com.onpill.shared.uicompose\n\npublic data class SettingsHistoryCallbacks(\n  val onOpenHistory: () -> Unit = {},\n  val onRetryHistory: () -> Unit = {},\n  val onReloadHistory: () -> Unit = {},\n)\n"
            .to_string(),
        language: "kotlin".to_string(),
        methods: vec![],
    };

    assert!(is_callback_contract_module(&file));
    assert!(is_intentional_surface_record(&file));

    let models_file = FileRecord {
        file_path: "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/PillitAppShellModels.kt"
            .to_string(),
        source: "package com.onpill.shared.uicompose\n\npublic data class OnPillAppShellCallbacks(\n  val onPrimaryTabSelected: (Int) -> Unit = {},\n  val onAppRefreshRequested: () -> Unit = {},\n  val onOnboardingContinue: () -> Unit = {},\n)\n"
            .to_string(),
        language: "kotlin".to_string(),
        methods: vec![],
    };

    assert!(is_callback_contract_module(&models_file));
    assert!(is_intentional_surface_record(&models_file));

    let bindings_file = FileRecord {
        file_path: "shared/ui-compose/src/commonMain/kotlin/com/onpill/shared/uicompose/OnPillShellBindings.kt"
            .to_string(),
        source: "package com.onpill.shared.uicompose\n\npublic data class OnPillShellBindings(\n  val onOpenHistory: () -> Unit = {},\n  val onReloadHistory: () -> Unit = {},\n  val onCloseRequested: () -> Unit = {},\n)\n"
            .to_string(),
        language: "kotlin".to_string(),
        methods: vec![],
    };

    assert!(is_callback_contract_module(&bindings_file));
    assert!(is_intentional_surface_record(&bindings_file));
}

#[test]
fn analysis_evidence_modules_are_treated_as_intentional_surfaces() {
    let file = FileRecord {
        file_path: "src/bumpkin/analysis/evidence.py".to_string(),
        source: "from __future__ import annotations\n\n\ndef build_evidence_items(findings, diff_text, behavior_contract_signals):\n    return []\n\n\ndef build_evidence_prompt_text(evidence_items, diff_text):\n    return \"\"\n"
            .to_string(),
        language: "python".to_string(),
        methods: vec![],
    };

    assert!(is_analysis_evidence_module(&file));
    assert!(is_intentional_surface_record(&file));
}

#[test]
fn service_worker_support_boundaries_are_treated_as_intentional_surfaces() {
    let file = FileRecord {
        file_path: "ui/background/core/service-worker-support.ts".to_string(),
        source: "export async function getImprovementTelemetryConsent() { return true; }\nexport async function setImprovementTelemetryConsent(enabled: boolean) { return enabled; }\nexport async function migrateNamesetStoreToCanonicalObject() { return; }\nexport async function readKillSwitches() { return {}; }\nexport function deriveFeedbackContextFromSender(sender: chrome.runtime.MessageSender) { return { domain: null, uriHash: null }; }\nexport async function encryptWithSessionKey(plaintext: string) { return plaintext; }\n".to_string(),
        language: "typescript".to_string(),
        methods: vec![],
    };

    assert!(is_support_boundary_module(&file));
    assert!(is_intentional_surface_record(&file));
}
