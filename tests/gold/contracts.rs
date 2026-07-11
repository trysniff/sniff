use super::*;

#[test]
fn kotlin_compose_bridge_hotspot_is_flagged_as_slop() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_kotlin_compose_bridge"));
    let bridge_dir = temp_root
        .join("shared")
        .join("ui-compose")
        .join("src")
        .join("iosMain")
        .join("kotlin")
        .join("com")
        .join("onpill")
        .join("shared")
        .join("uicompose");
    fs::create_dir_all(&bridge_dir).unwrap();

    let bridge_path = write_temp_file(
        &bridge_dir,
        "PillitAppShellIosBridge.kt",
        r#"
package com.onpill.shared.uicompose

interface OnPillAppShellNativeCallbacks {
    fun onPrimaryTabSelected(index: Int)
    fun onOpenReliabilitySettings()
    fun onReloadReminders()
    fun onMedicationNameChanged(value: String)
    fun onAddMedication()
    fun onOpenDetails(medicationId: Long)
    fun onRemoveMedication(medicationId: Long)
    fun onReloadCabinet()
    fun onOpenHistory()
    fun onRetryHistory()
    fun onHistoryStateSelected(surfaceState: String)
    fun onReloadHistory()
    fun onCloseHistoryRequested()
    fun onClearHistoryFilter()
    fun onEarlyRefillAlertsToggled(enabled: Boolean)
    fun onCrashCollectionToggled(enabled: Boolean)
    fun onTelemetryCollectionToggled(enabled: Boolean)
    fun onSoundToggled(enabled: Boolean)
    fun onVibrationToggled(enabled: Boolean)
    fun onThemeSelected(theme: String)
    fun onProfileUpdated(displayName: String?, email: String?)
    fun onProfilePhotoCaptureRequested()
    fun onProfilePhotoImportRequested()
    fun onProfilePhotoRemoved()
    fun onPolicyAccepted()
    fun onEditRequested()
    fun onRefillRequested()
    fun onCancelEditRequested()
    fun onConfirmDiscardRequested()
    fun onDismissDiscardRequested()
    fun onReloadRequested()
    fun onNameChanged(value: String)
    fun onTypeChanged(value: String)
    fun onStrengthChanged(value: String)
    fun onUnitChanged(value: String)
    fun onQuantityChanged(value: String)
    fun onInventoryAmountChanged(value: String)
    fun onInventoryUnitChanged(value: String)
    fun onDoseAmountChanged(value: String)
    fun onDoseUnitChanged(value: String)
    fun onRefillThresholdAmountChanged(value: String)
    fun onNotesChanged(value: String)
    fun onInstructionsChanged(value: String)
    fun onScheduleModeWeeklyChanged(value: Boolean)
    fun onScheduleTimeChanged(index: Int, hour: Int, minute: Int)
    fun onScheduleDoseCountChanged(index: Int, doseCount: Int)
    fun onAddScheduleTime()
    fun onRemoveScheduleTime(index: Int)
    fun onToggleWeekday(day: Int)
    fun onTogglePhotoPermission()
    fun onCapturePhoto()
    fun onImportPhoto()
    fun onRemovePhoto()
    fun onSaveRequested()
    fun onSnoozeDelayChanged(minutes: Int)
    fun onWeekStartPreferenceChanged(preference: String)
    fun onExportEncryptedBackupRequested(passphrase: String)
    fun onRunRefillForecastRequested()
    fun onBillingRefreshRequested()
    fun onBillingPurchasePersonalRequested()
    fun onBillingRestorePurchasesRequested()
    fun onAuthorizeLinkedDeviceRequested(linkToken: String, targetDeviceId: String, targetRole: String)
    fun onRevokeLinkedDeviceRequested(targetDeviceId: String)
    fun onRecoverOwnerDeviceRequested(recoveryCode: String, targetDeviceId: String)
}

class OnPillAppShellIosController {
    fun makeViewController() {
        val renderState = "state"
        val c1 = "c1"
        val c2 = "c2"
        val c3 = "c3"
        val c4 = "c4"
        val c5 = "c5"
        val c6 = "c6"
        val c7 = "c7"
        val c8 = "c8"
        val c9 = "c9"
        val c10 = "c10"
        val c11 = "c11"
        val c12 = "c12"
        val c13 = "c13"
        val c14 = "c14"
        val c15 = "c15"
        val c16 = "c16"
        val c17 = "c17"
        val c18 = "c18"
        val c19 = "c19"
        val c20 = "c20"
        val c21 = "c21"
        val c22 = "c22"
        val c23 = "c23"
        val c24 = "c24"
        val c25 = "c25"
        val c26 = "c26"
        val c27 = "c27"
        val c28 = "c28"
        val c29 = "c29"
        val c30 = "c30"
        val c31 = "c31"
        val c32 = "c32"
        val c33 = "c33"
        val c34 = "c34"
        val c35 = "c35"
        val c36 = "c36"
        val c37 = "c37"
        val c38 = "c38"
        val c39 = "c39"
        val c40 = "c40"
        val c41 = "c41"
        val c42 = "c42"
        val c43 = "c43"
        val c44 = "c44"
        val c45 = "c45"
        val c46 = "c46"
        val c47 = "c47"
        val c48 = "c48"
        val c49 = "c49"
        val c50 = "c50"
        val c51 = "c51"
        val c52 = "c52"
        val c53 = "c53"
        val c54 = "c54"
        val c55 = "c55"
        val c56 = "c56"
        val c57 = "c57"
        val c58 = "c58"
        val c59 = "c59"
        val c60 = "c60"
        val c61 = "c61"
        val c62 = "c62"
        val c63 = "c63"
        val c64 = "c64"
        val c65 = "c65"
        val c66 = "c66"
        val c67 = "c67"
        val c68 = "c68"
        val c69 = "c69"
        val c70 = "c70"
        val c71 = "c71"
        val c72 = "c72"
        val c73 = "c73"
        val c74 = "c74"
        val c75 = "c75"
        val c76 = "c76"
        val c77 = "c77"
        val c78 = "c78"
        val c79 = "c79"
        val c80 = "c80"
        val c81 = "c81"
        val c82 = "c82"
        val c83 = "c83"
        val c84 = "c84"
        val c85 = "c85"
        val c86 = "c86"
        val c87 = "c87"
        val c88 = "c88"
        val c89 = "c89"
        val c90 = "c90"
        val c91 = "c91"
        val c92 = "c92"
        val c93 = "c93"
        val c94 = "c94"
        val c95 = "c95"
        val c96 = "c96"
        val c97 = "c97"
        val c98 = "c98"
        val c99 = "c99"
        val c100 = "c100"
        val c101 = "c101"
        val c102 = "c102"
        val c103 = "c103"
        val c104 = "c104"
        val c105 = "c105"
        val c106 = "c106"
        val c107 = "c107"
        println(renderState + c1 + c2 + c3 + c4 + c5 + c6 + c7 + c8 + c9 + c10 + c11 + c12 + c13 + c14 + c15 + c16 + c17 + c18 + c19 + c20 + c21 + c22 + c23 + c24 + c25 + c26 + c27 + c28 + c29 + c30 + c31 + c32 + c33 + c34 + c35 + c36 + c37 + c38 + c39 + c40 + c41 + c42 + c43 + c44 + c45 + c46 + c47 + c48 + c49 + c50 + c51 + c52 + c53 + c54 + c55 + c56 + c57 + c58 + c59 + c60 + c61 + c62 + c63 + c64 + c65 + c66 + c67 + c68 + c69 + c70 + c71 + c72 + c73 + c74 + c75 + c76 + c77 + c78 + c79 + c80 + c81 + c82 + c83 + c84 + c85 + c86 + c87 + c88 + c89 + c90 + c91 + c92 + c93 + c94 + c95 + c96 + c97 + c98 + c99 + c100 + c101 + c102 + c103 + c104 + c105 + c106 + c107)
    }
}
"#,
    );

    let paths = vec![bridge_path];
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        flags.iter().any(|flag| {
            flag.file_path.ends_with("PillitAppShellIosBridge.kt") && flag.tier == FindingTier::Slop
        }),
        "expected the large iOS bridge to be scored as slop: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn kotlin_compose_screen_hotspot_is_flagged_as_slop() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_kotlin_compose_hotspot"));
    let screens_dir = temp_root.join("src").join("screens");
    fs::create_dir_all(&screens_dir).unwrap();

    let hero_path = write_temp_file(
        &screens_dir,
        "DashboardHero.kt",
        r#"
package screens

import androidx.compose.runtime.Composable

@Composable
fun DashboardHero(
    nextDose: String?,
    isOverdue: Boolean,
    isDueNow: Boolean,
    hasUpcomingDose: Boolean,
    hasNextScheduledDose: Boolean,
    onOpenDetails: () -> Unit,
) {
    val headline =
        when {
            isOverdue -> "OVERDUE DOSE"
            isDueNow -> "DUE NOW"
            hasUpcomingDose -> "UPCOMING DOSE"
            else -> "NO UPCOMING DOSES"
        }
    val subtitle =
        when {
            isOverdue && hasNextScheduledDose -> "Next scheduled dose is available"
            isDueNow -> "Take it now"
            hasUpcomingDose -> "Check the next reminder"
            else -> "Nothing scheduled yet"
        }
    if (isOverdue) {
        println("show overdue hero")
    }
    if (isDueNow) {
        println("show due now hero")
    }
    if (hasUpcomingDose) {
        println("show upcoming hero")
    }
    if (hasNextScheduledDose) {
        println("show next scheduled hero")
    }
    if (nextDose != null) {
        println("next dose: $nextDose")
    }
    if (isOverdue && isDueNow) {
        println("impossible but branchy")
    }
    if (!isOverdue && !isDueNow && !hasUpcomingDose) {
        println("empty state")
    }
    if (nextDose?.length ?: 0 > 10) {
        println("long dose name")
    }
    if (headline.length > 0) {
        println(headline)
    }
    if (subtitle.length > 0) {
        println(subtitle)
    }
    if (headline == "OVERDUE DOSE") {
        println("emphasize overdue state")
    }
    if (headline == "DUE NOW") {
        println("emphasize due now state")
    }
    if (headline == "UPCOMING DOSE") {
        println("emphasize upcoming state")
    }
    if (headline == "NO UPCOMING DOSES") {
        println("emphasize empty state")
    }
    if (hasUpcomingDose && hasNextScheduledDose) {
        println("two dose states")
    }
    if (isOverdue || isDueNow || hasUpcomingDose || hasNextScheduledDose) {
        println("hero is visible")
    }
    if (nextDose != null && nextDose.length > 2) {
        println("show a pill label")
    }
    if (nextDose != null && nextDose.length > 4) {
        println("show another pill label")
    }
    if (nextDose != null && nextDose.length > 6) {
        println("show a third pill label")
    }
    if (nextDose != null && nextDose.length > 8) {
        println("show a fourth pill label")
    }
    if (nextDose != null && nextDose.length > 10) {
        println("show a fifth pill label")
    }
    if (nextDose != null && nextDose.length > 12) {
        println("show a sixth pill label")
    }
    if (nextDose != null && nextDose.length > 14) {
        println("show a seventh pill label")
    }
    if (nextDose != null && nextDose.length > 16) {
        println("show an eighth pill label")
    }
    if (nextDose != null && nextDose.length > 18) {
        println("show a ninth pill label")
    }
    if (nextDose != null && nextDose.length > 20) {
        println("show a tenth pill label")
    }
    if (nextDose != null && nextDose.length > 22) {
        println("show an eleventh pill label")
    }
    if (nextDose != null && nextDose.length > 24) {
        println("show a twelfth pill label")
    }
    if (nextDose != null && nextDose.length > 26) {
        println("show a thirteenth pill label")
    }
    if (nextDose != null && nextDose.length > 28) {
        println("show a fourteenth pill label")
    }
    if (nextDose != null && nextDose.length > 30) {
        println("show a fifteenth pill label")
    }
    onOpenDetails()
}
"#,
    );

    let paths = vec![hero_path];
    let file_records = parse_records(&paths);
    let flags = score(&file_records, &ResolvedConfig::default());

    assert!(
        flags.iter().any(|flag| {
            flag.file_path.ends_with("DashboardHero.kt") && flag.tier == FindingTier::Slop
        }),
        "expected the large Kotlin Compose screen to be scored as slop: {:?}",
        flags
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn python_workspace_helpers_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_python_workspace_helpers"));
    let analysis_dir = temp_root.join("src").join("bumpkin").join("analysis");
    fs::create_dir_all(&analysis_dir).unwrap();

    let workspace_path = write_temp_file(
        &analysis_dir,
        "finding_workspace.py",
        r#"
from pathlib import Path


PYTHON_SOURCE_ROOT_NAMES = {"src", "python", "lib"}


def python_module_candidates(path):
    normalized = path.strip().replace("\\", "/").strip("/")
    if not normalized:
        return set()
    parts = normalized.split("/")
    if not parts:
        return set()
    module_parts = [*parts[:-1], Path(parts[-1]).stem]
    candidates = {".".join(module_parts)}
    if module_parts and module_parts[0] in PYTHON_SOURCE_ROOT_NAMES and len(module_parts) >= 2:
        candidates.add(".".join(module_parts[1:]))
    return {candidate for candidate in candidates if candidate}


def python_package_root(path):
    normalized = path.strip().replace("\\", "/").strip("/")
    if not normalized:
        return None
    parts = normalized.split("/")
    if len(parts) < 2:
        return None
    package_parts = parts[:-1]
    if parts[0] in PYTHON_SOURCE_ROOT_NAMES and len(parts) >= 3:
        package_parts = parts[1:-1]
    if not package_parts:
        return None
    package_root = ".".join(package_parts)
    return package_root or None
"#,
    );

    let paths = vec![workspace_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "workspace helper module should stay clean: {:?}",
        scorer_flags
    );
    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);
    assert!(
        file_verdicts[0].top_reasons.is_empty(),
        "workspace helper module should not ship verdict reasons"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn analyzer_verdicts_rules_facade_stays_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_analyzer_verdicts_rules"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let rules_path = write_temp_file(
        &src_dir,
        "analyzer_verdicts_rules.rs",
        r#"
#[path = "analyzer_verdicts_rules_analysis.rs"]
mod analysis;
#[path = "analyzer_verdicts_rules_parse.rs"]
mod parse;

pub(crate) use analysis::should_clear_analysis_verdict;
pub(crate) use parse::should_clear_parsing_verdict;
"#,
    );

    let paths = vec![rules_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "verdict rules facade should stay clean: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts.is_empty(),
        "pure facade modules should stay out of the report"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn file_verdicts_builder_stays_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_file_verdicts_builder"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let builder_path = write_temp_file(
        &src_dir,
        "file_verdicts_builder.rs",
        r#"
use std::collections::{BTreeMap, BTreeSet};

pub(super) enum SignalSeverity {
    Mild,
    Severe,
}

pub(super) struct FileVerdictBuilder;

impl FileVerdictBuilder {
    pub(super) fn new() -> Self {
        Self
    }

    pub(super) fn finish(self) {}
}
"#,
    );

    let paths = vec![builder_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "file verdict builder plumbing should stay clean: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts.is_empty(),
        "pure plumbing modules should stay out of the report"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn clean_llm_verdict_overrides_static_noise() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_clean_llm_override"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let file_path = write_temp_file(
        &src_dir,
        "support_helpers.rs",
        r#"
pub fn build_support_payload(value: i32) -> i32 {
    if value > 0 {
        return value;
    }
    value + 1
}
"#,
    );

    let file_records = parse_records(std::slice::from_ref(&file_path));
    let static_flags = vec![StaticFlag {
        flag_type: "file".to_string(),
        file_path: file_path.clone(),
        method_name: None,
        reasons: vec!["file does too much".to_string()],
        tier: FindingTier::Slop,
        gate: "scorer".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    }];
    let llm_verdicts = vec![sniff::report_types::LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file_path.clone(),
        method_name: None,
        check_type: "file_review".to_string(),
        smelly: false,
        tier: FindingTier::Clean,
        cohesive: Some(true),
        name_accurate: Some(true),
        evidence: String::new(),
        reason: "clean".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    }];

    let file_verdicts =
        sniff::file_verdicts::build_file_verdicts(&file_records, &static_flags, &llm_verdicts);

    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);
    assert!(
        file_verdicts[0].top_reasons.is_empty(),
        "clean LLM confirmation should clear static-only noise: {:?}",
        file_verdicts[0]
    );
    assert!(
        file_verdicts[0].flagged_methods.is_empty(),
        "clean LLM confirmation should not leave flagged methods behind: {:?}",
        file_verdicts[0]
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn smelly_llm_verdict_survives_even_when_static_is_quiet() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_smelly_llm_survives"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let file_path = write_temp_file(
        &src_dir,
        "surface_base.py",
        r#"
def collect_python_signature_source(lines, start_index):
    return lines[start_index]
"#,
    );

    let file_records = parse_records(std::slice::from_ref(&file_path));
    let llm_verdicts = vec![sniff::report_types::LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file_path.clone(),
        method_name: None,
        check_type: "file_review".to_string(),
        smelly: true,
        tier: FindingTier::Slop,
        cohesive: Some(false),
        name_accurate: Some(true),
        evidence: "collect_python_signature_source".to_string(),
        reason: "file does too much".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    }];

    let file_verdicts =
        sniff::file_verdicts::build_file_verdicts(&file_records, &[], &llm_verdicts);

    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Slop);
    assert!(
        file_verdicts[0]
            .top_reasons
            .iter()
            .any(|reason| reason.contains("file does too much")),
        "smelly LLM verdict should keep its reason: {:?}",
        file_verdicts[0]
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn walker_stays_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_walker"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let walker_path = write_temp_file(
        &src_dir,
        "walker.rs",
        r#"
use std::path::Path;

fn is_test_file(path: &Path) -> bool {
    path.file_name().is_some()
}

pub fn walk(root_path: &str) -> Vec<String> {
    if root_path.is_empty() {
        return Vec::new();
    }
    Vec::new()
}
"#,
    );

    let paths = vec![walker_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "walker plumbing should stay clean: {:?}",
        scorer_flags
    );
    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);
    assert!(
        file_verdicts[0].top_reasons.is_empty(),
        "walker plumbing should not ship verdict reasons"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn signal_layers_architecture_stays_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_signal_layers_architecture"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let arch_path = write_temp_file(
        &src_dir,
        "signal_layers_architecture.rs",
        r#"
pub struct ArchitectureMetrics;

impl ArchitectureMetrics {
    pub fn new() -> Self {
        Self
    }
}

pub fn architecture_flags() -> Vec<String> {
    Vec::new()
}
"#,
    );

    let paths = vec![arch_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "architecture signal plumbing should stay clean: {:?}",
        scorer_flags
    );
    assert_eq!(file_verdicts.len(), 1);
    assert_eq!(file_verdicts[0].verdict, FindingTier::Clean);
    assert!(
        file_verdicts[0].top_reasons.is_empty(),
        "architecture signal plumbing should not ship verdict reasons"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn python_package_init_reexports_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_python_init_reexport"));
    let src_dir = temp_root.join("src");
    let pkg_dir = src_dir.join("pkg");
    fs::create_dir_all(&pkg_dir).unwrap();

    let init_path = write_temp_file(
        &pkg_dir,
        "__init__.py",
        "from .impl import PromptPack, build_messages\n\n__all__ = [\"PromptPack\", \"build_messages\"]\n",
    );
    let _impl_path = write_temp_file(
        &pkg_dir,
        "impl.py",
        "class PromptPack:\n    pass\n\ndef build_messages():\n    return []\n",
    );

    let paths = vec![init_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "package init reexport shims should not be scored as slop: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts.is_empty(),
        "package init reexport shims should stay out of the final report"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn python_package_main_entrypoints_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_python_main_entrypoint"));
    let src_dir = temp_root.join("src");
    let app_dir = src_dir.join("app");
    fs::create_dir_all(&app_dir).unwrap();

    let main_path = write_temp_file(
        &app_dir,
        "__main__.py",
        "from .main import main\n\nif __name__ == \"__main__\":\n    raise SystemExit(main())\n",
    );
    let _entry_main_path = write_temp_file(&app_dir, "main.py", "def main():\n    return 0\n");

    let paths = vec![main_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "package entrypoint shims should not be scored as slop: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts.is_empty(),
        "package entrypoint shims should stay out of the final report"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn python_stub_package_facades_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_python_stub_facade"));
    let src_dir = temp_root.join("src");
    let pkg_dir = src_dir.join("typedpkg");
    fs::create_dir_all(&pkg_dir).unwrap();

    let init_stub_path = write_temp_file(
        &pkg_dir,
        "__init__.pyi",
        "from .api import PromptPack, build_messages\n\n__all__ = [\"PromptPack\", \"build_messages\"]\n",
    );
    let api_stub_path = write_temp_file(
        &pkg_dir,
        "api.pyi",
        "from .impl import PromptPack, build_messages\n\n__all__ = [\"PromptPack\", \"build_messages\"]\n",
    );
    let _impl_stub_path = write_temp_file(
        &pkg_dir,
        "impl.pyi",
        "class PromptPack: ...\n\ndef build_messages() -> list[str]: ...\n",
    );

    let paths = vec![init_stub_path, api_stub_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "typed package facade stubs should not be scored as slop: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts.is_empty(),
        "typed package facade stubs should stay out of the final report"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn python_stub_package_entrypoints_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_python_stub_entrypoint"));
    let src_dir = temp_root.join("src");
    let app_dir = src_dir.join("typedapp");
    fs::create_dir_all(&app_dir).unwrap();

    let main_stub_path = write_temp_file(
        &app_dir,
        "__main__.pyi",
        "from .main import main\n\nif __name__ == \"__main__\": ...\n",
    );
    let _main_stub_path = write_temp_file(&app_dir, "main.pyi", "def main() -> int: ...\n");

    let paths = vec![main_stub_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "typed package entrypoint stubs should not be scored as slop: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts.is_empty(),
        "typed package entrypoint stubs should stay out of the final report"
    );

    fs::remove_dir_all(&temp_root).ok();
}

#[test]
fn ts_and_rust_reexports_stay_clean_end_to_end() {
    let temp_root = std::env::temp_dir().join(unique_tag("sniff_crosslang_reexports"));
    let src_dir = temp_root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let ts_path = write_temp_file(&src_dir, "shim.ts", "export * from './impl';\n");
    let rust_path = write_temp_file(
        &src_dir,
        "shim.rs",
        "pub use crate::analysis::explanation_facts::*;\n",
    );

    let paths = vec![ts_path, rust_path];
    let file_records = parse_records(&paths);
    let scorer_flags = score(&file_records, &ResolvedConfig::default());
    let file_verdicts = sniff::file_verdicts::build_file_verdicts(&file_records, &[], &[]);

    assert!(
        scorer_flags.is_empty(),
        "cross-language reexport shims should not be scored as slop: {:?}",
        scorer_flags
    );
    assert!(
        file_verdicts.is_empty(),
        "cross-language reexport shims should stay out of the final report"
    );

    fs::remove_dir_all(&temp_root).ok();
}
