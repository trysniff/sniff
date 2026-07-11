use crate::config::ResolvedConfig;
use crate::language_adapter::LanguageAdapter;
use crate::report_types::StaticFlag;
use crate::roles::{
    FileRole, is_analysis_finding_support_module, is_detector_support_module,
    is_intentional_surface_record, is_parsing_or_serialization_helper_module,
};
use crate::types::FileRecord;
use std::collections::HashSet;
use std::path::Path;

use super::method::is_cfg_test_module_method;
use super::rules::score_method_reasons;

pub(super) struct FileSignalStats {
    pub method_smell_count: usize,
    pub method_locs: Vec<usize>,
}

fn concern_families(file: &FileRecord) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut families = Vec::new();

    for method in &file.methods {
        let name = method.name.trim().trim_start_matches('_');
        let family = name.split('_').next().unwrap_or("").trim().to_lowercase();
        if family.is_empty() || !seen.insert(family.clone()) {
            continue;
        }
        families.push(family);
    }

    families
}

pub(super) fn collect_file_signal_stats(
    file: &FileRecord,
    config: &ResolvedConfig,
    adapter: &LanguageAdapter,
) -> FileSignalStats {
    let mut method_smell_count = 0usize;
    let mut method_locs = Vec::new();

    for method in &file.methods {
        if is_cfg_test_module_method(file, method) {
            continue;
        }

        let reasons = score_method_reasons(method, config, adapter);
        if !reasons.is_empty() {
            method_smell_count += 1;
        }
        method_locs.push(method.loc);
    }

    FileSignalStats {
        method_smell_count,
        method_locs,
    }
}

fn file_role_allows_generic_filename(role: FileRole) -> bool {
    matches!(
        role,
        FileRole::Entrypoint | FileRole::Script | FileRole::Example | FileRole::Test
    )
}

fn file_role_tolerates_file_sprawl(role: FileRole) -> bool {
    matches!(
        role,
        FileRole::Entrypoint | FileRole::Script | FileRole::Example | FileRole::Test
    )
}

fn scoreable_method_count(file: &FileRecord) -> usize {
    file.methods
        .iter()
        .filter(|method| !is_cfg_test_module_method(file, method))
        .count()
}

fn is_placeholder_shell_file(file: &FileRecord, role: FileRole) -> bool {
    if matches!(
        role,
        FileRole::Docs | FileRole::Generated | FileRole::Fixture | FileRole::Test
    ) {
        return false;
    }

    let source = file.source.to_lowercase();
    let strong_markers = [
        "main logic here",
        "results['findings'] = []",
        "results[\"findings\"] = []",
        "findings'] = []",
        "findings\"] = []",
        "skeleton report",
        "placeholder implementation",
    ];

    if strong_markers.iter().any(|marker| source.contains(marker)) {
        return true;
    }

    let has_todo_implement = source.contains("todo: implement");
    let shell_like_state = source.contains("let _findings = []")
        || source.contains("let _findings = vec![]")
        || source.contains("results['findings'] = []")
        || source.contains("results[\"findings\"] = []")
        || source.contains("findings'] = []")
        || source.contains("findings\"] = []");

    has_todo_implement && shell_like_state
}

pub(super) fn score_file_reason_set(
    file: &FileRecord,
    config: &ResolvedConfig,
    path_obj: &Path,
    role: FileRole,
    stats: &FileSignalStats,
) -> Vec<String> {
    let mut reasons = Vec::new();
    let scoreable_methods = scoreable_method_count(file);

    if is_placeholder_shell_file(file, role) {
        reasons.push("placeholder implementation".to_string());
        return reasons;
    }

    if is_intentional_surface_record(file) {
        return reasons;
    }

    if !file_role_tolerates_file_sprawl(role)
        && scoreable_methods > config.thresholds.max_methods_per_file
        && stats.method_smell_count >= 2
    {
        reasons.push(format!(
            "{} methods with {} slop signals - file does too much",
            scoreable_methods, stats.method_smell_count
        ));
    }

    if let Some(stem) = path_obj.file_stem().and_then(|s| s.to_str())
        && stem != "llm"
        && config.generic_file_names.iter().any(|g| g == stem)
        && !file_role_allows_generic_filename(role)
    {
        reasons.push(format!("filename is vague '{}'", stem));
    }

    if !file_role_tolerates_file_sprawl(role)
        && scoreable_methods >= 3
        && stats.method_smell_count >= 2
        && let (Some(max_l), Some(min_l)) = (
            stats.method_locs.iter().max().copied(),
            stats.method_locs.iter().min().copied(),
        )
        && min_l > 0
        && (max_l as f64 / min_l as f64) > 10.0
        && max_l > config.thresholds.max_loc
    {
        reasons.push(format!(
            "functions vary widely in size ({}-{} lines)",
            min_l, max_l
        ));
    }

    if matches!(role, FileRole::AdapterIntegration)
        && scoreable_methods >= 12
        && concern_families(file).len() >= 6
    {
        let families = concern_families(file);
        reasons.push(format!(
            "file does too much across concern families ({})",
            families
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join("/")
        ));
    }
    reasons
}

pub(super) fn build_file_flags(file: &FileRecord, config: &ResolvedConfig) -> Vec<StaticFlag> {
    let mut flags = Vec::new();

    if is_detector_support_module(&file.file_path)
        || is_analysis_finding_support_module(&file.file_path)
    {
        return flags;
    }

    let path_obj = Path::new(&file.file_path);
    let ext = match path_obj.extension().and_then(|e| e.to_str()) {
        Some(e) => e,
        None => return flags,
    };
    let adapter = match crate::languages::get_adapter(ext) {
        Some(a) => a,
        None => return flags,
    };
    let role = crate::roles::classify_file_role(&file.file_path);
    let stats = collect_file_signal_stats(file, config, &adapter);

    if !is_parsing_or_serialization_helper_module(&file.file_path) {
        let f_reasons = score_file_reason_set(file, config, path_obj, role, &stats);
        if !f_reasons.is_empty() {
            let tier = crate::scorer::tiers::tier_for_reasons(&f_reasons);
            flags.push(StaticFlag {
                flag_type: "file".to_string(),
                file_path: file.file_path.clone(),
                method_name: None,
                reasons: f_reasons,
                tier,
                gate: "scorer".to_string(),
                loc: 0,
                start_line: 0,
                end_line: 0,
            });
        }
    }

    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ResolvedConfig, ThresholdsConfig};
    use crate::types::{FileRecord, MethodRecord};

    fn demo_file(method_count: usize) -> FileRecord {
        let methods = (0..method_count)
            .map(|idx| MethodRecord {
                name: format!("alpha{idx}"),
                file_path: "src/demo.rs".to_string(),
                source: "fn demo() {}".to_string(),
                loc: 1,
                param_count: 0,
                start_line: idx + 1,
                end_line: idx + 1,
                is_exported: false,
                language: "rust".to_string(),
                nesting_depth: 0,
                references: Vec::new(),
                real_ref_count: 0,
            })
            .collect();

        FileRecord {
            file_path: "src/demo.rs".to_string(),
            source: String::new(),
            language: "rust".to_string(),
            methods,
        }
    }

    #[test]
    fn one_smelly_method_does_not_auto_promote_file_sprawl() {
        let file = demo_file(21);
        let stats = FileSignalStats {
            method_smell_count: 1,
            method_locs: vec![1; 21],
        };

        let reasons = score_file_reason_set(
            &file,
            &ResolvedConfig::default(),
            Path::new(&file.file_path),
            FileRole::Library,
            &stats,
        );

        assert!(
            !reasons
                .iter()
                .any(|reason| reason.contains("file does too much"))
        );
    }

    #[test]
    fn two_smelly_methods_can_still_promote_file_sprawl() {
        let file = demo_file(21);
        let stats = FileSignalStats {
            method_smell_count: 2,
            method_locs: vec![1; 21],
        };

        let reasons = score_file_reason_set(
            &file,
            &ResolvedConfig::default(),
            Path::new(&file.file_path),
            FileRole::Library,
            &stats,
        );

        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("file does too much"))
        );
    }

    #[test]
    fn entrypoints_do_not_get_file_sprawl_variance_noise() {
        let file = demo_file(5);
        let stats = FileSignalStats {
            method_smell_count: 1,
            method_locs: vec![1, 2, 3, 120, 240],
        };

        let reasons = score_file_reason_set(
            &file,
            &ResolvedConfig::default(),
            Path::new(&file.file_path),
            FileRole::Entrypoint,
            &stats,
        );

        assert!(
            !reasons
                .iter()
                .any(|reason| reason.contains("functions vary widely"))
        );
    }

    #[test]
    fn placeholder_entrypoint_shell_is_flagged() {
        let file = FileRecord {
            file_path: "scripts/code_quality_checker.py".to_string(),
            source: r#"
class CodeQualityChecker:
    def analyze(self):
        self.results['findings'] = []
        # Main logic here
"#
            .to_string(),
            language: "python".to_string(),
            methods: vec![],
        };
        let stats = FileSignalStats {
            method_smell_count: 0,
            method_locs: vec![],
        };

        let reasons = score_file_reason_set(
            &file,
            &ResolvedConfig::default(),
            Path::new(&file.file_path),
            FileRole::Entrypoint,
            &stats,
        );

        assert!(
            reasons
                .iter()
                .any(|reason| reason == "placeholder implementation"),
            "expected placeholder shell to be flagged: {reasons:?}"
        );
    }

    #[test]
    fn placeholder_library_shell_is_flagged_too() {
        let file = FileRecord {
            file_path: "src/report_builder.rs".to_string(),
            source: r#"
pub fn build_report() {
    // TODO: implement
    let _findings = [];
}
"#
            .to_string(),
            language: "rust".to_string(),
            methods: vec![],
        };
        let stats = FileSignalStats {
            method_smell_count: 0,
            method_locs: vec![],
        };

        let reasons = score_file_reason_set(
            &file,
            &ResolvedConfig::default(),
            Path::new(&file.file_path),
            FileRole::Library,
            &stats,
        );

        assert!(
            reasons
                .iter()
                .any(|reason| reason == "placeholder implementation"),
            "expected placeholder library shell to be flagged: {reasons:?}"
        );
    }

    #[test]
    fn real_todo_comment_with_substantive_logic_is_not_flagged() {
        let file = FileRecord {
            file_path: "src/report_builder.rs".to_string(),
            source: r#"
pub fn build_report(items: &[&str]) -> Vec<String> {
    // TODO: implement a richer formatter later
    items.iter().map(|item| item.trim().to_string()).collect()
}
"#
            .to_string(),
            language: "rust".to_string(),
            methods: vec![],
        };
        let stats = FileSignalStats {
            method_smell_count: 0,
            method_locs: vec![],
        };

        let reasons = score_file_reason_set(
            &file,
            &ResolvedConfig::default(),
            Path::new(&file.file_path),
            FileRole::Library,
            &stats,
        );

        assert!(
            !reasons
                .iter()
                .any(|reason| reason == "placeholder implementation"),
            "expected a real function with a TODO note to stay out of placeholder scoring: {reasons:?}"
        );
    }

    #[test]
    fn one_smelly_method_does_not_trigger_file_size_variance() {
        let file = demo_file(5);
        let stats = FileSignalStats {
            method_smell_count: 1,
            method_locs: vec![1, 2, 3, 120, 240],
        };

        let reasons = score_file_reason_set(
            &file,
            &ResolvedConfig::default(),
            Path::new(&file.file_path),
            FileRole::Library,
            &stats,
        );

        assert!(
            !reasons
                .iter()
                .any(|reason| reason.contains("functions vary widely"))
        );
    }

    #[test]
    fn llm_filename_is_not_treated_as_vague() {
        let file = FileRecord {
            file_path: "src/llm.rs".to_string(),
            source: String::new(),
            language: "rust".to_string(),
            methods: vec![MethodRecord {
                name: "build_payload".to_string(),
                file_path: "src/llm.rs".to_string(),
                source: "fn build_payload() {}".to_string(),
                loc: 4,
                param_count: 0,
                start_line: 1,
                end_line: 4,
                is_exported: false,
                language: "rust".to_string(),
                nesting_depth: 0,
                references: Vec::new(),
                real_ref_count: 0,
            }],
        };
        let stats = FileSignalStats {
            method_smell_count: 1,
            method_locs: vec![4],
        };
        let reasons = score_file_reason_set(
            &file,
            &ResolvedConfig::default(),
            Path::new(&file.file_path),
            FileRole::Library,
            &stats,
        );

        assert!(
            !reasons
                .iter()
                .any(|reason| reason.contains("filename is vague")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn cfg_test_module_methods_do_not_count_toward_file_sprawl() {
        let file = FileRecord {
            file_path: "src/cli_pipeline.rs".to_string(),
            source: r#"
pub fn run() {}

#[cfg(test)]
mod tests {
    fn spawn_http_status_server() {}

    fn spawn_clean_review_server() {}
}
"#
            .to_string(),
            language: "rust".to_string(),
            methods: vec![
                MethodRecord {
                    name: "run".to_string(),
                    file_path: "src/cli_pipeline.rs".to_string(),
                    source: "pub fn run() {}".to_string(),
                    loc: 1,
                    param_count: 0,
                    start_line: 2,
                    end_line: 2,
                    is_exported: true,
                    language: "rust".to_string(),
                    nesting_depth: 0,
                    references: Vec::new(),
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "spawn_http_status_server".to_string(),
                    file_path: "src/cli_pipeline.rs".to_string(),
                    source: "fn spawn_http_status_server() {}".to_string(),
                    loc: 1,
                    param_count: 0,
                    start_line: 6,
                    end_line: 6,
                    is_exported: false,
                    language: "rust".to_string(),
                    nesting_depth: 0,
                    references: Vec::new(),
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "spawn_clean_review_server".to_string(),
                    file_path: "src/cli_pipeline.rs".to_string(),
                    source: "fn spawn_clean_review_server() {}".to_string(),
                    loc: 1,
                    param_count: 0,
                    start_line: 8,
                    end_line: 8,
                    is_exported: false,
                    language: "rust".to_string(),
                    nesting_depth: 0,
                    references: Vec::new(),
                    real_ref_count: 0,
                },
            ],
        };
        let stats = FileSignalStats {
            method_smell_count: 2,
            method_locs: vec![1],
        };
        let config = ResolvedConfig {
            thresholds: ThresholdsConfig {
                max_loc: 100,
                max_nesting: 6,
                max_params: 6,
                max_methods_per_file: 1,
            },
            ..ResolvedConfig::default()
        };

        let reasons = score_file_reason_set(
            &file,
            &config,
            Path::new(&file.file_path),
            FileRole::Library,
            &stats,
        );

        assert!(
            !reasons
                .iter()
                .any(|reason| reason.contains("file does too much")),
            "test scaffolding should not count toward file sprawl: {reasons:?}"
        );
    }

    #[test]
    fn adapter_integration_concern_family_spread_promotes_file_sprawl() {
        let methods = [
            "record_event",
            "get_event",
            "update_event_status",
            "list_deferred_merge_events",
            "latest_recommended_label_for_pr",
            "record_recommendation_snapshot",
            "upsert_release_backlog_item",
            "list_unreleased_release_backlog_items",
            "mark_release_backlog_items_included",
            "record_approval",
            "latest_approval_for_pr",
            "delete_approvals",
        ]
        .into_iter()
        .enumerate()
        .map(|(idx, name)| MethodRecord {
            name: name.to_string(),
            file_path: "src/persistence_sqlite.py".to_string(),
            source: "def demo():\n    return None".to_string(),
            loc: 2,
            param_count: 0,
            start_line: idx + 1,
            end_line: idx + 2,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 0,
            references: Vec::new(),
            real_ref_count: 0,
        })
        .collect();
        let file = FileRecord {
            file_path: "src/persistence_sqlite.py".to_string(),
            source: String::new(),
            language: "python".to_string(),
            methods,
        };
        let stats = FileSignalStats {
            method_smell_count: 0,
            method_locs: vec![2; 12],
        };

        let reasons = score_file_reason_set(
            &file,
            &ResolvedConfig::default(),
            Path::new(&file.file_path),
            FileRole::AdapterIntegration,
            &stats,
        );

        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("file does too much across concern families")),
            "expected concern-family spread to be flagged: {reasons:?}"
        );
    }
}
