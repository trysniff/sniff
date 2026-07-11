use crate::report_types::{LLMVerdict, RunReport, RunStats, StaticFlag};
use crate::types::{FileRecord, FindingTier};

pub(super) struct StatsInput<'a> {
    pub file_records: &'a [FileRecord],
    pub static_flags: &'a [StaticFlag],
    pub verdicts: &'a [LLMVerdict],
    pub in_tok: usize,
    pub out_tok: usize,
    pub ai_expected_reviews: usize,
}

#[allow(clippy::field_reassign_with_default)]
pub(super) fn generate_stats(input: StatsInput<'_>) -> RunStats {
    let mut stats = RunStats::default();
    stats.files_scanned = input.file_records.len();
    stats.methods_analyzed = input.file_records.iter().map(|f| f.methods.len()).sum();
    stats.flagged_by_ref_count = input
        .static_flags
        .iter()
        .filter(|f| f.gate == "ref_count")
        .count();
    stats.flagged_by_scorer = input
        .static_flags
        .iter()
        .filter(|f| f.gate == "scorer")
        .count();
    stats.duplication_static = input
        .static_flags
        .iter()
        .filter(|f| f.gate == "duplication")
        .count();
    stats.churn_static = input
        .static_flags
        .iter()
        .filter(|f| f.gate == "churn")
        .count();
    stats.architecture_static = input
        .static_flags
        .iter()
        .filter(|f| f.gate == "architecture")
        .count();
    stats.test_coupling_static = input
        .static_flags
        .iter()
        .filter(|f| f.gate == "test_coupling")
        .count();
    stats.provenance_static = input
        .static_flags
        .iter()
        .filter(|f| f.gate == "provenance")
        .count();
    stats.slop_static = input
        .static_flags
        .iter()
        .filter(|f| f.tier == FindingTier::Slop)
        .count();
    stats.kinda_slop_static = input
        .static_flags
        .iter()
        .filter(|f| f.tier == FindingTier::KindaSlop)
        .count();
    stats.slop_ai = input
        .verdicts
        .iter()
        .filter(|v| v.smelly && v.tier == FindingTier::Slop)
        .count();
    stats.kinda_slop_ai = input
        .verdicts
        .iter()
        .filter(|v| v.smelly && v.tier == FindingTier::KindaSlop)
        .count();
    stats.ai_reviews = input.verdicts.len();
    stats.ai_expected_reviews = input.ai_expected_reviews;
    stats.ai_failed_reviews = input
        .ai_expected_reviews
        .saturating_sub(input.verdicts.len());
    stats.dead_methods = input
        .static_flags
        .iter()
        .filter(|f| {
            f.gate == "ref_count"
                && f.reasons
                    .first()
                    .map(|r| r.contains("orphaned export"))
                    .unwrap_or(false)
        })
        .count();
    stats.inline_candidates = input
        .static_flags
        .iter()
        .filter(|f| {
            f.gate == "ref_count"
                && f.reasons
                    .first()
                    .map(|r| r.contains("overbuilt helper"))
                    .unwrap_or(false)
        })
        .count();
    stats.input_tokens = input.in_tok;
    stats.output_tokens = input.out_tok;
    stats
}

pub(super) fn build_run_report_from_parts(
    file_records: &[FileRecord],
    static_flags: Vec<StaticFlag>,
    verdicts: Vec<LLMVerdict>,
    stats: RunStats,
) -> (RunReport, bool) {
    let file_verdicts =
        crate::file_verdicts::build_file_verdicts(file_records, &static_flags, &verdicts);
    let run_report = RunReport {
        file_verdicts,
        static_flags,
        llm_verdicts: verdicts,
        stats,
    };

    let has_issues = run_report
        .file_verdicts
        .iter()
        .any(|verdict| verdict.verdict != crate::types::FindingTier::Clean);

    (run_report, has_issues)
}

#[allow(dead_code)]
pub(super) fn expected_ai_reviews(file_records: &[FileRecord], only_files: bool) -> usize {
    let method_reviews = reviewable_method_count(file_records, only_files);

    let file_reviews = file_records.len();

    method_reviews + file_reviews
}

pub(super) fn expected_ai_reviews_after_role_resolution(
    file_records: &[FileRecord],
    only_files: bool,
) -> usize {
    let method_reviews = reviewable_method_count(file_records, only_files);

    let file_reviews = file_records.len();

    method_reviews + file_reviews
}

fn reviewable_method_count(file_records: &[FileRecord], only_files: bool) -> usize {
    if only_files {
        return 0;
    }

    file_records
        .iter()
        .map(|file| {
            file.methods
                .iter()
                .filter(|method| !is_rust_cfg_test_method(file, method))
                .count()
        })
        .sum()
}

fn rust_cfg_test_start_line(source: &str) -> Option<usize> {
    source
        .lines()
        .position(|line| line.trim().starts_with("#[cfg(test)]"))
        .map(|idx| idx + 1)
}

fn is_rust_cfg_test_method(file: &FileRecord, method: &crate::types::MethodRecord) -> bool {
    if !file.file_path.ends_with(".rs") {
        return false;
    }

    let Some(cfg_test_line) = rust_cfg_test_start_line(&file.source) else {
        return false;
    };

    method.start_line > cfg_test_line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MethodRecord;

    fn file(path: &str, source: &str, methods: Vec<MethodRecord>) -> FileRecord {
        FileRecord {
            file_path: path.to_string(),
            source: source.to_string(),
            language: "tsx".to_string(),
            methods,
        }
    }

    fn method(path: &str, name: &str) -> MethodRecord {
        MethodRecord {
            name: name.to_string(),
            file_path: path.to_string(),
            source: String::new(),
            loc: 3,
            param_count: 0,
            start_line: 1,
            end_line: 3,
            is_exported: true,
            language: "tsx".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        }
    }

    #[test]
    fn expected_ai_reviews_counts_all_files_and_methods() {
        let files = vec![
            file(
                "src/app/page.tsx",
                "export default function Page() { return <main />; }",
                vec![method("src/app/page.tsx", "Page")],
            ),
            file(
                "src/hooks/useHasMounted.ts",
                "import { useState, useEffect } from 'react';",
                vec![method("src/hooks/useHasMounted.ts", "useHasMounted")],
            ),
            file(
                "src/core.ts",
                "export function core() { return 1; }",
                vec![method("src/core.ts", "core")],
            ),
        ];

        assert_eq!(expected_ai_reviews(&files, true), 3);
        assert_eq!(expected_ai_reviews(&files, false), 6);
    }

    #[test]
    fn rust_cfg_test_methods_are_not_counted_as_ai_reviews() {
        let file = FileRecord {
            file_path: "src/reporter_summary.rs".to_string(),
            source: r#"
pub(super) fn append_footer() {}

pub(super) fn print_summary() {}

#[cfg(test)]
mod tests {
    fn footer_counts_final_verdicts() {}
}
"#
            .to_string(),
            language: "rust".to_string(),
            methods: vec![
                method("src/reporter_summary.rs", "append_footer"),
                method("src/reporter_summary.rs", "print_summary"),
                MethodRecord {
                    name: "footer_counts_final_verdicts".to_string(),
                    file_path: "src/reporter_summary.rs".to_string(),
                    source: "fn footer_counts_final_verdicts() {}".to_string(),
                    loc: 1,
                    param_count: 0,
                    start_line: 8,
                    end_line: 8,
                    is_exported: false,
                    language: "rust".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
            ],
        };

        assert_eq!(expected_ai_reviews(&[file], false), 3);
    }

    #[test]
    fn real_webhook_service_counts_as_an_ai_review_target() {
        let file = crate::parser::parse_file(
            "C:\\Users\\User\\Bumpkin\\src\\bumpkin\\integrations\\github\\webhook_service.py",
        );

        assert_eq!(expected_ai_reviews(&[file], true), 1);
    }

    #[test]
    fn thin_wrapper_methods_are_counted_in_ai_coverage() {
        let file = file(
            "src/app/page.tsx",
            "import { renderPage as _renderPageImpl } from './renderPage';\n\nexport default function Page() {\n  return _renderPageImpl();\n}\n",
            vec![method("src/app/page.tsx", "Page")],
        );

        assert_eq!(expected_ai_reviews(&[file], false), 2);
    }
}
