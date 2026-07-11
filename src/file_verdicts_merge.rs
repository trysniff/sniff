use crate::report_types::{LLMVerdict, StaticFlag};
use crate::roles::{
    FileRole, classify_file_role, is_detector_support_module, is_module_barrel_module,
    is_pure_reexport_module, is_versioning_tag_module, is_wrapper_only_module,
};
use crate::types::FileRecord;

use super::builder::{FileVerdictBuilder, classify_signal_tier};
use super::signals::is_supporting_only_reason;

fn add_static_flag(builder: &mut FileVerdictBuilder, flag: &StaticFlag) {
    let Some(severity) = classify_signal_tier(flag.tier) else {
        return;
    };

    if flag
        .reasons
        .iter()
        .all(|reason| is_supporting_only_reason(reason))
    {
        return;
    }

    if let Some(method_name) = &flag.method_name {
        builder.add_method_reason(method_name.clone(), severity, flag.reasons.join("; "));
    } else {
        builder.add_file_reason(severity, flag.reasons.join("; "));
    }
}

fn add_llm_verdict(builder: &mut FileVerdictBuilder, verdict: &LLMVerdict) {
    builder.mark_llm_review(verdict.smelly, verdict.method_name.as_deref());
    if !verdict.smelly {
        return;
    }

    let Some(severity) = classify_signal_tier(verdict.tier) else {
        return;
    };

    if verdict.reason.is_empty() || is_supporting_only_reason(&verdict.reason) {
        return;
    }

    if let Some(method_name) = &verdict.method_name {
        let reason = if verdict.evidence.is_empty() {
            verdict.reason.clone()
        } else {
            format!("{} ({})", verdict.reason, verdict.evidence)
        };
        builder.add_method_reason(method_name.clone(), severity, reason);
    } else {
        let reason = if verdict.evidence.is_empty() {
            verdict.reason.clone()
        } else {
            format!("{} ({})", verdict.reason, verdict.evidence)
        };
        builder.add_file_reason(severity, reason);
    }
}

fn seed_builders(
    file_records: &[FileRecord],
) -> std::collections::BTreeMap<String, FileVerdictBuilder> {
    let mut builders = std::collections::BTreeMap::new();

    for file in file_records {
        let role = classify_file_role(&file.file_path);
        let skip_reason = if matches!(role, FileRole::Docs | FileRole::Generated) {
            Some(format!("role={:?}", role))
        } else if is_pure_reexport_module(file) {
            Some("pure_reexport".to_string())
        } else if is_module_barrel_module(file) {
            Some("module_barrel".to_string())
        } else if is_wrapper_only_module(file) {
            Some("wrapper_only".to_string())
        } else if is_detector_support_module(&file.file_path) {
            Some("detector_support".to_string())
        } else if is_versioning_tag_module(&file.file_path) {
            Some("versioning_tag".to_string())
        } else {
            None
        };

        if skip_reason.is_some() {
            continue;
        }

        builders.insert(
            file.file_path.clone(),
            FileVerdictBuilder::new(file.file_path.clone(), role, reviewable_method_count(file)),
        );
    }

    builders
}

fn reviewable_method_count(file: &FileRecord) -> usize {
    if !file.file_path.ends_with(".rs") {
        return file.methods.len();
    }

    let Some(cfg_test_line) = file
        .source
        .lines()
        .position(|line| line.trim().starts_with("#[cfg(test)]"))
        .map(|index| index + 1)
    else {
        return file.methods.len();
    };

    file.methods
        .iter()
        .filter(|method| method.start_line <= cfg_test_line)
        .count()
}

fn apply_static_flags(
    builders: &mut std::collections::BTreeMap<String, FileVerdictBuilder>,
    static_flags: &[StaticFlag],
) {
    for flag in static_flags {
        if let Some(builder) = builders.get_mut(&flag.file_path) {
            add_static_flag(builder, flag);
        }
    }
}

fn apply_llm_verdicts(
    builders: &mut std::collections::BTreeMap<String, FileVerdictBuilder>,
    llm_verdicts: &[LLMVerdict],
) {
    for verdict in llm_verdicts {
        if let Some(builder) = builders.get_mut(&verdict.file_path) {
            add_llm_verdict(builder, verdict);
        }
    }
}

pub fn build_file_verdicts(
    file_records: &[FileRecord],
    static_flags: &[StaticFlag],
    llm_verdicts: &[LLMVerdict],
) -> Vec<crate::report_types::FileVerdict> {
    let mut builders = seed_builders(file_records);
    apply_static_flags(&mut builders, static_flags);
    apply_llm_verdicts(&mut builders, llm_verdicts);

    builders
        .into_values()
        .map(FileVerdictBuilder::finish)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::build_file_verdicts;
    use crate::report_types::LLMVerdict;
    use crate::types::{FileRecord, FindingTier, MethodRecord};

    #[test]
    fn medication_numeric_rules_slop_survives_merge() {
        let file_path =
            "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/MedicationNumericRules.kt"
                .to_string();
        let file = FileRecord {
            file_path: file_path.clone(),
            source: "public fun sanitizeMedicationStrengthInput(value: String): String { return value }\n"
                .to_string(),
            language: "kotlin".to_string(),
            methods: vec![
                MethodRecord {
                    name: "sanitizeMedicationWholeNumberInput".to_string(),
                    file_path: file_path.clone(),
                    source: String::new(),
                    loc: 14,
                    param_count: 1,
                    start_line: 1,
                    end_line: 15,
                    is_exported: true,
                    language: "kotlin".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "sanitizeMedicationDecimalInput".to_string(),
                    file_path: file_path.clone(),
                    source: String::new(),
                    loc: 21,
                    param_count: 1,
                    start_line: 17,
                    end_line: 38,
                    is_exported: true,
                    language: "kotlin".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
                MethodRecord {
                    name: "sanitizeMedicationStrengthInput".to_string(),
                    file_path: file_path.clone(),
                    source: String::new(),
                    loc: 33,
                    param_count: 1,
                    start_line: 40,
                    end_line: 72,
                    is_exported: true,
                    language: "kotlin".to_string(),
                    nesting_depth: 0,
                    references: vec![],
                    real_ref_count: 0,
                },
            ],
        };
        let verdict = LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: file_path.clone(),
            method_name: None,
            check_type: "file".to_string(),
            smelly: true,
            tier: FindingTier::Slop,
            cohesive: Some(false),
            name_accurate: Some(false),
            evidence:
                "character == '/' && !slashSeen && currentPartHasDigits && !endsWith(\".\") -> {"
                    .to_string(),
            reason: "function is too big".to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        };

        let file_verdicts = build_file_verdicts(&[file], &[], &[verdict]);
        assert_eq!(file_verdicts.len(), 1);
        assert_eq!(file_verdicts[0].verdict, FindingTier::Slop);
        assert!(
            file_verdicts[0]
                .top_reasons
                .iter()
                .any(|reason| reason.contains("function is too big"))
        );
    }
}
