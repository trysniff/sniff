use sniff::file_verdicts::build_file_verdicts;
use sniff::report_types::{LLMVerdict, StaticFlag};
use sniff::types::{FileRecord, FindingTier, MethodRecord};

fn file(path: &str, methods: Vec<MethodRecord>) -> FileRecord {
    FileRecord {
        file_path: path.to_string(),
        source: String::new(),
        language: "python".to_string(),
        methods,
    }
}

fn method(name: &str, path: &str, loc: usize) -> MethodRecord {
    MethodRecord {
        name: name.to_string(),
        file_path: path.to_string(),
        source: String::new(),
        loc,
        param_count: 0,
        start_line: 1,
        end_line: loc.max(1),
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    }
}

fn method_flag(path: &str, name: &str, tier: FindingTier, reason: &str) -> StaticFlag {
    StaticFlag {
        flag_type: "method".to_string(),
        file_path: path.to_string(),
        method_name: Some(name.to_string()),
        reasons: vec![reason.to_string()],
        tier,
        gate: "scorer".to_string(),
        loc: 8,
        start_line: 1,
        end_line: 8,
    }
}

fn clean_method_verdict(path: &str, name: &str) -> LLMVerdict {
    LLMVerdict {
        verdict_type: "method".to_string(),
        file_path: path.to_string(),
        method_name: Some(name.to_string()),
        check_type: "method_review".to_string(),
        smelly: false,
        tier: FindingTier::Clean,
        cohesive: None,
        name_accurate: None,
        evidence: String::new(),
        reason: "clean".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    }
}

#[test]
fn one_mild_method_stays_clean() {
    let path = "src/sample.py";
    let file_records = vec![file(path, vec![method("helper", path, 8)])];
    let verdicts = build_file_verdicts(
        &file_records,
        &[method_flag(
            path,
            "helper",
            FindingTier::KindaSlop,
            "name is vague",
        )],
        &[] as &[LLMVerdict],
    );

    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].verdict, FindingTier::Clean);
    assert_eq!(verdicts[0].flagged_methods, vec!["helper".to_string()]);
}

#[test]
fn clean_file_review_clears_sprawling_static_candidates() {
    let path = "src/sample.py";
    let file_records = vec![file(
        path,
        vec![
            method("helper", path, 8),
            method("other", path, 12),
            method("third", path, 16),
            method("fourth", path, 20),
            method("fifth", path, 24),
            method("sixth", path, 28),
        ],
    )];
    let verdicts = build_file_verdicts(
        &file_records,
        &[method_flag(
            path,
            "helper",
            FindingTier::Slop,
            "function is too big",
        )],
        &[LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: path.to_string(),
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
        }],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::Clean);
    assert!(verdicts[0].flagged_methods.is_empty());
}

#[test]
fn clean_file_review_clears_small_severe_static_candidates() {
    let path = "src/sample.py";
    let file_records = vec![file(
        path,
        vec![
            method("helper", path, 8),
            method("other", path, 12),
            method("third", path, 16),
            method("fourth", path, 20),
            method("fifth", path, 24),
        ],
    )];
    let verdicts = build_file_verdicts(
        &file_records,
        &[method_flag(
            path,
            "helper",
            FindingTier::Slop,
            "function is too big",
        )],
        &[LLMVerdict {
            verdict_type: "file".to_string(),
            file_path: path.to_string(),
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
        }],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::Clean);
    assert!(verdicts[0].flagged_methods.is_empty());
}

#[test]
fn exhaustive_clean_ai_review_clears_shape_only_noise_in_large_files() {
    let path = "src/coherent_parser.py";
    let names = ["parse", "scan", "decode", "normalize", "validate", "render"];
    let file_records = vec![file(
        path,
        names.iter().map(|name| method(name, path, 48)).collect(),
    )];
    let mut llm_verdicts = vec![LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: path.to_string(),
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
    llm_verdicts.extend(names.iter().map(|name| clean_method_verdict(path, name)));

    let verdicts = build_file_verdicts(
        &file_records,
        &[method_flag(
            path,
            "parse",
            FindingTier::Slop,
            "function is too big",
        )],
        &llm_verdicts,
    );

    assert_eq!(verdicts[0].verdict, FindingTier::Clean);
    assert!(verdicts[0].flagged_methods.is_empty());
}

#[test]
fn clean_method_review_hides_static_method_noise_but_keeps_file_slop() {
    let path = "src/mixed.py";
    let file_records = vec![file(
        path,
        vec![
            method("clean_helper", path, 8),
            method("real_offender", path, 140),
        ],
    )];
    let verdicts = build_file_verdicts(
        &file_records,
        &[
            method_flag(
                path,
                "clean_helper",
                FindingTier::Slop,
                "branchy control flow (4 branches)",
            ),
            method_flag(
                path,
                "real_offender",
                FindingTier::Slop,
                "function is too big",
            ),
            StaticFlag {
                flag_type: "file".to_string(),
                file_path: path.to_string(),
                method_name: None,
                reasons: vec!["file does too much: mixes unrelated responsibilities".to_string()],
                tier: FindingTier::Slop,
                gate: "scorer".to_string(),
                loc: 0,
                start_line: 0,
                end_line: 0,
            },
        ],
        &[
            LLMVerdict {
                verdict_type: "file".to_string(),
                file_path: path.to_string(),
                method_name: None,
                check_type: "file_review".to_string(),
                smelly: true,
                tier: FindingTier::Slop,
                cohesive: Some(false),
                name_accurate: Some(true),
                evidence: "def real_offender".to_string(),
                reason: "file does too much: mixes unrelated responsibilities".to_string(),
                loc: 0,
                start_line: 0,
                end_line: 0,
            },
            clean_method_verdict(path, "clean_helper"),
            LLMVerdict {
                verdict_type: "method".to_string(),
                file_path: path.to_string(),
                method_name: Some("real_offender".to_string()),
                check_type: "method_review".to_string(),
                smelly: true,
                tier: FindingTier::Slop,
                cohesive: Some(false),
                name_accurate: Some(true),
                evidence: "def real_offender".to_string(),
                reason: "function is too big".to_string(),
                loc: 140,
                start_line: 1,
                end_line: 140,
            },
        ],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::Slop);
    assert!(
        verdicts[0]
            .flagged_methods
            .contains(&"real_offender".to_string())
    );
    assert!(
        !verdicts[0]
            .flagged_methods
            .contains(&"clean_helper".to_string())
    );
}

#[test]
fn rust_cfg_test_methods_do_not_block_clean_merge() {
    let path = "src/parser.rs";
    let file_records = vec![FileRecord {
        file_path: path.to_string(),
        source: "pub fn parse() {}\n\n#[cfg(test)]\nmod tests {\n    fn fixture() {}\n}\n"
            .to_string(),
        language: "rust".to_string(),
        methods: vec![
            MethodRecord {
                name: "parse".to_string(),
                file_path: path.to_string(),
                source: "pub fn parse() {}".to_string(),
                loc: 1,
                param_count: 0,
                start_line: 1,
                end_line: 1,
                is_exported: true,
                language: "rust".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "fixture".to_string(),
                file_path: path.to_string(),
                source: "fn fixture() {}".to_string(),
                loc: 1,
                param_count: 0,
                start_line: 5,
                end_line: 5,
                is_exported: false,
                language: "rust".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
        ],
    }];
    let verdicts = build_file_verdicts(
        &file_records,
        &[StaticFlag {
            flag_type: "file".to_string(),
            file_path: path.to_string(),
            method_name: None,
            reasons: vec!["function is too big".to_string()],
            tier: FindingTier::Slop,
            gate: "scorer".to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        }],
        &[
            LLMVerdict {
                verdict_type: "file".to_string(),
                file_path: path.to_string(),
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
            },
            clean_method_verdict(path, "parse"),
        ],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::Clean);
    assert!(verdicts[0].flagged_methods.is_empty());
}

#[test]
fn lone_file_level_filename_noise_stays_clean() {
    let path = "src/sample.py";
    let file_records = vec![file(path, vec![method("helper", path, 8)])];
    let verdicts = build_file_verdicts(
        &file_records,
        &[StaticFlag {
            flag_type: "file".to_string(),
            file_path: path.to_string(),
            method_name: None,
            reasons: vec!["filename is vague".to_string()],
            tier: FindingTier::KindaSlop,
            gate: "scorer".to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        }],
        &[] as &[LLMVerdict],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::Clean);
}

#[test]
fn lone_supporting_reason_is_detected_even_when_it_is_not_first() {
    let path = "src/sample.py";
    let file_records = vec![file(path, vec![method("helper", path, 8)])];
    let verdicts = build_file_verdicts(
        &file_records,
        &[StaticFlag {
            flag_type: "file".to_string(),
            file_path: path.to_string(),
            method_name: None,
            reasons: vec![
                "module has sprawling helper surface".to_string(),
                "orphaned export".to_string(),
            ],
            tier: FindingTier::KindaSlop,
            gate: "scorer".to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        }],
        &[] as &[LLMVerdict],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::Clean);
}

#[test]
fn lone_file_level_structure_signal_stays_kinda_slop() {
    let path = "src/sample.py";
    let file_records = vec![file(path, vec![method("helper", path, 8)])];
    let verdicts = build_file_verdicts(
        &file_records,
        &[StaticFlag {
            flag_type: "file".to_string(),
            file_path: path.to_string(),
            method_name: None,
            reasons: vec!["file does too much".to_string()],
            tier: FindingTier::KindaSlop,
            gate: "scorer".to_string(),
            loc: 0,
            start_line: 0,
            end_line: 0,
        }],
        &[] as &[LLMVerdict],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::KindaSlop);
}

#[test]
fn two_mild_methods_bump_to_kinda_slop() {
    let path = "src/sample.py";
    let file_records = vec![file(
        path,
        vec![method("helper", path, 8), method("other", path, 10)],
    )];
    let verdicts = build_file_verdicts(
        &file_records,
        &[
            method_flag(path, "helper", FindingTier::KindaSlop, "name is vague"),
            method_flag(path, "other", FindingTier::KindaSlop, "name is vague"),
        ],
        &[] as &[LLMVerdict],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::KindaSlop);
}

#[test]
fn one_mild_method_with_multiple_minor_reasons_stays_clean() {
    let path = "src/sample.py";
    let file_records = vec![file(path, vec![method("helper", path, 8)])];
    let verdicts = build_file_verdicts(
        &file_records,
        &[StaticFlag {
            flag_type: "method".to_string(),
            file_path: path.to_string(),
            method_name: Some("helper".to_string()),
            reasons: vec![
                "branchy control flow (5 branches)".to_string(),
                "loop-heavy control flow (2 loops)".to_string(),
            ],
            tier: FindingTier::KindaSlop,
            gate: "scorer".to_string(),
            loc: 8,
            start_line: 1,
            end_line: 8,
        }],
        &[] as &[LLMVerdict],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::Clean);
}

#[test]
fn two_control_flow_only_methods_stay_clean() {
    let path = "src/sample.py";
    let file_records = vec![file(
        path,
        vec![method("helper", path, 8), method("other", path, 10)],
    )];
    let verdicts = build_file_verdicts(
        &file_records,
        &[
            method_flag(
                path,
                "helper",
                FindingTier::KindaSlop,
                "branchy control flow (3 branches)",
            ),
            method_flag(
                path,
                "other",
                FindingTier::KindaSlop,
                "loop-heavy control flow (2 loops)",
            ),
        ],
        &[] as &[LLMVerdict],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::Clean);
}

#[test]
fn three_control_flow_only_methods_stay_kinda_slop() {
    let path = "src/sample.py";
    let file_records = vec![file(
        path,
        vec![
            method("helper", path, 8),
            method("other", path, 10),
            method("third", path, 12),
        ],
    )];
    let verdicts = build_file_verdicts(
        &file_records,
        &[
            method_flag(
                path,
                "helper",
                FindingTier::KindaSlop,
                "branchy control flow (3 branches)",
            ),
            method_flag(
                path,
                "other",
                FindingTier::KindaSlop,
                "branchy control flow (4 branches)",
            ),
            method_flag(
                path,
                "third",
                FindingTier::KindaSlop,
                "loop-heavy control flow (2 loops)",
            ),
        ],
        &[] as &[LLMVerdict],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::KindaSlop);
}

#[test]
fn severe_signal_bumps_to_slop() {
    let path = "src/sample.py";
    let file_records = vec![file(path, vec![method("helper", path, 8)])];
    let verdicts = build_file_verdicts(
        &file_records,
        &[method_flag(
            path,
            "helper",
            FindingTier::Slop,
            "function is too big",
        )],
        &[] as &[LLMVerdict],
    );

    assert_eq!(verdicts[0].verdict, FindingTier::Slop);
}

#[test]
fn generated_and_docs_files_are_skipped() {
    let file_records = vec![
        file(
            "generated/generated.py",
            vec![method("helper", "generated/generated.py", 8)],
        ),
        file(
            "docs/readme.py",
            vec![method("helper", "docs/readme.py", 8)],
        ),
    ];

    let verdicts = build_file_verdicts(&file_records, &[], &[] as &[LLMVerdict]);
    assert!(verdicts.is_empty());
}
