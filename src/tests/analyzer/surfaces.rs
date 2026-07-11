use super::*;

#[test]
fn medication_numeric_rules_slop_verdict_survives_normalization() {
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(
            ResolvedConfig::default(),
            Some("test-key".to_string()),
        )),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file_path =
        "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/MedicationNumericRules.kt"
            .to_string();
    let file = FileRecord {
        file_path: file_path.clone(),
        source: r#"
package com.onpill.shared.uicontract

public fun sanitizeMedicationWholeNumberInput(value: String): String {
  var digitSeen = false
  return buildString {
    for (character in value) {
      when {
        character.isDigit() -> {
          append(character)
          digitSeen = true
        }
        digitSeen -> break
      }
    }
  }.takeIf { digitSeen }.orEmpty()
}

public fun sanitizeMedicationDecimalInput(value: String): String {
  var decimalSeen = false
  var digitSeen = false
  return buildString {
    for (character in value.replace(',', '.')) {
      when {
        character.isDigit() -> {
          append(character)
          digitSeen = true
        }
        character == '.' && !decimalSeen -> {
          if (isEmpty()) {
            append('0')
          }
          append(character)
          decimalSeen = true
        }
      }
    }
  }.takeIf { digitSeen }.orEmpty()
}

public fun sanitizeMedicationStrengthInput(value: String): String {
  var slashSeen = false
  var currentPartHasDigits = false
  var currentPartHasDecimal = false
  var anyDigitSeen = false
  return buildString {
    for (character in value.replace(',', '.')) {
      when {
        character.isDigit() -> {
          append(character)
          currentPartHasDigits = true
          anyDigitSeen = true
        }
        character == '.' && !currentPartHasDecimal -> {
          if (!currentPartHasDigits) {
            append('0')
            currentPartHasDigits = true
            anyDigitSeen = true
          }
          append(character)
          currentPartHasDecimal = true
        }
        character == '/' && !slashSeen && currentPartHasDigits && !endsWith(".") -> {
          append(character)
          slashSeen = true
          currentPartHasDigits = false
          currentPartHasDecimal = false
        }
        character == '/' && slashSeen -> break
      }
    }
  }.takeIf { anyDigitSeen }.orEmpty()
}
"#
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
    let mut verdict = LLMVerdict {
        verdict_type: "file".to_string(),
        file_path: file_path.clone(),
        method_name: None,
        check_type: "file".to_string(),
        smelly: true,
        tier: FindingTier::Slop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "character == '/' && !slashSeen && currentPartHasDigits && !endsWith(\".\") -> {"
            .to_string(),
        reason: "function is too big".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);

    assert_eq!(verdict.tier, FindingTier::Slop);
    assert!(verdict.smelly);
    assert_eq!(verdict.reason, "function is too big");
    assert!(!verdict.evidence.is_empty());
}

#[tokio::test]
async fn medication_numeric_rules_file_review_surfaces_as_slop() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"character == '/' && !slashSeen && currentPartHasDigits && !endsWith(\\\".\\\") -> {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#;
    let (endpoint, hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file_path =
        "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/MedicationNumericRules.kt"
            .to_string();
    let file = FileRecord {
        file_path: file_path.clone(),
        source: r#"
package com.onpill.shared.uicontract

public fun sanitizeMedicationWholeNumberInput(value: String): String {
  var digitSeen = false
  return buildString {
    for (character in value) {
      when {
        character.isDigit() -> {
          append(character)
          digitSeen = true
        }
        digitSeen -> break
      }
    }
  }.takeIf { digitSeen }.orEmpty()
}

public fun sanitizeMedicationDecimalInput(value: String): String {
  var decimalSeen = false
  var digitSeen = false
  return buildString {
    for (character in value.replace(',', '.')) {
      when {
        character.isDigit() -> {
          append(character)
          digitSeen = true
        }
        character == '.' && !decimalSeen -> {
          if (isEmpty()) {
            append('0')
          }
          append(character)
          decimalSeen = true
        }
      }
    }
  }.takeIf { digitSeen }.orEmpty()
}

public fun sanitizeMedicationStrengthInput(value: String): String {
  var slashSeen = false
  var currentPartHasDigits = false
  var currentPartHasDecimal = false
  var anyDigitSeen = false
  return buildString {
    for (character in value.replace(',', '.')) {
      when {
        character.isDigit() -> {
          append(character)
          currentPartHasDigits = true
          anyDigitSeen = true
        }
        character == '.' && !currentPartHasDecimal -> {
          if (!currentPartHasDigits) {
            append('0')
            currentPartHasDigits = true
            anyDigitSeen = true
          }
          append(character)
          currentPartHasDecimal = true
        }
        character == '/' && !slashSeen && currentPartHasDigits && !endsWith(".") -> {
          append(character)
          slashSeen = true
          currentPartHasDigits = false
          currentPartHasDecimal = false
        }
        character == '/' && slashSeen -> break
      }
    }
  }.takeIf { anyDigitSeen }.orEmpty()
}
"#
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

    let (verdict, _, _) = analyzer
        .analyze_file(&file, &[])
        .await
        .expect("file review should complete");

    let verdict = verdict.expect("file review should return a verdict");
    assert_eq!(verdict.tier, FindingTier::Slop);
    assert!(verdict.smelly);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn medication_numeric_rules_stays_slop_with_static_signals() {
    let body = r#"{"choices":[{"message":{"content":"{\"smelly\":true,\"tier\":\"slop\",\"evidence\":\"character == '/' && !slashSeen && currentPartHasDigits && !endsWith(\\\".\\\") -> {\",\"cohesive\":false,\"name_accurate\":false,\"reason\":\"function is too big\"}"}}]}"#;
    let (endpoint, _hits) = spawn_openai_style_server(body);
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(cfg(&endpoint), Some("test-key".to_string()))),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file_path =
        "shared/contract/src/commonMain/kotlin/com/pillit/shared/uicontract/MedicationNumericRules.kt"
            .to_string();
    let file = FileRecord {
        file_path: file_path.clone(),
        source: r#"
package com.onpill.shared.uicontract

public fun sanitizeMedicationWholeNumberInput(value: String): String {
  var digitSeen = false
  return buildString {
    for (character in value) {
      when {
        character.isDigit() -> {
          append(character)
          digitSeen = true
        }
        digitSeen -> break
      }
    }
  }.takeIf { digitSeen }.orEmpty()
}

public fun sanitizeMedicationDecimalInput(value: String): String {
  var decimalSeen = false
  var digitSeen = false
  return buildString {
    for (character in value.replace(',', '.')) {
      when {
        character.isDigit() -> {
          append(character)
          digitSeen = true
        }
        character == '.' && !decimalSeen -> {
          if (isEmpty()) {
            append('0')
          }
          append(character)
          decimalSeen = true
        }
      }
    }
  }.takeIf { digitSeen }.orEmpty()
}

public fun sanitizeMedicationStrengthInput(value: String): String {
  var slashSeen = false
  var currentPartHasDigits = false
  var currentPartHasDecimal = false
  var anyDigitSeen = false
  return buildString {
    for (character in value.replace(',', '.')) {
      when {
        character.isDigit() -> {
          append(character)
          currentPartHasDigits = true
          anyDigitSeen = true
        }
        character == '.' && !currentPartHasDecimal -> {
          if (!currentPartHasDigits) {
            append('0')
            currentPartHasDigits = true
            anyDigitSeen = true
          }
          append(character)
          currentPartHasDecimal = true
        }
        character == '/' && !slashSeen && currentPartHasDigits && !endsWith(".") -> {
          append(character)
          slashSeen = true
          currentPartHasDigits = false
          currentPartHasDecimal = false
        }
        character == '/' && slashSeen -> break
      }
    }
  }.takeIf { anyDigitSeen }.orEmpty()
}
"#
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
    let static_flags =
        crate::scorer::score(std::slice::from_ref(&file), &ResolvedConfig::default());

    let (verdicts, _, _) = analyze_with_client(
        &[file],
        &static_flags,
        analyzer.llm_client,
        false,
        None::<fn()>,
    )
    .await
    .expect("analysis should complete");

    let verdict = verdicts
        .into_iter()
        .find(|verdict| {
            verdict.file_path.ends_with("MedicationNumericRules.kt")
                && verdict.method_name.is_none()
        })
        .expect("expected the file verdict");
    assert_eq!(verdict.tier, FindingTier::Slop);
    assert!(verdict.smelly);
}

#[test]
fn single_method_entrypoints_stay_clean_on_size_only_noise() {
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(
            ResolvedConfig::default(),
            Some("test-key".to_string()),
        )),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/main.py".to_string(),
        source: "def main():\n    return 0\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "main".to_string(),
            file_path: "src/main.py".to_string(),
            source: "def main():\n    return 0\n".to_string(),
            loc: 411,
            param_count: 2,
            start_line: 1,
            end_line: 411,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 5,
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
        tier: FindingTier::Slop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "main".to_string(),
        reason: "function is too big (411 LOC > 100); branchy control flow (26 branches)"
            .to_string(),
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
fn entrypoints_reject_import_only_file_level_smears() {
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(
            ResolvedConfig::default(),
            Some("test-key".to_string()),
        )),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "src/main.py".to_string(),
        source: "from __future__ import annotations\n\nimport argparse\n".to_string(),
        language: "python".to_string(),
        methods: vec![MethodRecord {
            name: "main".to_string(),
            file_path: "src/main.py".to_string(),
            source: "def main():\n    return 0\n".to_string(),
            loc: 48,
            param_count: 0,
            start_line: 1,
            end_line: 48,
            is_exported: true,
            language: "python".to_string(),
            nesting_depth: 2,
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
        tier: FindingTier::Slop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "from __future__ import annotations".to_string(),
        reason: "file does too much (from __future__ import annotations)".to_string(),
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
fn entrypoint_single_fallback_helper_is_only_kinda_slop() {
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(
            ResolvedConfig::default(),
            Some("test-key".to_string()),
        )),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "supabase/functions/signup-wrapper/index.ts".to_string(),
        source: "export async function handler(req: Request) {\n  return await req.json().catch(() => ({} as Record<string, any>));\n}\n".to_string(),
        language: "typescript".to_string(),
        methods: vec![MethodRecord {
            name: "body".to_string(),
            file_path: "supabase/functions/signup-wrapper/index.ts".to_string(),
            source: "const body = await req.json().catch(() => ({} as Record<string, any>))".to_string(),
            loc: 8,
            param_count: 0,
            start_line: 1,
            end_line: 8,
            is_exported: false,
            language: "typescript".to_string(),
            nesting_depth: 1,
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
        tier: FindingTier::Slop,
        cohesive: Some(false),
        name_accurate: Some(false),
        evidence: "const body = await req.json().catch(() => ({} as Record<string, any>))".to_string(),
        reason: "body: catch fallback uses a hardcoded empty object cast to Record<string, any>, which silently swallows JSON parse errors and loses the original error context, making debugging harder".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::KindaSlop);
    assert!(verdict.smelly);
    assert!(!verdict.reason.is_empty());
    assert!(!verdict.evidence.is_empty());
}

#[test]
fn entrypoint_small_helper_surface_is_only_kinda_slop() {
    let analyzer = Analyzer {
        llm_client: Arc::new(LLMClient::new(
            ResolvedConfig::default(),
            Some("test-key".to_string()),
        )),
        in_tok: AtomicUsize::new(0),
        out_tok: AtomicUsize::new(0),
    };
    let file = FileRecord {
        file_path: "supabase/functions/polar-webhook/index.ts".to_string(),
        source: "export async function handler(req: Request) {\n  return new Response('ok');\n}\n".to_string(),
        language: "typescript".to_string(),
        methods: vec![
            MethodRecord {
                name: "readAmountCents".to_string(),
                file_path: "supabase/functions/polar-webhook/index.ts".to_string(),
                source: "const totals = (order?.totals as Record<string, unknown> | undefined) ?? {};".to_string(),
                loc: 12,
                param_count: 1,
                start_line: 1,
                end_line: 12,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 1,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "readCustomerEmail".to_string(),
                file_path: "supabase/functions/polar-webhook/index.ts".to_string(),
                source: "const customer = (order?.customer as Record<string, unknown> | undefined) ?? {};".to_string(),
                loc: 11,
                param_count: 1,
                start_line: 1,
                end_line: 11,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 1,
                references: vec![],
                real_ref_count: 0,
            },
            MethodRecord {
                name: "readEnvBool".to_string(),
                file_path: "supabase/functions/polar-webhook/index.ts".to_string(),
                source: "const raw = String(Deno.env.get(name) ?? '').trim().toLowerCase();".to_string(),
                loc: 10,
                param_count: 2,
                start_line: 1,
                end_line: 10,
                is_exported: false,
                language: "typescript".to_string(),
                nesting_depth: 1,
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
        evidence: "const totals = (order?.totals as Record<string, unknown> | undefined) ?? {};".to_string(),
        reason: "readAmountCents: overbuilt fallback chain with unused totals variable; readCustomerEmail: unnecessary fallback to empty object for customer; readEnvBool: copy-pasted method body".to_string(),
        loc: 0,
        start_line: 0,
        end_line: 0,
    };

    normalize_file_verdict(&file, &analyzer.llm_client, &mut verdict);
    assert_eq!(verdict.tier, FindingTier::KindaSlop);
    assert!(verdict.smelly);
}
