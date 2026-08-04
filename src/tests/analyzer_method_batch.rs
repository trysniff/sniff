use super::super::verdicts::{IntentMethodReview, SemanticMethodReview};
use super::{
    BatchMethodReview, adversarial_batch_output_contract, compact_method_context,
    complete_method_context, indexed_reviews, intent_batch_output_contract, ordered_reviews,
    render_adjudication_batch_prompt, render_adversarial_batch_prompt, render_intent_batch_prompt,
    semantic_batch_output_contract,
};
use crate::types::{MethodRecord, Reference};
use std::path::PathBuf;

fn batch_item(name: &str, start_line: usize) -> BatchMethodReview {
    BatchMethodReview {
            method: MethodRecord {
                name: name.to_string(),
                file_path: "src/demo.py".to_string(),
                source: format!("def {name}():\n    return 1\n"),
                loc: 2,
                param_count: 0,
                start_line,
                end_line: start_line + 1,
                is_exported: false,
                language: "python".to_string(),
                nesting_depth: 0,
                references: vec![],
                real_ref_count: 0,
            },
            static_signals: vec![],
            full_file: "# SHARED_SENTINEL\n".into(),
            file_context: "Full containing file (authoritative source):\n---\n# SHARED_SENTINEL\n---\n\nMethod dossier:\n- direct".to_string(),
            project_root: Box::new(PathBuf::new()),
            callee_context: vec![],
            boundary_requirements: vec![],
            repository_private_unused_candidate: false,
            stale_discard_signature_proof: None,
        }
}

#[test]
fn compact_context_removes_the_repeated_full_file() {
    let context = "Full containing file (authoritative source):\n---\nfile\n---\n\nMethod dossier:\n- callers";
    assert_eq!(
        compact_method_context(context),
        "Method dossier:\n- callers"
    );
}

#[test]
fn focused_adjudication_context_reattaches_the_shared_full_file_once() {
    let mut item = batch_item("demo", 1);
    item.file_context = "Method dossier:\n- direct".to_string();

    let context = complete_method_context(&item);

    assert_eq!(context.matches("SHARED_SENTINEL").count(), 1);
    assert!(context.contains("Full containing file (authoritative source):"));
    assert!(context.contains("Method dossier:\n- direct"));
}

#[test]
fn intent_batch_contract_names_every_key_and_exact_enum() {
    let contract = intent_batch_output_contract(4);
    assert!(contract.contains("exactly 4 objects"));
    assert!(contract.contains("m0, m1, m2, m3"));
    assert!(contract.contains("`required`, `unnecessary`, or `unknown`"));
    assert!(contract.contains("do not use synonyms such as `necessary`"));
    assert!(!contract.contains("required|unnecessary|unknown"));
}

#[test]
fn semantic_batch_contract_is_complete_and_strict() {
    let contract = semantic_batch_output_contract(2);
    assert!(contract.contains("exactly 2 objects"));
    assert!(contract.contains("m0, m1"));
    assert!(contract.contains("Every object must contain all of"));
    assert!(contract.contains("`tier` must be exactly"));
    assert!(contract.contains("never use `necessary`"));
    assert!(contract.contains("For Slop or Kinda Slop"));
    assert!(contract.contains("Scope these fields to the exact cited machinery"));
    assert!(contract.contains("every expected key appears once"));
}

#[test]
fn adversarial_batch_contract_is_compact_only_for_non_findings() {
    let contract = adversarial_batch_output_contract(2);

    assert!(contract.contains("For Clean, return only method_key"));
    assert!(contract.contains("For Unresolved, return only method_key"));
    assert!(contract.contains("For Slop or Kinda Slop, return every field"));
    assert!(contract.contains("exact source evidence"));
}

#[test]
fn batch_reviews_are_restored_to_method_key_order() {
    let result = serde_json::json!({
        "reviews": [
            {"method_key": "m1"},
            {"method_key": "m0"}
        ]
    });
    let ordered = ordered_reviews(&result, 2).unwrap();
    assert_eq!(ordered[0]["method_key"], "m0");
    assert_eq!(ordered[1]["method_key"], "m1");
}

#[test]
fn batch_reviews_reject_duplicate_method_keys() {
    let result = serde_json::json!({
        "reviews": [
            {"method_key": "m0"},
            {"method_key": "m0"}
        ]
    });
    assert!(
        ordered_reviews(&result, 2)
            .unwrap_err()
            .contains("duplicated")
    );
}

#[test]
fn partial_batch_validation_preserves_valid_method_keys() {
    let result = serde_json::json!({
        "reviews": [
            {"method_key": "m0", "intent": "valid"}
        ]
    });

    let (reviews, errors) = indexed_reviews(&result, 2).unwrap();
    assert!(reviews[0].is_some());
    assert!(reviews[1].is_none());
    assert!(errors.iter().any(|error| error.contains("m1")));
}

#[test]
fn batch_prompt_shares_file_context_but_keeps_independent_method_blocks() {
    let prompt =
        render_intent_batch_prompt(&[batch_item("first", 2), batch_item("second", 5)]).unwrap();

    assert_eq!(prompt.matches("# SHARED_SENTINEL").count(), 1);
    assert!(prompt.contains("METHOD KEY: m0"));
    assert!(prompt.contains("METHOD KEY: m1"));
    assert!(prompt.contains("Method: first"));
    assert!(prompt.contains("Method: second"));
    assert!(prompt.contains("Do not compare methods, share a verdict"));
}

#[test]
fn batch_prompt_includes_each_method_source_only_in_the_authoritative_file() {
    let mut first = batch_item("first", 2);
    let mut second = batch_item("second", 5);
    let full_file = "     1 | # SHARED_SENTINEL\n     2 | def first():\n     3 |     return 'FIRST_BODY_SENTINEL'\n     4 | \n     5 | def second():\n     6 |     return 'SECOND_BODY_SENTINEL'";
    first.full_file = full_file.into();
    second.full_file = full_file.into();

    let prompt = render_intent_batch_prompt(&[first, second]).unwrap();

    assert_eq!(prompt.matches("FIRST_BODY_SENTINEL").count(), 1);
    assert_eq!(prompt.matches("SECOND_BODY_SENTINEL").count(), 1);
    assert!(prompt.contains("included exactly once in the matching authoritative file"));
}

#[test]
fn batch_prompt_compacts_references_whose_full_file_is_authoritative() {
    let mut item = batch_item("first", 2);
    item.method.references = vec![
            Reference {
                file_path: "src/demo.py".to_string(),
                line: 10,
                snippet: "Caller Method: local (lines 8-12)\nCall site at line 10:\n     9 | SAME_FILE_CONTEXT_SENTINEL\n    10 | first()\n    11 | after()"
                    .to_string(),
            },
            Reference {
                file_path: "src/external.py".to_string(),
                line: 20,
                snippet: "Caller Method: external (lines 18-22)\nCall site at line 20:\n    19 | EXTERNAL_CONTEXT_SENTINEL\n    20 | first()\n    21 | after()"
                    .to_string(),
            },
        ];
    item.method.real_ref_count = 2;

    let prompt = render_intent_batch_prompt(&[item]).unwrap();

    assert!(!prompt.contains("SAME_FILE_CONTEXT_SENTINEL"));
    assert!(prompt.contains("src/demo.py:10"));
    assert!(prompt.contains("src/external.py:20"));
    assert!(prompt.contains("EXTERNAL_CONTEXT_SENTINEL"));
    assert_eq!(prompt.matches("first()").count(), 2);
}

#[test]
fn batch_prompt_isolates_authoritative_context_across_files() {
    let first = batch_item("first", 2);
    let mut second = batch_item("second", 5);
    second.method.file_path = "src/other.py".to_string();
    second.full_file = "# OTHER_SENTINEL\n".into();
    second.file_context = "Method dossier:\n- other".to_string();

    let prompt = render_intent_batch_prompt(&[first, second]).unwrap();

    assert_eq!(prompt.matches("# SHARED_SENTINEL").count(), 1);
    assert_eq!(prompt.matches("# OTHER_SENTINEL").count(), 1);
    assert!(prompt.contains("Authoritative full containing file: src/demo.py"));
    assert!(prompt.contains("Authoritative full containing file: src/other.py"));
}

#[test]
fn all_three_batch_passes_share_the_complete_evidence_prefix() {
    let mut items = vec![batch_item("first", 2), batch_item("second", 5)];
    items[0].file_context.push_str(
        "\ngit history: not queried because no compatibility/migration signal was detected",
    );
    let intents = items
        .iter()
        .map(|item| IntentMethodReview {
            intent: format!("Return the value from {}.", item.method.name),
            contract_status: "required".to_string(),
            necessity_check: "The method has a coherent local purpose.".to_string(),
            missing_evidence: Vec::new(),
        })
        .collect::<Vec<_>>();
    let challenges = items
        .iter()
        .map(|item| SemanticMethodReview {
            tier: crate::types::FindingTier::Clean,
            pattern: "none".to_string(),
            intent: format!("Return the value from {}.", item.method.name),
            reason: "The implementation directly fulfills its purpose.".to_string(),
            evidence: Vec::new(),
            necessity_check: "The direct return is required behavior.".to_string(),
            contract_status: "required".to_string(),
            contract_impact: "The callable contract requires the returned value.".to_string(),
            dependency_impact: "Known consumers receive the returned value.".to_string(),
            simplification: "none".to_string(),
            change_scope: "none".to_string(),
            behavior_status: "preserved".to_string(),
            missing_evidence: Vec::new(),
        })
        .collect::<Vec<_>>();
    let mut expanded_items = items.clone();
    expanded_items[0].file_context = expanded_items[0].file_context.replace(
        "git history: not queried because no compatibility/migration signal was detected",
        "git history: queried after evidence escalation; abc123 compatibility boundary",
    );
    let intent = render_intent_batch_prompt(&items).unwrap();
    let adversarial = render_adversarial_batch_prompt(&expanded_items, &intents).unwrap();
    let adjudication =
        render_adjudication_batch_prompt(&expanded_items, &intents, &challenges).unwrap();
    let marker = "END SNIFF SEMANTIC EVIDENCE PACKET";
    let intent_end = intent.find(marker).unwrap() + marker.len();
    let adversarial_end = adversarial.find(marker).unwrap() + marker.len();
    let adjudication_end = adjudication.find(marker).unwrap() + marker.len();

    assert_eq!(&intent[..intent_end], &adversarial[..adversarial_end]);
    assert_eq!(&intent[..intent_end], &adjudication[..adjudication_end]);
    assert_eq!(intent.matches("# SHARED_SENTINEL").count(), 1);
    assert_eq!(adversarial.matches("# SHARED_SENTINEL").count(), 1);
    assert_eq!(adjudication.matches("# SHARED_SENTINEL").count(), 1);
    assert!(!intent.contains("abc123 compatibility boundary"));
    assert!(adversarial.contains("abc123 compatibility boundary"));
    assert!(adjudication.contains("abc123 compatibility boundary"));
}
