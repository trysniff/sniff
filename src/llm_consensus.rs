use serde_json::Value;
use std::collections::HashMap;

use super::{LLMClient, ResponseSchema};

pub(super) fn vote_key(schema: ResponseSchema, value: &Value) -> String {
    match schema {
        ResponseSchema::RoleClassification => value
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        ResponseSchema::MethodReview
        | ResponseSchema::MethodIntentReview
        | ResponseSchema::SemanticMethodReview
        | ResponseSchema::ScopedTierReview
        | ResponseSchema::CaseSynthesis
        | ResponseSchema::FileReview => value
            .get("tier")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        ResponseSchema::MethodIntentBatchReview
        | ResponseSchema::SemanticMethodBatchReview
        | ResponseSchema::CaseAdjudication => value.to_string(),
    }
}

fn semantic_consensus_key(value: &Value) -> String {
    let tier = value
        .get("tier")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let pattern = value
        .get("pattern")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    // Evidence quotes are allowed to vary between valid votes. The semantic
    // pass should agree on the judgment, while the outer adjudication pass
    // remains responsible for resolving concrete evidence differences.
    format!("{tier}|{pattern}")
}

fn pick_semantic_consensus(votes: Vec<Value>) -> Result<Option<Value>, String> {
    if votes.is_empty() {
        return Ok(None);
    }

    let mut buckets: HashMap<String, (usize, usize, Value)> = HashMap::new();
    for (idx, vote) in votes.into_iter().enumerate() {
        let key = semantic_consensus_key(&vote);
        buckets
            .entry(key)
            .and_modify(|entry| entry.0 += 1)
            .or_insert((1, idx, vote));
    }

    let max_count = buckets.values().map(|entry| entry.0).max().unwrap_or(0);
    let candidates = buckets
        .into_iter()
        .filter(|(_, entry)| entry.0 == max_count)
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err("semantic review consensus remained unresolved".to_string());
    }
    Ok(candidates.into_iter().next().map(|(_, (_, _, vote))| vote))
}

fn vote_rank(schema: ResponseSchema, value: &Value) -> usize {
    match schema {
        ResponseSchema::MethodReview
        | ResponseSchema::MethodIntentReview
        | ResponseSchema::SemanticMethodReview
        | ResponseSchema::ScopedTierReview
        | ResponseSchema::CaseSynthesis
        | ResponseSchema::FileReview => match value
            .get("tier")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
        {
            "clean" => 0,
            "kinda_slop" => 1,
            "slop" => 2,
            _ => 0,
        },
        ResponseSchema::MethodIntentBatchReview
        | ResponseSchema::SemanticMethodBatchReview
        | ResponseSchema::CaseAdjudication
        | ResponseSchema::RoleClassification => 0,
    }
}

pub(super) fn pick_consensus(schema: ResponseSchema, votes: Vec<Value>) -> Option<Value> {
    if votes.is_empty() {
        return None;
    }

    let mut buckets: HashMap<String, (usize, usize, Value)> = HashMap::new();
    for (idx, vote) in votes.into_iter().enumerate() {
        let key = vote_key(schema, &vote);
        buckets
            .entry(key)
            .and_modify(|entry| entry.0 += 1)
            .or_insert((1, idx, vote));
    }

    let max_count = buckets.values().map(|entry| entry.0).max().unwrap_or(0);
    let mut candidates: Vec<(String, usize, Value)> = buckets
        .into_iter()
        .filter(|(_, entry)| entry.0 == max_count)
        .map(|(key, (_count, idx, vote))| (key, idx, vote))
        .collect();

    if candidates.len() == 1 {
        return candidates.pop().map(|(_, _, vote)| vote);
    }

    if matches!(
        schema,
        ResponseSchema::MethodReview
            | ResponseSchema::MethodIntentReview
            | ResponseSchema::SemanticMethodReview
            | ResponseSchema::ScopedTierReview
            | ResponseSchema::CaseSynthesis
            | ResponseSchema::FileReview
    ) {
        if matches!(schema, ResponseSchema::SemanticMethodReview) {
            return None;
        }
        candidates.sort_by(|a, b| {
            let a_rank = vote_rank(schema, &a.2);
            let b_rank = vote_rank(schema, &b.2);
            // An unresolved tie is uncertainty, not evidence of slop. Keep
            // the least severe vote unless a real majority exists.
            a_rank.cmp(&b_rank).then_with(|| a.1.cmp(&b.1))
        });
        let (_, _, mut vote) = candidates.into_iter().next()?;
        if let Some(object) = vote.as_object_mut() {
            object.insert("tier".to_string(), Value::String("unresolved".to_string()));
            object.insert("smelly".to_string(), Value::Bool(false));
            object.insert(
                "reason".to_string(),
                Value::String("review votes tied; contract evidence is insufficient".to_string()),
            );
            if matches!(schema, ResponseSchema::FileReview) {
                object.insert("evidence".to_string(), Value::String(String::new()));
            }
        }
        return Some(vote);
    }

    candidates.sort_by_key(|a| a.1);
    candidates.into_iter().next().map(|(_, _, vote)| vote)
}

pub(super) async fn call_with_consensus(
    client: &LLMClient,
    prompt: &str,
    schema: ResponseSchema,
) -> Result<(Option<Value>, usize, usize), String> {
    let mut total_input = 0usize;
    let mut total_output = 0usize;
    let mut votes = Vec::new();
    let mut first_key: Option<String> = None;

    for attempt in 0..2 {
        let (result, in_tok, out_tok) = client.call_once(prompt, schema).await?;
        total_input += in_tok;
        total_output += out_tok;
        if let Some(value) = result {
            let key = if matches!(schema, ResponseSchema::SemanticMethodReview) {
                semantic_consensus_key(&value)
            } else {
                vote_key(schema, &value)
            };
            if attempt == 0 {
                first_key = Some(key.clone());
            }
            votes.push(value);
            if attempt == 1 && first_key.as_deref() != Some(key.as_str()) {
                let (third_result, in_tok, out_tok) = client.call_once(prompt, schema).await?;
                total_input += in_tok;
                total_output += out_tok;
                if let Some(value) = third_result {
                    votes.push(value);
                }
            }
        }
    }

    if matches!(schema, ResponseSchema::SemanticMethodReview) {
        return Ok((pick_semantic_consensus(votes)?, total_input, total_output));
    }

    Ok((pick_consensus(schema, votes), total_input, total_output))
}

#[cfg(test)]
mod tests {
    use super::{pick_consensus, pick_semantic_consensus, semantic_consensus_key, vote_key};
    use crate::llm::ResponseSchema;

    #[test]
    fn unresolved_method_tie_is_explicit() {
        let votes = vec![
            serde_json::json!({
                "smelly": false,
                "tier": "clean",
                "evidence": "",
                "reason": "clean"
            }),
            serde_json::json!({
                "smelly": true,
                "tier": "kinda_slop",
                "evidence": "return value",
                "reason": "small helper"
            }),
            serde_json::json!({
                "smelly": true,
                "tier": "slop",
                "evidence": "return value",
                "reason": "function is too big"
            }),
        ];

        let result = pick_consensus(ResponseSchema::MethodReview, votes).unwrap();
        assert_eq!(
            vote_key(ResponseSchema::MethodReview, &result),
            "unresolved"
        );
    }

    #[test]
    fn unresolved_semantic_tie_is_a_failure() {
        let votes = vec![
            serde_json::json!({
                "smelly": false,
                "tier": "clean",
                "pattern": "none",
                "evidence": []
            }),
            serde_json::json!({
                "smelly": true,
                "tier": "slop",
                "pattern": "contract_fog",
                "evidence": [{"start_line": 1, "end_line": 1, "quote": "return value"}]
            }),
            serde_json::json!({
                "smelly": true,
                "tier": "kinda_slop",
                "pattern": "ceremonial_logic",
                "evidence": [{"start_line": 1, "end_line": 1, "quote": "return value"}]
            }),
        ];

        let error = pick_semantic_consensus(votes).unwrap_err();
        assert!(error.contains("unresolved"));
    }

    #[test]
    fn semantic_consensus_allows_different_valid_evidence_quotes() {
        let votes = vec![
            serde_json::json!({
                "smelly": true,
                "tier": "slop",
                "pattern": "contract_fog",
                "evidence": [{"start_line": 1, "end_line": 1, "quote": "return value"}]
            }),
            serde_json::json!({
                "smelly": true,
                "tier": "slop",
                "pattern": "contract_fog",
                "evidence": [{"start_line": 2, "end_line": 2, "quote": "return helper(value)"}]
            }),
        ];

        let result = pick_semantic_consensus(votes).unwrap().unwrap();
        assert_eq!(semantic_consensus_key(&result), "slop|contract_fog");
    }
}
