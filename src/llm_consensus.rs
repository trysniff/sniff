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
        ResponseSchema::MethodReview | ResponseSchema::FileReview => value
            .get("tier")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
    }
}

fn vote_rank(schema: ResponseSchema, value: &Value) -> usize {
    match schema {
        ResponseSchema::MethodReview | ResponseSchema::FileReview => match value
            .get("tier")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
        {
            "clean" => 0,
            "kinda_slop" => 1,
            "slop" => 2,
            _ => 0,
        },
        ResponseSchema::RoleClassification => 0,
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
        ResponseSchema::MethodReview | ResponseSchema::FileReview
    ) {
        candidates.sort_by(|a, b| {
            let a_rank = vote_rank(schema, &a.2);
            let b_rank = vote_rank(schema, &b.2);
            // An unresolved tie is uncertainty, not evidence of slop. Keep
            // the least severe vote unless a real majority exists.
            a_rank.cmp(&b_rank).then_with(|| a.1.cmp(&b.1))
        });
        return candidates.into_iter().next().map(|(_, _, vote)| vote);
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
            let key = vote_key(schema, &value);
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

    let consensus = pick_consensus(schema, votes);
    Ok((consensus, total_input, total_output))
}

#[cfg(test)]
mod tests {
    use super::{pick_consensus, vote_key};
    use crate::llm::ResponseSchema;

    #[test]
    fn unresolved_method_tie_chooses_clean() {
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
        assert_eq!(vote_key(ResponseSchema::MethodReview, &result), "clean");
    }
}
