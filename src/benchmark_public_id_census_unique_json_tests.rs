use super::*;

fn assert_rehashed_duplicate_rejected(original: &str, replacement: &str) {
    let (policy, preflight, mut exchanges, _) = fixture_transcript();
    let exchange = exchanges
        .iter_mut()
        .find(|exchange| {
            matches!(exchange.request, PublicIdCensusRequest::Graphql { .. })
                && exchange.response_body.contains(original)
        })
        .unwrap();
    exchange.response_body = exchange.response_body.replacen(original, replacement, 1);
    exchange.response_sha256 = format!("{:x}", Sha256::digest(exchange.response_body.as_bytes()));
    // Prove this is not a stale raw-response digest rejection.
    validate_exchange_for_version(exchange, &policy.api_version).unwrap();
    let error = replay_public_id_census_v2(&policy, &preflight, &exchanges).unwrap_err();
    assert!(
        error.starts_with("invalid public-ID census GraphQL response: "),
        "{error}"
    );
    assert!(error.contains("duplicate JSON object key"), "{error}");
}

#[test]
fn rehashed_duplicate_visibility_cannot_become_an_eligible_repository() {
    assert_rehashed_duplicate_rejected(
        r#""isPrivate":false"#,
        r#""isPrivate":true,"isPrivate":false"#,
    );
}

#[test]
fn rehashed_duplicate_identity_cannot_select_the_last_repository_id() {
    assert_rehashed_duplicate_rejected(r#""databaseId":3"#, r#""databaseId":900,"databaseId":3"#);
}

#[test]
fn rehashed_duplicate_errors_cannot_hide_an_unrelated_failure() {
    assert_rehashed_duplicate_rejected(
        r#""errors":"#,
        r#""errors":[{"type":"RATE_LIMITED","message":"wait"}],"errors":"#,
    );
}

#[test]
fn rehashed_duplicate_error_path_cannot_select_a_null_exclusion() {
    assert_rehashed_duplicate_rejected(
        r#""path":["nodes",2]"#,
        r#""path":["nodes",0],"path":["nodes",2]"#,
    );
}

#[test]
fn rehashed_duplicate_creation_time_and_escaped_visibility_fail() {
    assert_rehashed_duplicate_rejected(
        r#""createdAt":"2026-08-08T00:00:00Z""#,
        r#""createdAt":"2020-01-01T00:00:00Z","createdAt":"2026-08-08T00:00:00Z""#,
    );
    assert_rehashed_duplicate_rejected(
        r#""isPrivate":false"#,
        r#""is\u0050rivate":true,"isPrivate":false"#,
    );
}

#[test]
fn v1_replay_uses_the_same_strict_raw_parser() {
    use crate::benchmark::release::public_id_census::replay::{
        replay_public_id_census, tests as v1,
    };
    let policy = crate::benchmark::committed_public_id_census_policy().unwrap();
    let preflight = v1::preflight_fixture();
    let mut exchanges = v1::transcript();
    let exchange = exchanges
        .iter_mut()
        .find(|exchange| matches!(exchange.request, PublicIdCensusRequest::Graphql { .. }))
        .unwrap();
    exchange.response_body = exchange.response_body.replacen(
        r#""isPrivate":false"#,
        r#""isPrivate":true,"isPrivate":false"#,
        1,
    );
    exchange.response_sha256 = format!("{:x}", Sha256::digest(exchange.response_body.as_bytes()));
    let error = replay_public_id_census(&policy, &preflight, &exchanges).unwrap_err();
    assert!(
        error.starts_with("invalid public-ID census GraphQL response: "),
        "{error}"
    );
    assert!(error.contains("duplicate JSON object key"), "{error}");
}

#[test]
fn graphql_nullable_fields_default_errors_and_unknown_metadata_remain_supported() {
    let (policy, preflight, exchanges, _) = fixture_transcript();
    let exchange = exchanges
        .iter()
        .find(|exchange| matches!(exchange.request, PublicIdCensusRequest::Graphql { .. }))
        .unwrap();
    let mut response: serde_json::Value = serde_json::from_str(&exchange.response_body).unwrap();
    response["data"]["nodes"]
        .as_array_mut()
        .unwrap()
        .retain(|node| !node.is_null());
    response.as_object_mut().unwrap().remove("errors");
    response["extensions"] = serde_json::json!({"unrequested": {"x": 1}});
    let nodes = response["data"]["nodes"].as_array_mut().unwrap();
    let listed = nodes
        .iter()
        .map(|node| RestRepository {
            id: node["databaseId"].as_u64().unwrap(),
            node_id: node["id"].as_str().unwrap().to_string(),
            full_name: node["nameWithOwner"].as_str().unwrap().to_string(),
        })
        .collect::<Vec<_>>();
    let node_ids = listed
        .iter()
        .map(|repository| repository.node_id.clone())
        .collect::<Vec<_>>();
    nodes[0]["primaryLanguage"] = serde_json::Value::Null;
    nodes[0]["mirrorUrl"] = serde_json::Value::Null;
    let parse = |body: &str| {
        parse_graphql_observations(
            body,
            &node_ids,
            &listed,
            &preflight.fetched_at_utc,
            policy.require_public_at_enrichment,
        )
    };
    assert_eq!(parse(&response.to_string()).unwrap().len(), listed.len());
    for field in ["primaryLanguage", "mirrorUrl"] {
        let mut missing = response.clone();
        missing["data"]["nodes"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            parse(&missing.to_string())
                .unwrap_err()
                .contains("omitted nullable metadata")
        );
    }
    let error = parse(&format!("{} {{}}", response)).unwrap_err();
    assert!(
        error.starts_with("invalid public-ID census GraphQL response: "),
        "{error}"
    );
    response["extensions"] = serde_json::Value::Null;
    let nested = response
        .to_string()
        .replace(r#""extensions":null"#, r#""extensions":{"x":1,"x":1}"#);
    assert!(
        parse(&nested)
            .unwrap_err()
            .contains("duplicate JSON object key")
    );
}
