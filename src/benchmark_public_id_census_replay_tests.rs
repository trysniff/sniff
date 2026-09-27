use super::*;
use crate::benchmark::committed_public_id_census_policy;

#[derive(Clone)]
struct FixtureRepository {
    id: u64,
    name: String,
    created_at: &'static str,
    language: Option<&'static str>,
}

fn repositories() -> Vec<FixtureRepository> {
    vec![
        FixtureRepository {
            id: 2,
            name: "before/repo".to_string(),
            created_at: "2026-08-07T23:59:59Z",
            language: Some("Go"),
        },
        FixtureRepository {
            id: 3,
            name: "go/repo".to_string(),
            created_at: "2026-08-08T00:00:00Z",
            language: Some("Go"),
        },
        FixtureRepository {
            id: 4,
            name: "js/repo".to_string(),
            created_at: "2026-08-14T23:59:59Z",
            language: Some("JavaScript"),
        },
        FixtureRepository {
            id: 5,
            name: "after/repo".to_string(),
            created_at: "2026-08-15T00:00:00Z",
            language: Some("Rust"),
        },
    ]
}

fn exchange(
    request: PublicIdCensusRequest,
    request_url: String,
    request_body: Option<String>,
    response_link: Option<String>,
    response_body: String,
) -> PublicIdCensusExchange {
    PublicIdCensusExchange {
        request,
        request_url,
        request_body,
        request_api_version: "2022-11-28".to_string(),
        response_status: 200,
        response_link,
        response_date: None,
        received_at_utc: "2026-09-27T00:00:00Z".to_string(),
        response_sha256: format!("{:x}", Sha256::digest(response_body.as_bytes())),
        response_body,
        failed_attempts: Vec::new(),
    }
}

fn rest(since: u64, repositories: &[FixtureRepository]) -> PublicIdCensusExchange {
    let selected = repositories
        .iter()
        .filter(|repository| repository.id > since)
        .take(100)
        .collect::<Vec<_>>();
    let has_more = repositories
        .iter()
        .filter(|repository| repository.id > since)
        .count()
        > 100;
    let response_body = serde_json::json!(
        selected
            .iter()
            .map(|repository| serde_json::json!({
                "id": repository.id,
                "node_id": format!("node-{}", repository.id),
                "full_name": &repository.name,
            }))
            .collect::<Vec<_>>()
    )
    .to_string();
    let response_link = has_more.then(|| {
        format!(
            "<https://api.github.com/repositories?per_page=100&since={}>; rel=\"next\"",
            selected.last().unwrap().id
        )
    });
    exchange(
        PublicIdCensusRequest::Rest { since },
        format!("https://api.github.com/repositories?per_page=100&since={since}"),
        None,
        response_link,
        response_body,
    )
}

fn graphql(repositories: &[FixtureRepository]) -> PublicIdCensusExchange {
    let node_ids = repositories
        .iter()
        .map(|repository| format!("node-{}", repository.id))
        .collect::<Vec<_>>();
    let response_body = serde_json::json!({
        "data": {
            "nodes": repositories.iter().map(|repository| serde_json::json!({
                "__typename": "Repository",
                "id": format!("node-{}", repository.id),
                "databaseId": repository.id,
                "nameWithOwner": &repository.name,
                "createdAt": repository.created_at,
                "primaryLanguage": repository.language.map(|name| serde_json::json!({"name": name})),
                "isArchived": false,
                "isFork": false,
                "isTemplate": false,
                "mirrorUrl": null,
                "isPrivate": false,
            })).collect::<Vec<_>>()
        }
    })
    .to_string();
    exchange(
        PublicIdCensusRequest::Graphql {
            node_ids: node_ids.clone(),
        },
        "https://api.github.com/graphql".to_string(),
        Some(public_id_census_graphql_body(&node_ids).unwrap()),
        None,
        response_body,
    )
}

fn transcript() -> Vec<PublicIdCensusExchange> {
    let rows = repositories();
    vec![
        rest(0, &rows),
        graphql(&rows[..1]),
        rest(1, &rows),
        graphql(&rows[..1]),
        rest(2, &rows),
        graphql(&rows[1..2]),
        rest(1, &rows),
        graphql(&rows[..1]),
        rest(2, &rows),
        graphql(&rows[1..2]),
        rest(1, &rows),
        graphql(&rows),
    ]
}

fn replace_response(exchange: &mut PublicIdCensusExchange, value: serde_json::Value) {
    exchange.response_body = value.to_string();
    exchange.response_sha256 = format!("{:x}", Sha256::digest(exchange.response_body.as_bytes()));
}

fn preflight_fixture() -> PublicIdCensusPreflight {
    let bytes = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("sniffbench/historical-v3-id-census/policy.json"),
    )
    .unwrap()
    .replace("\r\n", "\n");
    PublicIdCensusPreflight {
        public_policy_url: format!(
            "https://raw.githubusercontent.com/trysniff/sniff/{PUBLIC_ID_CENSUS_POLICY_COMMIT_SHA}/sniffbench/historical-v3-id-census/policy.json"
        ),
        fetched_policy_sha256: format!("{:x}", Sha256::digest(bytes.as_bytes())),
        fetched_policy: bytes,
        fetched_at_utc: "2026-09-26T00:00:00Z".to_string(),
        response_status: 200,
    }
}

fn replay_fixture(
    policy: &PublicIdCensusPolicy,
    exchanges: &[PublicIdCensusExchange],
) -> Result<PublicIdCensusReplay, String> {
    replay_public_id_census(policy, &preflight_fixture(), exchanges)
}

#[test]
fn derives_six_frames_from_one_ordered_transcript() {
    let policy = committed_public_id_census_policy().unwrap();
    let derived = replay_fixture(&policy, &transcript()).unwrap();
    assert_eq!(derived.frames.len(), 6);
    assert_eq!(derived.listed_repository_count, 4);
    assert_eq!(derived.in_window_repository_count, 2);
    assert_eq!(derived.excluded_repository_count, 0);
    assert_eq!(derived.lower_boundary_repository_id, 2);
    assert_eq!(derived.upper_boundary_repository_id, 5);
    assert_eq!(
        String::from_utf8(derived.frames["Go"].clone()).unwrap(),
        "repo,metadata\ngithub.com/go/repo,github_repository_id=3;created_at=2026-08-08T00:00:00Z\n"
    );
    assert_eq!(
        String::from_utf8(derived.frames["JavaScript"].clone()).unwrap(),
        "repo,metadata\ngithub.com/js/repo,github_repository_id=4;created_at=2026-08-14T23:59:59Z\n"
    );
    assert_eq!(derived.frames["Rust"], b"repo,metadata\n");
}

#[test]
fn rejects_null_or_mismatched_graphql_node() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[11].response_body).unwrap();
    response["data"]["nodes"][1] = serde_json::Value::Null;
    replace_response(&mut exchanges[11], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());

    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[11].response_body).unwrap();
    response["data"]["nodes"][1]["databaseId"] = serde_json::json!(99);
    replace_response(&mut exchanges[11], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_incomplete_or_extended_transcript() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    exchanges.pop();
    assert!(replay_fixture(&policy, &exchanges).is_err());
    let mut exchanges = transcript();
    exchanges.push(rest(5, &repositories()));
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_uncommitted_page_or_wrong_cursor() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    exchanges[10].response_sha256 = "0".repeat(64);
    assert!(replay_fixture(&policy, &exchanges).is_err());
    let mut exchanges = transcript();
    exchanges[10].request = PublicIdCensusRequest::Rest { since: 2 };
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_creation_order_inversion_and_private_node() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[11].response_body).unwrap();
    response["data"]["nodes"][2]["createdAt"] = serde_json::json!("2026-08-07T23:00:00Z");
    replace_response(&mut exchanges[11], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());

    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[11].response_body).unwrap();
    response["data"]["nodes"][2]["isPrivate"] = serde_json::Value::Bool(true);
    replace_response(&mut exchanges[11], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_missing_or_changed_public_preflight() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut preflight = preflight_fixture();
    preflight.public_policy_url = "https://raw.githubusercontent.com/trysniff/sniff/main/sniffbench/historical-v3-id-census/policy.json".to_string();
    assert!(replay_public_id_census(&policy, &preflight, &transcript()).is_err());
    let mut preflight = preflight_fixture();
    preflight.fetched_policy_sha256 = "0".repeat(64);
    assert!(replay_public_id_census(&policy, &preflight, &transcript()).is_err());
}

#[test]
fn validates_retry_evidence_and_limit() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let crawl = &mut exchanges[10];
    crawl.failed_attempts.push(PublicIdCensusFailedAttempt {
        request: crawl.request.clone(),
        request_url: crawl.request_url.clone(),
        request_body: crawl.request_body.clone(),
        request_api_version: crawl.request_api_version.clone(),
        received_at_utc: crawl.received_at_utc.clone(),
        response_status: Some(429),
        response_body: Some("rate limited".to_string()),
        response_sha256: Some(format!("{:x}", Sha256::digest(b"rate limited"))),
        transport_error: None,
    });
    assert!(replay_fixture(&policy, &exchanges).is_ok());
    exchanges[10].failed_attempts[0].response_status = Some(404);
    assert!(replay_fixture(&policy, &exchanges).is_err());
    exchanges[10].failed_attempts[0].response_status = Some(429);
    exchanges[10].failed_attempts = vec![exchanges[10].failed_attempts[0].clone(); 12];
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_short_page_with_next_and_malformed_final_link() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let short = serde_json::json!([
        {"id": 2, "node_id": "node-2", "full_name": "before/repo"},
        {"id": 3, "node_id": "node-3", "full_name": "go/repo"},
    ]);
    replace_response(&mut exchanges[10], short);
    exchanges[10].response_link = Some(
        "<https://api.github.com/repositories?per_page=100&since=3>; rel=\"next\"".to_string(),
    );
    assert!(replay_fixture(&policy, &exchanges).is_err());
    let mut exchanges = transcript();
    exchanges[10].response_link = Some("not a Link header".to_string());
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_impossible_utc_creation_time() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[11].response_body).unwrap();
    response["data"]["nodes"][2]["createdAt"] = serde_json::json!("2026-08-14T99:99:99Z");
    replace_response(&mut exchanges[11], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_crawl_that_omits_the_probed_first_in_window_repository() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let rows = repositories();
    let omitted = [rows[0].clone(), rows[2].clone(), rows[3].clone()];
    exchanges[10] = rest(1, &omitted);
    exchanges[11] = graphql(&omitted);
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_unclassified_transport_retry() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let crawl = &mut exchanges[10];
    crawl.failed_attempts.push(PublicIdCensusFailedAttempt {
        request: crawl.request.clone(),
        request_url: crawl.request_url.clone(),
        request_body: crawl.request_body.clone(),
        request_api_version: crawl.request_api_version.clone(),
        received_at_utc: crawl.received_at_utc.clone(),
        response_status: None,
        response_body: None,
        response_sha256: None,
        transport_error: Some("dns_error".to_string()),
    });
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_omitted_nullable_metadata_fields() {
    let policy = committed_public_id_census_policy().unwrap();
    for field in ["mirrorUrl", "primaryLanguage"] {
        let mut exchanges = transcript();
        let mut response: serde_json::Value =
            serde_json::from_str(&exchanges[11].response_body).unwrap();
        response["data"]["nodes"][1]
            .as_object_mut()
            .unwrap()
            .remove(field);
        replace_response(&mut exchanges[11], response);
        assert!(replay_fixture(&policy, &exchanges).is_err(), "{field}");
    }
}

#[test]
fn rejects_creation_after_graphql_receipt() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[11].response_body).unwrap();
    response["data"]["nodes"][3]["createdAt"] = serde_json::json!("2026-09-28T00:00:00Z");
    replace_response(&mut exchanges[11], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn follows_a_full_page_next_cursor_into_the_upper_boundary_page() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut rows = vec![repositories()[0].clone()];
    for id in 3..=101 {
        rows.push(FixtureRepository {
            id,
            name: format!("owner/repo{id}"),
            created_at: "2026-08-08T00:00:00Z",
            language: (id == 3).then_some("Go"),
        });
    }
    rows.push(FixtureRepository {
        id: 102,
        name: "after/repo".to_string(),
        created_at: "2026-08-15T00:00:00Z",
        language: Some("Rust"),
    });
    let exchanges = vec![
        rest(0, &rows),
        graphql(&rows[..1]),
        rest(1, &rows),
        graphql(&rows[..1]),
        rest(2, &rows),
        graphql(&rows[1..2]),
        rest(1, &rows),
        graphql(&rows[..1]),
        rest(2, &rows),
        graphql(&rows[1..2]),
        rest(1, &rows),
        graphql(&rows[..100]),
        rest(101, &rows),
        graphql(&rows[100..]),
    ];
    let derived = replay_fixture(&policy, &exchanges).unwrap();
    assert_eq!(derived.listed_repository_count, 101);
    assert_eq!(derived.in_window_repository_count, 99);
    assert_eq!(derived.excluded_repository_count, 98);
    assert_eq!(derived.upper_boundary_repository_id, 102);
    assert!(
        String::from_utf8(derived.frames["Go"].clone())
            .unwrap()
            .contains("github_repository_id=3")
    );
}

#[test]
fn rejects_rest_listing_before_repository_creation() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[11].response_body).unwrap();
    response["data"]["nodes"][3]["createdAt"] = serde_json::json!("2026-09-28T00:00:00Z");
    replace_response(&mut exchanges[11], response);
    exchanges[11].received_at_utc = "2026-09-29T00:00:00Z".to_string();
    assert!(replay_fixture(&policy, &exchanges).is_err());
}
