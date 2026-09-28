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

pub(crate) fn transcript() -> Vec<PublicIdCensusExchange> {
    let rows = repositories();
    vec![
        rest(0, &rows),
        graphql(&rows[..1]),
        rest(1, &rows),
        rest(2, &rows),
        graphql(&rows[1..2]),
        rest(1, &rows),
        rest(2, &rows),
        rest(1, &rows),
        graphql(&rows[2..]),
    ]
}

pub(crate) fn six_language_transcript() -> Vec<PublicIdCensusExchange> {
    let rows = vec![
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
            created_at: "2026-08-08T00:00:01Z",
            language: Some("JavaScript"),
        },
        FixtureRepository {
            id: 5,
            name: "kotlin/repo".to_string(),
            created_at: "2026-08-08T00:00:02Z",
            language: Some("Kotlin"),
        },
        FixtureRepository {
            id: 6,
            name: "python/repo".to_string(),
            created_at: "2026-08-08T00:00:03Z",
            language: Some("Python"),
        },
        FixtureRepository {
            id: 7,
            name: "rust/repo".to_string(),
            created_at: "2026-08-08T00:00:04Z",
            language: Some("Rust"),
        },
        FixtureRepository {
            id: 8,
            name: "ts/repo".to_string(),
            created_at: "2026-08-08T00:00:05Z",
            language: Some("TypeScript"),
        },
        FixtureRepository {
            id: 9,
            name: "after/repo".to_string(),
            created_at: "2026-08-15T00:00:00Z",
            language: Some("Rust"),
        },
    ];
    vec![
        rest(0, &rows),
        graphql(&rows[..1]),
        rest(1, &rows),
        rest(2, &rows),
        graphql(&rows[1..2]),
        rest(1, &rows),
        rest(2, &rows),
        rest(1, &rows),
        graphql(&rows[2..]),
    ]
}

pub(crate) fn capacity_six_language_transcript() -> Vec<PublicIdCensusExchange> {
    let mut rows = vec![FixtureRepository {
        id: 2,
        name: "before/repo".to_string(),
        created_at: "2026-08-07T23:59:59Z",
        language: Some("Go"),
    }];
    for language in ["Go", "JavaScript", "Kotlin", "Python", "Rust", "TypeScript"] {
        for index in 0..20 {
            rows.push(FixtureRepository {
                id: rows.len() as u64 + 2,
                name: format!("{}/repo-{index}", language.to_ascii_lowercase()),
                created_at: "2026-08-08T00:00:00Z",
                language: Some(language),
            });
        }
    }
    rows.push(FixtureRepository {
        id: 123,
        name: "after/repo".to_string(),
        created_at: "2026-08-15T00:00:00Z",
        language: Some("Rust"),
    });
    let mut exchanges = vec![
        rest(0, &rows),
        graphql(&rows[..1]),
        rest(1, &rows),
        rest(2, &rows),
        graphql(&rows[1..2]),
        rest(1, &rows),
        rest(2, &rows),
        rest(1, &rows),
        graphql(&rows[2..100]),
        rest(101, &rows),
        graphql(&rows[100..]),
    ];
    let first_template = "<https://api.github.com/repositories{?since}>; rel=\"first\"";
    exchanges[0].response_link = Some(format!(
        "{}, {first_template}",
        exchanges[0].response_link.as_deref().unwrap()
    ));
    exchanges[9].response_link = Some(first_template.to_string());
    exchanges
}

#[test]
fn capacity_fixture_replays_twenty_repositories_per_language() {
    let exchanges = capacity_six_language_transcript();
    assert!(
        exchanges[0]
            .response_link
            .as_ref()
            .unwrap()
            .contains("rel=\"next\"")
    );
    assert_eq!(
        exchanges[9].response_link.as_deref(),
        Some("<https://api.github.com/repositories{?since}>; rel=\"first\"")
    );
    let replay = replay_public_id_census(
        &committed_public_id_census_policy().unwrap(),
        &preflight_fixture(),
        &exchanges,
    )
    .unwrap();
    assert_eq!(replay.frames.len(), 6);
    assert!(
        replay
            .frames
            .values()
            .all(|frame| frame.iter().filter(|byte| **byte == b'\n').count() == 21)
    );
}

#[test]
fn github_templated_first_link_does_not_change_the_verified_next_cursor() {
    let policy = committed_public_id_census_policy().unwrap();
    let link = concat!(
        "<https://api.github.com/repositories?per_page=100&since=371>; rel=\"next\", ",
        "<https://api.github.com/repositories{?since}>; rel=\"first\""
    );
    assert_eq!(parse_next_since(Some(link), &policy).unwrap(), Some(371));
    for invalid in [
        "<https://api.github.com/other{?since}>; rel=\"first\"",
        "<https://api.github.com/repositories{?since}>; rel=\"next\"",
        "<https://api.github.com/repositories{?other}>; rel=\"first\"",
    ] {
        assert!(parse_next_since(Some(invalid), &policy).is_err());
    }
}

fn replace_response(exchange: &mut PublicIdCensusExchange, value: serde_json::Value) {
    exchange.response_body = value.to_string();
    exchange.response_sha256 = format!("{:x}", Sha256::digest(exchange.response_body.as_bytes()));
}

pub(crate) fn preflight_fixture() -> PublicIdCensusPreflight {
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
fn observes_each_rest_id_through_graphql_once() {
    let policy = committed_public_id_census_policy().unwrap();
    let exchanges = transcript();
    let observed = exchanges
        .iter()
        .filter_map(|exchange| match &exchange.request {
            PublicIdCensusRequest::Graphql { node_ids } => Some(node_ids.iter()),
            PublicIdCensusRequest::Rest { .. } => None,
        })
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(observed, ["node-2", "node-3", "node-4", "node-5"]);
    assert!(replay_fixture(&policy, &exchanges).is_ok());

    let mut repeated = exchanges;
    repeated.insert(3, graphql(&repositories()[..1]));
    assert!(replay_fixture(&policy, &repeated).is_err());
}

#[test]
fn rejects_null_or_mismatched_graphql_node() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[8].response_body).unwrap();
    response["data"]["nodes"][0] = serde_json::Value::Null;
    replace_response(&mut exchanges[8], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());

    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[8].response_body).unwrap();
    response["data"]["nodes"][0]["databaseId"] = serde_json::json!(99);
    replace_response(&mut exchanges[8], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn attributes_not_found_to_exact_rest_id_but_v1_still_fails_closed() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[8].response_body).unwrap();
    response["data"]["nodes"][0] = serde_json::Value::Null;
    response["errors"] = serde_json::json!([{
        "type": "NOT_FOUND",
        "path": ["nodes", 0],
        "locations": [{"line": 1, "column": 40}],
        "message": "Could not resolve to a node with the global id of 'node-4'."
    }]);
    let listed = [
        RestRepository {
            id: 4,
            node_id: "node-4".to_string(),
            full_name: "js/repo".to_string(),
        },
        RestRepository {
            id: 5,
            node_id: "node-5".to_string(),
            full_name: "after/repo".to_string(),
        },
    ];
    let observations = parse_graphql_observations(
        &response.to_string(),
        &["node-4".to_string(), "node-5".to_string()],
        &listed,
        "2026-09-27T00:00:00Z",
        true,
    )
    .unwrap();
    assert!(matches!(
        &observations[..],
        [GraphqlNodeObservation::NotFound { node_id, repository_id },
         GraphqlNodeObservation::Repository(_)]
            if node_id == "node-4" && *repository_id == 4
    ));
    replace_response(&mut exchanges[8], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn refuses_ambiguous_or_unrelated_graphql_null_errors() {
    let rows = repositories();
    let mut response: serde_json::Value =
        serde_json::from_str(&graphql(&rows[1..3]).response_body).unwrap();
    response["data"]["nodes"][0] = serde_json::Value::Null;
    let listed = [
        RestRepository {
            id: 3,
            node_id: "node-3".to_string(),
            full_name: "go/repo".to_string(),
        },
        RestRepository {
            id: 4,
            node_id: "node-4".to_string(),
            full_name: "js/repo".to_string(),
        },
    ];
    let ids = ["node-3".to_string(), "node-4".to_string()];
    let parses = |response: &serde_json::Value| {
        parse_graphql_observations(
            &response.to_string(),
            &ids,
            &listed,
            "2026-09-27T00:00:00Z",
            true,
        )
    };
    assert!(parses(&response).is_err());

    response["errors"] = serde_json::json!([{
        "type":"NOT_FOUND",
        "path":["nodes",0],
        "message":"Could not resolve to a node with the global id of 'node-3'."
    }]);
    assert!(matches!(
        &parses(&response).unwrap()[..],
        [
            GraphqlNodeObservation::NotFound {
                repository_id: 3,
                ..
            },
            GraphqlNodeObservation::Repository(_)
        ]
    ));
    assert!(
        parse_graphql_observations(
            &response.to_string(),
            &["node-4".to_string(), "node-3".to_string()],
            &listed,
            "2026-09-27T00:00:00Z",
            true,
        )
        .is_err()
    );
    let mut duplicate_node = listed.clone();
    duplicate_node[1].node_id = "node-3".to_string();
    assert!(
        parse_graphql_observations(
            &response.to_string(),
            &["node-3".to_string(), "node-3".to_string()],
            &duplicate_node,
            "2026-09-27T00:00:00Z",
            true,
        )
        .unwrap_err()
        .contains("repeats a REST identity")
    );
    let mut duplicate_repository = listed.clone();
    duplicate_repository[1].id = 3;
    assert!(
        parse_graphql_observations(
            &response.to_string(),
            &ids,
            &duplicate_repository,
            "2026-09-27T00:00:00Z",
            true,
        )
        .unwrap_err()
        .contains("repeats a REST identity")
    );
    response["errors"] = serde_json::json!([{
        "type":"NOT_FOUND",
        "path":["nodes",0],
        "message":"Could not resolve to a node with the global id of 'node-4'."
    }]);
    assert!(parses(&response).is_err());
    for errors in [
        serde_json::json!([{"type":"FORBIDDEN","path":["nodes",0]}]),
        serde_json::json!([{"type":"NOT_FOUND","path":["nodes",1]}]),
        serde_json::json!([{"type":"NOT_FOUND","path":["nodes",2]}]),
        serde_json::json!([{"type":"NOT_FOUND","path":["nodes",0,"id"]}]),
        serde_json::json!([{"type":"NOT_FOUND","path":["other",0]}]),
        serde_json::json!([{"type":"NOT_FOUND","path":["nodes",0]},
                           {"type":"NOT_FOUND","path":["nodes",0]}]),
    ] {
        response["errors"] = errors;
        assert!(parses(&response).is_err());
    }
    response["errors"] = serde_json::json!([{
        "type":"NOT_FOUND",
        "path":["nodes",0],
        "message":"Could not resolve to a node with the global id of 'node-3'."
    }]);
    response["data"]["nodes"][1] = serde_json::Value::Null;
    assert!(parses(&response).is_err());
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
    exchanges[7].response_sha256 = "0".repeat(64);
    assert!(replay_fixture(&policy, &exchanges).is_err());
    let mut exchanges = transcript();
    exchanges[7].request = PublicIdCensusRequest::Rest { since: 2 };
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_creation_order_inversion_and_private_node() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[8].response_body).unwrap();
    response["data"]["nodes"][0]["createdAt"] = serde_json::json!("2026-08-07T23:00:00Z");
    replace_response(&mut exchanges[8], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());

    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[8].response_body).unwrap();
    response["data"]["nodes"][0]["isPrivate"] = serde_json::Value::Bool(true);
    replace_response(&mut exchanges[8], response);
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
    let crawl = &mut exchanges[7];
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
    exchanges[7].failed_attempts[0].response_status = Some(404);
    assert!(replay_fixture(&policy, &exchanges).is_err());
    exchanges[7].failed_attempts[0].response_status = Some(429);
    exchanges[7].failed_attempts = vec![exchanges[7].failed_attempts[0].clone(); 12];
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
    replace_response(&mut exchanges[7], short);
    exchanges[7].response_link = Some(
        "<https://api.github.com/repositories?per_page=100&since=3>; rel=\"next\"".to_string(),
    );
    assert!(replay_fixture(&policy, &exchanges).is_err());
    let mut exchanges = transcript();
    exchanges[7].response_link = Some("not a Link header".to_string());
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_impossible_utc_creation_time() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[8].response_body).unwrap();
    response["data"]["nodes"][0]["createdAt"] = serde_json::json!("2026-08-14T99:99:99Z");
    replace_response(&mut exchanges[8], response);
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_crawl_that_omits_the_probed_first_in_window_repository() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let rows = repositories();
    let omitted = [rows[0].clone(), rows[2].clone(), rows[3].clone()];
    exchanges[7] = rest(1, &omitted);
    exchanges[8] = graphql(&omitted[1..]);
    assert!(replay_fixture(&policy, &exchanges).is_err());
}

#[test]
fn rejects_unclassified_transport_retry() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let crawl = &mut exchanges[7];
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
            serde_json::from_str(&exchanges[8].response_body).unwrap();
        response["data"]["nodes"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        replace_response(&mut exchanges[8], response);
        assert!(replay_fixture(&policy, &exchanges).is_err(), "{field}");
    }
}

#[test]
fn rejects_creation_after_graphql_receipt() {
    let policy = committed_public_id_census_policy().unwrap();
    let mut exchanges = transcript();
    let mut response: serde_json::Value =
        serde_json::from_str(&exchanges[8].response_body).unwrap();
    response["data"]["nodes"][1]["createdAt"] = serde_json::json!("2026-09-28T00:00:00Z");
    replace_response(&mut exchanges[8], response);
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
        rest(2, &rows),
        graphql(&rows[1..2]),
        rest(1, &rows),
        rest(2, &rows),
        rest(1, &rows),
        graphql(&rows[2..100]),
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
        serde_json::from_str(&exchanges[8].response_body).unwrap();
    response["data"]["nodes"][1]["createdAt"] = serde_json::json!("2026-09-28T00:00:00Z");
    replace_response(&mut exchanges[8], response);
    exchanges[8].received_at_utc = "2026-09-29T00:00:00Z".to_string();
    assert!(replay_fixture(&policy, &exchanges).is_err());
}
