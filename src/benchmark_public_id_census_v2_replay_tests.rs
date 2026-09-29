use super::*;
use crate::benchmark::committed_public_id_census_v2_policy;

#[derive(Clone)]
struct FixtureRepository {
    id: u64,
    name: &'static str,
    created_at: Option<&'static str>,
    language: &'static str,
}

fn rows() -> Vec<FixtureRepository> {
    vec![
        FixtureRepository {
            id: 2,
            name: "before/repo",
            created_at: Some("2026-08-07T23:59:59Z"),
            language: "Go",
        },
        FixtureRepository {
            id: 3,
            name: "go/repo",
            created_at: Some("2026-08-08T00:00:00Z"),
            language: "Go",
        },
        FixtureRepository {
            id: 4,
            name: "missing/repo",
            created_at: None,
            language: "Python",
        },
        FixtureRepository {
            id: 5,
            name: "rust/repo",
            created_at: Some("2026-08-14T23:59:59Z"),
            language: "Rust",
        },
        FixtureRepository {
            id: 6,
            name: "after/repo",
            created_at: Some("2026-08-15T00:00:00Z"),
            language: "Rust",
        },
    ]
}

fn preflight() -> PublicIdCensusPreflight {
    let fetched_policy = super::super::PUBLIC_POLICY.replace("\r\n", "\n");
    PublicIdCensusPreflight {
        public_policy_url: format!(
            "https://raw.githubusercontent.com/trysniff/sniff/{PUBLIC_ID_CENSUS_V2_POLICY_COMMIT_SHA}/sniffbench/historical-v3-id-census-v2/policy.json"
        ),
        fetched_policy_sha256: format!("{:x}", Sha256::digest(fetched_policy.as_bytes())),
        fetched_policy,
        fetched_at_utc: "2026-09-27T00:00:00Z".to_string(),
        response_status: 200,
    }
}

fn synthetic_exchange(
    request: PublicIdCensusRequest,
    url: String,
    body: Option<String>,
    rows: &[FixtureRepository],
) -> PublicIdCensusExchange {
    let (response_body, response_link) =
        match &request {
            PublicIdCensusRequest::Rest { since } => {
                let visible = rows
                    .iter()
                    .filter(|row| row.id > *since)
                    .take(100)
                    .collect::<Vec<_>>();
                let response = visible
                    .iter()
                    .map(|row| {
                        serde_json::json!({
                            "id": row.id,
                            "node_id": format!("node-{}", row.id),
                            "full_name": row.name,
                        })
                    })
                    .collect::<Vec<_>>();
                let link = (rows.iter().filter(|row| row.id > *since).count() > visible.len())
                .then(|| format!(
                    "<https://api.github.com/repositories?per_page=100&since={}>; rel=\"next\"",
                    visible.last().unwrap().id
                ));
                (serde_json::to_string(&response).unwrap(), link)
            }
            PublicIdCensusRequest::Graphql { node_ids } => {
                let mut errors = Vec::new();
                let nodes = node_ids
                    .iter()
                    .enumerate()
                    .map(|(index, node_id)| {
                        let row = rows
                            .iter()
                            .find(|row| node_id == &format!("node-{}", row.id))
                            .unwrap();
                        if row.created_at.is_none() {
                            errors.push(serde_json::json!({
                                "type": "NOT_FOUND",
                                "path": ["nodes", index],
                                "message": format!(
                                    "Could not resolve to a node with the global id of '{node_id}'."
                                ),
                            }));
                            serde_json::Value::Null
                        } else {
                            serde_json::json!({
                                "__typename": "Repository",
                                "id": node_id,
                                "databaseId": row.id,
                                "nameWithOwner": row.name,
                                "createdAt": row.created_at,
                                "primaryLanguage": {"name": row.language},
                                "isArchived": false,
                                "isFork": false,
                                "isTemplate": false,
                                "mirrorUrl": null,
                                "isPrivate": false,
                            })
                        }
                    })
                    .collect::<Vec<_>>();
                (
                    serde_json::json!({"data": {"nodes": nodes}, "errors": errors}).to_string(),
                    None,
                )
            }
        };
    PublicIdCensusExchange {
        request,
        request_url: url,
        request_body: body,
        request_api_version: "2022-11-28".to_string(),
        response_status: 200,
        response_link,
        response_date: None,
        received_at_utc: "2026-09-28T00:00:00Z".to_string(),
        response_sha256: format!("{:x}", Sha256::digest(response_body.as_bytes())),
        response_body,
        failed_attempts: Vec::new(),
    }
}

pub(crate) fn fixture_transcript() -> (
    PublicIdCensusV2Policy,
    PublicIdCensusPreflight,
    Vec<PublicIdCensusExchange>,
    PublicIdCensusV2Replay,
) {
    fixture_transcript_with_rows(rows())
}

pub(crate) fn six_language_fixture_transcript() -> (
    PublicIdCensusV2Policy,
    PublicIdCensusPreflight,
    Vec<PublicIdCensusExchange>,
    PublicIdCensusV2Replay,
) {
    let mut rows = vec![FixtureRepository {
        id: 2,
        name: "before/repo",
        created_at: Some("2026-08-07T23:59:59Z"),
        language: "Go",
    }];
    for (id, name, language) in [
        (3, "go/repo", "Go"),
        (4, "javascript/repo", "JavaScript"),
        (5, "kotlin/repo", "Kotlin"),
        (6, "python/repo", "Python"),
        (7, "rust/repo", "Rust"),
        (8, "typescript/repo", "TypeScript"),
    ] {
        rows.push(FixtureRepository {
            id,
            name,
            created_at: Some("2026-08-08T00:00:00Z"),
            language,
        });
    }
    rows.push(FixtureRepository {
        id: 9,
        name: "missing/repo",
        created_at: None,
        language: "Go",
    });
    rows.push(FixtureRepository {
        id: 10,
        name: "after/repo",
        created_at: Some("2026-08-15T00:00:00Z"),
        language: "Go",
    });
    fixture_transcript_with_rows(rows)
}

pub(crate) fn capacity_six_language_fixture_transcript() -> (
    PublicIdCensusV2Policy,
    PublicIdCensusPreflight,
    Vec<PublicIdCensusExchange>,
    PublicIdCensusV2Replay,
) {
    let mut rows = vec![FixtureRepository {
        id: 2,
        name: "before/repo",
        created_at: Some("2026-08-07T23:59:59Z"),
        language: "Go",
    }];
    let mut id = 3;
    for (language, slug) in [
        ("Go", "go"),
        ("JavaScript", "javascript"),
        ("Kotlin", "kotlin"),
        ("Python", "python"),
        ("Rust", "rust"),
        ("TypeScript", "typescript"),
    ] {
        for index in 0..20 {
            let name: &'static str = Box::leak(format!("{slug}/repo-{index:02}").into_boxed_str());
            rows.push(FixtureRepository {
                id,
                name,
                created_at: Some("2026-08-08T00:00:00Z"),
                language,
            });
            id += 1;
        }
    }
    rows.push(FixtureRepository {
        id,
        name: "missing/repo",
        created_at: None,
        language: "Go",
    });
    rows.push(FixtureRepository {
        id: id + 1,
        name: "after/repo",
        created_at: Some("2026-08-15T00:00:00Z"),
        language: "Go",
    });
    fixture_transcript_with_rows(rows)
}

fn fixture_transcript_with_rows(
    rows: Vec<FixtureRepository>,
) -> (
    PublicIdCensusV2Policy,
    PublicIdCensusPreflight,
    Vec<PublicIdCensusExchange>,
    PublicIdCensusV2Replay,
) {
    let policy = committed_public_id_census_v2_policy().unwrap();
    let preflight = preflight();
    let mut exchanges = Vec::new();
    let replay =
        replay_public_id_census_v2_with_source(&policy, &preflight, |request, url, body| {
            let exchange = synthetic_exchange(request, url, body, &rows);
            exchanges.push(exchange.clone());
            Ok(exchange)
        })
        .unwrap();
    (policy, preflight, exchanges, replay)
}

#[test]
fn null_on_retained_page_is_audited_and_never_framed() {
    let policy = committed_public_id_census_v2_policy().unwrap();
    let rows = rows();
    let mut exchanges = Vec::new();
    let result =
        replay_public_id_census_v2_with_source(&policy, &preflight(), |request, url, body| {
            let exchange = synthetic_exchange(request, url, body, &rows);
            exchanges.push(exchange.clone());
            Ok(exchange)
        })
        .unwrap();
    assert_eq!(result.listed_repository_count, 5);
    assert_eq!(result.resolved_in_window_count, 2);
    assert_eq!(result.crawled_null_count, 1);
    assert_eq!(result.probe_only_null_count, 0);
    assert_eq!(result.null_ledger.len(), 1);
    assert_eq!(result.null_ledger[0].repository_id, 4);
    assert!(result.null_ledger[0].crawled);
    assert_eq!(result.null_ledger[0].batch_index, 2);
    assert_eq!(result.null_ledger[0].graphql_exchange_sequence, 1);
    assert!(
        String::from_utf8_lossy(&result.frames["Go"])
            .contains("github.com/go/repo,github_repository_id=3")
    );
    assert!(
        String::from_utf8_lossy(&result.frames["Rust"])
            .contains("github.com/rust/repo,github_repository_id=5")
    );
    assert_eq!(result.frames["Python"], b"repo,metadata\n");
    assert_eq!(
        exchanges
            .iter()
            .filter(|exchange| matches!(exchange.request, PublicIdCensusRequest::Graphql { .. }))
            .count(),
        1
    );
    assert_eq!(
        replay_public_id_census_v2(&policy, &preflight(), &exchanges).unwrap(),
        result
    );
}

#[test]
fn rejects_ambiguous_not_found_and_trailing_exchange() {
    let policy = committed_public_id_census_v2_policy().unwrap();
    let rows = rows();
    let mut exchanges = Vec::new();
    replay_public_id_census_v2_with_source(&policy, &preflight(), |request, url, body| {
        let exchange = synthetic_exchange(request, url, body, &rows);
        exchanges.push(exchange.clone());
        Ok(exchange)
    })
    .unwrap();
    let mut changed = exchanges.clone();
    let mut response: serde_json::Value = serde_json::from_str(&changed[1].response_body).unwrap();
    response["errors"][0]["message"] = serde_json::json!("some other repository");
    changed[1].response_body = response.to_string();
    changed[1].response_sha256 =
        format!("{:x}", Sha256::digest(changed[1].response_body.as_bytes()));
    assert!(replay_public_id_census_v2(&policy, &preflight(), &changed).is_err());
    let mut trailing = exchanges.clone();
    trailing.push(exchanges[0].clone());
    assert!(replay_public_id_census_v2(&policy, &preflight(), &trailing).is_err());
}

#[test]
fn cached_upper_on_probe_page_requires_matching_node_identity() {
    let policy = committed_public_id_census_v2_policy().unwrap();
    let rows = rows();
    let mut exchanges = Vec::new();
    replay_public_id_census_v2_with_source(&policy, &preflight(), |request, url, body| {
        let exchange = synthetic_exchange(request, url, body, &rows);
        exchanges.push(exchange.clone());
        Ok(exchange)
    })
    .unwrap();
    let mut page: serde_json::Value = serde_json::from_str(&exchanges[2].response_body).unwrap();
    page[4]["node_id"] = serde_json::json!("reused-id");
    exchanges[2].response_body = page.to_string();
    exchanges[2].response_sha256 = format!(
        "{:x}",
        Sha256::digest(exchanges[2].response_body.as_bytes())
    );
    assert!(replay_public_id_census_v2(&policy, &preflight(), &exchanges).is_err());
}

#[test]
fn missing_next_on_pre_window_boundary_page_cannot_be_bypassed() {
    let policy = committed_public_id_census_v2_policy().unwrap();
    let mut rows = (2..=101)
        .map(|id| FixtureRepository {
            id,
            name: "before/repo",
            created_at: Some("2026-08-07T23:59:59Z"),
            language: "Go",
        })
        .collect::<Vec<_>>();
    rows.extend((129..=300).map(|id| FixtureRepository {
        id,
        name: "after/repo",
        created_at: Some("2026-08-15T00:00:00Z"),
        language: "Rust",
    }));
    let mut exchanges = Vec::new();
    replay_public_id_census_v2_with_source(&policy, &preflight(), |request, url, body| {
        let exchange = synthetic_exchange(request, url, body, &rows);
        exchanges.push(exchange.clone());
        Ok(exchange)
    })
    .unwrap();
    let mut probe_missing = exchanges.clone();
    let probe = probe_missing
        .iter_mut()
        .find(|exchange| exchange.request == PublicIdCensusRequest::Rest { since: 64 })
        .unwrap();
    assert!(probe.response_link.is_some());
    probe.response_link = None;
    assert!(
        replay_public_id_census_v2(&policy, &preflight(), &probe_missing)
            .unwrap_err()
            .contains("boundary probe lacks its next cursor")
    );
    assert!(exchanges[0].response_link.is_some());
    exchanges[0].response_link = None;
    assert!(
        replay_public_id_census_v2(&policy, &preflight(), &exchanges)
            .unwrap_err()
            .contains("initial page lacks its next cursor")
    );
}

#[test]
fn initial_all_null_page_is_probe_evidence_not_cohort_exclusion() {
    let policy = committed_public_id_census_v2_policy().unwrap();
    let mut rows = (2..=101)
        .map(|id| FixtureRepository {
            id,
            name: "missing/repo",
            created_at: None,
            language: "Go",
        })
        .collect::<Vec<_>>();
    rows.push(FixtureRepository {
        id: 102,
        name: "before/repo",
        created_at: Some("2026-08-07T23:59:59Z"),
        language: "Go",
    });
    rows.extend((129..=300).map(|id| FixtureRepository {
        id,
        name: "after/repo",
        created_at: Some("2026-08-15T00:00:00Z"),
        language: "Rust",
    }));
    let mut exchanges = Vec::new();
    let result =
        replay_public_id_census_v2_with_source(&policy, &preflight(), |request, url, body| {
            let exchange = synthetic_exchange(request, url, body, &rows);
            exchanges.push(exchange.clone());
            Ok(exchange)
        })
        .unwrap();
    assert_eq!(result.probe_only_null_count, 100);
    assert_eq!(result.crawled_null_count, 0);
    assert!(result.null_ledger.iter().all(|record| !record.crawled));
    assert_eq!(
        replay_public_id_census_v2(&policy, &preflight(), &exchanges).unwrap(),
        result
    );
}

#[test]
fn null_binary_probe_keeps_lower_witness_and_reuses_its_observation() {
    let policy = committed_public_id_census_v2_policy().unwrap();
    let mut rows = (2..=101)
        .map(|id| FixtureRepository {
            id,
            name: "before/repo",
            created_at: Some("2026-08-07T23:59:59Z"),
            language: "Go",
        })
        .collect::<Vec<_>>();
    rows.push(FixtureRepository {
        id: 129,
        name: "missing/repo",
        created_at: None,
        language: "Python",
    });
    rows.extend((130..=500).map(|id| FixtureRepository {
        id,
        name: "after/repo",
        created_at: Some("2026-08-15T00:00:00Z"),
        language: "Rust",
    }));
    let mut exchanges = Vec::new();
    let result =
        replay_public_id_census_v2_with_source(&policy, &preflight(), |request, url, body| {
            let exchange = synthetic_exchange(request, url, body, &rows);
            exchanges.push(exchange.clone());
            Ok(exchange)
        })
        .unwrap();
    assert_eq!(result.crawled_null_count, 1);
    assert_eq!(result.probe_only_null_count, 0);
    assert_eq!(result.null_ledger[0].repository_id, 129);
    assert_eq!(
        exchanges
            .iter()
            .filter(|exchange| match &exchange.request {
                PublicIdCensusRequest::Graphql { node_ids } =>
                    node_ids.iter().any(|id| id == "node-129"),
                _ => false,
            })
            .count(),
        1
    );
    assert_eq!(
        replay_public_id_census_v2(&policy, &preflight(), &exchanges).unwrap(),
        result
    );
}

#[test]
fn reused_node_id_is_rejected_before_graphql_enrichment() {
    let policy = committed_public_id_census_v2_policy().unwrap();
    let rows = rows();
    let mut graphql_calls = 0;
    let result =
        replay_public_id_census_v2_with_source(&policy, &preflight(), |request, url, body| {
            let mut exchange = synthetic_exchange(request, url, body, &rows);
            if matches!(&exchange.request, PublicIdCensusRequest::Rest { .. }) {
                let mut page: serde_json::Value =
                    serde_json::from_str(&exchange.response_body).unwrap();
                let aliased = page
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|repository| repository["id"].as_u64() == Some(4))
                    .unwrap();
                aliased["node_id"] = serde_json::Value::String("node-3".to_string());
                exchange.response_body = serde_json::to_string(&page).unwrap();
                exchange.response_sha256 =
                    format!("{:x}", Sha256::digest(exchange.response_body.as_bytes()));
            } else {
                graphql_calls += 1;
            }
            Ok(exchange)
        });
    assert!(result.unwrap_err().contains("node ID aliases two REST IDs"));
    assert_eq!(graphql_calls, 0);
}
