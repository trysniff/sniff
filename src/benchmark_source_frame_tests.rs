use super::*;

fn policy() -> SourceFrameCollectionPolicy {
    SourceFrameCollectionPolicy {
        schema_version: SOURCE_FRAME_COLLECTION_POLICY_SCHEMA_VERSION,
        frame_id: "blind-oss-v1-kotlin-frame-1".to_string(),
        source: "https://api.github.com/search/repositories".to_string(),
        api_version: "2022-11-28".to_string(),
        language: "Kotlin".to_string(),
        created_day_utc: "2026-05-10".to_string(),
        derivation_seed: "10afa5d22d090d7ac02e4621d89de24d0a8fd926".to_string(),
        derivation_period_start_utc: "2026-04-01".to_string(),
        derivation_period_days: 91,
        derivation_rule: "first_8_hex_u32_mod_period_days".to_string(),
        partition: "utc_hour".to_string(),
        include_forks: false,
        include_archived: false,
        include_mirrors: false,
        include_templates: false,
        ordering: "github_repository_id_ascending".to_string(),
        attestation: "The date and query contract were fixed before collection.".to_string(),
    }
}

fn raw(query: &str, page: usize, response: &str) -> SourceFrameRawPage {
    SourceFrameRawPage {
        query: query.to_string(),
        page,
        per_page: GITHUB_PAGE_SIZE,
        response_sha256: sha256(response.as_bytes()),
        response: response.to_string(),
    }
}

fn frozen_day(
    state: &Path,
    policy: &SourceFrameCollectionPolicy,
    first_response: &str,
) -> Vec<(PathBuf, SourceFrameRawPage)> {
    fs::create_dir_all(state).unwrap();
    (0..24)
        .map(|hour| {
            let query = hourly_query(policy, hour);
            let response = if hour == 0 {
                first_response
            } else {
                r#"{"total_count":0,"incomplete_results":false,"items":[]}"#
            };
            let page = raw(&query, 1, response);
            let path = state.join(format!("hour-{hour:02}-page-001.json"));
            fs::write(&path, serde_json::to_vec_pretty(&page).unwrap()).unwrap();
            (path, page)
        })
        .collect()
}

#[test]
fn source_frame_is_ordered_by_repository_id_and_commits_raw_pages() {
    let output = tempfile::tempdir().unwrap();
    let state = output.path().join("raw");
    let query = hourly_query(&policy(), 0);
    let response = r#"{"total_count":2,"incomplete_results":false,"items":[{"id":9,"full_name":"Example/Nine","created_at":"2026-05-10T00:01:00Z","language":"Kotlin","fork":false,"archived":false,"mirror_url":null,"is_template":false},{"id":2,"full_name":"Example/Two","created_at":"2026-05-10T00:02:00Z","language":"Kotlin","fork":false,"archived":false,"mirror_url":null,"is_template":false}]}"#;
    assert_eq!(query, hourly_query(&policy(), 0));
    let pages = frozen_day(&state, &policy(), response);

    let manifest = build_source_frame(
        policy(),
        &state,
        &output.path().join("frame.csv"),
        &output.path().join("manifest.json"),
        pages,
    )
    .unwrap();

    let frame = fs::read_to_string(output.path().join("frame.csv")).unwrap();
    assert!(frame.find("example/two").unwrap() < frame.find("example/nine").unwrap());
    assert_eq!(manifest.repository_count, 2);
    assert_eq!(manifest.pages.len(), 24);
    assert_eq!(
        manifest.manifest_sha256,
        manifest.computed_manifest_sha256().unwrap()
    );
    validate_source_frame_manifest(&manifest, output.path(), frame.as_bytes()).unwrap();

    let first_page = output.path().join(&manifest.pages[0].artifact_path);
    fs::write(&first_page, b"tampered").unwrap();
    assert!(
        validate_source_frame_manifest(&manifest, output.path(), frame.as_bytes())
            .unwrap_err()
            .contains("commitment changed")
    );
}

#[test]
fn source_frame_rejects_incomplete_or_over_limit_partitions() {
    let output = tempfile::tempdir().unwrap();
    let state = output.path().join("raw");
    fs::create_dir_all(&state).unwrap();
    let query = hourly_query(&policy(), 0);
    for response in [
        r#"{"total_count":1,"incomplete_results":true,"items":[]}"#,
        r#"{"total_count":1001,"incomplete_results":false,"items":[]}"#,
    ] {
        let page = raw(&query, 1, response);
        let page_path = state.join(format!("{}.json", sha256(response.as_bytes())));
        fs::write(&page_path, serde_json::to_vec_pretty(&page).unwrap()).unwrap();
        let error = build_source_frame(
            policy(),
            &state,
            &output
                .path()
                .join(format!("{}.csv", sha256(response.as_bytes()))),
            &output
                .path()
                .join(format!("{}.manifest", sha256(response.as_bytes()))),
            vec![(page_path, page)],
        )
        .unwrap_err();
        assert!(error.contains("incomplete") || error.contains("1,000"));
    }
}

#[test]
fn source_frame_rejects_changed_checkpoint_payloads() {
    let query = hourly_query(&policy(), 0);
    let mut page = raw(
        &query,
        1,
        r#"{"total_count":0,"incomplete_results":false,"items":[]}"#,
    );
    page.response.push(' ');
    assert!(
        validate_raw_page(&page)
            .unwrap_err()
            .contains("commitment changed")
    );
}

#[test]
fn source_frame_policy_recomputes_the_seeded_calendar_day() {
    validate_policy(&policy()).unwrap();
    let mut changed_day = policy();
    changed_day.created_day_utc = "2026-05-11".to_string();
    assert!(
        validate_policy(&changed_day)
            .unwrap_err()
            .contains("policy-derived day")
    );

    let mut invalid_start = policy();
    invalid_start.derivation_period_start_utc = "2026-02-30".to_string();
    assert!(validate_policy(&invalid_start).is_err());
}
