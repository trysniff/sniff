use super::*;

#[test]
fn post_august_seven_historical_v3_frame_policies_are_fixed_and_valid() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let policies_dir = root.join("sniffbench/historical-v3-source-frames");
    if !policies_dir.exists() && !root.join(".git").exists() {
        return; // The published crate intentionally excludes repository-only benchmark policies.
    }
    let policies = [
        ("Go", "go-policy.json"),
        ("JavaScript", "javascript-policy.json"),
        ("Kotlin", "kotlin-policy.json"),
        ("Python", "python-policy.json"),
        ("Rust", "rust-policy.json"),
        ("TypeScript", "typescript-policy.json"),
    ];
    let mut frame_ids = std::collections::HashSet::new();
    for (language, file) in policies {
        let bytes = fs::read_to_string(policies_dir.join(file)).unwrap();
        let policy: SourceFrameCollectionPolicy = serde_json::from_str(&bytes).unwrap();
        validate_policy(&policy).unwrap();
        assert_eq!(
            policy.schema_version,
            SOURCE_FRAME_COLLECTION_FULL_PERIOD_SCHEMA_VERSION
        );
        assert_eq!(policy.language, language);
        assert!(policy.created_day_utc.as_str() > "2026-08-07");
        assert_eq!(policy.derivation_period_start_utc, "2026-08-08");
        assert_eq!(policy.derivation_period_days, 7);
        assert!(frame_ids.insert(policy.frame_id.clone()));
        let seed = format!(
            "{:x}",
            Sha256::digest(format!(
                "sniff-historical-v3-post-aug-2026-09-26-{language}"
            ))
        );
        assert_eq!(policy.derivation_seed, seed);
        let days = frame_days(&policy).unwrap();
        assert_eq!(days.len(), 7);
        assert_eq!(days[0], policy.created_day_utc);
        assert_eq!(days.into_iter().collect::<HashSet<_>>().len(), 7);
    }
}

#[test]
fn five_minute_amendments_preserve_the_original_cohorts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let policies_dir = root.join("sniffbench/historical-v3-source-frames");
    if !policies_dir.exists() && !root.join(".git").exists() {
        return;
    }
    for language in ["javascript", "python", "typescript"] {
        let original: SourceFrameCollectionPolicy = serde_json::from_slice(
            &fs::read(policies_dir.join(format!("{language}-policy.json"))).unwrap(),
        )
        .unwrap();
        let amended: SourceFrameCollectionPolicy = serde_json::from_slice(
            &fs::read(policies_dir.join(format!("{language}-five-minute-policy.json"))).unwrap(),
        )
        .unwrap();
        validate_policy(&amended).unwrap();
        assert_eq!(
            amended.schema_version,
            SOURCE_FRAME_COLLECTION_FIVE_MINUTE_SCHEMA_VERSION
        );
        assert_eq!(
            amended.amendment_of_policy_sha256,
            Some(json_sha256(&original).unwrap())
        );
        assert_eq!(amended.predecessor_policy.as_deref(), Some(&original));
        assert_eq!(amended.language, original.language);
        assert_eq!(amended.created_day_utc, original.created_day_utc);
        assert_eq!(amended.derivation_seed, original.derivation_seed);
        assert_eq!(
            amended.derivation_period_start_utc,
            original.derivation_period_start_utc
        );
        assert_eq!(
            amended.derivation_period_days,
            original.derivation_period_days
        );
        assert_eq!(amended.derivation_rule, original.derivation_rule);
        assert_eq!(amended.include_forks, original.include_forks);
        assert_eq!(amended.include_archived, original.include_archived);
        assert_eq!(amended.include_mirrors, original.include_mirrors);
        assert_eq!(amended.include_templates, original.include_templates);
        assert_eq!(amended.ordering, original.ordering);
        let partitions = frame_partitions(&amended).unwrap();
        assert_eq!(partitions.len(), 2_016);
        assert_eq!(partitions[0].bounds(&amended).0, "2026-08-12T00:00:00Z");
        assert_eq!(partitions[0].bounds(&amended).1, "2026-08-12T00:04:59Z");
        assert_eq!(
            partitions.last().unwrap().bounds(&amended).1,
            "2026-08-11T23:59:59Z"
        );
    }
}

#[test]
fn five_minute_partition_rejects_relocated_repository_and_missing_window() {
    let mut policy = policy();
    policy.schema_version = SOURCE_FRAME_COLLECTION_FIVE_MINUTE_SCHEMA_VERSION;
    policy.partition = "utc_five_minute".to_string();
    policy.derivation_period_start_utc = "2026-08-08".to_string();
    policy.derivation_period_days = 7;
    policy.created_day_utc = "2026-08-08".to_string();
    policy.derivation_seed = "0".repeat(64);
    policy.derivation_rule = "rotated_full_period_days".to_string();
    let mut predecessor = policy.clone();
    predecessor.schema_version = SOURCE_FRAME_COLLECTION_FULL_PERIOD_SCHEMA_VERSION;
    predecessor.partition = "utc_hour".to_string();
    policy.amendment_of_policy_sha256 = Some(json_sha256(&predecessor).unwrap());
    policy.predecessor_policy = Some(Box::new(predecessor));
    validate_policy(&policy).unwrap();
    let mut changed_cohort = policy.clone();
    changed_cohort.include_forks = true;
    assert!(
        validate_policy(&changed_cohort)
            .unwrap_err()
            .contains("changed its predecessor cohort")
    );
    let mut changed_predecessor = policy.clone();
    changed_predecessor
        .predecessor_policy
        .as_mut()
        .unwrap()
        .include_forks = true;
    assert!(
        validate_policy(&changed_predecessor)
            .unwrap_err()
            .contains("predecessor commitment changed")
    );
    let mut missing_predecessor = policy.clone();
    missing_predecessor.predecessor_policy = None;
    assert!(validate_policy(&missing_predecessor).is_err());
    let partitions = frame_partitions(&policy).unwrap();
    assert_eq!(partitions.len(), 2_016);
    assert_eq!(partitions[0].bounds(&policy).1, "2026-08-08T00:04:59Z");
    assert_eq!(partitions[1].bounds(&policy).0, "2026-08-08T00:05:00Z");

    let (start, end) = partitions[0].bounds(&policy);
    let repository = GithubSearchRepository {
        id: 42,
        full_name: "Example/FortyTwo".to_string(),
        created_at: "2026-08-08T00:05:00Z".to_string(),
        fork: false,
        archived: false,
        mirror_url: None,
        is_template: false,
    };
    assert!(validate_repository(&policy, &start, &end, &repository).is_err());

    let output = tempfile::tempdir().unwrap();
    let state = output.path().join("raw");
    fs::create_dir_all(&state).unwrap();
    let pages = partitions
        .iter()
        .take(2_015)
        .map(|partition| {
            let query = partition_query(&policy, partition);
            let page = raw(
                &query,
                1,
                r#"{"total_count":0,"incomplete_results":false,"items":[]}"#,
            );
            let path = state.join(format!(
                "{}-page-001.json",
                partition.checkpoint_key(&policy)
            ));
            fs::write(&path, serde_json::to_vec_pretty(&page).unwrap()).unwrap();
            (path, page)
        })
        .collect();
    assert!(
        derive_source_frame(&policy, output.path(), pages)
            .unwrap_err()
            .contains("missing UTC five-minute partition")
    );
}

#[test]
fn full_period_frame_requires_every_hour_and_replays_raw_pages() {
    let mut policy = policy();
    policy.schema_version = SOURCE_FRAME_COLLECTION_FULL_PERIOD_SCHEMA_VERSION;
    policy.derivation_period_start_utc = "2026-08-08".to_string();
    policy.derivation_period_days = 7;
    policy.created_day_utc = "2026-08-08".to_string();
    policy.derivation_seed = "0".repeat(64);
    policy.derivation_rule = "rotated_full_period_days".to_string();
    let output = tempfile::tempdir().unwrap();
    let state = output.path().join("raw");
    fs::create_dir_all(&state).unwrap();
    let days = frame_days(&policy).unwrap();
    let final_day = days.last().unwrap();
    let mut pages = Vec::new();
    for day in &days {
        for hour in 0..24 {
            let query = hourly_query_for_day(&policy, day, hour);
            let response = if day == final_day && hour == 23 {
                serde_json::json!({
                    "total_count": 1,
                    "incomplete_results": false,
                    "items": [{
                        "id": 42,
                        "full_name": "Example/FortyTwo",
                        "created_at": format!("{day}T23:12:00Z"),
                        "fork": false,
                        "archived": false,
                        "mirror_url": null,
                        "is_template": false
                    }]
                })
                .to_string()
            } else {
                r#"{"total_count":0,"incomplete_results":false,"items":[]}"#.to_string()
            };
            let page = raw(&query, 1, &response);
            let path = state.join(format!("day-{day}-hour-{hour:02}-page-001.json"));
            fs::write(&path, serde_json::to_vec_pretty(&page).unwrap()).unwrap();
            pages.push((path, page));
        }
    }
    assert_eq!(pages.len(), 168);
    assert!(
        derive_source_frame(&policy, output.path(), pages[..167].to_vec())
            .unwrap_err()
            .contains("missing UTC hour partition")
    );
    let manifest = build_source_frame(
        policy,
        &state,
        &output.path().join("frame.csv"),
        &output.path().join("manifest.json"),
        pages,
    )
    .unwrap();
    assert_eq!(manifest.pages.len(), 168);
    assert_eq!(manifest.repository_count, 1);
    let frame = fs::read(output.path().join("frame.csv")).unwrap();
    validate_source_frame_manifest(&manifest, output.path(), &frame).unwrap();
}

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
        amendment_of_policy_sha256: None,
        predecessor_policy: None,
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
    let response = r#"{"total_count":2,"incomplete_results":false,"items":[{"id":9,"full_name":"Example/Nine","created_at":"2026-05-10T00:01:00Z","language":null,"fork":false,"archived":false,"mirror_url":null,"is_template":false},{"id":2,"full_name":"Example/Two","created_at":"2026-05-10T00:02:00Z","language":"Kotlin","fork":false,"archived":false,"mirror_url":null,"is_template":false}]}"#;
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
        assert!(validate_checkpointable_page(&page).is_err());
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

#[test]
fn source_frame_policy_supports_every_product_language_without_accepting_others() {
    for language in ["Go", "JavaScript", "Kotlin", "Python", "Rust", "TypeScript"] {
        let mut candidate = policy();
        candidate.language = language.to_string();
        validate_policy(&candidate).unwrap();
    }

    let mut unsupported = policy();
    unsupported.language = "Java".to_string();
    assert!(
        validate_policy(&unsupported)
            .unwrap_err()
            .contains("unsupported contract")
    );
}
