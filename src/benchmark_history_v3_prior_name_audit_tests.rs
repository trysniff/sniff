use super::*;
use crate::benchmark::release::{
    HistoricalV3PriorArtifactBinding, prepare_historical_v3_prior_identity_seal,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn seal() -> HistoricalV3PriorBenchmarkIdentitySeal {
    prepare_historical_v3_prior_identity_seal(vec![HistoricalV3PriorArtifactBinding {
        artifact_id: "frozen-prior".to_string(),
        artifact_sha256: "a".repeat(64),
        repositories: vec![
            "legacy/one".to_string(),
            "legacy/two".to_string(),
            "legacy/three".to_string(),
        ],
    }])
    .unwrap()
}

fn write_checkpoint(directory: &Path, name: &str, checkpoint: Value) {
    let path = directory.join(format!("{}.json", sha256(name.as_bytes())));
    fs::write(path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
}

fn response_checkpoint(
    seal: &HistoricalV3PriorBenchmarkIdentitySeal,
    name: &str,
    version: u32,
    response: Value,
) -> Value {
    let raw = serde_json::to_vec(&response).unwrap();
    let status = if response["message"] == "Not Found" {
        404
    } else {
        200
    };
    let mut checkpoint = json!({
        "schema_version": version,
        "prior_seal_sha256": seal.seal_sha256,
        "prior_name": name,
        "request_url": format!("https://api.github.com/repos/{name}"),
        "status": status,
        "repository_id": response["id"],
        "current_name": response["full_name"],
        "created_at": if status == 200 { Value::String(response["created_at"].as_str().unwrap().to_string()) } else { Value::Null },
        "response_sha256": sha256(&raw),
        "response_base64": base64::engine::general_purpose::STANDARD.encode(raw),
    });
    if version == 1 {
        checkpoint["final_url"] = Value::String(format!("https://api.github.com/repos/{name}"));
        checkpoint["redirected"] = Value::Bool(false);
    } else {
        checkpoint["transport"] = Value::String("gh api".to_string());
    }
    checkpoint
}

fn fixture() -> (TempDir, HistoricalV3PriorBenchmarkIdentitySeal) {
    let directory = tempfile::tempdir().unwrap();
    let seal = seal();
    let mut old = response_checkpoint(
        &seal,
        "legacy/one",
        1,
        json!({"id": 42, "full_name": "renamed/one", "created_at": "2020-01-02T03:04:05Z"}),
    );
    old["redirected"] = Value::Bool(true);
    old["final_url"] = Value::String("https://api.github.com/repositories/42".to_string());
    write_checkpoint(directory.path(), "legacy/one", old);
    let mut replacement = response_checkpoint(
        &seal,
        "legacy/two",
        2,
        json!({"id": 99, "full_name": "legacy/two", "created_at": "2026-09-03T22:41:59Z"}),
    );
    replacement["created_at"] = Value::String("03/09/2026 22:41:59".to_string());
    write_checkpoint(directory.path(), "legacy/two", replacement);
    let missing = response_checkpoint(&seal, "legacy/three", 2, json!({"message": "Not Found"}));
    write_checkpoint(directory.path(), "legacy/three", missing);
    (directory, seal)
}

#[test]
fn replay_reports_current_name_observations_without_claiming_historical_identity() {
    let (directory, seal) = fixture();
    let audit = audit_historical_v3_prior_names(&seal, &[directory.path()]).unwrap();
    assert_eq!(audit.observations.len(), 3);
    assert_eq!(
        audit.observations[0].status,
        HistoricalV3PriorNameObservationStatus::ObservedPreCutoffId
    );
    assert_eq!(
        audit.observations[1].status,
        HistoricalV3PriorNameObservationStatus::ObservedNotFound
    );
    assert_eq!(
        audit.observations[2].status,
        HistoricalV3PriorNameObservationStatus::ObservedPostCutoffId
    );
    assert_eq!(audit.observations[2].observed_repository_id, Some(99));
    assert_eq!(
        audit.proof_scope,
        "saved_name_lookup_only_not_historical_repository_identity"
    );
    verify_historical_v3_prior_name_audit(&seal, &[directory.path()], &audit).unwrap();
}

#[test]
fn replay_rejects_missing_extra_duplicate_and_seal_mismatched_checkpoints() {
    let (directory, seal) = fixture();
    let path = directory
        .path()
        .join(format!("{}.json", sha256(b"legacy/three")));
    fs::remove_file(&path).unwrap();
    assert!(audit_historical_v3_prior_names(&seal, &[directory.path()]).is_err());

    write_checkpoint(
        directory.path(),
        "legacy/three",
        response_checkpoint(&seal, "legacy/three", 2, json!({"message": "Not Found"})),
    );
    let extra = directory.path().join("unexpected.json");
    fs::write(&extra, b"{}").unwrap();
    assert!(audit_historical_v3_prior_names(&seal, &[directory.path()]).is_err());
    fs::remove_file(extra).unwrap();

    let duplicate = tempfile::tempdir().unwrap();
    fs::copy(
        directory
            .path()
            .join(format!("{}.json", sha256(b"legacy/one"))),
        duplicate
            .path()
            .join(format!("{}.json", sha256(b"legacy/one"))),
    )
    .unwrap();
    assert!(audit_historical_v3_prior_names(&seal, &[directory.path(), duplicate.path()]).is_err());

    let mut changed = seal.clone();
    changed.seal_sha256 = "b".repeat(64);
    assert!(audit_historical_v3_prior_names(&changed, &[directory.path()]).is_err());
}

#[test]
fn replay_rejects_tampered_response_metadata_and_audit() {
    let (directory, seal) = fixture();
    let path = directory
        .path()
        .join(format!("{}.json", sha256(b"legacy/two")));
    let original = fs::read(&path).unwrap();
    let mut checkpoint: Value = serde_json::from_slice(&original).unwrap();
    checkpoint["repository_id"] = json!(100);
    fs::write(&path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    assert!(audit_historical_v3_prior_names(&seal, &[directory.path()]).is_err());
    fs::write(&path, &original).unwrap();

    let mut checkpoint: Value = serde_json::from_slice(&original).unwrap();
    let nested = br#"{"id":99,"full_name":"legacy/two","created_at":"2026-09-03T22:41:59Z","owner":{"id":1,"id":1}}"#;
    checkpoint["response_base64"] =
        Value::String(base64::engine::general_purpose::STANDARD.encode(nested));
    checkpoint["response_sha256"] = Value::String(sha256(nested));
    fs::write(&path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    assert!(audit_historical_v3_prior_names(&seal, &[directory.path()]).is_err());
    fs::write(&path, &original).unwrap();

    let mut checkpoint: Value = serde_json::from_slice(&original).unwrap();
    let ambiguous =
        br#"{"id":100,"id":99,"full_name":"legacy/two","created_at":"2026-09-03T22:41:59Z"}"#;
    checkpoint["response_base64"] =
        Value::String(base64::engine::general_purpose::STANDARD.encode(ambiguous));
    checkpoint["response_sha256"] = Value::String(sha256(ambiguous));
    fs::write(&path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    assert!(audit_historical_v3_prior_names(&seal, &[directory.path()]).is_err());
    fs::write(&path, &original).unwrap();

    let redirect_path = directory
        .path()
        .join(format!("{}.json", sha256(b"legacy/one")));
    let redirect_original = fs::read(&redirect_path).unwrap();
    let mut redirect: Value = serde_json::from_slice(&redirect_original).unwrap();
    redirect["final_url"] = Value::String("https://api.github.com/repositories/100".to_string());
    fs::write(&redirect_path, serde_json::to_vec(&redirect).unwrap()).unwrap();
    assert!(audit_historical_v3_prior_names(&seal, &[directory.path()]).is_err());
    fs::write(&redirect_path, &redirect_original).unwrap();

    let mut checkpoint: Value = serde_json::from_slice(&original).unwrap();
    checkpoint["response_sha256"] = Value::String("f".repeat(64));
    fs::write(&path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    assert!(audit_historical_v3_prior_names(&seal, &[directory.path()]).is_err());
    fs::write(&path, &original).unwrap();

    let mut audit = audit_historical_v3_prior_names(&seal, &[directory.path()]).unwrap();
    audit.observations[2].observed_repository_id = Some(100);
    assert!(verify_historical_v3_prior_name_audit(&seal, &[directory.path()], &audit).is_err());
}

#[cfg(unix)]
#[test]
fn replay_rejects_symlinked_checkpoint() {
    let (directory, seal) = fixture();
    let path = directory
        .path()
        .join(format!("{}.json", sha256(b"legacy/one")));
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("target");
    fs::rename(&path, &target).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(audit_historical_v3_prior_names(&seal, &[directory.path()]).is_err());
}

#[test]
fn fractional_creation_time_retains_its_precision_at_the_cutoff() {
    let (directory, seal) = fixture();
    let path = directory
        .path()
        .join(format!("{}.json", sha256(b"legacy/two")));
    let mut checkpoint: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let created_at = "2026-08-07T20:46:11.500Z";
    let raw =
        serde_json::to_vec(&json!({"id": 99, "full_name": "legacy/two", "created_at": created_at}))
            .unwrap();
    checkpoint["created_at"] = Value::String(created_at.to_string());
    checkpoint["response_base64"] =
        Value::String(base64::engine::general_purpose::STANDARD.encode(&raw));
    checkpoint["response_sha256"] = Value::String(sha256(&raw));
    fs::write(path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    let audit = audit_historical_v3_prior_names(&seal, &[directory.path()]).unwrap();
    assert_eq!(
        audit.observations[2].status,
        HistoricalV3PriorNameObservationStatus::ObservedPostCutoffId
    );
    assert_eq!(
        audit.observations[2].observed_created_at_utc.as_deref(),
        Some(created_at)
    );
}
