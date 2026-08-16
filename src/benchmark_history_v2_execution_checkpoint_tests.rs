use super::store::ExecutionSlotStore;
use super::*;
use crate::benchmark::{
    HistoricalV2ExecutionPolicy, HistoricalV2IdenticalTestExecution, HistoricalV2IdenticalTestPlan,
};
use std::fs;

#[test]
fn transaction_round_trips_and_cannot_be_replaced() {
    let root = tempfile::tempdir().unwrap();
    let store = ExecutionSlotStore::open(root.path(), "python", 1).unwrap();
    let (checkpoint, plan, execution) = fixtures();
    assert!(store.load().unwrap().is_none());
    store.publish(&checkpoint, &plan, &execution).unwrap();
    let loaded = store.load().unwrap().unwrap();
    assert_eq!(loaded.checkpoint, checkpoint);
    assert_eq!(loaded.plan, plan);
    assert_eq!(loaded.execution, execution);
    assert!(store.publish(&checkpoint, &plan, &execution).is_err());
}

#[test]
fn corrupt_or_extra_transaction_files_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let store = ExecutionSlotStore::open(root.path(), "python", 1).unwrap();
    let (checkpoint, plan, execution) = fixtures();
    store.publish(&checkpoint, &plan, &execution).unwrap();
    let slot = root.path().join("python/slot-0001");
    fs::write(slot.join("plan.json"), b"{}\n").unwrap();
    assert!(store.load().is_err());

    let root = tempfile::tempdir().unwrap();
    let store = ExecutionSlotStore::open(root.path(), "python", 1).unwrap();
    store.publish(&checkpoint, &plan, &execution).unwrap();
    fs::write(root.path().join("python/slot-0001/extra"), b"nope").unwrap();
    assert!(store.load().is_err());
}

#[test]
fn incomplete_transaction_is_removed_only_under_the_slot_lock() {
    let root = tempfile::tempdir().unwrap();
    {
        let _store = ExecutionSlotStore::open(root.path(), "python", 1).unwrap();
        let incomplete = root.path().join("python/.slot-0001.incomplete");
        fs::create_dir(&incomplete).unwrap();
        fs::write(incomplete.join("partial"), b"torn").unwrap();
    }
    let _store = ExecutionSlotStore::open(root.path(), "python", 1).unwrap();
    assert!(!root.path().join("python/.slot-0001.incomplete").exists());
}

#[test]
fn concurrent_slot_writer_is_rejected_and_crash_style_release_recovers() {
    let root = tempfile::tempdir().unwrap();
    let first = ExecutionSlotStore::open(root.path(), "rust", 9).unwrap();
    assert!(ExecutionSlotStore::open(root.path(), "rust", 9).is_err());
    drop(first);
    ExecutionSlotStore::open(root.path(), "rust", 9).unwrap();
}

fn fixtures() -> (
    HistoricalV2ExecutionCheckpoint,
    HistoricalV2IdenticalTestPlan,
    HistoricalV2IdenticalTestExecution,
) {
    let plan = HistoricalV2IdenticalTestPlan {
        schema_version: 1,
        plan_contract: "fixture".to_string(),
        assessment_identity_sha256: "a".repeat(64),
        qualification_sha256: "b".repeat(64),
        test_recipe_sha256: "c".repeat(64),
        execution_harness_sha256: "d".repeat(64),
        materialization_sha256: "e".repeat(64),
        test_materialization_sha256: None,
        language: "python".to_string(),
        slot_number: 1,
        canonical_repository: "github.com/example/project".to_string(),
        base_commit_oid: "1".repeat(40),
        patched_commit_oid: "2".repeat(40),
        base_image_name: "python_3.11".to_string(),
        dockerfile_path: "base_dockerfiles/Dockerfile_python_3.11".to_string(),
        dockerfile_blob_oid: "3".repeat(40),
        install_commands: Vec::new(),
        install_command_sha256: Vec::new(),
        test_commands: vec!["pytest".to_string()],
        test_script_sha256: "f".repeat(64),
        policy: HistoricalV2ExecutionPolicy {
            platform: "linux/amd64".to_string(),
            cpu_limit_millis: 4_000,
            memory_limit_bytes: 8 * 1024 * 1024 * 1024,
            process_limit: 1_024,
            temporary_filesystem_bytes: 2 * 1024 * 1024 * 1024,
            install_command_timeout_seconds: 1_800,
            test_timeout_seconds: 3_600,
            retained_output_bytes: 64 * 1024,
            install_network_enabled: true,
            test_network_enabled: false,
            ephemeral_root_filesystem: true,
            host_source_mounts_forbidden: true,
            all_capabilities_dropped: true,
            no_new_privileges: true,
        },
        plan_sha256: "0".repeat(64),
    };
    let execution = HistoricalV2IdenticalTestExecution {
        schema_version: 1,
        execution_contract: "fixture".to_string(),
        plan_sha256: plan.plan_sha256.clone(),
        image_id: format!("sha256:{}", "9".repeat(64)),
        events: Vec::new(),
        outcome: HistoricalV2IdenticalTestOutcome::Passed,
        execution_sha256: "8".repeat(64),
    };
    let checkpoint = HistoricalV2ExecutionCheckpoint {
        schema_version: HISTORICAL_V2_EXECUTION_CHECKPOINT_SCHEMA_VERSION,
        checkpoint_contract: CHECKPOINT_CONTRACT.to_string(),
        selection_sha256: "7".repeat(64),
        assessment_identity_sha256: plan.assessment_identity_sha256.clone(),
        language: plan.language.clone(),
        slot_number: plan.slot_number,
        canonical_repository: plan.canonical_repository.clone(),
        qualification_sha256: plan.qualification_sha256.clone(),
        test_recipe_sha256: plan.test_recipe_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        execution_sha256: execution.execution_sha256.clone(),
        disposition: HistoricalV2ExecutionCheckpointDisposition::ReadyForReview,
        checkpoint_sha256: "6".repeat(64),
    };
    (checkpoint, plan, execution)
}
