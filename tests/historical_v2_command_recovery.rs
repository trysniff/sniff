use serde::Serialize;
use sha2::{Digest, Sha256};
use sniff::benchmark::{
    HISTORICAL_V2_FRAME_SCHEMA_VERSION, HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION,
    HistoricalV2Frame, HistoricalV2FrameDisposition, HistoricalV2ProjectedRow,
    HistoricalV2SelectedPayload, HistoricalV2SelectedPayloads, HistoricalV2SlotOutcome,
    HistoricalV2SlotSelection, HistoricalV2SlotStage, HistoricalV2SlotStageJournal,
    derive_historical_v2_exclusion_manifest, derive_historical_v2_frame_record,
    historical_v2_frame_sha256, select_historical_v2_slots, validate_historical_v2_protocol,
    validate_historical_v2_selected_payloads_commitment,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PROTOCOL: &[u8] = include_bytes!("../sniffbench/historical-v2-protocol.json");
const PAYLOAD_CONTRACT: &str = "sniffbench-historical-v2-selected-payloads-v1";
const SLOTS_PER_LANGUAGE: usize = 128;
const LANGUAGES: [(&str, &str); 6] = [
    ("go", "go"),
    ("javascript", "js"),
    ("kotlin", "kt"),
    ("python", "py"),
    ("rust", "rs"),
    ("typescript", "ts"),
];

#[test]
fn killed_fixed_slot_command_resumes_without_crossing_the_stage_ceiling() {
    let fixture = Fixture::new();
    let mut interrupted = fixture.command();
    interrupted.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = interrupted.spawn().unwrap();
    let completed_before_kill =
        interrupt_after_durable_progress(&mut child, &fixture.state_root, fixture.selected_count);
    assert!(completed_before_kill > 0);
    assert!(completed_before_kill < fixture.selected_count);

    let status = fixture
        .command()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        completed_payload_count(&fixture.state_root),
        fixture.selected_count
    );
    assert_all_slots_stop_after_payload(&fixture.state_root);
    assert_no_stage_work(&fixture.work_root);

    let before_replay = committed_payload_bytes(&fixture.state_root);
    let replay = fixture
        .command()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(replay.success());
    assert_eq!(before_replay, committed_payload_bytes(&fixture.state_root));
    assert_all_slots_stop_after_payload(&fixture.state_root);
    assert_no_stage_work(&fixture.work_root);
}

struct Fixture {
    _root: tempfile::TempDir,
    protocol: PathBuf,
    artifact_root: PathBuf,
    frame: PathBuf,
    exclusions: PathBuf,
    selection: PathBuf,
    payloads: PathBuf,
    state_root: PathBuf,
    work_root: PathBuf,
    harness_root: PathBuf,
    missing_docker: PathBuf,
    selected_count: usize,
}

impl Fixture {
    fn new() -> Self {
        let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = tempfile::tempdir().unwrap();
        let protocol_path = root.path().join("protocol.json");
        fs::write(&protocol_path, PROTOCOL).unwrap();
        let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
        let exclusions =
            derive_historical_v2_exclusion_manifest(PROTOCOL, &repository_root).unwrap();
        let (frame, source_rows) = frame(&protocol);
        let selection =
            select_historical_v2_slots(PROTOCOL, &repository_root, &frame, &exclusions).unwrap();
        let payloads = payloads(&protocol, &frame, &exclusions, &selection, &source_rows);
        validate_historical_v2_selected_payloads_commitment(
            &protocol,
            &frame,
            &exclusions,
            &selection,
            &payloads,
        )
        .unwrap();
        let expected = LANGUAGES.len() * SLOTS_PER_LANGUAGE;
        assert_eq!(selection.selected_count, expected);
        assert_eq!(payloads.selected_count, expected);

        let frame_path = root.path().join("frame.json");
        let exclusions_path = root.path().join("exclusions.json");
        let selection_path = root.path().join("selection.json");
        let payloads_path = root.path().join("payloads.json");
        write_json(&frame_path, &frame);
        write_json(&exclusions_path, &exclusions);
        write_json(&selection_path, &selection);
        write_json(&payloads_path, &payloads);

        Self {
            protocol: protocol_path,
            artifact_root: repository_root.clone(),
            frame: frame_path,
            exclusions: exclusions_path,
            selection: selection_path,
            payloads: payloads_path,
            state_root: root.path().join("state"),
            work_root: root.path().join("work"),
            harness_root: repository_root,
            missing_docker: root.path().join("docker-must-not-run"),
            selected_count: expected,
            _root: root,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sniffbench-frame"));
        command
            .arg("run-slots")
            .arg("--protocol")
            .arg(&self.protocol)
            .arg("--artifact-root")
            .arg(&self.artifact_root)
            .arg("--frame")
            .arg(&self.frame)
            .arg("--exclusions")
            .arg(&self.exclusions)
            .arg("--selection")
            .arg(&self.selection)
            .arg("--payloads")
            .arg(&self.payloads)
            .arg("--state-root")
            .arg(&self.state_root)
            .arg("--work-root")
            .arg(&self.work_root)
            .arg("--harness-repository-root")
            .arg(&self.harness_root)
            .arg("--docker-executable")
            .arg(&self.missing_docker)
            .arg("--through-stage")
            .arg("payload");
        command
    }
}

#[derive(Clone)]
struct SourceRow {
    source_shard_index: usize,
    source_row_index: usize,
    instance_id: String,
    patch: String,
}

fn frame(
    protocol: &sniff::benchmark::ValidatedHistoricalV2Protocol,
) -> (HistoricalV2Frame, BTreeMap<usize, SourceRow>) {
    let mut records = Vec::with_capacity(LANGUAGES.len() * SLOTS_PER_LANGUAGE);
    let mut source_rows = BTreeMap::new();
    for (shard, (language, extension)) in LANGUAGES.into_iter().enumerate() {
        for source_row_index in 0..SLOTS_PER_LANGUAGE {
            let global_row_index = records.len();
            let repository = format!("recovery-{language}-{source_row_index:03}/fixture");
            let instance_id = format!(
                "recovery-{language}-{source_row_index:03}__fixture-{}",
                source_row_index + 1
            );
            let patch = reducing_patch(extension, global_row_index);
            let source = SourceRow {
                source_shard_index: shard,
                source_row_index,
                instance_id: instance_id.clone(),
                patch: patch.clone(),
            };
            let record = derive_historical_v2_frame_record(
                HistoricalV2ProjectedRow {
                    source_shard_index: shard,
                    source_row_index,
                    global_row_index,
                    base_commit: "1".repeat(40),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    instance_id,
                    license: "MIT".to_string(),
                    patch,
                    pull_number: i64::try_from(source_row_index + 1).unwrap(),
                    repo: repository,
                },
                &protocol.protocol.selection.ranking_seed,
            );
            assert!(matches!(
                record.disposition,
                HistoricalV2FrameDisposition::Eligible { .. }
            ));
            source_rows.insert(global_row_index, source);
            records.push(record);
        }
    }
    let mut frame = HistoricalV2Frame {
        schema_version: HISTORICAL_V2_FRAME_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256.clone(),
        dataset_revision: protocol.protocol.dataset.revision.clone(),
        ranking_seed: protocol.protocol.selection.ranking_seed.clone(),
        shards: Vec::new(),
        row_count: records.len(),
        eligible_count: records.len(),
        excluded_count: 0,
        records,
        frame_sha256: String::new(),
    };
    frame.frame_sha256 = historical_v2_frame_sha256(&frame).unwrap();
    (frame, source_rows)
}

fn payloads(
    protocol: &sniff::benchmark::ValidatedHistoricalV2Protocol,
    frame: &HistoricalV2Frame,
    exclusions: &sniff::benchmark::HistoricalV2ExclusionManifest,
    selection: &HistoricalV2SlotSelection,
    source_rows: &BTreeMap<usize, SourceRow>,
) -> HistoricalV2SelectedPayloads {
    let mut records = Vec::with_capacity(selection.selected_count);
    for slot in &selection.slots {
        let HistoricalV2SlotOutcome::Selected {
            global_row_index,
            instance_id,
            patch_sha256,
            ..
        } = &slot.outcome
        else {
            continue;
        };
        let source = source_rows.get(global_row_index).unwrap();
        assert_eq!(instance_id, &source.instance_id);
        assert_eq!(patch_sha256, &sha256(source.patch.as_bytes()));
        let mut payload = HistoricalV2SelectedPayload {
            language: slot.language.clone(),
            slot_number: slot.slot_number,
            source_shard_index: source.source_shard_index,
            source_row_index: source.source_row_index,
            global_row_index: *global_row_index,
            instance_id: source.instance_id.clone(),
            patch: source.patch.clone(),
            patch_sha256: patch_sha256.clone(),
            install_config: None,
            install_config_sha256: None,
            test_patch: None,
            test_patch_sha256: None,
            payload_sha256: String::new(),
        };
        payload.payload_sha256 = payload_sha256(&payload);
        records.push(payload);
    }
    let mut payloads = HistoricalV2SelectedPayloads {
        schema_version: HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION,
        payload_contract: PAYLOAD_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        frame_sha256: frame.frame_sha256.clone(),
        exclusion_manifest_sha256: exclusions.manifest_sha256.clone(),
        selection_sha256: selection.selection_sha256.clone(),
        selected_count: records.len(),
        records,
        payloads_sha256: String::new(),
    };
    payloads.payloads_sha256 = payloads_sha256(&payloads);
    payloads
}

fn interrupt_after_durable_progress(
    child: &mut Child,
    state_root: &Path,
    selected_count: usize,
) -> usize {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let completed = completed_payload_count(state_root);
        if completed > 0 && completed < selected_count {
            child.kill().unwrap();
            let status = child.wait().unwrap();
            assert!(!status.success());
            return completed_payload_count(state_root);
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("slot sweep completed before forced termination: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "slot sweep made no interruptible durable progress"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn completed_payload_count(state_root: &Path) -> usize {
    LANGUAGES
        .iter()
        .map(|(language, _)| {
            (1..=SLOTS_PER_LANGUAGE)
                .filter(|slot| payload_checkpoint(state_root, language, *slot).is_file())
                .count()
        })
        .sum()
}

fn assert_all_slots_stop_after_payload(state_root: &Path) {
    for (language, _) in LANGUAGES {
        for slot in 1..=SLOTS_PER_LANGUAGE {
            let journal = HistoricalV2SlotStageJournal::open(state_root, language, slot).unwrap();
            assert_eq!(journal.history().len(), 1);
            assert_eq!(
                journal.history()[0].checkpoint.stage,
                HistoricalV2SlotStage::Payload
            );
        }
    }
}

fn committed_payload_bytes(state_root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    for (language, _) in LANGUAGES {
        for slot in 1..=SLOTS_PER_LANGUAGE {
            let stage = state_root
                .join(language)
                .join(format!("slot-{slot:04}"))
                .join("0001-payload");
            for name in ["checkpoint.json", "artifact.json", "_transaction.json"] {
                let path = stage.join(name);
                files.insert(
                    path.strip_prefix(state_root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    files
}

fn payload_checkpoint(state_root: &Path, language: &str, slot: usize) -> PathBuf {
    state_root
        .join(language)
        .join(format!("slot-{slot:04}"))
        .join("0001-payload")
        .join("checkpoint.json")
}

fn assert_no_stage_work(path: &Path) {
    let mut languages = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    languages.sort();
    assert_eq!(languages.len(), LANGUAGES.len());
    for language in languages {
        assert!(language.is_dir());
        assert!(fs::read_dir(language).unwrap().next().is_none());
    }
}

fn reducing_patch(extension: &str, index: usize) -> String {
    format!(
        "diff --git a/src/item_{index}.{extension} b/src/item_{index}.{extension}\n--- a/src/item_{index}.{extension}\n+++ b/src/item_{index}.{extension}\n@@ -1,2 +1 @@\n-old_one_{index} = prepare()\n-old_two_{index} = finish(old_one_{index})\n+result_{index} = finish(prepare())\n"
    )
}

fn payload_sha256(payload: &HistoricalV2SelectedPayload) -> String {
    hash_json(&(
        &payload.language,
        payload.slot_number,
        payload.source_shard_index,
        payload.source_row_index,
        payload.global_row_index,
        &payload.instance_id,
        &payload.patch,
        &payload.patch_sha256,
        &payload.install_config,
        &payload.install_config_sha256,
        &payload.test_patch,
        &payload.test_patch_sha256,
    ))
}

fn payloads_sha256(payloads: &HistoricalV2SelectedPayloads) -> String {
    hash_json(&(
        payloads.schema_version,
        &payloads.payload_contract,
        &payloads.protocol_sha256,
        &payloads.frame_sha256,
        &payloads.exclusion_manifest_sha256,
        &payloads.selection_sha256,
        payloads.selected_count,
        &payloads.records,
    ))
}

fn hash_json(value: &impl Serialize) -> String {
    sha256(&serde_json::to_vec(value).unwrap())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_json(path: &Path, value: &impl Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
