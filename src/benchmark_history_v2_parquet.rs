use super::{
    HISTORICAL_V2_FRAME_SCHEMA_VERSION, HistoricalV2Frame, HistoricalV2FrameDisposition,
    HistoricalV2FrameExclusionReason, HistoricalV2FrameRecord, HistoricalV2FrameShard,
    HistoricalV2ProjectedRow, derive_historical_v2_frame_record, historical_v2_frame_sha256,
    validate_historical_v2_frame_commitment, validate_historical_v2_protocol,
};
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field;
use parquet::schema::parser::parse_message_type;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path};

const EXPECTED_DATASET_FIELDS: [&str; 16] = [
    "FAIL_TO_PASS",
    "PASS_TO_PASS",
    "base_commit",
    "created_at",
    "hints_text",
    "install_config",
    "instance_id",
    "interface",
    "license",
    "meta",
    "patch",
    "pr_description",
    "problem_statement",
    "pull_number",
    "repo",
    "test_patch",
];

const PROJECTED_SCHEMA: &str = r#"
message schema {
  OPTIONAL BYTE_ARRAY base_commit (UTF8);
  OPTIONAL BYTE_ARRAY created_at (UTF8);
  OPTIONAL BYTE_ARRAY instance_id (UTF8);
  OPTIONAL BYTE_ARRAY license (UTF8);
  OPTIONAL BYTE_ARRAY patch (UTF8);
  OPTIONAL INT64 pull_number;
  OPTIONAL BYTE_ARRAY repo (UTF8);
}
"#;

pub fn build_historical_v2_frame(
    protocol_bytes: &[u8],
    dataset_root: &Path,
) -> Result<HistoricalV2Frame, String> {
    let validated = validate_historical_v2_protocol(protocol_bytes)?;
    let canonical_root = fs::canonicalize(dataset_root)
        .map_err(|error| format!("failed to resolve historical-v2 dataset root: {error}"))?;
    let mut records = Vec::with_capacity(validated.protocol.dataset.expected_rows);
    let mut shards = Vec::with_capacity(validated.protocol.dataset.shards.len());
    let mut global_row_index = 0;

    for (source_shard_index, expected) in validated.protocol.dataset.shards.iter().enumerate() {
        let relative = safe_relative_path(&expected.path)?;
        let path = fs::canonicalize(canonical_root.join(relative)).map_err(|error| {
            format!(
                "failed to resolve historical-v2 shard {}: {error}",
                expected.path
            )
        })?;
        if !path.starts_with(&canonical_root) {
            return Err(format!(
                "historical-v2 shard escapes the dataset root: {}",
                expected.path
            ));
        }
        let metadata = fs::metadata(&path).map_err(|error| {
            format!(
                "failed to inspect historical-v2 shard {}: {error}",
                expected.path
            )
        })?;
        if metadata.len() != expected.size_bytes {
            return Err(format!(
                "historical-v2 shard size changed for {}",
                expected.path
            ));
        }
        let shard_sha256 = sha256_file(&path)?;
        if !shard_sha256.eq_ignore_ascii_case(&expected.lfs_sha256) {
            return Err(format!(
                "historical-v2 shard SHA-256 changed for {}",
                expected.path
            ));
        }
        let start = global_row_index;
        let row_count =
            visit_historical_v2_projected_shard(&path, source_shard_index, start, |row| {
                global_row_index += 1;
                records.push(derive_historical_v2_frame_record(
                    row,
                    &validated.protocol.selection.ranking_seed,
                ));
                Ok(())
            })?;
        shards.push(HistoricalV2FrameShard {
            source_shard_index,
            artifact_path: expected.path.clone(),
            size_bytes: metadata.len(),
            sha256: shard_sha256,
            row_count,
        });
    }
    if records.len() != validated.protocol.dataset.expected_rows {
        return Err(format!(
            "historical-v2 row count changed: expected {}, got {}",
            validated.protocol.dataset.expected_rows,
            records.len()
        ));
    }
    mark_duplicate_pull_requests(&mut records);
    let eligible_count = records
        .iter()
        .filter(|record| {
            matches!(
                record.disposition,
                HistoricalV2FrameDisposition::Eligible { .. }
            )
        })
        .count();
    let mut frame = HistoricalV2Frame {
        schema_version: HISTORICAL_V2_FRAME_SCHEMA_VERSION,
        protocol_sha256: validated.protocol_sha256,
        dataset_revision: validated.protocol.dataset.revision,
        ranking_seed: validated.protocol.selection.ranking_seed,
        shards,
        row_count: records.len(),
        eligible_count,
        excluded_count: records.len() - eligible_count,
        records,
        frame_sha256: String::new(),
    };
    frame.frame_sha256 = historical_v2_frame_sha256(&frame)?;
    validate_historical_v2_frame_commitment(&frame)?;
    Ok(frame)
}

pub fn write_historical_v2_frame(
    protocol_bytes: &[u8],
    dataset_root: &Path,
    output_path: &Path,
) -> Result<HistoricalV2Frame, String> {
    let frame = build_historical_v2_frame(protocol_bytes, dataset_root)?;
    let bytes = serde_json::to_vec_pretty(&frame)
        .map_err(|error| format!("failed to serialize historical-v2 frame: {error}"))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output_path)
        .map_err(|error| format!("failed to create historical-v2 frame: {error}"))?;
    output
        .write_all(&bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("failed to persist historical-v2 frame: {error}"))?;
    Ok(frame)
}

pub fn validate_historical_v2_frame_sources(
    protocol_bytes: &[u8],
    dataset_root: &Path,
    frame: &HistoricalV2Frame,
) -> Result<(), String> {
    validate_historical_v2_frame_commitment(frame)?;
    let reproduced = build_historical_v2_frame(protocol_bytes, dataset_root)?;
    if &reproduced != frame {
        return Err("historical-v2 frame does not replay from its pinned shards".to_string());
    }
    Ok(())
}

pub fn visit_historical_v2_projected_shard<F>(
    path: &Path,
    source_shard_index: usize,
    global_row_start: usize,
    mut visitor: F,
) -> Result<usize, String>
where
    F: FnMut(HistoricalV2ProjectedRow) -> Result<(), String>,
{
    let file = File::open(path)
        .map_err(|error| format!("failed to open historical-v2 Parquet shard: {error}"))?;
    let reader = SerializedFileReader::new(file)
        .map_err(|error| format!("failed to read historical-v2 Parquet metadata: {error}"))?;
    validate_dataset_schema(&reader)?;
    let projection = parse_message_type(PROJECTED_SCHEMA)
        .map_err(|error| format!("invalid built-in historical-v2 projection: {error}"))?;
    let expected_rows = usize::try_from(reader.metadata().file_metadata().num_rows())
        .map_err(|_| "historical-v2 shard row count is negative or too large".to_string())?;
    let rows = reader
        .get_row_iter(Some(projection))
        .map_err(|error| format!("failed to project historical-v2 Parquet rows: {error}"))?;
    let mut row_count = 0;
    for row in rows {
        let row = row.map_err(|error| {
            format!("failed to decode historical-v2 projected row {row_count}: {error}")
        })?;
        visitor(projected_row(
            source_shard_index,
            row_count,
            global_row_start + row_count,
            row.into_columns(),
        )?)?;
        row_count += 1;
    }
    if row_count != expected_rows {
        return Err(format!(
            "historical-v2 projected row count changed: metadata {expected_rows}, decoded {row_count}"
        ));
    }
    Ok(row_count)
}

fn validate_dataset_schema(reader: &SerializedFileReader<File>) -> Result<(), String> {
    let fields = reader
        .metadata()
        .file_metadata()
        .schema_descr()
        .root_schema()
        .get_fields();
    let names = fields
        .iter()
        .map(|field| field.name())
        .collect::<BTreeSet<_>>();
    if fields.len() != EXPECTED_DATASET_FIELDS.len()
        || names != EXPECTED_DATASET_FIELDS.into_iter().collect()
    {
        return Err("historical-v2 Parquet schema fields changed".to_string());
    }
    Ok(())
}

fn projected_row(
    source_shard_index: usize,
    source_row_index: usize,
    global_row_index: usize,
    columns: Vec<(String, Field)>,
) -> Result<HistoricalV2ProjectedRow, String> {
    let mut fields = BTreeMap::new();
    for (name, field) in columns {
        if fields.insert(name, field).is_some() {
            return Err("historical-v2 projected row repeats a field".to_string());
        }
    }
    let row = HistoricalV2ProjectedRow {
        source_shard_index,
        source_row_index,
        global_row_index,
        base_commit: take_string(&mut fields, "base_commit")?,
        created_at: take_string(&mut fields, "created_at")?,
        instance_id: take_string(&mut fields, "instance_id")?,
        license: take_string(&mut fields, "license")?,
        patch: take_string(&mut fields, "patch")?,
        pull_number: take_long(&mut fields, "pull_number")?,
        repo: take_string(&mut fields, "repo")?,
    };
    if !fields.is_empty() {
        return Err("historical-v2 projection decoded an unlisted field".to_string());
    }
    Ok(row)
}

fn take_string(fields: &mut BTreeMap<String, Field>, name: &str) -> Result<String, String> {
    match fields.remove(name) {
        Some(Field::Str(value)) => Ok(value),
        Some(_) => Err(format!(
            "historical-v2 projected field {name} is not a string"
        )),
        None => Err(format!("historical-v2 projected field {name} is missing")),
    }
}

fn take_long(fields: &mut BTreeMap<String, Field>, name: &str) -> Result<i64, String> {
    match fields.remove(name) {
        Some(Field::Long(value)) => Ok(value),
        Some(_) => Err(format!("historical-v2 projected field {name} is not int64")),
        None => Err(format!("historical-v2 projected field {name} is missing")),
    }
}

fn mark_duplicate_pull_requests(records: &mut [HistoricalV2FrameRecord]) {
    let mut seen = HashSet::new();
    for record in records {
        let (Some(repository), Some(pull_number)) =
            (&record.canonical_repository, record.pull_number)
        else {
            continue;
        };
        if !seen.insert((repository.clone(), pull_number)) {
            record.disposition = HistoricalV2FrameDisposition::Excluded {
                reason: HistoricalV2FrameExclusionReason::DuplicatePullRequest,
            };
        }
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|error| format!("failed to open historical-v2 shard for hashing: {error}"))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash historical-v2 shard: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn safe_relative_path(value: &str) -> Result<&Path, String> {
    let path = Path::new(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe historical-v2 shard path: {value}"));
    }
    Ok(path)
}
