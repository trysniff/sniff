use super::HistoricalV2ProjectedPayloadRow;
use super::history_v2_parquet::validate_dataset_schema;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field;
use parquet::schema::parser::parse_message_type;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;

const POST_SELECTION_SCHEMA: &str = r#"
message schema {
  OPTIONAL BYTE_ARRAY instance_id (UTF8);
  OPTIONAL BYTE_ARRAY patch (UTF8);
  OPTIONAL BYTE_ARRAY install_config (UTF8);
  OPTIONAL BYTE_ARRAY test_patch (UTF8);
}
"#;

pub(super) fn visit_historical_v2_post_selection_shard<F>(
    path: &Path,
    source_shard_index: usize,
    global_row_start: usize,
    selected_global_rows: &BTreeSet<usize>,
    mut visitor: F,
) -> Result<usize, String>
where
    F: FnMut(HistoricalV2ProjectedPayloadRow) -> Result<(), String>,
{
    let file = File::open(path)
        .map_err(|error| format!("failed to open historical-v2 Parquet shard: {error}"))?;
    let reader = SerializedFileReader::new(file)
        .map_err(|error| format!("failed to read historical-v2 Parquet metadata: {error}"))?;
    validate_dataset_schema(&reader)?;
    let projection = parse_message_type(POST_SELECTION_SCHEMA)
        .map_err(|error| format!("invalid built-in historical-v2 payload projection: {error}"))?;
    let expected_rows = usize::try_from(reader.metadata().file_metadata().num_rows())
        .map_err(|_| "historical-v2 shard row count is negative or too large".to_string())?;
    let rows = reader
        .get_row_iter(Some(projection))
        .map_err(|error| format!("failed to project historical-v2 payload rows: {error}"))?;
    let mut row_count = 0;
    for row in rows {
        let global_row_index = global_row_start + row_count;
        let row = row.map_err(|error| {
            format!("failed to decode historical-v2 payload row {row_count}: {error}")
        })?;
        if selected_global_rows.contains(&global_row_index) {
            visitor(projected_payload_row(
                source_shard_index,
                row_count,
                global_row_index,
                row.into_columns(),
            )?)?;
        }
        row_count += 1;
    }
    if row_count != expected_rows {
        return Err(format!(
            "historical-v2 payload row count changed: metadata {expected_rows}, decoded {row_count}"
        ));
    }
    Ok(row_count)
}

fn projected_payload_row(
    source_shard_index: usize,
    source_row_index: usize,
    global_row_index: usize,
    columns: Vec<(String, Field)>,
) -> Result<HistoricalV2ProjectedPayloadRow, String> {
    let mut fields = BTreeMap::new();
    for (name, field) in columns {
        if fields.insert(name, field).is_some() {
            return Err("historical-v2 payload row repeats a field".to_string());
        }
    }
    let row = HistoricalV2ProjectedPayloadRow {
        source_shard_index,
        source_row_index,
        global_row_index,
        instance_id: take_required_string(&mut fields, "instance_id")?,
        patch: take_required_string(&mut fields, "patch")?,
        install_config: take_optional_string(&mut fields, "install_config")?,
        test_patch: take_optional_string(&mut fields, "test_patch")?,
    };
    if !fields.is_empty() {
        return Err("historical-v2 payload projection decoded an unlisted field".to_string());
    }
    Ok(row)
}

fn take_required_string(
    fields: &mut BTreeMap<String, Field>,
    name: &str,
) -> Result<String, String> {
    match fields.remove(name) {
        Some(Field::Str(value)) => Ok(value),
        Some(_) => Err(format!(
            "historical-v2 payload field {name} is not a string"
        )),
        None => Err(format!("historical-v2 payload field {name} is missing")),
    }
}

fn take_optional_string(
    fields: &mut BTreeMap<String, Field>,
    name: &str,
) -> Result<Option<String>, String> {
    match fields.remove(name) {
        Some(Field::Str(value)) => Ok(Some(value)),
        Some(Field::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "historical-v2 payload field {name} is not a string"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::basic::Compression;
    use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
    use parquet::file::properties::WriterProperties;
    use parquet::file::writer::SerializedFileWriter;
    use std::sync::Arc;

    const DATASET_SCHEMA: &str = r#"
message schema {
  OPTIONAL BYTE_ARRAY base_commit (UTF8);
  OPTIONAL BYTE_ARRAY created_at (UTF8);
  OPTIONAL BYTE_ARRAY hints_text (UTF8);
  OPTIONAL BYTE_ARRAY instance_id (UTF8);
  OPTIONAL BYTE_ARRAY patch (UTF8);
  OPTIONAL BYTE_ARRAY pr_description (UTF8);
  OPTIONAL BYTE_ARRAY problem_statement (UTF8);
  OPTIONAL INT64 pull_number;
  OPTIONAL BYTE_ARRAY repo (UTF8);
  OPTIONAL BYTE_ARRAY test_patch (UTF8);
  OPTIONAL BYTE_ARRAY FAIL_TO_PASS (UTF8);
  OPTIONAL BYTE_ARRAY PASS_TO_PASS (UTF8);
  OPTIONAL BYTE_ARRAY interface (UTF8);
  OPTIONAL BYTE_ARRAY license (UTF8);
  OPTIONAL BYTE_ARRAY install_config (UTF8);
  OPTIONAL BYTE_ARRAY meta (UTF8);
}
"#;

    #[test]
    fn opens_only_selected_post_selection_payloads() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.parquet");
        write_fixture(&path, DATASET_SCHEMA);
        let selected = BTreeSet::from([10]);
        let mut rows = Vec::new();

        let count = visit_historical_v2_post_selection_shard(&path, 2, 10, &selected, |row| {
            rows.push(row);
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].global_row_index, 10);
        assert_eq!(rows[0].instance_id, "owner__repo-42");
        assert_eq!(rows[0].patch, "diff --git a/x.py b/x.py");
        assert_eq!(rows[0].install_config.as_deref(), Some("install config"));
        assert_eq!(rows[0].test_patch.as_deref(), Some("test patch"));
    }

    #[test]
    fn rejects_schema_injection_and_does_not_emit_unselected_rows() {
        let directory = tempfile::tempdir().unwrap();
        let normal = directory.path().join("normal.parquet");
        write_fixture(&normal, DATASET_SCHEMA);
        let mut rows = Vec::new();
        visit_historical_v2_post_selection_shard(&normal, 0, 0, &BTreeSet::from([99]), |row| {
            rows.push(row);
            Ok(())
        })
        .unwrap();
        assert!(rows.is_empty());

        let injected = directory.path().join("injected.parquet");
        let schema = DATASET_SCHEMA.replace(
            "\n}",
            "\n  OPTIONAL BYTE_ARRAY generated_reasoning (UTF8);\n}",
        );
        write_fixture(&injected, &schema);
        let error =
            visit_historical_v2_post_selection_shard(&injected, 0, 0, &BTreeSet::from([0]), |_| {
                Ok(())
            })
            .unwrap_err();
        assert!(error.contains("schema fields changed"));
    }

    fn write_fixture(path: &Path, schema: &str) {
        let schema = Arc::new(parse_message_type(schema).unwrap());
        let properties = Arc::new(
            WriterProperties::builder()
                .set_compression(Compression::SNAPPY)
                .build(),
        );
        let mut writer =
            SerializedFileWriter::new(File::create(path).unwrap(), schema, properties).unwrap();
        let mut row_group = writer.next_row_group().unwrap();
        let string_values = [
            "a".repeat(40).into_bytes(),
            b"2025-01-02 03:04:05".to_vec(),
            b"forbidden hint".to_vec(),
            b"owner__repo-42".to_vec(),
            b"diff --git a/x.py b/x.py".to_vec(),
            b"forbidden description".to_vec(),
            vec![0xff, 0xfe, 0xfd],
            b"owner/repo".to_vec(),
            b"test patch".to_vec(),
            b"forbidden fail labels".to_vec(),
            b"forbidden pass labels".to_vec(),
            b"forbidden interface".to_vec(),
            b"mit".to_vec(),
            b"install config".to_vec(),
            b"forbidden metadata".to_vec(),
        ];
        let mut string_index = 0;
        let mut column_index = 0;
        while let Some(mut column) = row_group.next_column().unwrap() {
            if column_index == 7 {
                column
                    .typed::<Int64Type>()
                    .write_batch(&[42], Some(&[1]), None)
                    .unwrap();
            } else {
                let bytes = string_values
                    .get(string_index)
                    .cloned()
                    .unwrap_or_else(|| b"forbidden injected field".to_vec());
                let value = ByteArray::from(bytes);
                column
                    .typed::<ByteArrayType>()
                    .write_batch(&[value], Some(&[1]), None)
                    .unwrap();
                string_index += 1;
            }
            column.close().unwrap();
            column_index += 1;
        }
        row_group.close().unwrap();
        writer.close().unwrap();
    }
}
