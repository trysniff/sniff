#![cfg(feature = "sniffbench-frame")]

use parquet::basic::Compression;
use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use sniff::benchmark::visit_historical_v2_projected_shard;
use std::fs::File;
use std::path::Path;
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
fn projects_only_the_protocol_allowlist() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixture.parquet");
    write_fixture(&path, DATASET_SCHEMA);

    let mut rows = Vec::new();
    let count = visit_historical_v2_projected_shard(&path, 2, 10, |row| {
        rows.push(row);
        Ok(())
    })
    .unwrap();

    assert_eq!(count, 1);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.source_shard_index, 2);
    assert_eq!(row.source_row_index, 0);
    assert_eq!(row.global_row_index, 10);
    assert_eq!(row.base_commit, "a".repeat(40));
    assert_eq!(row.instance_id, "owner__repo-42");
    assert_eq!(row.pull_number, 42);
    assert_eq!(row.repo, "owner/repo");
    assert_eq!(row.license, "mit");
}

#[test]
fn rejects_an_unlisted_dataset_field() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("extra.parquet");
    let schema = DATASET_SCHEMA.replace(
        "\n}",
        "\n  OPTIONAL BYTE_ARRAY generated_reasoning (UTF8);\n}",
    );
    write_fixture(&path, &schema);

    let error = visit_historical_v2_projected_shard(&path, 0, 0, |_| Ok(())).unwrap_err();
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
        b"diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,2 +1 @@\n-a\n-b\n+a\n".to_vec(),
        b"forbidden description".to_vec(),
        vec![0xff, 0xfe, 0xfd],
        b"owner/repo".to_vec(),
        b"forbidden test patch".to_vec(),
        b"forbidden fail labels".to_vec(),
        b"forbidden pass labels".to_vec(),
        b"forbidden interface".to_vec(),
        b"mit".to_vec(),
        b"forbidden install config".to_vec(),
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
                .unwrap_or_else(|| b"forbidden extra field".to_vec());
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
