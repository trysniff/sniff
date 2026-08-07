use super::{compact_output, go_executable_name, parse_go_origin_hash, parse_json_string};

#[test]
fn json_integrity_values_must_be_strings() {
    assert_eq!(
        parse_json_string(br#""sha512-example""#, "integrity").unwrap(),
        "sha512-example"
    );
    assert!(parse_json_string(br#"{"integrity":"wrong-shape"}"#, "integrity").is_err());
}

#[test]
fn command_output_is_bounded_and_compacted() {
    let output = compact_output(b"one\n two\tthree");
    assert_eq!(output, "one two three");
    let long = compact_output(&vec![b'x'; 500]);
    assert_eq!(long.len(), 403);
    assert!(long.ends_with("..."));
}

#[test]
fn go_installation_uses_the_native_executable_name() {
    let expected = if cfg!(windows) { "go.exe" } else { "go" };
    assert_eq!(go_executable_name().to_string_lossy(), expected);
}

#[test]
fn go_module_metadata_accepts_a_json_stream_and_selects_the_pinned_module() {
    let metadata = br#"{"Path":"dependency","Origin":{"Hash":"wrong"}}
{"Path":"github.com/scip-code/scip-go","Origin":{"Hash":"expected"}}"#;
    assert_eq!(
        parse_go_origin_hash(metadata, "github.com/scip-code/scip-go").unwrap(),
        "expected"
    );
}
