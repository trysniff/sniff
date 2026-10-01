use super::*;

const PACKAGE: &str = r#"{"Dir":"/repo/api","ImportPath":"example.com/api","Name":"api","GoFiles":["api.go"],"CgoFiles":[],"IgnoredGoFiles":["windows.go"],"Module":{"Path":"example.com","Version":"","Dir":"/repo","GoMod":"/repo/go.mod","Main":true},"Incomplete":false,"Error":null}"#;

fn decode(stdout: &[u8]) -> Result<Vec<GoListPackage>, String> {
    parse_go_list_packages(stdout).collect()
}

#[test]
fn shared_go_projection_preserves_the_original_serialized_field_contract() {
    assert_eq!(
        canonical_go_list_projection(PACKAGE).unwrap(),
        [PACKAGE.as_bytes()]
    );
}

#[test]
fn shared_go_decoder_accepts_complete_concatenated_objects() {
    let stdout = format!(
        "{PACKAGE}\n{}\n",
        PACKAGE.replace("example.com/api", "example.com/second")
    );
    let packages = decode(stdout.as_bytes()).unwrap();
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].import_path, "example.com/api");
    assert_eq!(packages[1].import_path, "example.com/second");
    assert_eq!(packages[0].go_files, ["api.go"]);
    assert_eq!(packages[0].ignored_go_files, ["windows.go"]);
}

#[test]
fn shared_go_projection_does_not_depend_on_package_emission_order() {
    let second = PACKAGE.replace("example.com/api", "example.com/second");
    assert_eq!(
        canonical_go_list_projection(&format!("{PACKAGE}{second}")).unwrap(),
        canonical_go_list_projection(&format!("{second}{PACKAGE}")).unwrap(),
    );
}

#[test]
fn shared_go_decoder_rejects_truncated_and_nonobject_output() {
    for stdout in [
        format!("{PACKAGE}{{"),
        format!("{PACKAGE} garbage"),
        "[]".to_string(),
        "null".to_string(),
    ] {
        assert!(decode(stdout.as_bytes()).is_err(), "{stdout}");
    }
    assert!(decode(&[0xff]).is_err());
}

#[test]
fn shared_go_decoder_rejects_missing_and_repeated_identity_fields() {
    let missing = PACKAGE.replace(r#""ImportPath":"example.com/api","#, "");
    let repeated = PACKAGE.replace(r#""Name":"api""#, r#""Name":"api","Name":"second""#);
    assert!(decode(missing.as_bytes()).is_err());
    assert!(decode(repeated.as_bytes()).is_err());
}

#[test]
fn shared_go_decoder_retains_rejections_without_calling_them_successes() {
    let stdout = PACKAGE.replace(
        r#""Incomplete":false,"Error":null"#,
        r#""Incomplete":true,"Error":{"Err":"build rejected"}"#,
    );
    let [package] = decode(stdout.as_bytes()).unwrap().try_into().unwrap();
    assert!(package.incomplete);
    assert_eq!(package.error.unwrap().message, "build rejected");
}

#[test]
fn shared_go_decoder_accepts_an_empty_compiler_package_set() {
    assert!(decode(b" \n").unwrap().is_empty());
    assert!(canonical_go_list_projection("").unwrap().is_empty());
}

#[test]
fn shared_go_decoder_streams_packages_without_hiding_malformed_tails() {
    let stdout = format!("{PACKAGE}{{");
    let mut packages = parse_go_list_packages(stdout.as_bytes());
    assert_eq!(
        packages.next().unwrap().unwrap().import_path,
        "example.com/api"
    );
    assert!(packages.next().unwrap().is_err());
    assert!(packages.next().is_none());
    assert!(canonical_go_list_projection(&stdout).is_err());
}

#[test]
fn shared_go_decoder_preserves_omitted_defaults_and_null_contracts() {
    let stdout = r#"{"Dir":"/repo/api","ImportPath":"example.com/api","Name":"api"}"#;
    let packages = decode(stdout.as_bytes()).unwrap();
    let package = &packages[0];
    assert!(package.go_files.is_empty());
    assert!(package.cgo_files.is_empty());
    assert!(package.ignored_go_files.is_empty());
    assert!(package.module.is_none());
    assert!(package.error.is_none());
    assert!(!package.incomplete);
    assert!(
        decode(
            PACKAGE
                .replace(r#""GoFiles":["api.go"]"#, r#""GoFiles":null"#)
                .as_bytes()
        )
        .is_err()
    );

    let omitted = PACKAGE.replace(r#""Version":"","#, "");
    assert_eq!(
        canonical_go_list_projection(&omitted).unwrap(),
        [PACKAGE.as_bytes()]
    );
    let omitted_main = PACKAGE.replace(r#","Main":true"#, "");
    assert!(
        !decode(omitted_main.as_bytes()).unwrap()[0]
            .module
            .as_ref()
            .unwrap()
            .main
    );
}

#[test]
fn shared_go_query_and_architecture_keep_frozen_benchmark_encodings() {
    assert_eq!(
        serde_json::to_string(&GoCompilerQuery::ModulePackages).unwrap(),
        r#"{"kind":"module_packages"}"#
    );
    assert_eq!(
        serde_json::to_string(&GoCompilerArchitecture::Default).unwrap(),
        r#"{"kind":"default"}"#
    );
    let query = GoCompilerQuery::StandaloneSource {
        source_repository_path: "tools/generate.go".to_string(),
    };
    let architecture = GoCompilerArchitecture::Explicit {
        environment_variable: "GOAMD64".to_string(),
        value: "v3".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&query).unwrap(),
        r#"{"kind":"standalone_source","source_repository_path":"tools/generate.go"}"#
    );
    assert_eq!(
        serde_json::to_string(&architecture).unwrap(),
        r#"{"kind":"explicit","environment_variable":"GOAMD64","value":"v3"}"#
    );
    assert_eq!(
        serde_json::from_str::<GoCompilerQuery>(&serde_json::to_string(&query).unwrap()).unwrap(),
        query
    );
    assert_eq!(
        serde_json::from_str::<GoCompilerArchitecture>(
            &serde_json::to_string(&architecture).unwrap()
        )
        .unwrap(),
        architecture
    );
}
