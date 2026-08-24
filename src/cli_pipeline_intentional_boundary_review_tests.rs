use super::*;

fn missing_inputs<'a>(
    checkout: &'a Path,
    output: &'a Path,
) -> IntentionalBoundarySourceBundleInputs<'a> {
    IntentionalBoundarySourceBundleInputs {
        policy_path: "missing-policy",
        population_path: "missing-population",
        blind_seal_path: "missing-blind-seal",
        protocol_path: "missing-protocol",
        task_path: "missing-task",
        frame_path: "missing-frame",
        state_directory: "missing-state",
        checkout_directory: checkout.to_str().unwrap(),
        output_directory: output.to_str().unwrap(),
    }
}

#[test]
fn existing_bundle_fails_before_inputs_or_checkout_are_touched() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("source-bundle");
    fs::create_dir(&output).unwrap();
    let checkout = root.path().join("checkouts");

    let error =
        prepare_intentional_boundary_source_bundle(missing_inputs(&checkout, &output)).unwrap_err();

    assert_eq!(
        error.downcast_ref::<IoError>().unwrap().kind(),
        ErrorKind::AlreadyExists
    );
    assert!(!checkout.exists());
}

#[test]
fn missing_bundle_parent_fails_before_inputs_or_checkout_are_touched() {
    let root = tempfile::tempdir().unwrap();
    let checkout = root.path().join("checkouts");
    let output = root.path().join("missing").join("source-bundle");

    let error =
        prepare_intentional_boundary_source_bundle(missing_inputs(&checkout, &output)).unwrap_err();

    assert_eq!(
        error.downcast_ref::<IoError>().unwrap().kind(),
        ErrorKind::NotFound
    );
    assert!(!checkout.exists());
}

#[test]
fn resumable_checkout_root_rejects_uncommitted_entries() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("unexpected"), b"preserve").unwrap();
    let selected = BTreeSet::from([1]);

    let error = inspect_checkout_root(root.path().to_str().unwrap(), &selected).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert!(error.to_string().contains("unexpected entry"));
    assert_eq!(
        fs::read(root.path().join("unexpected")).unwrap(),
        b"preserve"
    );
}

#[test]
fn source_bundle_roots_must_be_disjoint() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let checkout = state.join("checkouts");
    fs::create_dir(&state).unwrap();
    let state = fs::canonicalize(state).unwrap();
    let checkout = inspect_checkout_root(checkout.to_str().unwrap(), &BTreeSet::new()).unwrap();
    let output = root.path().join("source-bundle");

    let error = reject_overlapping_roots(&state, &checkout, &output).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert!(error.to_string().contains("must be disjoint"));
    assert!(!checkout.exists());
    assert!(!output.exists());
}
