use super::*;
use std::os::windows::process::ExitStatusExt;

fn fixture() -> (
    tempfile::TempDir,
    PathBuf,
    PathBuf,
    PathBuf,
    Binding,
    PathBuf,
) {
    let owner = tempfile::tempdir().unwrap();
    let sdk = owner.path().join("sdk");
    let repo = owner.path().join("repository");
    let base = owner.path().join("cache");
    fs::create_dir_all(sdk.join("bin")).unwrap();
    fs::create_dir(&repo).unwrap();
    fs::write(sdk.join("bin/go.exe"), b"fixture driver: not executed").unwrap();
    let input = binding(&sdk.join("bin/go.exe"), &sdk).unwrap();
    let parent =
        cache::prepare_parent(&base, &canonical(&repo).unwrap(), &canonical(&sdk).unwrap())
            .unwrap();
    let root = parent
        .path
        .join(digest(&serde_json::to_vec(&input).unwrap()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::write(
        root.join("bin/go.exe"),
        b"fixture adapted driver: not executed",
    )
    .unwrap();
    let output = crate::bounded_process::BoundedOutput {
        status: std::process::ExitStatus::from_raw(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_sha256: digest(b""),
        stderr_sha256: digest(b""),
        stdout_byte_count: 0,
        stderr_byte_count: 0,
        timed_out: false,
        stdout_truncated: false,
        stderr_truncated: false,
    };
    cache::seal(&root, &input, &output).unwrap();
    (owner, sdk, repo, base, input, root)
}

#[test]
fn verified_cache_hit_preserves_exact_selected_sdk_binding() {
    let (_owner, sdk, repo, base, input, root) = fixture();
    let adapted = prepare_at(&sdk.join("bin/go.exe"), &sdk, &repo, &base).unwrap();
    assert_eq!(adapted.executable, root.join("bin/go.exe"));
    assert_eq!(cache::verify(&root, &input).unwrap().record, adapted.record);
}

#[test]
fn every_binding_dimension_invalidates_a_cached_driver() {
    let (_owner, _sdk, _repo, _base, input, root) = fixture();
    for dimension in 0..5 {
        let mut changed = input.clone();
        let value = match dimension {
            0 => &mut changed.contract,
            1 => &mut changed.platform,
            2 => &mut changed.original_driver_sha256,
            3 => &mut changed.sdk_sha256,
            _ => &mut changed.recipe_sha256,
        };
        value.push('x');
        assert!(
            cache::verify(&root, &changed).is_err(),
            "dimension {dimension}"
        );
    }
}

#[test]
fn corrupt_existing_output_is_rejected_without_rebuilding_or_fallback() {
    let (_owner, sdk, repo, base, _input, root) = fixture();
    fs::write(root.join("bin/go.exe"), b"corrupt").unwrap();
    assert!(prepare_at(&sdk.join("bin/go.exe"), &sdk, &repo, &base).is_err());
    assert_eq!(fs::read(root.join("bin/go.exe")).unwrap(), b"corrupt");
}

#[test]
fn added_companion_or_incomplete_record_is_not_trusted() {
    for added in [true, false] {
        let (_owner, sdk, repo, base, _input, root) = fixture();
        if added {
            fs::write(root.join("bin/extra.dll"), b"unapproved").unwrap();
        } else {
            fs::write(root.join("adapter.json"), b"{}").unwrap();
        }
        assert!(prepare_at(&sdk.join("bin/go.exe"), &sdk, &repo, &base).is_err());
    }
}

#[test]
fn sdk_driver_and_cache_cannot_be_repository_controlled() {
    let (owner, sdk, repo, _base, _input, _root) = fixture();
    assert!(
        prepare_at(
            &sdk.join("bin/go.exe"),
            &sdk,
            &repo,
            &repo.join("new-cache")
        )
        .is_err()
    );
    assert!(!repo.join("new-cache").exists());
    assert!(prepare_at(&sdk.join("bin/go.exe"), &sdk, &repo, &sdk.join("new-cache")).is_err());
    assert!(!sdk.join("new-cache").exists());
    let alternate = owner.path().join("alternate.exe");
    fs::copy(sdk.join("bin/go.exe"), &alternate).unwrap();
    assert!(prepare_at(&alternate, &sdk, &repo, &owner.path().join("other-cache")).is_err());
    assert!(
        prepare_at(
            &sdk.join("bin/go.exe"),
            &sdk,
            &repo,
            Path::new("relative-cache")
        )
        .is_err()
    );
    let nested_repo = sdk.join("nested-repository");
    fs::create_dir(&nested_repo).unwrap();
    assert!(
        prepare_at(
            &sdk.join("bin/go.exe"),
            &sdk,
            &nested_repo,
            &owner.path().join("new-cache")
        )
        .is_err()
    );
    assert!(!owner.path().join("new-cache").exists());
}

#[test]
#[ignore = "requires installed Go SDK source; executes the real normal adapter producer"]
fn real_selected_sdk_adapter_is_produced_once_and_reused_verified() {
    let go = std::env::split_paths(&std::env::var_os("PATH").expect("Go must be installed"))
        .map(|path| path.join("go.exe"))
        .find(|path| path.is_file())
        .expect("Go must be installed");
    let repo = tempfile::tempdir().unwrap();
    let goroot = discover_goroot(&go, repo.path()).unwrap();
    let base = tempfile::tempdir().unwrap();
    let first = prepare_at(&go, &goroot, repo.path(), base.path()).unwrap();
    let record = fs::read(&first.record).unwrap();
    let timestamp = fs::metadata(&first.executable).unwrap().modified().unwrap();
    let second = prepare_at(&go, &goroot, repo.path(), base.path()).unwrap();
    assert_eq!(first.executable, second.executable);
    assert_eq!(record, fs::read(&second.record).unwrap());
    assert_eq!(
        timestamp,
        fs::metadata(&second.executable)
            .unwrap()
            .modified()
            .unwrap()
    );
    assert_eq!(
        fs::read_dir(base.path().join("go-runtime-adapters-v1"))
            .unwrap()
            .count(),
        1
    );
    let mut command = Command::new(&second.executable);
    build::control_environment(&mut command);
    command.arg("version").env("GOROOT", &goroot);
    let result = crate::bounded_process::run(&mut command, Duration::from_secs(30)).unwrap();
    assert!(
        !result.timed_out && result.status.success(),
        "real adapted driver must execute"
    );
    let executable = second.executable.clone();
    drop(first);
    drop(second);
    fs::write(executable, b"corrupt owned cached driver").unwrap();
    assert!(prepare_at(&go, &goroot, repo.path(), base.path()).is_err());
}

#[test]
fn matching_record_does_not_authorize_shared_writable_cache_entries() {
    for relative in ["", "bin", "bin/go.exe", "adapter.json"] {
        let (_owner, sdk, repo, base, input, root) = fixture();
        security::make_shared_writable_for_test(&root.join(relative));
        assert!(
            cache::verify(&root, &input).is_err(),
            "shared-writable {relative}"
        );
        assert!(prepare_at(&sdk.join("bin/go.exe"), &sdk, &repo, &base).is_err());
    }
}

#[test]
fn shared_writable_namespace_is_not_adopted_or_repaired() {
    let (_owner, sdk, repo, base, _input, root) = fixture();
    security::make_shared_writable_for_test(root.parent().unwrap());
    let before = fs::read(root.join("adapter.json")).unwrap();
    assert!(prepare_at(&sdk.join("bin/go.exe"), &sdk, &repo, &base).is_err());
    assert_eq!(before, fs::read(root.join("adapter.json")).unwrap());
}

#[test]
fn verified_adapter_lease_prevents_ancestor_replacement_and_output_mutation() {
    let (_owner, sdk, repo, base, _input, root) = fixture();
    let adapted = prepare_at(&sdk.join("bin/go.exe"), &sdk, &repo, &base).unwrap();
    assert!(fs::rename(&base, base.with_extension("moved")).is_err());
    assert!(fs::write(&adapted.executable, b"replace after verification").is_err());
    assert!(fs::write(&adapted.record, b"replace after verification").is_err());
    drop(adapted);
    fs::write(root.join("bin/go.exe"), b"lease released").unwrap();
}

#[test]
fn protected_namespace_allows_owned_atomic_publication() {
    let (_owner, sdk, repo, base, _input, _root) = fixture();
    let namespace =
        cache::prepare_parent(&base, &canonical(&repo).unwrap(), &canonical(&sdk).unwrap())
            .unwrap();
    let stage = namespace.path.join("owned-stage");
    fs::create_dir(&stage).unwrap();
    fs::write(stage.join("owned-output"), b"owned").unwrap();
    let published = namespace.path.join("owned-published");
    let old_read_only_directory_lease = security::lock_base(&namespace.path, false).unwrap();
    assert!(fs::rename(&stage, &published).is_err());
    drop(old_read_only_directory_lease);
    fs::rename(&stage, &published).unwrap();
    assert_eq!(fs::read(published.join("owned-output")).unwrap(), b"owned");
    assert!(fs::rename(&base, base.with_extension("moved")).is_err());
}

#[test]
fn repository_owned_driver_is_rejected_before_sdk_discovery_execution() {
    let (_owner, sdk, _repo, _base, _input, _root) = fixture();
    let error = discover_goroot(&sdk.join("bin/go.exe"), &sdk).unwrap_err();
    assert_eq!(
        error,
        "selected Go driver must be outside the repository before SDK discovery"
    );
}
