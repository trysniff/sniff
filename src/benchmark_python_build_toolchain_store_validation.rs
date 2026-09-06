use super::super::python_build_requirement::{
    validate_python_build_requirement, validate_python_package_index,
};
use super::files::*;
use super::*;

pub(super) fn seal_entry(
    request: &PythonBuildToolchainRequest,
    root: &Path,
) -> Result<PreparedPythonBuildToolchain, String> {
    validate_request(request)?;
    validate_prepared_root(root)?;
    let lock = root.join(LOCK_NAME);
    let requirements_contract_path = root.join(REQUIREMENTS_NAME);
    let provenance_path = root.join(PROVENANCE_NAME);
    let wheelhouse = root.join(WHEELHOUSE_NAME);
    let lock_bytes = read_bounded_regular_file(&lock, MAX_LOCK_BYTES, "requirements lock")?;
    let request_sha256 = request_sha256(request)?;
    let lock_sha256 = sha256(&lock_bytes);
    let requirements_contract_bytes =
        read_requirements_contract(&requirements_contract_path, request)?;
    let requirements_contract_sha256 = sha256(&requirements_contract_bytes);
    let provenance_bytes = read_wheelhouse_provenance(&provenance_path, &wheelhouse, &lock_bytes)?;
    let provenance_sha256 = sha256(&provenance_bytes);
    let wheelhouse_tree_sha256 = hash_tree(&wheelhouse)?;
    let toolchain_identity_sha256 = hash_json(&(
        STORE_CONTRACT,
        &request_sha256,
        &lock_sha256,
        &requirements_contract_sha256,
        &provenance_sha256,
        &wheelhouse_tree_sha256,
    ))?;
    let record = PythonBuildToolchainRecord {
        version: 1,
        contract: STORE_CONTRACT.to_string(),
        request_sha256,
        request: request.clone(),
        lock_sha256,
        requirements_contract_sha256,
        provenance_sha256,
        wheelhouse_tree_sha256,
        toolchain_identity_sha256,
    };
    write_record(&root.join(RECORD_NAME), &record)?;
    verify_entry(request, root)
}

pub(super) fn verify_entry(
    request: &PythonBuildToolchainRequest,
    root: &Path,
) -> Result<PreparedPythonBuildToolchain, String> {
    validate_request(request)?;
    let record_path = root.join(RECORD_NAME);
    let record_bytes = read_bounded_regular_file(&record_path, MAX_RECORD_BYTES, "record")?;
    let record: PythonBuildToolchainRecord =
        serde_json::from_slice(&record_bytes).map_err(|error| {
            format!(
                "Python build-toolchain record is corrupt at {}: {error}",
                record_path.display()
            )
        })?;
    let expected_request_sha256 = request_sha256(request)?;
    if record.version != 1
        || record.contract != STORE_CONTRACT
        || record.request_sha256 != expected_request_sha256
        || record.request != *request
    {
        return Err(format!(
            "Python build-toolchain request identity mismatch at {}",
            root.display()
        ));
    }
    let lock = root.join(LOCK_NAME);
    let requirements_contract_path = root.join(REQUIREMENTS_NAME);
    let provenance_path = root.join(PROVENANCE_NAME);
    let wheelhouse = root.join(WHEELHOUSE_NAME);
    let lock_bytes = read_bounded_regular_file(&lock, MAX_LOCK_BYTES, "requirements lock")?;
    let lock_sha256 = sha256(&lock_bytes);
    let requirements_contract_bytes =
        read_requirements_contract(&requirements_contract_path, request)?;
    let requirements_contract_sha256 = sha256(&requirements_contract_bytes);
    let provenance_bytes = read_wheelhouse_provenance(&provenance_path, &wheelhouse, &lock_bytes)?;
    let provenance_sha256 = sha256(&provenance_bytes);
    let wheelhouse_tree_sha256 = hash_tree(&wheelhouse)?;
    let identity_sha256 = hash_json(&(
        STORE_CONTRACT,
        &expected_request_sha256,
        &lock_sha256,
        &requirements_contract_sha256,
        &provenance_sha256,
        &wheelhouse_tree_sha256,
    ))?;
    if record.lock_sha256 != lock_sha256
        || record.requirements_contract_sha256 != requirements_contract_sha256
        || record.provenance_sha256 != provenance_sha256
        || record.wheelhouse_tree_sha256 != wheelhouse_tree_sha256
        || record.toolchain_identity_sha256 != identity_sha256
    {
        return Err(format!(
            "Python build-toolchain checksum mismatch at {}",
            root.display()
        ));
    }
    Ok(PreparedPythonBuildToolchain {
        root: root.to_path_buf(),
        lock,
        requirements_contract: requirements_contract_path,
        provenance: provenance_path,
        wheelhouse,
        identity_sha256,
    })
}

fn validate_request(request: &PythonBuildToolchainRequest) -> Result<(), String> {
    if !is_sha256(&request.manifest_source_sha256)
        || !is_sha256(&request.python_runtime_identity_sha256)
        || !is_sha256(&request.pip_runtime_identity_sha256)
        || request.repository_revision.trim().is_empty()
        || request.build_backend.trim().is_empty()
        || request.target_platform.trim().is_empty()
    {
        return Err("Python build-toolchain request is incomplete or unsafe".to_string());
    }
    validate_python_package_index(&request.package_index)?;
    for requirement in &request.build_requirements {
        validate_python_build_requirement(requirement)?;
    }
    validate_relative_path(
        Path::new(&request.manifest_repository_path),
        "distribution manifest",
    )?;
    for path in &request.backend_path {
        if path != "." {
            validate_relative_path(Path::new(path), "backend path")?;
        }
    }
    Ok(())
}

pub(super) fn validate_prepared_root(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        format!(
            "failed to inspect prepared Python build toolchain {}: {error}",
            root.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "prepared Python build toolchain is not a regular directory: {}",
            root.display()
        ));
    }
    let mut names = fs::read_dir(root)
        .map_err(|error| format!("failed to list prepared Python build toolchain: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("failed to list prepared Python build toolchain: {error}"))
                .and_then(|entry| {
                    entry.file_name().into_string().map_err(|_| {
                        "prepared Python build toolchain contains a non-UTF-8 name".to_string()
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    let mut expected = vec![
        LOCK_NAME.to_string(),
        PROVENANCE_NAME.to_string(),
        REQUIREMENTS_NAME.to_string(),
        WHEELHOUSE_NAME.to_string(),
    ];
    expected.sort();
    if names != expected {
        return Err("prepared Python build toolchain has an unexpected layout".to_string());
    }
    read_bounded_regular_file(&root.join(LOCK_NAME), MAX_LOCK_BYTES, "requirements lock")?;
    read_bounded_regular_file(
        &root.join(REQUIREMENTS_NAME),
        MAX_LOCK_BYTES,
        "requirements contract",
    )?;
    read_bounded_regular_file(
        &root.join(PROVENANCE_NAME),
        MAX_LOCK_BYTES,
        "wheelhouse provenance",
    )?;
    let wheelhouse = root.join(WHEELHOUSE_NAME);
    let wheelhouse_metadata = fs::symlink_metadata(&wheelhouse).map_err(|error| {
        format!(
            "prepared Python wheelhouse is missing at {}: {error}",
            wheelhouse.display()
        )
    })?;
    if !wheelhouse_metadata.is_dir() || wheelhouse_metadata.file_type().is_symlink() {
        return Err(format!(
            "prepared Python wheelhouse is not a regular directory: {}",
            wheelhouse.display()
        ));
    }
    Ok(())
}

fn read_requirements_contract(
    path: &Path,
    request: &PythonBuildToolchainRequest,
) -> Result<Vec<u8>, String> {
    let bytes = read_bounded_regular_file(path, MAX_LOCK_BYTES, "requirements contract")?;
    let contract: PythonBuildRequirementsContract =
        serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "Python build-toolchain requirements contract is corrupt at {}: {error}",
                path.display()
            )
        })?;
    if contract.static_requirements != request.build_requirements {
        return Err(format!(
            "Python build-toolchain requirements contract changed at {}",
            path.display()
        ));
    }
    for requirement in &contract.dynamic_requirements {
        validate_python_build_requirement(requirement)?;
    }
    Ok(bytes)
}

fn read_wheelhouse_provenance(
    path: &Path,
    wheelhouse: &Path,
    lock_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let bytes = read_bounded_regular_file(path, MAX_LOCK_BYTES, "wheelhouse provenance")?;
    let provenance: PythonWheelhouseProvenance =
        serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "Python wheelhouse provenance is corrupt at {}: {error}",
                path.display()
            )
        })?;
    if provenance.version != 1 || provenance.contract != WHEELHOUSE_CONTRACT {
        return Err(format!(
            "Python wheelhouse provenance contract changed at {}",
            path.display()
        ));
    }
    if provenance.artifacts.len() > MAX_TREE_FILES {
        return Err(format!(
            "Python wheelhouse exceeds {MAX_TREE_FILES} artifacts"
        ));
    }
    if provenance
        .artifacts
        .windows(2)
        .any(|pair| pair[0].name >= pair[1].name)
    {
        return Err("Python wheelhouse artifacts are not uniquely name-sorted".to_string());
    }

    let metadata = fs::symlink_metadata(wheelhouse).map_err(|error| {
        format!(
            "failed to inspect Python wheelhouse {}: {error}",
            wheelhouse.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "Python wheelhouse is not a regular directory: {}",
            wheelhouse.display()
        ));
    }

    let mut expected_names = Vec::with_capacity(provenance.artifacts.len());
    let mut total_bytes = 0_u64;
    let mut expected_lock = String::new();
    for artifact in &provenance.artifacts {
        validate_wheel_artifact(artifact)?;
        let wheel = wheelhouse.join(&artifact.filename);
        let wheel_metadata = fs::symlink_metadata(&wheel).map_err(|error| {
            format!(
                "failed to inspect Python wheel {}: {error}",
                wheel.display()
            )
        })?;
        if !wheel_metadata.is_file()
            || wheel_metadata.file_type().is_symlink()
            || wheel_metadata.len() != artifact.size
        {
            return Err(format!(
                "Python wheel size or file type changed: {}",
                wheel.display()
            ));
        }
        total_bytes = total_bytes.saturating_add(artifact.size);
        if total_bytes > MAX_TREE_BYTES {
            return Err(format!("Python wheelhouse exceeds {MAX_TREE_BYTES} bytes"));
        }
        if hash_regular_file(&wheel)? != artifact.sha256 {
            return Err(format!(
                "Python wheel checksum changed: {}",
                wheel.display()
            ));
        }
        expected_names.push(artifact.filename.clone());
        expected_lock.push_str(&format!(
            "{}=={} --hash=sha256:{}\n",
            artifact.name, artifact.version, artifact.sha256
        ));
    }
    if lock_bytes != expected_lock.as_bytes() {
        return Err("Python requirements lock does not match wheelhouse provenance".to_string());
    }

    let mut actual_names = fs::read_dir(wheelhouse)
        .map_err(|error| format!("failed to list Python wheelhouse: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("failed to list Python wheelhouse: {error}"))
                .and_then(|entry| {
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| "Python wheelhouse contains a non-UTF-8 filename".to_string())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    actual_names.sort();
    expected_names.sort();
    if actual_names != expected_names {
        return Err("Python wheelhouse files do not match provenance".to_string());
    }
    Ok(bytes)
}

fn validate_wheel_artifact(artifact: &PythonWheelArtifact) -> Result<(), String> {
    let canonical_name = !artifact.name.is_empty()
        && artifact
            .name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && artifact
            .name
            .bytes()
            .next()
            .is_some_and(|byte| byte != b'-')
        && artifact
            .name
            .bytes()
            .last()
            .is_some_and(|byte| byte != b'-')
        && !artifact.name.contains("--");
    let safe_version = !artifact.version.is_empty()
        && artifact.version.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'!' | b'+' | b'-' | b'_')
        });
    let filename = Path::new(&artifact.filename);
    let safe_filename = artifact.filename.is_ascii()
        && filename.components().count() == 1
        && filename
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("whl"));
    if !canonical_name
        || !safe_version
        || !safe_filename
        || !is_sha256(&artifact.sha256)
        || artifact.size == 0
    {
        return Err("Python wheelhouse provenance contains an unsafe artifact".to_string());
    }
    validate_relative_path(filename, "wheel filename")
}

pub(super) fn request_sha256(request: &PythonBuildToolchainRequest) -> Result<String, String> {
    hash_json(&(STORE_CONTRACT, request))
}
