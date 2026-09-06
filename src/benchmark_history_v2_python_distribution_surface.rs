use super::intentional_boundary_inventory::{
    read_intentional_boundary_git_blob_typed,
    validate_intentional_boundary_repository_inventory_typed,
};
use super::{
    BoundaryGitEntryKind, HISTORICAL_V2_PYTHON_DISTRIBUTION_SURFACE_CENSUS_SCHEMA_VERSION,
    HistoricalV2PythonBuildRequirement, HistoricalV2PythonDistribution,
    HistoricalV2PythonDistributionModule, HistoricalV2PythonDistributionSurfaceCensus,
    HistoricalV2PythonModuleKind, HistoricalV2PythonWheelRoot,
    IntentionalBoundaryRepositoryInventory,
};
use base64::Engine;
use pep440_rs::Version;
use serde::Serialize;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Component, Path};
use std::str::FromStr;

const PYTHON_DISTRIBUTION_SURFACE_CONTRACT: &str =
    "sniffbench-historical-v2-python-distribution-surfaces-v1";
pub(super) const PYTHON_WHEEL_BUILD_COMMAND_CONTRACT: &str =
    "pep517-wheel-isolated-python-offline-v1";
const MAX_WHEEL_MEMBER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_WHEEL_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

#[path = "benchmark_history_v2_python_distribution_surface_runtime.rs"]
mod runtime;

pub(in crate::benchmark::release) use runtime::{
    census_historical_v2_python_distribution_surfaces,
    validate_historical_v2_python_distribution_surface_census_commitment,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PythonWheelBuildOutput {
    pub(super) toolchain_identity_sha256: String,
    pub(super) wheel_filename: String,
    pub(super) wheel_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedPythonDistributionManifest {
    repository_path: String,
    object_id: String,
    source_sha256: String,
    build_backend: String,
    backend_path: Vec<String>,
    build_requirements: Vec<HistoricalV2PythonBuildRequirement>,
}

#[derive(Debug)]
struct ParsedWheel {
    distribution_name: String,
    normalized_distribution_name: String,
    distribution_version: String,
    wheel_root: HistoricalV2PythonWheelRoot,
    metadata_member_path: String,
    wheel_metadata_member_path: String,
    record_member_path: String,
    modules: Vec<ParsedWheelModule>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ParsedWheelModule {
    import_name: String,
    kind: HistoricalV2PythonModuleKind,
    archive_member_path: Option<String>,
    installed_path: Option<String>,
    member_sha256: Option<String>,
    member_byte_length: Option<u64>,
}

pub(super) fn census_historical_v2_python_distribution_surfaces_with_executor<F>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    mut executor: F,
) -> Result<HistoricalV2PythonDistributionSurfaceCensus, String>
where
    F: FnMut(&Path, &str) -> Result<PythonWheelBuildOutput, String>,
{
    validate_intentional_boundary_repository_inventory_typed(repository, revision, root, inventory)
        .map_err(|error| error.detail)?;
    let manifests = python_distribution_manifests(root, inventory)?;
    let mut distributions = Vec::new();
    let mut modules = Vec::new();
    for manifest in manifests {
        let output = executor(root, &manifest.repository_path)?;
        if !is_sha256(&output.toolchain_identity_sha256) {
            return Err(format!(
                "Python wheel builder returned an invalid toolchain identity for {}",
                manifest.repository_path
            ));
        }
        let parsed = parse_wheel(&output.wheel_filename, &output.wheel_bytes)?;
        let wheel_sha256 = sha256(&output.wheel_bytes);
        let wheel_byte_length = u64::try_from(output.wheel_bytes.len())
            .map_err(|_| "Python wheel byte length exceeds u64".to_string())?;
        let distribution_id = hash_json(&(
            "sniffbench-historical-v2-python-distribution-v1",
            &manifest.repository_path,
            &manifest.object_id,
            &manifest.source_sha256,
            &manifest.build_backend,
            &manifest.backend_path,
            &manifest.build_requirements,
            &output.toolchain_identity_sha256,
            PYTHON_WHEEL_BUILD_COMMAND_CONTRACT,
            &output.wheel_filename,
            &wheel_sha256,
            wheel_byte_length,
            &parsed.distribution_name,
            &parsed.normalized_distribution_name,
            &parsed.distribution_version,
            parsed.wheel_root,
        ))
        .map(|hash| format!("h2pyd-v1:{hash}"))?;
        let module_start = modules.len();
        for parsed_module in parsed.modules {
            let surface_slot_id = python_module_surface_slot_id(
                &parsed.normalized_distribution_name,
                &parsed_module.import_name,
                parsed_module.kind,
            )?;
            let module_exposure_id = hash_json(&(
                "sniffbench-historical-v2-python-module-exposure-v1",
                &distribution_id,
                &surface_slot_id,
                &parsed_module.archive_member_path,
                &parsed_module.installed_path,
                &parsed_module.member_sha256,
                parsed_module.member_byte_length,
            ))
            .map(|hash| format!("h2pyme-v1:{hash}"))?;
            modules.push(HistoricalV2PythonDistributionModule {
                module_exposure_id,
                surface_slot_id,
                distribution_id: distribution_id.clone(),
                normalized_distribution_name: parsed.normalized_distribution_name.clone(),
                import_name: parsed_module.import_name.clone(),
                kind: parsed_module.kind,
                is_distribution_root: !parsed_module.import_name.contains('.'),
                archive_member_path: parsed_module.archive_member_path,
                installed_path: parsed_module.installed_path,
                member_sha256: parsed_module.member_sha256,
                member_byte_length: parsed_module.member_byte_length,
            });
        }
        distributions.push(HistoricalV2PythonDistribution {
            distribution_id,
            manifest_repository_path: manifest.repository_path,
            manifest_object_id: manifest.object_id,
            manifest_source_sha256: manifest.source_sha256,
            build_backend: manifest.build_backend,
            backend_path: manifest.backend_path,
            build_requirements: manifest.build_requirements,
            toolchain_identity_sha256: output.toolchain_identity_sha256,
            command_contract: PYTHON_WHEEL_BUILD_COMMAND_CONTRACT.to_string(),
            wheel_filename: output.wheel_filename,
            wheel_sha256,
            wheel_byte_length,
            distribution_name: parsed.distribution_name,
            normalized_distribution_name: parsed.normalized_distribution_name,
            distribution_version: parsed.distribution_version,
            wheel_root: parsed.wheel_root,
            metadata_member_path: parsed.metadata_member_path,
            wheel_metadata_member_path: parsed.wheel_metadata_member_path,
            record_member_path: parsed.record_member_path,
            module_count: modules.len() - module_start,
        });
    }
    distributions.sort();
    modules.sort();
    if distributions
        .windows(2)
        .any(|pair| pair[0].distribution_id == pair[1].distribution_id)
        || modules
            .windows(2)
            .any(|pair| pair[0].module_exposure_id == pair[1].module_exposure_id)
    {
        return Err("historical-v2 Python distribution surface census is non-unique".to_string());
    }
    let module_count_by_kind = modules.iter().fold(BTreeMap::new(), |mut counts, module| {
        *counts.entry(module.kind).or_insert(0) += 1;
        counts
    });
    let mut census = HistoricalV2PythonDistributionSurfaceCensus {
        schema_version: HISTORICAL_V2_PYTHON_DISTRIBUTION_SURFACE_CENSUS_SCHEMA_VERSION,
        contract: PYTHON_DISTRIBUTION_SURFACE_CONTRACT.to_string(),
        repository: inventory.repository.clone(),
        revision: inventory.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        distributions,
        modules,
        module_count_by_kind,
        census_sha256: String::new(),
    };
    census.census_sha256 = python_distribution_surface_census_sha256(&census)?;
    Ok(census)
}

fn validate_historical_v2_python_distribution_surface_census_with_executor<F>(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    census: &HistoricalV2PythonDistributionSurfaceCensus,
    executor: F,
) -> Result<(), String>
where
    F: FnMut(&Path, &str) -> Result<PythonWheelBuildOutput, String>,
{
    if census.schema_version != HISTORICAL_V2_PYTHON_DISTRIBUTION_SURFACE_CENSUS_SCHEMA_VERSION
        || census.contract != PYTHON_DISTRIBUTION_SURFACE_CONTRACT
        || census.repository != inventory.repository
        || census.revision != inventory.revision
        || census.inventory_sha256 != inventory.inventory_sha256
        || census.census_sha256 != python_distribution_surface_census_sha256(census)?
    {
        return Err("historical-v2 Python distribution surface commitment changed".to_string());
    }
    let counts = census
        .modules
        .iter()
        .fold(BTreeMap::new(), |mut counts, module| {
            *counts.entry(module.kind).or_insert(0) += 1;
            counts
        });
    if counts != census.module_count_by_kind
        || census
            .distributions
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || census.modules.windows(2).any(|pair| pair[0] >= pair[1])
        || census.distributions.iter().any(|distribution| {
            distribution.module_count
                != census
                    .modules
                    .iter()
                    .filter(|module| module.distribution_id == distribution.distribution_id)
                    .count()
        })
        || census.modules.iter().any(|module| {
            !census
                .distributions
                .iter()
                .any(|distribution| distribution.distribution_id == module.distribution_id)
        })
    {
        return Err("historical-v2 Python distribution surface commitment changed".to_string());
    }
    let expected = census_historical_v2_python_distribution_surfaces_with_executor(
        &inventory.repository,
        &inventory.revision,
        root,
        inventory,
        executor,
    )?;
    if census != &expected {
        return Err("historical-v2 Python distribution surface census changed".to_string());
    }
    Ok(())
}

fn python_distribution_manifests(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<Vec<ParsedPythonDistributionManifest>, String> {
    let mut manifests = Vec::new();
    for entry in inventory
        .tracked_entries
        .iter()
        .filter(|entry| entry.repository_path.rsplit('/').next() == Some("pyproject.toml"))
    {
        if entry.kind != BoundaryGitEntryKind::RegularBlob {
            return Err(format!(
                "historical-v2 Python project manifest is not a regular Git blob: {}",
                entry.repository_path
            ));
        }
        let byte_length = entry.byte_length.ok_or_else(|| {
            format!(
                "historical-v2 Python project manifest has no committed byte length: {}",
                entry.repository_path
            )
        })?;
        let bytes = read_intentional_boundary_git_blob_typed(root, &entry.object_id, byte_length)
            .map_err(|error| error.detail)?;
        let source = std::str::from_utf8(&bytes).map_err(|_| {
            format!(
                "historical-v2 Python project manifest is not UTF-8: {}",
                entry.repository_path
            )
        })?;
        if let Some(manifest) =
            parse_python_distribution_manifest(&entry.repository_path, &entry.object_id, source)?
        {
            manifests.push(manifest);
        }
    }
    manifests.sort_by(|left, right| left.repository_path.cmp(&right.repository_path));
    Ok(manifests)
}

fn parse_python_distribution_manifest(
    repository_path: &str,
    object_id: &str,
    source: &str,
) -> Result<Option<ParsedPythonDistributionManifest>, String> {
    let document = toml_edit::ImDocument::parse(source).map_err(|error| {
        format!("failed to parse Python project manifest {repository_path}: {error}")
    })?;
    let Some(build_system) = document.get("build-system") else {
        return Ok(None);
    };
    let table = build_system
        .as_table_like()
        .ok_or_else(|| format!("Python build-system must be a table in {repository_path}"))?;
    let build_backend = table
        .get("build-backend")
        .and_then(toml_edit::Item::as_str)
        .filter(|value| !value.trim().is_empty() && value.trim() == *value)
        .ok_or_else(|| {
            format!(
                "Python build-system.build-backend must be an explicit non-empty string in {repository_path}"
            )
        })?
        .to_string();
    let requires = table
        .get("requires")
        .and_then(toml_edit::Item::as_array)
        .ok_or_else(|| {
            format!("Python build-system.requires must be an explicit array in {repository_path}")
        })?;
    let build_requirements = requires
        .iter()
        .enumerate()
        .map(|(ordinal, value)| {
            let requirement = value
                .as_str()
                .filter(|value| !value.trim().is_empty() && value.trim() == *value)
                .ok_or_else(|| {
                    format!(
                        "Python build-system.requires[{ordinal}] is not an exact non-empty string in {repository_path}"
                    )
                })?;
            Ok(HistoricalV2PythonBuildRequirement {
                ordinal,
                requirement: requirement.to_string(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let backend_path = table
        .get("backend-path")
        .map(|item| {
            let values = item.as_array().ok_or_else(|| {
                format!("Python build-system.backend-path must be an array in {repository_path}")
            })?;
            values
                .iter()
                .enumerate()
                .map(|(ordinal, value)| {
                    let path = value.as_str().ok_or_else(|| {
                        format!(
                            "Python build-system.backend-path[{ordinal}] is not a string in {repository_path}"
                        )
                    })?;
                    validate_relative_manifest_path(path, repository_path)?;
                    Ok(path.to_string())
                })
                .collect::<Result<Vec<_>, String>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(Some(ParsedPythonDistributionManifest {
        repository_path: repository_path.to_string(),
        object_id: object_id.to_string(),
        source_sha256: sha256(source.as_bytes()),
        build_backend,
        backend_path,
        build_requirements,
    }))
}

fn validate_relative_manifest_path(path: &str, manifest: &str) -> Result<(), String> {
    if path == "." {
        return Ok(());
    }
    if path.is_empty()
        || path.contains('\\')
        || Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "Python build-system.backend-path escapes or is non-canonical in {manifest}: {path}"
        ));
    }
    Ok(())
}

fn parse_wheel(filename: &str, bytes: &[u8]) -> Result<ParsedWheel, String> {
    if !filename.ends_with(".whl")
        || Path::new(filename).file_name().and_then(|v| v.to_str()) != Some(filename)
    {
        return Err(format!(
            "Python wheel filename is unsafe or invalid: {filename}"
        ));
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("failed to parse Python wheel {filename}: {error}"))?;
    let mut members = BTreeMap::<String, Vec<u8>>::new();
    let mut seen_paths = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|error| format!("failed to read Python wheel member: {error}"))?;
        let name = file.name().to_string();
        validate_wheel_member_path(&name)?;
        if file.encrypted() {
            return Err(format!("Python wheel member is encrypted: {name}"));
        }
        if file.unix_mode().is_some_and(|mode| {
            let file_type = mode & 0o170000;
            file_type != 0 && file_type != 0o100000 && file_type != 0o040000
        }) {
            return Err(format!(
                "Python wheel member is not a regular file or directory: {name}"
            ));
        }
        if !seen_paths.insert(name.clone()) {
            return Err(format!("Python wheel repeats archive member: {name}"));
        }
        if file.is_dir() {
            continue;
        }
        let declared_size = file.size();
        if declared_size > MAX_WHEEL_MEMBER_BYTES {
            return Err(format!("Python wheel member exceeds size limit: {name}"));
        }
        total_bytes = total_bytes
            .checked_add(declared_size)
            .ok_or_else(|| "Python wheel expanded size overflowed".to_string())?;
        if total_bytes > MAX_WHEEL_TOTAL_BYTES {
            return Err("Python wheel expanded size exceeds limit".to_string());
        }
        let capacity = usize::try_from(declared_size)
            .map_err(|_| format!("Python wheel member is too large for this host: {name}"))?;
        let mut contents = Vec::with_capacity(capacity);
        file.read_to_end(&mut contents)
            .map_err(|error| format!("failed to decompress Python wheel member {name}: {error}"))?;
        if contents.len() as u64 != declared_size {
            return Err(format!(
                "Python wheel member size changed while reading: {name}"
            ));
        }
        members.insert(name, contents);
    }
    let metadata_member_path = unique_dist_info_member(&members, "METADATA")?;
    let wheel_metadata_member_path = unique_dist_info_member(&members, "WHEEL")?;
    let record_member_path = unique_dist_info_member(&members, "RECORD")?;
    let dist_info = metadata_member_path
        .strip_suffix("/METADATA")
        .ok_or_else(|| "Python wheel METADATA path changed".to_string())?;
    if wheel_metadata_member_path.strip_suffix("/WHEEL") != Some(dist_info)
        || record_member_path.strip_suffix("/RECORD") != Some(dist_info)
    {
        return Err("Python wheel metadata files use different dist-info directories".to_string());
    }
    verify_record(&members, &record_member_path)?;
    let metadata = parse_email_headers(
        members
            .get(&metadata_member_path)
            .ok_or_else(|| "Python wheel METADATA disappeared".to_string())?,
        "METADATA",
    )?;
    let distribution_name = unique_header(&metadata, "Metadata-Version", "METADATA")
        .and_then(|_| unique_header(&metadata, "Name", "METADATA"))?
        .to_string();
    let distribution_version = unique_header(&metadata, "Version", "METADATA")?.to_string();
    let normalized_distribution_name = normalize_distribution_name(&distribution_name)?;
    validate_wheel_filename(
        filename,
        &normalized_distribution_name,
        &distribution_version,
        dist_info,
    )?;
    let wheel = parse_email_headers(
        members
            .get(&wheel_metadata_member_path)
            .ok_or_else(|| "Python wheel WHEEL metadata disappeared".to_string())?,
        "WHEEL",
    )?;
    let wheel_version = unique_header(&wheel, "Wheel-Version", "WHEEL")?;
    if !wheel_version.starts_with("1.") {
        return Err(format!("unsupported Python Wheel-Version: {wheel_version}"));
    }
    let wheel_root = match unique_header(&wheel, "Root-Is-Purelib", "WHEEL")? {
        "true" => HistoricalV2PythonWheelRoot::Purelib,
        "false" => HistoricalV2PythonWheelRoot::Platlib,
        value => return Err(format!("invalid Python Root-Is-Purelib value: {value}")),
    };
    let modules = parse_wheel_modules(&members, dist_info, &normalized_distribution_name)?;
    Ok(ParsedWheel {
        distribution_name,
        normalized_distribution_name,
        distribution_version,
        wheel_root,
        metadata_member_path,
        wheel_metadata_member_path,
        record_member_path,
        modules,
    })
}

fn validate_wheel_member_path(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.contains('\\')
        || name.contains('\0')
        || name.starts_with('/')
        || Path::new(name)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("Python wheel member path is unsafe: {name:?}"));
    }
    Ok(())
}

fn unique_dist_info_member(
    members: &BTreeMap<String, Vec<u8>>,
    filename: &str,
) -> Result<String, String> {
    let suffix = format!(".dist-info/{filename}");
    let matches = members
        .keys()
        .filter(|path| path.ends_with(&suffix) && path.split('/').count() == 2)
        .cloned()
        .collect::<Vec<_>>();
    let [path] = matches.as_slice() else {
        return Err(format!(
            "Python wheel contains {} {filename} members; expected exactly one",
            matches.len()
        ));
    };
    Ok(path.clone())
}

fn verify_record(
    members: &BTreeMap<String, Vec<u8>>,
    record_member_path: &str,
) -> Result<(), String> {
    let record = members
        .get(record_member_path)
        .ok_or_else(|| "Python wheel RECORD disappeared".to_string())?;
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .from_reader(record.as_slice());
    let mut recorded = BTreeSet::new();
    for row in reader.records() {
        let row = row.map_err(|error| format!("failed to parse Python wheel RECORD: {error}"))?;
        if row.len() != 3 {
            return Err("Python wheel RECORD row does not have three fields".to_string());
        }
        let path = row.get(0).unwrap_or_default();
        validate_wheel_member_path(path)?;
        if !recorded.insert(path.to_string()) {
            return Err(format!("Python wheel RECORD repeats member: {path}"));
        }
        let contents = members
            .get(path)
            .ok_or_else(|| format!("Python wheel RECORD names an absent member: {path}"))?;
        let hash = row.get(1).unwrap_or_default();
        let size = row.get(2).unwrap_or_default();
        if path == record_member_path {
            if !hash.is_empty() || !size.is_empty() {
                return Err(
                    "Python wheel RECORD must leave its own hash and size empty".to_string()
                );
            }
            continue;
        }
        verify_record_hash(path, contents, hash)?;
        let expected_size = size
            .parse::<u64>()
            .map_err(|_| format!("Python wheel RECORD has an invalid size for {path}: {size}"))?;
        if expected_size != contents.len() as u64 {
            return Err(format!("Python wheel RECORD size mismatch for {path}"));
        }
    }
    for path in members.keys() {
        if !recorded.contains(path) && !is_record_signature(path, record_member_path) {
            return Err(format!("Python wheel member is absent from RECORD: {path}"));
        }
    }
    Ok(())
}

fn verify_record_hash(path: &str, contents: &[u8], recorded: &str) -> Result<(), String> {
    let (algorithm, encoded) = recorded
        .split_once('=')
        .ok_or_else(|| format!("Python wheel RECORD has no hash algorithm for {path}"))?;
    let digest = match algorithm {
        "sha256" => Sha256::digest(contents).to_vec(),
        "sha384" => Sha384::digest(contents).to_vec(),
        "sha512" => Sha512::digest(contents).to_vec(),
        _ => {
            return Err(format!(
                "unsupported Python wheel RECORD hash {algorithm} for {path}"
            ));
        }
    };
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    if encoded != expected {
        return Err(format!("Python wheel RECORD hash mismatch for {path}"));
    }
    Ok(())
}

fn is_record_signature(path: &str, record_member_path: &str) -> bool {
    let Some(prefix) = record_member_path.strip_suffix("RECORD") else {
        return false;
    };
    path == format!("{prefix}RECORD.jws") || path == format!("{prefix}RECORD.p7s")
}

fn parse_email_headers(bytes: &[u8], label: &str) -> Result<BTreeMap<String, Vec<String>>, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| format!("Python wheel {label} is not UTF-8"))?;
    let mut headers = BTreeMap::<String, Vec<String>>::new();
    let mut current: Option<(String, String)> = None;
    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            let Some((_, value)) = current.as_mut() else {
                return Err(format!("Python wheel {label} starts with a folded header"));
            };
            value.push(' ');
            value.push_str(line.trim());
            continue;
        }
        if let Some((name, value)) = current.take() {
            headers.entry(name).or_default().push(value);
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("Python wheel {label} contains a malformed header"))?;
        if name.is_empty() || value.trim().is_empty() {
            return Err(format!("Python wheel {label} contains an empty header"));
        }
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!(
                "Python wheel {label} contains an invalid header name"
            ));
        }
        current = Some((name.to_ascii_lowercase(), value.trim().to_string()));
    }
    if let Some((name, value)) = current {
        headers.entry(name).or_default().push(value);
    }
    Ok(headers)
}

fn unique_header<'a>(
    headers: &'a BTreeMap<String, Vec<String>>,
    name: &str,
    label: &str,
) -> Result<&'a str, String> {
    let values = headers
        .get(&name.to_ascii_lowercase())
        .map(Vec::as_slice)
        .unwrap_or_default();
    let [value] = values else {
        return Err(format!(
            "Python wheel {label} contains {} {name} headers; expected exactly one",
            values.len()
        ));
    };
    Ok(value)
}

fn normalize_distribution_name(name: &str) -> Result<String, String> {
    if name.trim() != name
        || name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
    {
        return Err("Python wheel distribution name is empty or padded".to_string());
    }
    let mut normalized = String::new();
    let mut separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            separator = true;
            continue;
        }
        if separator && !normalized.is_empty() {
            normalized.push('-');
        }
        separator = false;
        normalized.extend(character.to_lowercase());
    }
    if normalized.is_empty() || normalized.ends_with('-') {
        return Err(format!("Python wheel distribution name is invalid: {name}"));
    }
    Ok(normalized)
}

fn validate_wheel_filename(
    filename: &str,
    normalized_distribution_name: &str,
    distribution_version: &str,
    dist_info: &str,
) -> Result<(), String> {
    let stem = filename
        .strip_suffix(".whl")
        .ok_or_else(|| "Python wheel filename lost its extension".to_string())?;
    let parts = stem.split('-').collect::<Vec<_>>();
    if !matches!(parts.len(), 5 | 6) || parts.iter().any(|part| part.is_empty()) {
        return Err(format!(
            "Python wheel filename has an invalid tag shape: {filename}"
        ));
    }
    if parts.len() == 6
        && (!parts[2].as_bytes()[0].is_ascii_digit()
            || !parts[2]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    {
        return Err(format!(
            "Python wheel filename has an invalid build tag: {filename}"
        ));
    }
    if normalize_distribution_name(parts[0])? != normalized_distribution_name {
        return Err("Python wheel filename disagrees with METADATA Name".to_string());
    }
    let normalized_version = Version::from_str(distribution_version)
        .map_err(|error| format!("Python wheel METADATA Version is not PEP 440: {error}"))?
        .to_string();
    if parts[1] != normalized_version || dist_info != format!("{}-{}.dist-info", parts[0], parts[1])
    {
        return Err(
            "Python wheel filename disagrees with METADATA Version or dist-info".to_string(),
        );
    }
    Ok(())
}

fn parse_wheel_modules(
    members: &BTreeMap<String, Vec<u8>>,
    dist_info: &str,
    normalized_distribution_name: &str,
) -> Result<Vec<ParsedWheelModule>, String> {
    let mut installed = BTreeMap::<String, (&str, &[u8])>::new();
    for (archive_path, contents) in members {
        let Some(installed_path) = installed_python_path(archive_path, dist_info)? else {
            continue;
        };
        if installed
            .insert(installed_path.clone(), (archive_path, contents))
            .is_some()
        {
            return Err(format!(
                "Python wheel installs two members to the same path: {installed_path}"
            ));
        }
    }
    let mut modules = Vec::new();
    let mut concrete_packages = BTreeSet::new();
    let mut module_names = BTreeSet::new();
    for (installed_path, (archive_path, contents)) in &installed {
        if installed_path.ends_with(".pth")
            || installed_path.ends_with(".pyc")
            || installed_path.ends_with(".pyo")
        {
            return Err(format!(
                "Python wheel contains dynamic or bytecode-only import state: {installed_path}"
            ));
        }
        let Some((import_name, kind)) = python_module_identity(installed_path)? else {
            continue;
        };
        if matches!(
            kind,
            HistoricalV2PythonModuleKind::SourcePackageInit
                | HistoricalV2PythonModuleKind::StubPackageInit
        ) {
            concrete_packages.insert(import_name.clone());
        }
        module_names.insert(import_name.clone());
        modules.push(ParsedWheelModule {
            import_name,
            kind,
            archive_member_path: Some((*archive_path).to_string()),
            installed_path: Some(installed_path.clone()),
            member_sha256: Some(sha256(contents)),
            member_byte_length: Some(contents.len() as u64),
        });
    }
    let mut namespaces = BTreeSet::new();
    for module_name in &module_names {
        let segments = module_name.split('.').collect::<Vec<_>>();
        for end in 1..segments.len() {
            let prefix = segments[..end].join(".");
            if module_names.contains(&prefix) && !concrete_packages.contains(&prefix) {
                return Err(format!(
                    "Python distribution {normalized_distribution_name} installs both module and package identities for {prefix}"
                ));
            }
            if !concrete_packages.contains(&prefix) && !module_names.contains(&prefix) {
                namespaces.insert(prefix);
            }
        }
    }
    modules.extend(namespaces.into_iter().map(|import_name| ParsedWheelModule {
        import_name,
        kind: HistoricalV2PythonModuleKind::NamespacePackage,
        archive_member_path: None,
        installed_path: None,
        member_sha256: None,
        member_byte_length: None,
    }));
    modules.sort();
    if modules
        .windows(2)
        .any(|pair| pair[0].import_name == pair[1].import_name && pair[0].kind == pair[1].kind)
    {
        return Err(format!(
            "Python distribution {normalized_distribution_name} repeats an importable module variant"
        ));
    }
    Ok(modules)
}

fn installed_python_path(archive_path: &str, dist_info: &str) -> Result<Option<String>, String> {
    if archive_path.starts_with(&format!("{dist_info}/")) {
        return Ok(None);
    }
    let components = archive_path.split('/').collect::<Vec<_>>();
    if components
        .first()
        .is_some_and(|component| component.ends_with(".dist-info"))
    {
        return Err(format!(
            "Python wheel contains a second dist-info tree: {archive_path}"
        ));
    }
    if components
        .first()
        .is_some_and(|component| component.ends_with(".data"))
    {
        let Some(scheme) = components.get(1) else {
            return Err(format!(
                "Python wheel data member has no install scheme: {archive_path}"
            ));
        };
        if !matches!(*scheme, "purelib" | "platlib") {
            return Ok(None);
        }
        if components.len() < 3 {
            return Err(format!(
                "Python wheel library member has no installed path: {archive_path}"
            ));
        }
        return Ok(Some(components[2..].join("/")));
    }
    Ok(Some(archive_path.to_string()))
}

fn python_module_identity(
    installed_path: &str,
) -> Result<Option<(String, HistoricalV2PythonModuleKind)>, String> {
    let (without_suffix, stub) = if let Some(path) = installed_path.strip_suffix(".py") {
        (path, false)
    } else if let Some(path) = installed_path.strip_suffix(".pyi") {
        (path, true)
    } else if installed_path.ends_with(".so") || installed_path.ends_with(".pyd") {
        let path = installed_path
            .rsplit_once('/')
            .map_or(installed_path, |(_, name)| name);
        let stem = path.split('.').next().unwrap_or_default();
        let parent = installed_path
            .rsplit_once('/')
            .map(|(parent, _)| format!("{parent}/{stem}"))
            .unwrap_or_else(|| stem.to_string());
        let import_name = import_name_from_path(&parent)?;
        return Ok(Some((
            import_name,
            HistoricalV2PythonModuleKind::ExtensionModule,
        )));
    } else {
        return Ok(None);
    };
    let is_init = without_suffix.ends_with("/__init__") || without_suffix == "__init__";
    let module_path = if is_init {
        without_suffix.strip_suffix("/__init__").unwrap_or_default()
    } else {
        without_suffix
    };
    if module_path.is_empty() {
        return Err(format!(
            "Python wheel has a top-level __init__ module: {installed_path}"
        ));
    }
    let import_name = import_name_from_path(module_path)?;
    let kind = match (stub, is_init) {
        (false, false) => HistoricalV2PythonModuleKind::SourceModule,
        (false, true) => HistoricalV2PythonModuleKind::SourcePackageInit,
        (true, false) => HistoricalV2PythonModuleKind::StubModule,
        (true, true) => HistoricalV2PythonModuleKind::StubPackageInit,
    };
    Ok(Some((import_name, kind)))
}

fn import_name_from_path(path: &str) -> Result<String, String> {
    let import_name = path.replace('/', ".");
    let probe = format!("import {import_name}\n");
    rustpython_parser::parse(&probe, rustpython_parser::Mode::Module, "<wheel-module>")
        .map_err(|_| format!("Python wheel contains a non-importable module path: {path}"))?;
    Ok(import_name)
}

fn python_module_surface_slot_id(
    normalized_distribution_name: &str,
    import_name: &str,
    kind: HistoricalV2PythonModuleKind,
) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-python-module-surface-slot-v1",
        normalized_distribution_name,
        import_name,
        kind,
    ))
    .map(|hash| format!("h2pyms-v1:{hash}"))
}

fn python_distribution_surface_census_sha256(
    census: &HistoricalV2PythonDistributionSurfaceCensus,
) -> Result<String, String> {
    hash_json(&(
        census.schema_version,
        &census.contract,
        &census.repository,
        &census.revision,
        &census.inventory_sha256,
        &census.distributions,
        &census.modules,
        &census.module_count_by_kind,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 Python surfaces: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
#[path = "benchmark_history_v2_python_distribution_surface_tests.rs"]
mod tests;
