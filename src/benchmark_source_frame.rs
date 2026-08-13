#[path = "benchmark_source_frame_schema.rs"]
mod schema;

#[path = "benchmark_source_frame_transport.rs"]
mod transport;

pub use schema::*;
use transport::fetch_search_page;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::time::Duration;

const GITHUB_SEARCH_LIMIT: usize = 1_000;
const GITHUB_PAGE_SIZE: usize = 100;

#[derive(Debug, Deserialize)]
struct GithubSearchResponse {
    total_count: usize,
    incomplete_results: bool,
    items: Vec<GithubSearchRepository>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GithubSearchRepository {
    id: u64,
    full_name: String,
    created_at: String,
    language: Option<String>,
    fork: bool,
    archived: bool,
    mirror_url: Option<String>,
    is_template: bool,
}

pub async fn collect_source_frame(
    policy: SourceFrameCollectionPolicy,
    state_directory: &Path,
    frame_output: &Path,
    manifest_output: &Path,
    github_token: Option<&str>,
) -> Result<SourceFrameCollectionManifest, String> {
    validate_policy(&policy)?;
    let artifact_root = manifest_output
        .parent()
        .ok_or_else(|| "source frame manifest has no parent directory".to_string())?;
    state_directory.strip_prefix(artifact_root).map_err(|_| {
        "source-frame state directory must be inside the manifest artifact root".to_string()
    })?;
    if frame_output.is_file() && manifest_output.is_file() {
        let manifest: SourceFrameCollectionManifest = serde_json::from_slice(
            &fs::read(manifest_output)
                .map_err(|error| format!("failed to read source-frame manifest: {error}"))?,
        )
        .map_err(|error| format!("failed to parse source-frame manifest: {error}"))?;
        if manifest.policy != policy {
            return Err("existing source-frame manifest uses a different policy".to_string());
        }
        let frame = fs::read(frame_output)
            .map_err(|error| format!("failed to read source frame: {error}"))?;
        validate_source_frame_manifest(&manifest, artifact_root, &frame)?;
        return Ok(manifest);
    }
    fs::create_dir_all(state_directory)
        .map_err(|error| format!("failed to create source-frame state: {error}"))?;
    let client = Client::builder()
        .user_agent("trysniff-sniffbench-frame-collector/1")
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|error| format!("failed to build GitHub frame client: {error}"))?;
    let mut raw_pages = Vec::new();
    for hour in 0..24 {
        let query = hourly_query(&policy, hour);
        let first =
            load_or_fetch_page(&client, github_token, state_directory, &query, hour, 1).await?;
        let parsed = parse_search_response(&first.1)?;
        if parsed.total_count > GITHUB_SEARCH_LIMIT {
            return Err(format!(
                "GitHub search partition {query:?} has {} results and exceeds the 1,000-result completeness limit",
                parsed.total_count
            ));
        }
        let pages = parsed.total_count.div_ceil(GITHUB_PAGE_SIZE).max(1);
        raw_pages.push(first);
        for page in 2..=pages {
            raw_pages.push(
                load_or_fetch_page(&client, github_token, state_directory, &query, hour, page)
                    .await?,
            );
        }
    }
    build_source_frame(
        policy,
        state_directory,
        frame_output,
        manifest_output,
        raw_pages,
    )
}

pub fn validate_source_frame_manifest(
    manifest: &SourceFrameCollectionManifest,
    artifact_root: &Path,
    frame: &[u8],
) -> Result<(), String> {
    if manifest.schema_version != SOURCE_FRAME_COLLECTION_MANIFEST_SCHEMA_VERSION {
        return Err("source-frame manifest schema is unsupported".to_string());
    }
    validate_policy(&manifest.policy)?;
    require_sha256("source-frame policy SHA-256", &manifest.policy_sha256)?;
    require_sha256("source-frame SHA-256", &manifest.frame_sha256)?;
    require_sha256("source-frame manifest SHA-256", &manifest.manifest_sha256)?;
    if manifest.policy_sha256 != json_sha256(&manifest.policy)?
        || manifest.frame_sha256 != sha256(frame)
        || manifest.manifest_sha256 != manifest.computed_manifest_sha256()?
    {
        return Err("source-frame manifest commitment changed".to_string());
    }
    let canonical_root = fs::canonicalize(artifact_root)
        .map_err(|error| format!("failed to resolve source-frame artifact root: {error}"))?;
    let mut raw_pages = Vec::with_capacity(manifest.pages.len());
    for commitment in &manifest.pages {
        let relative = safe_relative_path(&commitment.artifact_path)?;
        let path = fs::canonicalize(artifact_root.join(relative)).map_err(|error| {
            format!(
                "failed to resolve source-frame page {}: {error}",
                commitment.artifact_path
            )
        })?;
        if !path.starts_with(&canonical_root) {
            return Err("source-frame page escapes its artifact root".to_string());
        }
        let bytes = fs::read(&path).map_err(|error| {
            format!(
                "failed to read source-frame page {}: {error}",
                commitment.artifact_path
            )
        })?;
        require_sha256("source-frame page SHA-256", &commitment.artifact_sha256)?;
        require_sha256("source-frame response SHA-256", &commitment.response_sha256)?;
        if sha256(&bytes) != commitment.artifact_sha256 {
            return Err(format!(
                "source-frame page commitment changed: {}",
                commitment.artifact_path
            ));
        }
        let raw: SourceFrameRawPage = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "failed to parse source-frame page {}: {error}",
                commitment.artifact_path
            )
        })?;
        validate_raw_page(&raw)?;
        if raw.query != commitment.query
            || raw.page != commitment.page
            || raw.response_sha256 != commitment.response_sha256
        {
            return Err(format!(
                "source-frame page identity changed: {}",
                commitment.artifact_path
            ));
        }
        raw_pages.push((path, raw));
    }
    let (replayed_frame, replayed_pages, repository_count) =
        derive_source_frame(&manifest.policy, &canonical_root, raw_pages)?;
    if replayed_frame != frame
        || replayed_pages != manifest.pages
        || repository_count != manifest.repository_count
    {
        return Err("source-frame manifest does not replay to its committed frame".to_string());
    }
    Ok(())
}

fn build_source_frame(
    policy: SourceFrameCollectionPolicy,
    state_directory: &Path,
    frame_output: &Path,
    manifest_output: &Path,
    raw_pages: Vec<(PathBuf, SourceFrameRawPage)>,
) -> Result<SourceFrameCollectionManifest, String> {
    let artifact_root = manifest_output
        .parent()
        .ok_or_else(|| "source frame manifest has no parent directory".to_string())?;
    state_directory.strip_prefix(artifact_root).map_err(|_| {
        "source-frame state directory must be inside the manifest artifact root".to_string()
    })?;
    let (frame_bytes, page_commitments, repository_count) =
        derive_source_frame(&policy, artifact_root, raw_pages)?;
    write_or_verify_new(frame_output, &frame_bytes, "source frame")?;
    let policy_sha256 = json_sha256(&policy)?;
    let mut manifest = SourceFrameCollectionManifest {
        schema_version: SOURCE_FRAME_COLLECTION_MANIFEST_SCHEMA_VERSION,
        policy,
        policy_sha256,
        frame_sha256: sha256(&frame_bytes),
        repository_count,
        pages: page_commitments,
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = manifest.computed_manifest_sha256()?;
    let bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("failed to serialize source-frame manifest: {error}"))?;
    write_or_verify_new(manifest_output, &bytes, "source frame manifest")?;
    validate_source_frame_manifest(&manifest, artifact_root, &frame_bytes)?;
    Ok(manifest)
}

fn derive_source_frame(
    policy: &SourceFrameCollectionPolicy,
    artifact_root: &Path,
    raw_pages: Vec<(PathBuf, SourceFrameRawPage)>,
) -> Result<(Vec<u8>, Vec<SourceFramePageCommitment>, usize), String> {
    validate_policy(policy)?;
    let mut repositories = BTreeMap::new();
    let mut identities = HashSet::new();
    let mut page_commitments = Vec::new();
    let mut partitions = BTreeMap::<String, (usize, BTreeMap<usize, usize>)>::new();
    for (path, raw) in raw_pages {
        validate_raw_page(&raw)?;
        let parsed = parse_search_response(&raw)?;
        if parsed.incomplete_results {
            return Err(format!(
                "GitHub returned incomplete results for {:?}",
                raw.query
            ));
        }
        if parsed.total_count > GITHUB_SEARCH_LIMIT {
            return Err(format!(
                "GitHub search partition {:?} exceeds 1,000 results",
                raw.query
            ));
        }
        let partition = partitions
            .entry(raw.query.clone())
            .or_insert_with(|| (parsed.total_count, BTreeMap::new()));
        if partition.0 != parsed.total_count
            || partition.1.insert(raw.page, parsed.items.len()).is_some()
        {
            return Err("GitHub search pagination changed within one partition".to_string());
        }
        for repository in parsed.items {
            validate_repository(policy, &raw.query, &repository)?;
            let identity = normalize_full_name(&repository.full_name)?;
            if repositories
                .insert(repository.id, repository.clone())
                .is_some()
            {
                return Err(format!(
                    "GitHub repository ID {} repeats across frozen search pages",
                    repository.id
                ));
            }
            if !identities.insert(identity) {
                return Err("GitHub frame repeats one repository under different IDs".to_string());
            }
            repositories.insert(repository.id, repository);
        }
        let bytes = fs::read(&path).map_err(|error| {
            format!(
                "failed to read source-frame page {}: {error}",
                path.display()
            )
        })?;
        page_commitments.push(SourceFramePageCommitment {
            query: raw.query,
            page: raw.page,
            artifact_path: portable_relative(artifact_root, &path)?,
            artifact_sha256: sha256(&bytes),
            response_sha256: raw.response_sha256,
        });
    }
    for hour in 0..24 {
        let query = hourly_query(policy, hour);
        let Some((total_count, pages)) = partitions.remove(&query) else {
            return Err(format!(
                "source frame is missing UTC hour partition {hour:02}"
            ));
        };
        let expected_pages = total_count.div_ceil(GITHUB_PAGE_SIZE).max(1);
        if pages.keys().copied().ne(1..=expected_pages)
            || pages.values().sum::<usize>() != total_count
        {
            return Err(format!(
                "GitHub search partition {query:?} does not contain its complete page and item census"
            ));
        }
    }
    if !partitions.is_empty() {
        return Err("source frame contains a query outside the precommitted UTC day".to_string());
    }
    page_commitments.sort_by(|left, right| {
        (&left.query, left.page, &left.artifact_path).cmp(&(
            &right.query,
            right.page,
            &right.artifact_path,
        ))
    });
    let mut frame = String::from("repo,metadata\n");
    for repository in repositories.values() {
        let identity = normalize_full_name(&repository.full_name)?;
        frame.push_str("github.com/");
        frame.push_str(&identity);
        frame.push_str(",github_repository_id=");
        frame.push_str(&repository.id.to_string());
        frame.push_str(";created_at=");
        frame.push_str(&repository.created_at);
        frame.push('\n');
    }
    Ok((frame.into_bytes(), page_commitments, repositories.len()))
}

async fn load_or_fetch_page(
    client: &Client,
    github_token: Option<&str>,
    state_directory: &Path,
    query: &str,
    hour: usize,
    page: usize,
) -> Result<(PathBuf, SourceFrameRawPage), String> {
    let path = state_directory.join(format!("hour-{hour:02}-page-{page:03}.json"));
    if path.is_file() {
        let raw: SourceFrameRawPage = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("failed to read source-frame page: {error}"))?,
        )
        .map_err(|error| {
            format!(
                "failed to parse source-frame page {}: {error}",
                path.display()
            )
        })?;
        if raw.query != query || raw.page != page || raw.per_page != GITHUB_PAGE_SIZE {
            return Err(format!(
                "source-frame checkpoint does not match {}",
                path.display()
            ));
        }
        validate_raw_page(&raw)?;
        return Ok((path, raw));
    }
    let response = fetch_search_page(client, github_token, query, page).await?;
    let raw = SourceFrameRawPage {
        query: query.to_string(),
        page,
        per_page: GITHUB_PAGE_SIZE,
        response_sha256: sha256(response.as_bytes()),
        response,
    };
    validate_raw_page(&raw)?;
    let bytes = serde_json::to_vec_pretty(&raw)
        .map_err(|error| format!("failed to serialize source-frame page: {error}"))?;
    write_atomic_checkpoint(&path, &bytes, "source-frame page")?;
    Ok((path, raw))
}

fn hourly_query(policy: &SourceFrameCollectionPolicy, hour: usize) -> String {
    let start = format!("{}T{hour:02}:00:00Z", policy.created_day_utc);
    let end = format!("{}T{hour:02}:59:59Z", policy.created_day_utc);
    format!(
        "language:{} created:{start}..{end} fork:{} archived:{} mirror:{} template:{}",
        policy.language,
        if policy.include_forks {
            "true"
        } else {
            "false"
        },
        if policy.include_archived {
            "true"
        } else {
            "false"
        },
        if policy.include_mirrors {
            "true"
        } else {
            "false"
        },
        if policy.include_templates {
            "true"
        } else {
            "false"
        },
    )
}

fn parse_search_response(raw: &SourceFrameRawPage) -> Result<GithubSearchResponse, String> {
    let parsed: GithubSearchResponse = serde_json::from_str(&raw.response)
        .map_err(|error| format!("invalid GitHub search response: {error}"))?;
    if parsed.total_count > GITHUB_SEARCH_LIMIT {
        return Err(
            "GitHub search partition exceeds the 1,000-result completeness limit".to_string(),
        );
    }
    let expected_pages = parsed.total_count.div_ceil(GITHUB_PAGE_SIZE).max(1);
    if raw.page > expected_pages || parsed.items.len() > GITHUB_PAGE_SIZE {
        return Err("GitHub search response has inconsistent pagination".to_string());
    }
    if raw.page < expected_pages && parsed.items.len() != GITHUB_PAGE_SIZE {
        return Err("GitHub search response ended before its declared final page".to_string());
    }
    Ok(parsed)
}

fn validate_raw_page(raw: &SourceFrameRawPage) -> Result<(), String> {
    if raw.query.trim().is_empty() || raw.page == 0 || raw.per_page != GITHUB_PAGE_SIZE {
        return Err("source-frame page has an invalid request identity".to_string());
    }
    require_sha256("source-frame response SHA-256", &raw.response_sha256)?;
    if raw.response_sha256 != sha256(raw.response.as_bytes()) {
        return Err("source-frame response commitment changed".to_string());
    }
    Ok(())
}

fn validate_repository(
    policy: &SourceFrameCollectionPolicy,
    query: &str,
    repository: &GithubSearchRepository,
) -> Result<(), String> {
    let expected_hour = (0..24)
        .find(|hour| hourly_query(policy, *hour) == query)
        .ok_or_else(|| "GitHub response belongs to an uncommitted query".to_string())?;
    let expected_prefix = format!("{}T{expected_hour:02}:", policy.created_day_utc);
    if repository.id == 0
        || !repository.created_at.starts_with(&expected_prefix)
        || repository.language.as_deref() != Some(policy.language.as_str())
        || repository.fork != policy.include_forks
        || repository.archived != policy.include_archived
        || repository.mirror_url.is_some() != policy.include_mirrors
        || repository.is_template != policy.include_templates
    {
        return Err(format!(
            "GitHub repository {} does not satisfy its frozen source-frame query",
            repository.full_name
        ));
    }
    Ok(())
}

fn validate_policy(policy: &SourceFrameCollectionPolicy) -> Result<(), String> {
    if policy.schema_version != SOURCE_FRAME_COLLECTION_POLICY_SCHEMA_VERSION
        || policy.frame_id.trim().is_empty()
        || policy.source != "https://api.github.com/search/repositories"
        || policy.api_version != "2022-11-28"
        || policy.language != "Kotlin"
        || policy.partition != "utc_hour"
        || policy.ordering != "github_repository_id_ascending"
        || policy.attestation.trim().is_empty()
        || policy.derivation_rule != "first_8_hex_u32_mod_period_days"
        || policy.derivation_period_days == 0
        || policy.derivation_period_days > 366
    {
        return Err("source-frame collection policy uses an unsupported contract".to_string());
    }
    require_hex_commitment("source-frame derivation seed", &policy.derivation_seed)?;
    let seed_prefix = u32::from_str_radix(&policy.derivation_seed[..8], 16)
        .map_err(|_| "source-frame derivation seed prefix is invalid".to_string())?;
    let offset = (u64::from(seed_prefix)
        % u64::try_from(policy.derivation_period_days)
            .map_err(|_| "source-frame derivation period is too large".to_string())?)
        as usize;
    let expected_day = add_days(&policy.derivation_period_start_utc, offset)?;
    if policy.created_day_utc != expected_day {
        return Err(format!(
            "source-frame day is not the policy-derived day: expected {expected_day}"
        ));
    }
    Ok(())
}

fn add_days(value: &str, days: usize) -> Result<String, String> {
    let (mut year, mut month, mut day) = parse_date(value)?;
    for _ in 0..days {
        day += 1;
        if day > days_in_month(year, month) {
            day = 1;
            month += 1;
            if month > 12 {
                month = 1;
                year += 1;
            }
        }
    }
    Ok(format!("{year:04}-{month:02}-{day:02}"))
}

fn parse_date(value: &str) -> Result<(u32, u32, u32), String> {
    if value.len() != 10 || value.as_bytes()[4] != b'-' || value.as_bytes()[7] != b'-' {
        return Err("source-frame derivation period has an invalid date".to_string());
    }
    let year = value[..4]
        .parse::<u32>()
        .map_err(|_| "source-frame derivation period has an invalid year".to_string())?;
    let month = value[5..7]
        .parse::<u32>()
        .map_err(|_| "source-frame derivation period has an invalid month".to_string())?;
    let day = value[8..]
        .parse::<u32>()
        .map_err(|_| "source-frame derivation period has an invalid day".to_string())?;
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return Err("source-frame derivation period has an invalid calendar date".to_string());
    }
    Ok((year, month, day))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    #[allow(clippy::manual_is_multiple_of)]
    fn leap_year(year: u32) -> bool {
        year % 400 == 0 || (year % 4 == 0 && year % 100 != 0)
    }
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn normalize_full_name(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    let parts = normalized.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(format!("invalid GitHub repository identity: {value}"));
    }
    Ok(normalized)
}

fn write_new(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("failed to create {label} {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to persist {label}: {error}"))
}

fn write_atomic_checkpoint(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let temporary = temporary_path(path)?;
    if temporary.exists() {
        fs::remove_file(&temporary).map_err(|error| {
            format!(
                "failed to remove stale {label} temporary {}: {error}",
                temporary.display()
            )
        })?;
    }
    write_new(&temporary, bytes, label)?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("failed to publish {label} {}: {error}", path.display()))
}

fn write_or_verify_new(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    if path.is_file() {
        let existing =
            fs::read(path).map_err(|error| format!("failed to read existing {label}: {error}"))?;
        if existing == bytes {
            return Ok(());
        }
        return Err(format!(
            "existing {label} differs from the derived artifact: {}",
            path.display()
        ));
    }
    write_atomic_checkpoint(path, bytes, label)
}

fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "source-frame output name is not portable UTF-8".to_string())?;
    Ok(path.with_file_name(format!("{name}.tmp-{}", std::process::id())))
}

fn portable_relative(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map_err(|_| "source-frame page is outside its state directory".to_string())?
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => value
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| "source-frame path is not UTF-8".to_string()),
            _ => Err("source-frame path is not portable".to_string()),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join("/"))
}

fn safe_relative_path(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "source-frame artifact path is not a safe relative path: {value}"
        ));
    }
    Ok(path.to_path_buf())
}

fn require_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(format!("{label} must be a 64-character SHA-256 digest"))
    } else {
        Ok(())
    }
}

fn require_hex_commitment(label: &str, value: &str) -> Result<(), String> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(format!(
            "{label} must be a 40- or 64-character hexadecimal commitment"
        ))
    } else {
        Ok(())
    }
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to serialize source-frame commitment: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn bounded(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

#[cfg(test)]
#[path = "benchmark_source_frame_tests.rs"]
mod tests;
