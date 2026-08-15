use super::{
    HistoricalV2FrameDisposition, HistoricalV2FrameExclusionReason, HistoricalV2FrameRecord,
    HistoricalV2PatchFacts, HistoricalV2ProjectedRow,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const RANK_DOMAIN: &str = "sniffbench-historical-v2-rank-v1";

pub fn derive_historical_v2_frame_record(
    row: HistoricalV2ProjectedRow,
    ranking_seed: &str,
) -> HistoricalV2FrameRecord {
    let patch_sha256 = sha256(row.patch.as_bytes());
    let projected_row_sha256 = projected_row_sha256(&row);
    let canonical_repository = canonical_repository(&row.repo);
    let base_revision = canonical_revision(&row.base_commit);
    let pull_number = u64::try_from(row.pull_number)
        .ok()
        .filter(|value| *value > 0);
    let disposition =
        exclusion_before_patch(&row, &canonical_repository, &base_revision, pull_number)
            .map_or_else(
                || match classify_historical_v2_patch(&row.patch) {
                    Ok(facts) => HistoricalV2FrameDisposition::Eligible {
                        rank_sha256: historical_v2_rank_sha256(
                            ranking_seed,
                            canonical_repository
                                .as_deref()
                                .expect("validated repository"),
                            pull_number.expect("validated pull number"),
                            base_revision.as_deref().expect("validated revision"),
                            &patch_sha256,
                        ),
                        facts,
                    },
                    Err(reason) => HistoricalV2FrameDisposition::Excluded { reason },
                },
                |reason| HistoricalV2FrameDisposition::Excluded { reason },
            );
    HistoricalV2FrameRecord {
        source_shard_index: row.source_shard_index,
        source_row_index: row.source_row_index,
        global_row_index: row.global_row_index,
        instance_id: row.instance_id,
        canonical_repository,
        pull_number,
        base_revision,
        created_at: row.created_at,
        license: row.license,
        patch_size_bytes: row.patch.len(),
        patch_sha256,
        projected_row_sha256,
        disposition,
    }
}

pub fn classify_historical_v2_patch(
    patch: &str,
) -> Result<HistoricalV2PatchFacts, HistoricalV2FrameExclusionReason> {
    let mut paths = BTreeSet::new();
    let mut languages = BTreeSet::new();
    let mut old_path = None;
    let mut new_path = None;
    let mut active_language = None;
    let mut in_hunk = false;
    let mut saw_hunk = false;
    let mut added = 0;
    let mut deleted = 0;

    for line in patch.lines() {
        if line.starts_with("diff --git ") {
            old_path = None;
            new_path = None;
            active_language = None;
            in_hunk = false;
            continue;
        }
        if !in_hunk {
            if let Some(value) = line.strip_prefix("--- ") {
                old_path = diff_path(value)?;
                continue;
            }
            if let Some(value) = line.strip_prefix("+++ ") {
                new_path = diff_path(value)?;
                continue;
            }
        }
        if line.starts_with("@@ ") || line == "@@" {
            let path = new_path
                .as_ref()
                .or(old_path.as_ref())
                .ok_or(HistoricalV2FrameExclusionReason::MalformedPatch)?;
            active_language = language_for_path(path);
            if let Some(language) = active_language {
                paths.insert(path.clone());
                languages.insert(language.to_string());
            }
            in_hunk = true;
            saw_hunk = true;
            continue;
        }
        let Some(_) = active_language else {
            continue;
        };
        if line
            .strip_prefix('+')
            .is_some_and(|value| !value.trim().is_empty())
        {
            added += 1;
        } else if line
            .strip_prefix('-')
            .is_some_and(|value| !value.trim().is_empty())
        {
            deleted += 1;
        }
    }

    if !saw_hunk {
        return Err(HistoricalV2FrameExclusionReason::MalformedPatch);
    }
    if languages.is_empty() {
        return Err(HistoricalV2FrameExclusionReason::NoSupportedLanguage);
    }
    if languages.len() != 1 {
        return Err(HistoricalV2FrameExclusionReason::MultipleSupportedLanguages);
    }
    if added == 0 && deleted == 0 {
        return Err(HistoricalV2FrameExclusionReason::NoSupportedLanguageHunks);
    }
    if deleted <= added {
        return Err(HistoricalV2FrameExclusionReason::NoNetSupportedLanguageReduction);
    }
    Ok(HistoricalV2PatchFacts {
        language: languages.into_iter().next().expect("one language"),
        changed_paths: paths.into_iter().collect(),
        added_non_whitespace_lines: added,
        deleted_non_whitespace_lines: deleted,
    })
}

pub fn historical_v2_rank_sha256(
    ranking_seed: &str,
    canonical_repository: &str,
    pull_number: u64,
    base_revision: &str,
    patch_sha256: &str,
) -> String {
    sha256(
        format!(
            "{RANK_DOMAIN}\0{ranking_seed}\0{canonical_repository}\0{pull_number}\0{base_revision}\0{patch_sha256}"
        )
        .as_bytes(),
    )
}

fn exclusion_before_patch(
    row: &HistoricalV2ProjectedRow,
    repository: &Option<String>,
    revision: &Option<String>,
    pull_number: Option<u64>,
) -> Option<HistoricalV2FrameExclusionReason> {
    if row.instance_id.trim().is_empty() {
        Some(HistoricalV2FrameExclusionReason::EmptyInstanceId)
    } else if repository.is_none() {
        Some(HistoricalV2FrameExclusionReason::InvalidRepository)
    } else if revision.is_none() {
        Some(HistoricalV2FrameExclusionReason::InvalidBaseRevision)
    } else if pull_number.is_none() {
        Some(HistoricalV2FrameExclusionReason::InvalidPullNumber)
    } else if row.created_at.trim().is_empty() {
        Some(HistoricalV2FrameExclusionReason::EmptyCreatedAt)
    } else if row.license.trim().is_empty() {
        Some(HistoricalV2FrameExclusionReason::EmptyLicense)
    } else {
        None
    }
}

fn canonical_repository(value: &str) -> Option<String> {
    let mut segments = value.trim().split('/');
    let owner = segments.next()?;
    let repository = segments.next()?;
    if segments.next().is_some()
        || !valid_repository_segment(owner)
        || !valid_repository_segment(repository)
    {
        return None;
    }
    Some(format!("{owner}/{repository}").to_ascii_lowercase())
}

fn valid_repository_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn canonical_revision(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn diff_path(value: &str) -> Result<Option<String>, HistoricalV2FrameExclusionReason> {
    let value = value.trim();
    if value == "/dev/null" {
        return Ok(None);
    }
    if value.starts_with('"') || value.contains('\t') {
        return Err(HistoricalV2FrameExclusionReason::MalformedPatch);
    }
    let path = value
        .strip_prefix("a/")
        .or_else(|| value.strip_prefix("b/"))
        .unwrap_or(value);
    if path.is_empty() || path.starts_with('/') || path.split('/').any(|part| part == "..") {
        return Err(HistoricalV2FrameExclusionReason::MalformedPatch);
    }
    Ok(Some(path.replace('\\', "/")))
}

fn language_for_path(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let extension = lower.rsplit_once('.')?.1;
    match extension {
        "go" => Some("go"),
        "js" | "jsx" | "mjs" | "cjs" => Some("javascript"),
        "kt" | "kts" => Some("kotlin"),
        "py" | "pyi" => Some("python"),
        "rs" => Some("rust"),
        "ts" | "tsx" | "mts" | "cts" => Some("typescript"),
        _ => None,
    }
}

fn projected_row_sha256(row: &HistoricalV2ProjectedRow) -> String {
    #[derive(Serialize)]
    struct Commitment<'a> {
        base_commit: &'a str,
        created_at: &'a str,
        instance_id: &'a str,
        license: &'a str,
        patch: &'a str,
        pull_number: i64,
        repo: &'a str,
    }
    let bytes = serde_json::to_vec(&Commitment {
        base_commit: &row.base_commit,
        created_at: &row.created_at,
        instance_id: &row.instance_id,
        license: &row.license,
        patch: &row.patch,
        pull_number: row.pull_number,
        repo: &row.repo,
    })
    .expect("projected row commitment must serialize");
    sha256(&bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
