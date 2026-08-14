use super::non_blind_history_artifacts::verify_published_rank;
use super::non_blind_history_candidate::{
    CandidateRuntime, HistoricalRepositoryCloner, NetworkHistoricalCloner, assess_candidate,
};
use super::{
    HistoricalAssessmentDisposition, HistoricalRepositoryAssessment, NonBlindHistoryAssessment,
    NonBlindSelectionPolicy, complete_non_blind_history_assessment,
    load_non_blind_history_checkpoints, validate_non_blind_history_assessment,
    write_non_blind_history_checkpoint,
};
use reqwest::Client;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const MINIMUM_FREE_BYTES: u64 = 1_073_741_824;

pub async fn assess_non_blind_history(
    policy_bytes: &[u8],
    worksheet_bytes: &[u8],
    protocol_bytes: &[u8],
    template: NonBlindHistoryAssessment,
    state_directory: &Path,
) -> Result<NonBlindHistoryAssessment, String> {
    let client = Client::builder()
        .user_agent("trysniff-sniffbench-history-assessor/1")
        .build()
        .map_err(|error| format!("failed to build historical assessment client: {error}"))?;
    assess_with_cloner(
        policy_bytes,
        worksheet_bytes,
        protocol_bytes,
        template,
        state_directory,
        &client,
        &NetworkHistoricalCloner,
        None,
        true,
    )
    .await
}

pub async fn assess_non_blind_history_slice(
    policy_bytes: &[u8],
    worksheet_bytes: &[u8],
    protocol_bytes: &[u8],
    template: NonBlindHistoryAssessment,
    state_directory: &Path,
    maximum_new_ranks: usize,
) -> Result<NonBlindHistoryAssessment, String> {
    if maximum_new_ranks == 0 {
        return Err("historical assessment slice must process at least one new rank".to_string());
    }
    let client = Client::builder()
        .user_agent("trysniff-sniffbench-history-assessor/1")
        .build()
        .map_err(|error| format!("failed to build historical assessment client: {error}"))?;
    assess_with_cloner(
        policy_bytes,
        worksheet_bytes,
        protocol_bytes,
        template,
        state_directory,
        &client,
        &NetworkHistoricalCloner,
        Some(maximum_new_ranks),
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn assess_with_cloner<C: HistoricalRepositoryCloner>(
    policy_bytes: &[u8],
    worksheet_bytes: &[u8],
    protocol_bytes: &[u8],
    template: NonBlindHistoryAssessment,
    state_directory: &Path,
    client: &Client,
    cloner: &C,
    maximum_new_ranks: Option<usize>,
    require_complete: bool,
) -> Result<NonBlindHistoryAssessment, String> {
    validate_non_blind_history_assessment(
        policy_bytes,
        worksheet_bytes,
        protocol_bytes,
        &template,
    )?;
    if template
        .assessments
        .iter()
        .any(|assessment| assessment.disposition.is_some())
    {
        return Err(
            "historical assessment input must be the immutable blank prepared ledger".to_string(),
        );
    }
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("failed to parse non-blind selection policy: {error}"))?;
    fs::create_dir_all(state_directory)
        .map_err(|error| format!("failed to create historical assessment state: {error}"))?;
    let state_root = fs::canonicalize(state_directory)
        .map(normalize_path)
        .map_err(|error| format!("failed to resolve historical assessment state: {error}"))?;
    let checkpoint_root = state_root.join("checkpoints");
    let work_root = state_root.join("work");
    fs::create_dir_all(&checkpoint_root)
        .map_err(|error| format!("failed to create historical checkpoints: {error}"))?;
    fs::create_dir_all(&work_root)
        .map_err(|error| format!("failed to create historical work root: {error}"))?;

    let mut completed = recover_state(
        policy_bytes,
        worksheet_bytes,
        protocol_bytes,
        &template,
        &state_root,
        &checkpoint_root,
    )?;
    let mut result = template.clone();
    apply_prefix(&mut result, &completed)?;
    validate_non_blind_history_assessment(policy_bytes, worksheet_bytes, protocol_bytes, &result)?;
    for (new_ranks, index) in (completed.len()..template.assessments.len()).enumerate() {
        if maximum_new_ranks.is_some_and(|maximum| new_ranks >= maximum) {
            break;
        }
        require_disk_headroom(&state_root)?;
        let candidate = &template.assessments[index].candidate;
        eprintln!(
            "Assessing historical repository {}/{}: {}",
            candidate.rank,
            template.assessments.len(),
            candidate.repository
        );
        let selected_counts = selected_counts(&policy, &completed)?;
        let runtime = CandidateRuntime {
            policy: &policy,
            state_root: &state_root,
            work_root: &work_root,
            selected_counts: &selected_counts,
            http: client,
            cloner,
        };
        let pending = assess_candidate(&runtime, candidate).await?;
        let assessment = pending.assessment.clone();
        result.assessments[index] = assessment.clone();
        validate_non_blind_history_assessment(
            policy_bytes,
            worksheet_bytes,
            protocol_bytes,
            &result,
        )?;
        pending.publish(&template.task_sha256)?;
        write_non_blind_history_checkpoint(&checkpoint_root, &template.task_sha256, &assessment)?;
        completed.push(assessment);
    }

    let all_ranks_complete = result
        .assessments
        .iter()
        .all(|assessment| assessment.disposition.is_some());
    if require_complete || all_ranks_complete {
        complete_non_blind_history_assessment(
            policy_bytes,
            worksheet_bytes,
            protocol_bytes,
            &result,
        )?;
    } else {
        validate_non_blind_history_assessment(
            policy_bytes,
            worksheet_bytes,
            protocol_bytes,
            &result,
        )?;
    }
    Ok(result)
}

fn recover_state(
    policy_bytes: &[u8],
    worksheet_bytes: &[u8],
    protocol_bytes: &[u8],
    template: &NonBlindHistoryAssessment,
    state_root: &Path,
    checkpoint_root: &Path,
) -> Result<Vec<HistoricalRepositoryAssessment>, String> {
    let mut completed = load_non_blind_history_checkpoints(template, checkpoint_root)?;
    for assessment in &completed {
        let published =
            verify_published_rank(state_root, assessment.candidate.rank, &template.task_sha256)?
                .ok_or_else(|| {
                    format!(
                        "historical checkpoint rank {} has no published artifact transaction",
                        assessment.candidate.rank
                    )
                })?;
        if published != *assessment {
            return Err(format!(
                "historical checkpoint rank {} disagrees with its artifact transaction",
                assessment.candidate.rank
            ));
        }
    }

    while completed.len() < template.assessments.len() {
        let rank = completed.len() + 1;
        let Some(published) = verify_published_rank(state_root, rank, &template.task_sha256)?
        else {
            break;
        };
        if published.candidate != template.assessments[rank - 1].candidate {
            return Err(format!(
                "published historical rank {rank} changed its immutable candidate"
            ));
        }
        let mut recovered = template.clone();
        apply_prefix(&mut recovered, &completed)?;
        recovered.assessments[rank - 1] = published.clone();
        validate_non_blind_history_assessment(
            policy_bytes,
            worksheet_bytes,
            protocol_bytes,
            &recovered,
        )?;
        write_non_blind_history_checkpoint(checkpoint_root, &template.task_sha256, &published)?;
        completed.push(published);
    }
    reject_noncontiguous_artifacts(state_root, completed.len())?;
    Ok(completed)
}

fn reject_noncontiguous_artifacts(state_root: &Path, completed: usize) -> Result<(), String> {
    let artifacts_root = state_root.join("artifacts");
    if !artifacts_root.exists() {
        return Ok(());
    }
    let mut ranks = Vec::new();
    for entry in fs::read_dir(&artifacts_root)
        .map_err(|error| format!("failed to inspect historical artifacts: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("failed to inspect historical artifact: {error}"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| "historical artifact name is not UTF-8".to_string())?;
        let rank = name
            .strip_prefix("rank-")
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| format!("unexpected historical artifact directory: {name}"))?;
        if !entry
            .file_type()
            .map_err(|error| format!("failed to inspect historical artifact: {error}"))?
            .is_dir()
        {
            return Err(format!(
                "historical rank artifact is not a directory: {name}"
            ));
        }
        ranks.push(rank);
    }
    ranks.sort_unstable();
    let expected = (1..=completed).collect::<Vec<_>>();
    if ranks != expected {
        return Err(format!(
            "historical artifact transactions are not one contiguous ranked prefix: {ranks:?}"
        ));
    }
    Ok(())
}

fn apply_prefix(
    assessment: &mut NonBlindHistoryAssessment,
    completed: &[HistoricalRepositoryAssessment],
) -> Result<(), String> {
    if completed.len() > assessment.assessments.len() {
        return Err("historical checkpoint prefix exceeds its immutable task".to_string());
    }
    for (target, source) in assessment.assessments.iter_mut().zip(completed) {
        if target.candidate != source.candidate {
            return Err("historical checkpoint prefix changed candidate order".to_string());
        }
        *target = source.clone();
    }
    Ok(())
}

fn selected_counts(
    policy: &NonBlindSelectionPolicy,
    completed: &[HistoricalRepositoryAssessment],
) -> Result<BTreeMap<String, usize>, String> {
    let mut counts = policy
        .supported_languages
        .iter()
        .map(|language| (language.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for assessment in completed {
        if assessment.disposition != Some(HistoricalAssessmentDisposition::Selected) {
            continue;
        }
        let language = assessment
            .facts
            .as_ref()
            .and_then(|facts| facts.quota_language.as_ref())
            .ok_or_else(|| "selected historical checkpoint has no quota language".to_string())?;
        let count = counts
            .get_mut(language)
            .ok_or_else(|| "selected historical checkpoint has unsupported language".to_string())?;
        *count = count
            .checked_add(1)
            .ok_or_else(|| "historical quota count overflowed".to_string())?;
    }
    Ok(counts)
}

fn require_disk_headroom(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        wide.push(0);
        let mut available = 0_u64;
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err("failed to determine historical-assessment free disk space".to_string());
        }
        require_available_bytes(available)?;
    }
    #[cfg(not(windows))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "historical-assessment path contains a NUL byte".to_string())?;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        let status = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
        if status != 0 {
            return Err("failed to determine historical-assessment free disk space".to_string());
        }
        let stats = unsafe { stats.assume_init() };
        #[allow(clippy::unnecessary_cast)]
        let available = (stats.f_bavail as u64)
            .checked_mul(stats.f_frsize as u64)
            .ok_or_else(|| "historical-assessment free disk space overflowed".to_string())?;
        require_available_bytes(available)?;
    }
    Ok(())
}

fn require_available_bytes(available: u64) -> Result<(), String> {
    if available < MINIMUM_FREE_BYTES {
        Err(format!(
            "historical assessment paused before cloning because only {available} bytes are free; at least {MINIMUM_FREE_BYTES} are required"
        ))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn normalize_path(path: std::path::PathBuf) -> std::path::PathBuf {
    let text = path.to_string_lossy().into_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return std::path::PathBuf::from(format!(r"\\{rest}"));
    }
    text.strip_prefix(r"\\?\")
        .map_or(path, std::path::PathBuf::from)
}

#[cfg(not(windows))]
fn normalize_path(path: std::path::PathBuf) -> std::path::PathBuf {
    path
}

#[cfg(test)]
#[path = "benchmark_non_blind_history_runner_tests.rs"]
mod tests;
