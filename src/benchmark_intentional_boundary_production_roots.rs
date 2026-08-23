use super::super::history_v2_slot_store_support::{
    canonical_directory, require_plain_directory, sync_directory,
};
use super::super::{IntentionalBoundaryRankStage, IntentionalBoundaryRankStageError};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) struct ProductionRoots {
    pub state: PathBuf,
    pub work: PathBuf,
    pub frame: PathBuf,
}

impl ProductionRoots {
    pub fn prepare(
        state: &Path,
        work: &Path,
        frame: &Path,
    ) -> Result<Self, IntentionalBoundaryRankStageError> {
        let planned_state = prospective_plain_directory(state, "rank state root")?;
        let planned_work = prospective_plain_directory(work, "rank work root")?;
        let planned_frame = prospective_plain_directory(frame, "rank frame root")?;
        require_separate(&planned_state, &planned_work, &planned_frame)?;
        let state = create_plain_directory(state, "rank state root")?;
        let work = create_plain_directory(work, "rank work root")?;
        let frame = create_plain_directory(frame, "rank frame root")?;
        require_separate(&state, &work, &frame)?;
        if state != planned_state || work != planned_work || frame != planned_frame {
            return Err(infrastructure(
                "intentional-boundary production root identity changed during creation",
            ));
        }
        Ok(Self { state, work, frame })
    }

    pub fn checkout(&self, population_rank: usize) -> PathBuf {
        self.work.join(format!("rank-{population_rank:04}"))
    }

    pub fn require_checkout(
        &self,
        population_rank: usize,
        stage: IntentionalBoundaryRankStage,
    ) -> Result<PathBuf, IntentionalBoundaryRankStageError> {
        let path = self.checkout(population_rank);
        require_plain_directory(&path, "intentional-boundary rank checkout")
            .map_err(|detail| IntentionalBoundaryRankStageError::invalid(stage, detail))?;
        let resolved = canonical_directory(&path, "intentional-boundary rank checkout")
            .map_err(|detail| IntentionalBoundaryRankStageError::infrastructure(stage, detail))?;
        if resolved.parent() != Some(self.work.as_path()) {
            return Err(IntentionalBoundaryRankStageError::invalid(
                stage,
                "intentional-boundary rank checkout escaped its work root",
            ));
        }
        Ok(resolved)
    }

    pub fn remove_checkout(
        &self,
        population_rank: usize,
        stage: IntentionalBoundaryRankStage,
    ) -> Result<(), IntentionalBoundaryRankStageError> {
        let path = self.checkout(population_rank);
        if !path.exists() {
            return Ok(());
        }
        let resolved = self.require_checkout(population_rank, stage)?;
        fs::remove_dir_all(&resolved).map_err(|error| {
            IntentionalBoundaryRankStageError::infrastructure(
                stage,
                format!("failed to remove intentional-boundary rank checkout: {error}"),
            )
        })?;
        sync_directory(&self.work)
            .map_err(|detail| IntentionalBoundaryRankStageError::infrastructure(stage, detail))
    }
}

fn prospective_plain_directory(
    path: &Path,
    label: &str,
) -> Result<PathBuf, IntentionalBoundaryRankStageError> {
    if !path.is_absolute() {
        return Err(invalid(format!(
            "intentional-boundary {label} must be absolute"
        )));
    }
    if path.exists() {
        return canonical_directory(path, label).map_err(invalid);
    }
    let mut ancestor = path;
    let mut missing = Vec::<OsString>::new();
    while !ancestor.exists() {
        let component = ancestor
            .file_name()
            .ok_or_else(|| invalid(format!("intentional-boundary {label} has no ancestor")))?;
        if component == "." || component == ".." {
            return Err(invalid(format!(
                "intentional-boundary {label} contains a dot component"
            )));
        }
        missing.push(component.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| invalid(format!("intentional-boundary {label} has no ancestor")))?;
    }
    let mut resolved = canonical_directory(ancestor, label).map_err(invalid)?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn create_plain_directory(
    path: &Path,
    label: &str,
) -> Result<PathBuf, IntentionalBoundaryRankStageError> {
    fs::create_dir_all(path).map_err(|error| {
        infrastructure(format!(
            "failed to create intentional-boundary {label}: {error}"
        ))
    })?;
    canonical_directory(path, label).map_err(infrastructure)
}

fn require_separate(
    state: &Path,
    work: &Path,
    frame: &Path,
) -> Result<(), IntentionalBoundaryRankStageError> {
    for (left, right, label) in [
        (state, work, "state and work roots"),
        (state, frame, "state and frame roots"),
        (work, frame, "work and frame roots"),
    ] {
        if left.starts_with(right) || right.starts_with(left) {
            return Err(invalid(format!(
                "intentional-boundary {label} must not overlap"
            )));
        }
    }
    Ok(())
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryRankStageError {
    IntentionalBoundaryRankStageError::invalid(
        IntentionalBoundaryRankStage::Materialization,
        detail,
    )
}

fn infrastructure(detail: impl Into<String>) -> IntentionalBoundaryRankStageError {
    IntentionalBoundaryRankStageError::infrastructure(
        IntentionalBoundaryRankStage::Materialization,
        detail,
    )
}
