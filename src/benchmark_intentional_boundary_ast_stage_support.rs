use super::intentional_boundary_ast::AstSyntaxExtractor;
use super::intentional_boundary_ast_outcome::{
    AstDerivationError, AstDerivationErrorKind, ast_invalid,
};
use super::{
    IntentionalBoundaryAstCensus, IntentionalBoundaryAstCensusExclusionReason,
    IntentionalBoundaryAstCensusFailureEvidence, IntentionalBoundaryAstCensusStageError,
    IntentionalBoundaryAstCensusStageErrorKind, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySourceCensus,
};
use crate::types::FileRecord;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const RETAINED_EVIDENCE_LIMIT: usize = 4 * 1024;

pub(super) enum ResolvedAstRun {
    Completed(Vec<IntentionalBoundaryAstCensus>),
    Excluded(Vec<IntentionalBoundaryAstCensusFailureEvidence>),
}

pub(super) fn derive_repository_ast_runs(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    files: &[FileRecord],
) -> Vec<Result<IntentionalBoundaryAstCensus, AstDerivationError>> {
    if files.len() != source_census.source_files.len() {
        return vec![Err(ast_invalid(
            "repository",
            None,
            "intentional-boundary AST input omitted source files",
        ))];
    }
    for (source_file, file) in source_census.source_files.iter().zip(files) {
        if source_file.language != file.language {
            return vec![Err(ast_invalid(
                &source_file.language,
                Some(&source_file.repository_path),
                "intentional-boundary AST input changed parser language",
            ))];
        }
    }
    source_census
        .source_files
        .iter()
        .map(|file| file.language.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .flat_map(|language| derive_language(source_census, semantic_census, files, language))
        .collect()
}

fn derive_language(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    files: &[FileRecord],
    language: &str,
) -> Vec<Result<IntentionalBoundaryAstCensus, AstDerivationError>> {
    let extractor: AstSyntaxExtractor = match language {
        "go" => super::intentional_boundary_ast_go_kotlin::go_syntax_facts,
        "javascript" | "typescript" => super::intentional_boundary_ast_js_ts::js_ts_syntax_facts,
        "kotlin" => super::intentional_boundary_ast_go_kotlin::kotlin_syntax_facts,
        "python" => super::intentional_boundary_ast_python::python_syntax_facts,
        "rust" => super::intentional_boundary_ast_rust::rust_syntax_facts,
        other => {
            return vec![Err(ast_invalid(
                other,
                None,
                format!("intentional-boundary AST stage received unsupported language {other}"),
            ))];
        }
    };
    let failures = source_census
        .source_files
        .iter()
        .zip(files)
        .filter(|(source_file, _)| source_file.language == language)
        .filter_map(|(source_file, file)| {
            extractor(&source_file.repository_path, file).err().map(Err)
        })
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        return failures;
    }
    let census = match language {
        "go" => super::intentional_boundary_ast_go_kotlin::derive_go_ast_census(
            source_census,
            semantic_census,
            files,
        ),
        "javascript" | "typescript" => {
            super::intentional_boundary_ast_js_ts::derive_js_ts_ast_census(
                source_census,
                semantic_census,
                files,
                language,
            )
        }
        "kotlin" => super::intentional_boundary_ast_go_kotlin::derive_kotlin_ast_census(
            source_census,
            semantic_census,
            files,
        ),
        "python" => super::intentional_boundary_ast_python::derive_python_ast_census(
            source_census,
            semantic_census,
            files,
        ),
        "rust" => super::intentional_boundary_ast_rust::derive_rust_ast_census(
            source_census,
            semantic_census,
            files,
        ),
        _ => Err(ast_invalid(
            language,
            None,
            "intentional-boundary AST stage language dispatch changed after preflight",
        )),
    };
    vec![census]
}

pub(super) fn resolve_ast_runs(
    runs: Vec<Result<IntentionalBoundaryAstCensus, AstDerivationError>>,
) -> Result<ResolvedAstRun, IntentionalBoundaryAstCensusStageError> {
    let mut censuses = Vec::new();
    let mut terminal = Vec::new();
    let mut operational = Vec::new();
    for run in runs {
        match run {
            Ok(census) => censuses.push(census),
            Err(error) if error.kind == AstDerivationErrorKind::InvalidInput => {
                operational.push(error.detail);
            }
            Err(error) => terminal.push(failure_evidence(error)?),
        }
    }
    if !operational.is_empty() {
        return Err(IntentionalBoundaryAstCensusStageError {
            kind: IntentionalBoundaryAstCensusStageErrorKind::InvalidInput,
            detail: operational.join("; additionally, "),
        });
    }
    if !terminal.is_empty() {
        terminal.sort_by(failure_key);
        return Ok(ResolvedAstRun::Excluded(terminal));
    }
    let mut seen = BTreeSet::new();
    for census in &censuses {
        let [language] = census.languages.as_slice() else {
            return Err(invalid(
                "intentional-boundary AST stage requires one language per census",
            ));
        };
        if !seen.insert(language.as_str()) {
            return Err(invalid(format!(
                "intentional-boundary AST stage repeated language {language}"
            )));
        }
    }
    censuses.sort_by(|left, right| left.languages.cmp(&right.languages));
    Ok(ResolvedAstRun::Completed(censuses))
}

fn failure_evidence(
    error: AstDerivationError,
) -> Result<IntentionalBoundaryAstCensusFailureEvidence, IntentionalBoundaryAstCensusStageError> {
    let reason = match error.kind {
        AstDerivationErrorKind::SourceParserRejected => {
            IntentionalBoundaryAstCensusExclusionReason::SourceParserRejected
        }
        AstDerivationErrorKind::CensusIncomplete => {
            IntentionalBoundaryAstCensusExclusionReason::CensusIncomplete
        }
        AstDerivationErrorKind::InvalidInput => {
            return Err(invalid(error.detail));
        }
    };
    let (retained_detail, detail_truncated) = retain(&error.detail);
    Ok(IntentionalBoundaryAstCensusFailureEvidence {
        reason,
        language: error.language,
        repository_path: error.repository_path,
        detail_sha256: sha256(error.detail.as_bytes()),
        retained_detail,
        detail_truncated,
    })
}

pub(super) fn failure_key(
    left: &IntentionalBoundaryAstCensusFailureEvidence,
    right: &IntentionalBoundaryAstCensusFailureEvidence,
) -> std::cmp::Ordering {
    (
        &left.language,
        &left.repository_path,
        left.reason,
        &left.detail_sha256,
    )
        .cmp(&(
            &right.language,
            &right.repository_path,
            right.reason,
            &right.detail_sha256,
        ))
}

fn retain(value: &str) -> (String, bool) {
    if value.len() <= RETAINED_EVIDENCE_LIMIT {
        return (value.to_string(), false);
    }
    let mut end = RETAINED_EVIDENCE_LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_string(), true)
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryAstCensusStageError {
    IntentionalBoundaryAstCensusStageError {
        kind: IntentionalBoundaryAstCensusStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
