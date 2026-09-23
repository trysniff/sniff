use super::super::intentional_boundary_source_census::intentional_boundary_file_records_typed;
use super::super::{
    HistoricalV3ChangedMethod, HistoricalV3IdenticalTestOutcome, HistoricalV3IdenticalTests,
    HistoricalV3MechanicalQualification, HistoricalV3Protocol, HistoricalV3SemanticCensus,
    HistoricalV3SemanticSnapshot, HistoricalV3SourceSide, HistoricalV3SourceSnapshot,
    HistoricalV3TestRecipe, IntentionalBoundarySemanticMethod,
    validate_historical_v3_identical_tests, validate_historical_v3_mechanical_qualification,
    validate_historical_v3_protocol, validate_historical_v3_test_recipe,
};
use super::{
    HISTORICAL_V3_SOURCE_REVIEW_BUNDLE_SCHEMA_VERSION, HistoricalV3ReviewBehaviorEvidence,
    HistoricalV3ReviewCommandResult, HistoricalV3ReviewMethod, HistoricalV3SourceReviewBundle,
    HistoricalV3SourceReviewInputs, HistoricalV3SourceReviewRoots, REVIEW_ITEM_CONTRACT,
    SOURCE_REVIEW_BUNDLE_CONTRACT,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn build_historical_v3_source_review_bundle(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    roots: &HistoricalV3SourceReviewRoots<'_>,
) -> Result<HistoricalV3SourceReviewBundle, String> {
    validate_inputs(inputs)?;
    let protocol = inputs.protocol;
    let source_census = inputs.source_census;
    let semantic_census = inputs.semantic_census;
    let qualification = inputs.qualification;
    let recipe = inputs.recipe;
    let execution = inputs.execution;
    let base_records = intentional_boundary_file_records_typed(
        roots.base_root,
        &source_census.base.inventory,
        &source_census.base.source_census,
    )
    .map_err(|error| error.detail)?;
    let merge_records = intentional_boundary_file_records_typed(
        roots.merge_root,
        &source_census.merge.inventory,
        &source_census.merge.source_census,
    )
    .map_err(|error| error.detail)?;
    let methods = qualification
        .evidence
        .changed_methods
        .iter()
        .map(|changed| match changed.side {
            HistoricalV3SourceSide::Base => review_method(
                changed,
                &source_census.base,
                &semantic_census.base,
                &base_records,
            ),
            HistoricalV3SourceSide::Merge => review_method(
                changed,
                &source_census.merge,
                &semantic_census.merge,
                &merge_records,
            ),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut bundle = HistoricalV3SourceReviewBundle {
        schema_version: HISTORICAL_V3_SOURCE_REVIEW_BUNDLE_SCHEMA_VERSION,
        bundle_contract: SOURCE_REVIEW_BUNDLE_CONTRACT.to_string(),
        review_item_id: review_item_id(protocol, qualification, execution)?,
        language: language_name(qualification.rank.language()).to_string(),
        source_only: true,
        repository_identity_included: false,
        change_metadata_included: false,
        sniff_output_included: false,
        prior_labels_included: false,
        public_surface_preserved: qualification.evidence.public_surface.preserved,
        public_surface_delta_sha256: qualification.evidence.public_surface.delta_sha256.clone(),
        simplifications: qualification.evidence.simplifications.clone(),
        methods,
        behavior: behavior(recipe, execution),
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = source_review_bundle_sha256(&bundle)?;
    validate_historical_v3_source_review_bundle(inputs, &bundle)?;
    Ok(bundle)
}

pub fn validate_historical_v3_source_review_bundle(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
) -> Result<(), String> {
    validate_inputs(inputs)?;
    let protocol = inputs.protocol;
    let semantic_census = inputs.semantic_census;
    let qualification = inputs.qualification;
    let recipe = inputs.recipe;
    let execution = inputs.execution;
    if bundle.schema_version != HISTORICAL_V3_SOURCE_REVIEW_BUNDLE_SCHEMA_VERSION
        || bundle.bundle_contract != SOURCE_REVIEW_BUNDLE_CONTRACT
        || bundle.review_item_id != review_item_id(protocol, qualification, execution)?
        || bundle.language != language_name(qualification.rank.language())
        || !bundle.source_only
        || bundle.repository_identity_included
        || bundle.change_metadata_included
        || bundle.sniff_output_included
        || bundle.prior_labels_included
        || !bundle.public_surface_preserved
        || bundle.public_surface_delta_sha256 != qualification.evidence.public_surface.delta_sha256
        || bundle.simplifications != qualification.evidence.simplifications
        || bundle.behavior != behavior(recipe, execution)
        || bundle.bundle_sha256 != source_review_bundle_sha256(bundle)?
        || bundle.methods.len() != qualification.evidence.changed_methods.len()
    {
        return Err("historical-v3 source-review bundle commitment changed".to_string());
    }
    for (method, changed) in bundle
        .methods
        .iter()
        .zip(&qualification.evidence.changed_methods)
    {
        validate_review_method(method, changed, semantic_census)?;
    }
    Ok(())
}

fn validate_inputs(inputs: &HistoricalV3SourceReviewInputs<'_>) -> Result<(), String> {
    let protocol = inputs.protocol;
    let source_census = inputs.source_census;
    let semantic_census = inputs.semantic_census;
    let qualification = inputs.qualification;
    let recipe = inputs.recipe;
    let execution = inputs.execution;
    validate_historical_v3_protocol(protocol)?;
    validate_historical_v3_mechanical_qualification(
        protocol,
        inputs.collection,
        inputs.materialization,
        source_census,
        semantic_census,
        qualification,
    )?;
    validate_historical_v3_test_recipe(
        protocol,
        inputs.collection,
        inputs.materialization,
        source_census,
        semantic_census,
        qualification,
        recipe,
    )?;
    validate_historical_v3_identical_tests(protocol, recipe, execution)?;
    if !matches!(execution.outcome, HistoricalV3IdenticalTestOutcome::Passed)
        || source_census.rank != semantic_census.rank
        || source_census.rank != qualification.rank
        || source_census.rank != recipe.rank
        || source_census.rank != execution.rank
        || source_census.rank.protocol_sha256 != protocol.protocol_sha256
        || source_census.source_census_sha256 != semantic_census.source_census_sha256
        || source_census.source_census_sha256 != qualification.source_census_sha256
        || semantic_census.semantic_census_sha256 != qualification.semantic_census_sha256
        || qualification.qualification_sha256 != recipe.qualification_sha256
        || recipe.recipe_sha256 != execution.test_recipe_sha256
        || !qualification.evidence.public_surface.preserved
        || qualification.evidence.changed_methods.is_empty()
        || !qualification.evidence.unresolved_changed_methods.is_empty()
        || qualification.evidence.simplifications.is_empty()
    {
        return Err(
            "historical-v3 source-review inputs are not a passed qualified rank".to_string(),
        );
    }
    Ok(())
}

fn review_method(
    changed: &HistoricalV3ChangedMethod,
    source: &HistoricalV3SourceSnapshot,
    semantic: &HistoricalV3SemanticSnapshot,
    records: &[crate::types::FileRecord],
) -> Result<HistoricalV3ReviewMethod, String> {
    let file_index = source
        .source_census
        .source_files
        .iter()
        .position(|file| file.repository_path == changed.repository_path)
        .ok_or_else(|| "historical-v3 review method source file disappeared".to_string())?;
    let source_file = &source.source_census.source_files[file_index];
    let method_index = source_file
        .methods
        .iter()
        .position(|method| method.parser_unit_id == changed.parser_unit_id)
        .ok_or_else(|| "historical-v3 review method disappeared from source census".to_string())?;
    let record = records
        .get(file_index)
        .ok_or_else(|| "historical-v3 review source record disappeared".to_string())?;
    let parsed = record
        .methods
        .get(method_index)
        .ok_or_else(|| "historical-v3 review parsed method disappeared".to_string())?;
    let semantic = semantic_method(semantic, changed)?;
    if parsed.name != changed.symbol_name
        || parsed.start_line != changed.start_line
        || parsed.end_line != changed.end_line
        || sha256(parsed.source.as_bytes()) != changed.source_sha256
    {
        return Err("historical-v3 review method source changed".to_string());
    }
    Ok(HistoricalV3ReviewMethod {
        side: changed.side,
        language: changed.language.clone(),
        repository_path: changed.repository_path.clone(),
        parser_unit_id: changed.parser_unit_id.clone(),
        symbol_name: changed.symbol_name.clone(),
        start_line: changed.start_line,
        end_line: changed.end_line,
        source_sha256: changed.source_sha256.clone(),
        source: parsed.source.clone(),
        semantic: semantic.clone(),
    })
}

fn validate_review_method(
    method: &HistoricalV3ReviewMethod,
    changed: &HistoricalV3ChangedMethod,
    census: &HistoricalV3SemanticCensus,
) -> Result<(), String> {
    let snapshot = match changed.side {
        HistoricalV3SourceSide::Base => &census.base,
        HistoricalV3SourceSide::Merge => &census.merge,
    };
    let semantic = semantic_method(snapshot, changed)?;
    if method.side != changed.side
        || method.language != changed.language
        || method.repository_path != changed.repository_path
        || method.parser_unit_id != changed.parser_unit_id
        || method.symbol_name != changed.symbol_name
        || method.start_line != changed.start_line
        || method.end_line != changed.end_line
        || method.source_sha256 != changed.source_sha256
        || sha256(method.source.as_bytes()) != changed.source_sha256
        || method.semantic != *semantic
    {
        return Err("historical-v3 source-review method changed".to_string());
    }
    Ok(())
}

fn semantic_method<'a>(
    snapshot: &'a HistoricalV3SemanticSnapshot,
    changed: &HistoricalV3ChangedMethod,
) -> Result<&'a IntentionalBoundarySemanticMethod, String> {
    let method = snapshot
        .semantic_census
        .methods
        .iter()
        .find(|method| method.parser_unit_id == changed.parser_unit_id)
        .ok_or_else(|| {
            "historical-v3 review method disappeared from semantic census".to_string()
        })?;
    if method.repository_path != changed.repository_path
        || method.symbol_name != changed.symbol_name
        || method.start_line != changed.start_line
        || method.end_line != changed.end_line
        || method.indexer != changed.indexer
    {
        return Err("historical-v3 review semantic method identity changed".to_string());
    }
    Ok(method)
}

fn behavior(
    recipe: &HistoricalV3TestRecipe,
    execution: &HistoricalV3IdenticalTests,
) -> HistoricalV3ReviewBehaviorEvidence {
    HistoricalV3ReviewBehaviorEvidence {
        preparation_commands: recipe.preparation_commands.clone(),
        test_command: recipe.test_command.clone(),
        execution_platform: recipe.execution_platform.clone(),
        image_digest: execution.image_digest.clone(),
        toolchain_manifest_sha256: execution.toolchain_manifest_sha256.clone(),
        dependency_store_sha256: execution.dependency_store_sha256.clone(),
        results: execution
            .events
            .iter()
            .map(|event| HistoricalV3ReviewCommandResult {
                side: event.side,
                phase: event.phase,
                command_index: event.command_index,
                command_sha256: event.command_sha256.clone(),
                exit_code: event.exit_code,
                timed_out: event.timed_out,
                duration_millis: event.duration_millis,
                stdout_sha256: event.stdout_sha256.clone(),
                stderr_sha256: event.stderr_sha256.clone(),
                stdout_byte_count: event.stdout_byte_count,
                stderr_byte_count: event.stderr_byte_count,
                stdout_truncated: event.stdout_truncated,
                stderr_truncated: event.stderr_truncated,
            })
            .collect(),
    }
}

fn review_item_id(
    protocol: &HistoricalV3Protocol,
    qualification: &HistoricalV3MechanicalQualification,
    execution: &HistoricalV3IdenticalTests,
) -> Result<String, String> {
    Ok(format!(
        "hvr3:{}",
        json_sha256(&(
            REVIEW_ITEM_CONTRACT,
            &protocol.protocol_sha256,
            &qualification.rank.rank_sha256,
            &qualification.qualification_sha256,
            &execution.execution_sha256,
        ))?
    ))
}

#[cfg(test)]
pub(super) fn seal_source_review_bundle(
    mut bundle: HistoricalV3SourceReviewBundle,
) -> Result<HistoricalV3SourceReviewBundle, String> {
    bundle.bundle_sha256.clear();
    bundle.bundle_sha256 = source_review_bundle_sha256(&bundle)?;
    Ok(bundle)
}

fn source_review_bundle_sha256(bundle: &HistoricalV3SourceReviewBundle) -> Result<String, String> {
    let mut committed = bundle.clone();
    committed.bundle_sha256.clear();
    json_sha256(&committed)
}

fn language_name(language: super::super::HistoricalV3Language) -> &'static str {
    use super::super::HistoricalV3Language as Language;
    match language {
        Language::Go => "go",
        Language::JavaScript => "javascript",
        Language::Kotlin => "kotlin",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::TypeScript => "typescript",
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v3 source review: {error}"))
}
