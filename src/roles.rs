use crate::llm::{LLMClient, ResponseSchema};
use crate::review_journal::{
    JournalRoleCompletion, JournalStage, JournalStore, scan_id, sha256_text,
};
use crate::types::FileRecord;
use std::collections::HashMap;
use std::path::Path;
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{Arc, OnceLock, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRole {
    Entrypoint,
    Script,
    Example,
    Fixture,
    Test,
    Docs,
    Generated,
    AdapterIntegration,
    Library,
    Mixed,
}

#[path = "utility_names.rs"]
mod names;

#[path = "roles_heuristics.rs"]
mod heuristics;
#[path = "roles_paths.rs"]
mod paths;
#[path = "roles_python_names.rs"]
mod python_names;
#[path = "roles_surface.rs"]
mod surface;

#[cfg(test)]
pub(crate) static ROLE_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub use heuristics::heuristic_file_role;
pub use names::is_utility_helper_name;
pub use paths::{
    contains_any, file_name, is_adapter_integration_path, is_cli_path, is_docs_path,
    is_entrypoint_path, is_example_path, is_fixture_path, is_generated_path, is_script_path,
    is_test_path, normalize_path, starts_with_segment,
};
pub use python_names::{is_python_alias_export_assignment, is_python_identifier_like};
pub use surface::{
    is_callback_contract_module, is_config_validation_module, is_detector_facade_module,
    is_hydration_hook_module, is_language_protocol_method, is_module_barrel_module,
    is_presentation_surface_module, is_protocol_stub_method, is_protocol_surface_module,
    is_pure_reexport_module, is_thin_delegation_method, is_thin_wrapper_export,
    is_wrapper_assignment, is_wrapper_only_module, source_looks_like_wrapper_module,
};

pub fn is_intentional_surface_path(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    let name = file_name(&normalized);

    is_entrypoint_path(&normalized, name)
        || is_script_path(&normalized)
        || is_example_path(&normalized)
        || is_fixture_path(&normalized)
        || is_test_path(&normalized, name)
        || is_docs_path(&normalized)
        || is_generated_path(&normalized, name)
}

pub fn is_detector_support_module(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    matches!(
        normalized.as_str(),
        "src/roles.rs"
            | "src/roles_paths.rs"
            | "src/roles_python_names.rs"
            | "src/roles_heuristics.rs"
            | "src/roles_surface.rs"
            | "src/roles_surface_presentation.rs"
            | "src/roles_surface_assignment.rs"
            | "src/roles_surface_facade.rs"
            | "src/roles_surface_protocol.rs"
            | "src/utility_names.rs"
            | "src/analyzer_support.rs"
            | "src/analyzer_file_verdicts.rs"
            | "src/analyzer_verdicts_detector.rs"
            | "src/analyzer_verdicts_rules.rs"
            | "src/analyzer_verdicts_rules_analysis.rs"
            | "src/file_verdicts_builder.rs"
            | "src/scorer_file.rs"
            | "src/scorer_method.rs"
            | "src/reporter_console.rs"
            | "src/parser_impl.rs"
            | "src/signal_layers_similarity_roles.rs"
    ) || normalized.ends_with("/src/roles.rs")
        || normalized.ends_with("/src/roles_paths.rs")
        || normalized.ends_with("/src/roles_python_names.rs")
        || normalized.ends_with("/src/roles_heuristics.rs")
        || normalized.ends_with("/src/roles_surface.rs")
        || normalized.ends_with("/src/roles_surface_presentation.rs")
        || normalized.ends_with("/src/roles_surface_assignment.rs")
        || normalized.ends_with("/src/roles_surface_facade.rs")
        || normalized.ends_with("/src/roles_surface_protocol.rs")
        || normalized.ends_with("/src/utility_names.rs")
        || normalized.ends_with("/analyzer_support.rs")
        || normalized.ends_with("/analyzer_file_verdicts.rs")
        || normalized.ends_with("/analyzer_verdicts_detector.rs")
        || normalized.ends_with("/analyzer_verdicts_rules.rs")
        || normalized.ends_with("/analyzer_verdicts_rules_analysis.rs")
        || normalized.ends_with("/file_verdicts_builder.rs")
        || normalized.ends_with("/scorer_file.rs")
        || normalized.ends_with("/scorer_method.rs")
        || normalized.ends_with("/reporter_console.rs")
        || normalized.ends_with("/parser_impl.rs")
        || normalized.ends_with("/signal_layers_similarity_roles.rs")
}

fn truncate_source(source: &str, max_chars: usize) -> String {
    if source.chars().count() <= max_chars {
        return source.to_string();
    }

    let head = max_chars / 2;
    let tail = max_chars - head;
    let head_text: String = source.chars().take(head).collect();
    let tail_text: String = source
        .chars()
        .rev()
        .take(tail)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head_text}\n...\n{tail_text}")
}

fn parse_role(value: &serde_json::Value) -> Result<FileRole, String> {
    let role = value
        .get("role")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "role classification response is missing a string role".to_string())?
        .trim()
        .to_lowercase();

    match role.as_str() {
        "cli_entrypoint" | "entrypoint" => Ok(FileRole::Entrypoint),
        "adapter_integration" => Ok(FileRole::AdapterIntegration),
        "example" => Ok(FileRole::Example),
        "fixture" => Ok(FileRole::Fixture),
        "test" => Ok(FileRole::Test),
        "docs" => Ok(FileRole::Docs),
        "generated" => Ok(FileRole::Generated),
        "core_library" | "library" => Ok(FileRole::Library),
        "mixed" => Ok(FileRole::Mixed),
        other => Err(format!(
            "role classification returned unsupported role `{other}`"
        )),
    }
}

async fn classify_with_llm(
    client: &LLMClient,
    file: &FileRecord,
) -> (Result<FileRole, String>, usize, usize) {
    let prompt = format!(
        "You classify codebase file roles for Sniff.\n\
Choose exactly one role from: core_library, adapter_integration, cli_entrypoint, example, test, docs, generated, mixed.\n\
- core_library: reusable product logic\n\
- adapter_integration: glue code that adapts between the core and an external system or framework\n\
- cli_entrypoint: main functions and command entrypoints\n\
- example: sample or demo code\n\
- test: test code\n\
- docs: documentation\n\
- generated: generated code\n\
- mixed: the file mixes concerns or is too ambiguous to place cleanly\n\n\
File path: {}\n\
Language: {}\n\
\n\
Source:\n\
---\n\
{}\n\
---\n\n\
Return only JSON:\n\
{{\n\
  \"role\": \"core_library | adapter_integration | cli_entrypoint | example | test | docs | generated | mixed\",\n\
  \"reason\": \"short plain-English explanation\"\n\
}}",
        file.file_path,
        file.language,
        truncate_source(&file.source, 2800)
    );

    // Role is supporting repository metadata, not a semantic slop verdict.
    // Schema retries already protect this call; consensus would buy the same
    // temperature-zero classification at least twice for every unresolved file.
    match client
        .call_single(&prompt, ResponseSchema::RoleClassification)
        .await
    {
        Ok((result, in_tok, out_tok)) => {
            let role = result
                .ok_or_else(|| {
                    "role classification returned no valid JSON response after retries".to_string()
                })
                .and_then(|result| parse_role(&result));
            (role, in_tok, out_tok)
        }
        Err(err) => (Err(err), 0, 0),
    }
}

fn role_journal_key(file: &FileRecord) -> String {
    sha256_text(&format!(
        "role\n{}\n{}\n{}",
        file.file_path,
        file.language,
        sha256_text(&file.source)
    ))
}

pub async fn resolve_file_roles(
    file_records: &[FileRecord],
    client: Arc<LLMClient>,
) -> Result<(usize, usize), String> {
    resolve_file_roles_with_journal(file_records, client, None, None).await
}

pub async fn resolve_file_roles_with_journal(
    file_records: &[FileRecord],
    client: Arc<LLMClient>,
    journal_path: Option<&Path>,
    run_id: Option<&str>,
) -> Result<(usize, usize), String> {
    let mut input_tokens = 0usize;
    let mut output_tokens = 0usize;
    let mut unresolved = Vec::new();
    let context = client.review_context_key();

    for file in file_records {
        if let Some(role) = heuristic_file_role(&file.file_path) {
            cache_file_role(&file.file_path, role);
            continue;
        }

        unresolved.push(file.clone());
    }

    if unresolved.is_empty() {
        return Ok((input_tokens, output_tokens));
    }

    let derived_run_id;
    let run_id = if let Some(run_id) = run_id {
        run_id
    } else {
        derived_run_id = scan_id(file_records, &context);
        &derived_run_id
    };
    let mut journal = journal_path
        .map(|path| {
            JournalStore::load_for_scan(
                path,
                run_id,
                JournalStage::Role,
                run_id,
                &context,
                unresolved.len(),
            )
        })
        .transpose()?;
    for file in unresolved {
        let key = role_journal_key(&file);
        if let Some((role_label, is_current_scan)) =
            journal.as_ref().and_then(|store| store.reusable_role(&key))
        {
            let role = parse_role(&serde_json::json!({"role": role_label}))?;
            if !is_current_scan {
                journal
                    .as_mut()
                    .expect("cached role requires a journal store")
                    .record_role(
                        key,
                        sha256_text(&file.source),
                        JournalRoleCompletion {
                            role: Some(file_role_label(role).to_string()),
                            in_tok: 0,
                            out_tok: 0,
                            cached_in_tok: 0,
                            retry_on_resume: false,
                        },
                    )?;
            }
            cache_file_role(&file.file_path, role);
            continue;
        }

        let (attempt, usage) =
            LLMClient::track_usage(classify_with_llm(client.as_ref(), &file)).await;
        let (result, in_tok, out_tok) = attempt;
        let in_tok = in_tok.saturating_add(usage.failed_input_tokens);
        let out_tok = out_tok.saturating_add(usage.failed_output_tokens);
        let cached_in_tok = usage.cached_input_tokens;
        match result {
            Ok(role) => {
                let file_path = file.file_path.clone();
                if let Some(store) = journal.as_mut() {
                    store.record_role(
                        key,
                        sha256_text(&file.source),
                        JournalRoleCompletion {
                            role: Some(file_role_label(role).to_string()),
                            in_tok,
                            out_tok,
                            cached_in_tok,
                            retry_on_resume: false,
                        },
                    )?;
                }
                cache_file_role(&file_path, role);
                input_tokens += in_tok;
                output_tokens += out_tok;
            }
            Err(err) => {
                if let Some(store) = journal.as_mut() {
                    store.record_role(
                        key,
                        sha256_text(&file.source),
                        JournalRoleCompletion {
                            role: None,
                            in_tok,
                            out_tok,
                            cached_in_tok,
                            retry_on_resume: true,
                        },
                    )?;
                }
                return Err(format!(
                    "Role resolution failed for {}: {}",
                    file.file_path, err
                ));
            }
        }
    }

    Ok((input_tokens, output_tokens))
}

fn cache_key(file_path: &str) -> String {
    normalize_path(file_path)
}

fn role_cache() -> &'static RwLock<HashMap<String, FileRole>> {
    static ROLE_CACHE: OnceLock<RwLock<HashMap<String, FileRole>>> = OnceLock::new();
    ROLE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn clear_file_role_cache() {
    if let Ok(mut cache) = role_cache().write() {
        cache.clear();
    }
}

pub fn cache_file_role(file_path: &str, role: FileRole) {
    if let Ok(mut cache) = role_cache().write() {
        cache.insert(cache_key(file_path), role);
    }
}

fn cached_file_role(file_path: &str) -> Option<FileRole> {
    role_cache()
        .read()
        .ok()
        .and_then(|cache| cache.get(&cache_key(file_path)).copied())
}

pub fn classify_file_role(file_path: &str) -> FileRole {
    if let Some(role) = cached_file_role(file_path) {
        return role;
    }

    heuristic_file_role(file_path).unwrap_or(FileRole::Mixed)
}

pub fn file_role_label(role: FileRole) -> &'static str {
    match role {
        FileRole::Entrypoint => "cli_entrypoint",
        FileRole::Script => "cli_entrypoint",
        FileRole::Example => "example",
        FileRole::Fixture => "example",
        FileRole::Test => "test",
        FileRole::Docs => "docs",
        FileRole::Generated => "generated",
        FileRole::AdapterIntegration => "adapter_integration",
        FileRole::Library => "core_library",
        FileRole::Mixed => "mixed",
    }
}

pub fn is_intentional_surface(file_path: &str) -> bool {
    if is_intentional_surface_path(file_path) {
        return true;
    }

    matches!(
        classify_file_role(file_path),
        FileRole::Entrypoint
            | FileRole::Script
            | FileRole::Example
            | FileRole::Fixture
            | FileRole::Test
            | FileRole::Docs
            | FileRole::Generated
    )
}

pub fn is_intentional_surface_record(file: &FileRecord) -> bool {
    is_intentional_surface(&file.file_path)
        || is_compatibility_shim_record(file)
        || is_analysis_reexports_module(&file.file_path)
        || is_analysis_findings_facade_module(&file.file_path)
        || is_analysis_finding_workspace_module(&file.file_path)
        || is_support_boundary_module(file)
        || is_data_catalog_module(file)
        || is_contract_type_module(file)
        || is_support_plumbing_module(&file.file_path)
        || is_provider_facade_module(file)
        || is_utility_surface_module(file)
        || is_protocol_surface_module(file)
        || is_presentation_surface_module(file)
        || is_hydration_hook_module(file)
        || is_callback_contract_module(file)
        || is_config_validation_module(file)
        || is_analysis_evidence_module(file)
        || is_module_barrel_module(file)
}

pub fn is_utility_surface_module(file: &FileRecord) -> bool {
    if file.methods.len() < 3 {
        return false;
    }

    let normalized = normalize_path(&file.file_path);
    let stem = file_name(&normalized)
        .split('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    let path_is_utility_like = normalized.contains("/utils/")
        || normalized.contains("/common/")
        || normalized.contains("/shared/")
        || normalized.ends_with("/utils.ts")
        || normalized.ends_with("/utils.js")
        || normalized.ends_with("/utils.py");
    let stem_is_generic = matches!(
        stem.as_str(),
        "helpers" | "helper" | "utils" | "common" | "shared"
    );
    let stem_looks_like_domain_rules = stem.contains("rules");
    let method_names_are_utility_like = file
        .methods
        .iter()
        .all(|method| is_utility_helper_name(&method.name));

    if stem_looks_like_domain_rules && !stem_is_generic {
        return false;
    }

    (path_is_utility_like && stem_is_generic) || method_names_are_utility_like
}

pub fn is_compatibility_shim_path(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    normalized == "src/llm.py" || normalized.ends_with("/src/llm.py")
}

pub fn is_compatibility_shim_record(file: &FileRecord) -> bool {
    is_compatibility_shim_path(&file.file_path) || source_looks_like_compatibility_shim(file)
}

fn source_looks_like_compatibility_shim(file: &FileRecord) -> bool {
    if !file.methods.is_empty() {
        return false;
    }

    let lower = file.source.to_lowercase();
    if !lower.contains("compatibility shim") {
        return false;
    }

    file.source.lines().all(|line| {
        let trimmed = line.trim();
        trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with("@file:")
            || trimmed.starts_with("package ")
            || trimmed.starts_with("import ")
            || trimmed.starts_with("#")
    })
}

pub fn is_support_boundary_module(file: &FileRecord) -> bool {
    let normalized = normalize_path(&file.file_path);
    let name = file_name(&normalized);

    let is_explicit_boundary = matches!(
        name,
        "service-worker-support.ts"
            | "feature-flags.ts"
            | "password-session-cache.ts"
            | "service-worker-support.js"
            | "service-worker-support.py"
            | "service-worker-support.rs"
            | "service-worker-support.kt"
    );

    let looks_like_support_boundary = is_explicit_boundary
        || (normalized.contains("/src/lib/")
            && (name.ends_with("-support.ts")
                || name.ends_with("-flags.ts")
                || name.ends_with("-cache.ts")))
        || name.ends_with("-support.js")
        || name.ends_with("-support.py")
        || name.ends_with("-support.rs")
        || name.ends_with("-support.kt");

    if !looks_like_support_boundary {
        return false;
    }

    if !is_explicit_boundary && file.methods.len() > 8 {
        return false;
    }

    normalized.contains("/background/core/")
        || normalized.contains("/src/lib/")
        || normalized.contains("/lib/")
        || normalized.contains("/core/")
        || normalized.contains("/support/")
}

pub fn is_data_catalog_module(file: &FileRecord) -> bool {
    let normalized = normalize_path(&file.file_path);
    if !normalized.contains("/src/data/") {
        return false;
    }

    if file.methods.len() < 3 {
        return false;
    }

    let source = file.source.to_lowercase();
    let looks_like_catalog =
        source.contains("record<string,") || source.contains("object.fromentries(");
    let has_exported_surface = source.contains("export const ")
        || source.contains("export function ")
        || source.contains("export interface ")
        || source.contains("export type ");

    looks_like_catalog && has_exported_surface
}

pub fn is_contract_type_module(file: &FileRecord) -> bool {
    if !file.methods.is_empty() {
        return false;
    }

    let normalized = normalize_path(&file.file_path);
    let name = file_name(&normalized);
    let looks_like_contract_path = normalized.contains("/contracts/")
        || name.ends_with("-contracts.ts")
        || name.ends_with("contracts.ts")
        || name.ends_with(".types.ts")
        || name.ends_with("_types.ts");
    if !looks_like_contract_path {
        return false;
    }

    let source = file.source.to_lowercase();
    let has_type_declarations = source.contains("export type ")
        || source.contains("export interface ")
        || source.contains("interface ")
        || source.contains("type ");
    let has_runtime_code = source.contains("function ")
        || source.contains("class ")
        || source.contains("=> {")
        || source.contains("async ")
        || source.contains("return ");

    has_type_declarations && !has_runtime_code
}

pub fn is_analysis_finding_helper_module(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    let name = file_name(&normalized);
    normalized.contains("/analysis/")
        && name.starts_with("finding_")
        && name.ends_with(".py")
        && !name.contains("signatures")
}

pub fn is_analysis_finding_support_module(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    let name = file_name(&normalized);
    normalized.contains("/analysis/")
        && name.starts_with("finding_")
        && name.ends_with(".py")
        && (name.ends_with("_base.py")
            || name.ends_with("_compat.py")
            || name == "finding_diff.py"
            || name.ends_with("_public_names.py")
            || name.ends_with("_all_contract.py")
            || name.ends_with("_packaging.py")
            || name.ends_with("_workspace.py")
            || name == "finding_workspace.py")
        && !name.contains("signatures")
        && !name.contains("findings")
        && !name.contains("detection_context")
}

pub fn is_analysis_finding_workspace_module(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    normalized.ends_with("/analysis/finding_workspace.py")
}

pub fn is_analysis_findings_facade_module(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    normalized.ends_with("/analysis/findings.py")
}

pub fn is_analysis_explanation_support_module(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    normalized.ends_with("/analysis/explanation_facts.py")
}

pub fn is_analysis_reexports_module(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    let name = file_name(&normalized);
    normalized.contains("/analysis/") && name.ends_with("_reexports.py")
}

pub fn is_analysis_evidence_module(file: &FileRecord) -> bool {
    let normalized = normalize_path(&file.file_path);
    normalized.ends_with("/analysis/evidence.py")
        || normalized.ends_with("/analysis/evidence.ts")
        || normalized.ends_with("/analysis/evidence.kt")
        || normalized.ends_with("/analysis/evidence.rs")
}

pub fn is_support_plumbing_module(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    if is_smart_filler_support_module(&normalized)
        || is_session_state_contract_module(&normalized)
        || is_user_safe_support_module(&normalized)
        || is_core_planning_support_module(&normalized)
        || is_appstore_row_helper_module(&normalized)
        || is_design_tokens_module(&normalized)
        || is_appstore_hydration_module(&normalized)
        || is_host_support_surface_module(&normalized)
        || is_shared_contract_surface_module(&normalized)
    {
        return true;
    }
    normalized.ends_with("/analysis/diff_text.py")
        || normalized.ends_with("/analysis/finding_diff.py")
        || normalized.ends_with("/release/candidate.py")
        || normalized.ends_with("/eval/fixtures.py")
        || normalized.ends_with("/analyzer_support.rs")
        || normalized.ends_with("/analyzer_verdicts_rules_analysis.rs")
        || normalized.ends_with("/file_verdicts_builder.rs")
        || normalized.ends_with("/parser_impl.rs")
        || normalized.contains("/parser_impl/")
        || normalized.ends_with("/signal_layers_similarity_roles.rs")
        || normalized.ends_with("/analyzer.rs")
        || normalized.ends_with("/scorer_name_utils.rs")
        || normalized.ends_with("/symbol_graph_resolver.rs")
        || normalized.ends_with("/walker.rs")
        || normalized.ends_with("/analyzer_verdicts_rules.rs")
        || normalized.ends_with("/orchestrator/explanation_facts.py")
        || normalized.ends_with("/orchestrator/base_classification.py")
        || normalized.ends_with("/orchestrator/analysis_stage.py")
        || normalized.ends_with("/orchestrator/explainability.py")
        || normalized.ends_with("/orchestrator/explanation_polish.py")
        || normalized.ends_with("/orchestrator/court_output.py")
        || normalized.ends_with("/orchestrator/court_payload.py")
        || normalized.ends_with("/orchestrator/court_setup.py")
        || normalized.ends_with("/orchestrator/adjudication.py")
        || normalized.ends_with("/orchestrator/scope.py")
        || normalized.ends_with("/config.py")
        || normalized.ends_with("/planner.py")
        || normalized.ends_with("/versioning/tags.py")
        || normalized.ends_with("/prompt_pack.py")
        || normalized.ends_with("/licensing/policy.py")
        || normalized.ends_with("/io/tokens.py")
        || normalized.ends_with("/policies/guards.py")
        || normalized.ends_with("/integrations/github/guards.py")
        || normalized.ends_with("/integrations/github/events.py")
        || normalized.ends_with("/integrations/github/server.py")
        || normalized.ends_with("/integrations/github/runtime.py")
        || normalized.ends_with("/integrations/github/persistence_postgres_publish_decision_ops.py")
        || normalized.ends_with("/integrations/github/persistence_serialization.py")
        || normalized.ends_with("/integrations/github/persistence_ephemeral.py")
        || normalized.ends_with("/providers/llm_transport.py")
        || normalized.ends_with("/providers/llm_payloads.py")
        || normalized.ends_with("/retry.py")
        || normalized.ends_with("/providers/llm.py")
        || normalized.ends_with("/llm_json.rs")
        || normalized == "src/analyzer_verdicts_rules.rs"
}

fn is_host_support_surface_module(normalized: &str) -> bool {
    let name = file_name(normalized)
        .split('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    let host_context = normalized.contains("/host/")
        || normalized.contains("/androidhost/")
        || normalized.contains("/reminder-host-jvm/")
        || normalized.contains("/services/");
    let supportish = name.contains("support")
        || name.ends_with("adapters")
        || name.ends_with("models")
        || name.ends_with("localization")
        || name.ends_with("callbacks")
        || (name.ends_with("runtime") && name.contains("host"));

    host_context && supportish
}

fn is_shared_contract_surface_module(normalized: &str) -> bool {
    let name = file_name(normalized)
        .split('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    let shared_context = normalized.contains("/shared/core/")
        || normalized.contains("/shared/contract/")
        || normalized.contains("/shared/uicontract/");
    let surfaceish = name.ends_with("contract")
        || name.ends_with("contracts")
        || name.ends_with("protocol")
        || name.ends_with("protocols")
        || name.ends_with("model")
        || name.ends_with("models")
        || name.ends_with("hydration")
        || name.ends_with("shadowruntimehandlers")
        || name.ends_with("callbacks")
        || name.ends_with("facade");

    shared_context && surfaceish
}

pub fn is_provider_facade_module(file: &FileRecord) -> bool {
    is_provider_facade_path(&file.file_path)
        && file.methods.len() >= 8
        && is_provider_facade_shape(file)
}

pub fn is_provider_facade_path(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    normalized.ends_with("/providers/llm.py")
}

fn is_provider_facade_shape(file: &FileRecord) -> bool {
    let lowered = file.source.to_lowercase();
    let import_count = lowered.matches("from bumpkin.providers").count();
    let wrapper_count = file
        .methods
        .iter()
        .filter(|method| {
            let name = method.name.as_str();
            name.starts_with('_')
                || name.starts_with("get_")
                || name.starts_with("validate_")
                || name.starts_with("normalize_")
        })
        .count();

    import_count >= 4 && wrapper_count >= 4
}

fn is_smart_filler_support_module(normalized: &str) -> bool {
    if !normalized.contains("/smart-filler/") {
        return false;
    }

    matches!(
        file_name(normalized),
        "heuristics.ts" | "dom-utils.ts" | "smart-filler-lib.ts"
    ) || normalized.ends_with("/smart-filler/heuristics.ts")
        || normalized.ends_with("/smart-filler/dom-utils.ts")
        || normalized.ends_with("/smart-filler-lib.ts")
}

fn is_session_state_contract_module(normalized: &str) -> bool {
    normalized.ends_with("/session/session.types.ts")
        || normalized.ends_with("/session.types.ts")
        || normalized.contains("/session/") && file_name(normalized).ends_with(".types.ts")
}

fn is_user_safe_support_module(normalized: &str) -> bool {
    let name = file_name(normalized);
    normalized.contains("ui/src/lib/") && (name.starts_with("user-safe-") || name == "logo-drag.ts")
}

fn is_appstore_hydration_module(normalized: &str) -> bool {
    let name = file_name(normalized)
        .split('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    normalized.contains("/shared/core/appstore/") && name.ends_with("hydration")
}

fn is_core_planning_support_module(normalized: &str) -> bool {
    let name = file_name(normalized)
        .split('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    normalized.contains("/shared/core/") && name.ends_with("planner")
}

fn is_appstore_row_helper_module(normalized: &str) -> bool {
    let name = file_name(normalized)
        .split('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    normalized.contains("/shared/core/appstore/") && name.ends_with("cabinetrows")
}

fn is_design_tokens_module(normalized: &str) -> bool {
    let name = file_name(normalized)
        .split('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    normalized.contains("/design/") && name.ends_with("tokens")
}

pub fn is_parsing_or_serialization_helper_module(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    let name = file_name(&normalized);
    name.ends_with("_parsing.py")
        || name.ends_with("_serialization.py")
        || name.ends_with("_serialization_helpers.py")
        || normalized.ends_with("/analysis/diff_text.py")
        || normalized.ends_with("/release/candidate.py")
}

pub fn is_versioning_tag_module(file_path: &str) -> bool {
    let normalized = normalize_path(file_path);
    normalized.ends_with("/versioning/tags.py")
}

#[cfg(test)]
mod intentional_surface_path_tests {
    use super::is_intentional_surface_path;

    #[test]
    fn path_based_intentional_surfaces_are_always_skipped() {
        assert!(is_intentional_surface_path("tests/test_callgraph.py"));
        assert!(is_intentional_surface_path(
            "tests/fixtures/clean/well_structured.py"
        ));
        assert!(is_intentional_surface_path("scripts/run_app_server.py"));
        assert!(is_intentional_surface_path("src/main.tsx"));
    }
}

#[cfg(test)]
mod role_parse_tests {
    use super::{FileRole, parse_role};

    #[test]
    fn invalid_llm_role_is_a_hard_error() {
        let error = parse_role(&serde_json::json!({"role": "probably_library"}))
            .expect_err("unknown roles must not silently become mixed");
        assert!(error.contains("unsupported role"));
    }

    #[test]
    fn missing_llm_role_is_a_hard_error() {
        let error = parse_role(&serde_json::json!({"reason": "ambiguous"}))
            .expect_err("missing roles must not silently become mixed");
        assert!(error.contains("missing a string role"));
    }

    #[test]
    fn supported_llm_role_is_parsed_without_fallback() {
        assert_eq!(
            parse_role(&serde_json::json!({"role": "core_library"})).unwrap(),
            FileRole::Library
        );
    }
}

#[cfg(test)]
#[path = "tests/roles.rs"]
mod tests;
