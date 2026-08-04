use crate::config::ResolvedConfig;
use crate::env_value;
use crate::llm::LLMClient;
use crate::roles;
use crate::types::FileRecord;
use std::path::Path;
use std::sync::Arc;

pub(super) fn build_llm_client(config: &ResolvedConfig) -> Result<Option<Arc<LLMClient>>, String> {
    let api_key = env_value::read("SNIFF_API_KEY");
    let endpoint = config.llm.endpoint.trim();
    if api_key.is_none() || endpoint.is_empty() {
        return Ok(None);
    }

    Ok(Some(Arc::new(LLMClient::try_new(config.clone(), api_key)?)))
}

pub(super) async fn resolve_roles(
    file_records: &[FileRecord],
    client: Option<Arc<LLMClient>>,
    checkpoint_path: Option<&Path>,
) -> Result<(usize, usize, Option<Arc<LLMClient>>), String> {
    let (role_in_tok, role_out_tok) = if let Some(client) = client.as_ref() {
        roles::resolve_file_roles_with_checkpoint(file_records, Arc::clone(client), checkpoint_path)
            .await?
    } else {
        (0, 0)
    };

    Ok((role_in_tok, role_out_tok, client))
}
