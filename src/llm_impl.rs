use crate::config::ResolvedConfig;
use crate::env_value;
use serde_json::Value;
use std::env;
use std::time::Duration;
use tokio::sync::Semaphore;

#[path = "llm_call.rs"]
mod llm_call;
#[path = "llm_consensus.rs"]
mod llm_consensus;
#[path = "llm_content.rs"]
mod llm_content;
#[path = "llm_json.rs"]
mod llm_json;
#[path = "llm_payload.rs"]
mod llm_payload;
#[path = "llm_repair.rs"]
mod llm_repair;
#[path = "llm_response.rs"]
mod llm_response;
#[path = "llm_retry.rs"]
mod llm_retry;
#[path = "llm_schema.rs"]
mod llm_schema;
#[path = "llm_text.rs"]
mod llm_text;
#[path = "llm_transport.rs"]
mod llm_transport;
#[path = "llm_usage.rs"]
mod llm_usage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseSchema {
    MethodReview,
    FileReview,
    RoleClassification,
}

pub struct LLMClient {
    config: ResolvedConfig,
    api_key: Option<String>,
    client: reqwest::Client,
    sem: Semaphore,
}

impl LLMClient {
    pub fn try_new(config: ResolvedConfig, api_key: Option<String>) -> Result<Self, String> {
        let api_key = api_key
            .map(|value| env_value::normalize(&value))
            .filter(|value| !value.is_empty());
        let client = reqwest::Client::builder()
            .http1_only()
            .timeout(client_timeout())
            .build()
            .map_err(|err| format!("failed to build LLM HTTP client: {err}"))?;

        Ok(LLMClient {
            config,
            api_key,
            client,
            sem: Semaphore::new(max_concurrency()),
        })
    }

    pub fn new(config: ResolvedConfig, api_key: Option<String>) -> Self {
        Self::try_new(config, api_key).expect("failed to build LLM HTTP client")
    }

    pub(crate) fn config(&self) -> &ResolvedConfig {
        &self.config
    }

    pub async fn probe(&self) -> Result<(), String> {
        let prompt = "Return exactly one JSON object with this shape: {\"role\":\"mixed\",\"reason\":\"probe\"}.";
        match self
            .call_once(prompt, ResponseSchema::RoleClassification)
            .await
        {
            Ok((Some(_), _, _)) => Ok(()),
            Ok((None, _, _)) => {
                Err("LLM preflight failed: no valid JSON response after retries".to_string())
            }
            Err(err) => Err(format!("LLM preflight failed: {}", err)),
        }
    }

    pub(super) async fn acquire_permit(&self) -> Result<tokio::sync::SemaphorePermit<'_>, String> {
        self.sem.acquire().await.map_err(|e| e.to_string())
    }

    pub(super) async fn try_call_raw(
        &self,
        prompt: &str,
    ) -> Result<(String, usize, usize), String> {
        llm_response::try_call_raw(&self.client, &self.config, self.api_key.as_ref(), prompt).await
    }

    async fn call_once(
        &self,
        prompt: &str,
        schema: ResponseSchema,
    ) -> Result<(Option<Value>, usize, usize), String> {
        llm_call::execute_call(self, prompt, schema).await
    }

    pub async fn call(
        &self,
        prompt: &str,
        schema: ResponseSchema,
    ) -> Result<(Option<serde_json::Value>, usize, usize), String> {
        llm_consensus::call_with_consensus(self, prompt, schema).await
    }
}

fn max_concurrency() -> usize {
    env::var("SNIFF_LLM_MAX_CONCURRENCY")
        .or_else(|_| env::var("LLM_MAX_CONCURRENCY"))
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5)
}

fn client_timeout() -> Duration {
    env::var("SNIFF_LLM_CLIENT_TIMEOUT_SECS")
        .or_else(|_| env::var("LLM_CLIENT_TIMEOUT_SECS"))
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(600))
}

#[cfg(test)]
#[path = "tests/llm_impl.rs"]
mod tests;
