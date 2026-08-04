use crate::config::ResolvedConfig;
use crate::env_value;
use serde_json::Value;
use std::env;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Semaphore;

#[allow(dead_code)] // Used by the semantic review checkpoint layer in a later stacked PR.
const REVIEW_CONTRACT_VERSION: &str = "semantic-method-v25";
const DEFAULT_CONTEXT_TOKENS: usize = 128_000;
const RESERVED_OUTPUT_TOKENS: usize = 8_192;
const CONSERVATIVE_CHARS_PER_TOKEN: usize = 3;

tokio::task_local! {
    static TASK_CACHED_INPUT_TOKENS: AtomicUsize;
}

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
    MethodIntentReview,
    MethodIntentBatchReview,
    SemanticMethodReview,
    SemanticMethodBatchReview,
    ScopedTierReview,
    FileReview,
    RoleClassification,
}

#[allow(dead_code)] // Later stacked PRs consume the review scheduling fields.
pub struct LLMClient {
    config: ResolvedConfig,
    api_key: Option<String>,
    sem: Semaphore,
    max_concurrency: usize,
    max_attempt_count: usize,
    max_prompt_chars: usize,
    cached_input_tokens: AtomicUsize,
}

#[allow(dead_code)] // Preserve a buildable transport-first PR before its consumers land.
impl LLMClient {
    pub fn try_new(config: ResolvedConfig, api_key: Option<String>) -> Result<Self, String> {
        let api_key = api_key
            .map(|value| env_value::normalize(&value))
            .filter(|value| !value.is_empty());
        let timeout = client_timeout();
        build_http_client(timeout)?;
        let max_concurrency = max_concurrency();
        let max_attempt_count = llm_retry::max_attempts();
        let max_prompt_chars = max_prompt_chars();

        Ok(LLMClient {
            config,
            api_key,
            sem: Semaphore::new(max_concurrency),
            max_concurrency,
            max_attempt_count,
            max_prompt_chars,
            cached_input_tokens: AtomicUsize::new(0),
        })
    }

    pub fn new(config: ResolvedConfig, api_key: Option<String>) -> Self {
        Self::try_new(config, api_key).expect("failed to build LLM HTTP client")
    }

    pub(crate) fn config(&self) -> &ResolvedConfig {
        &self.config
    }

    pub(crate) fn review_context_key(&self) -> String {
        format!(
            "review_contract={}\nmodel={}\nendpoint={}\nsystem_context={}",
            REVIEW_CONTRACT_VERSION,
            self.config.model,
            self.config.llm.endpoint,
            self.config.llm.system_context
        )
    }

    pub(crate) fn max_concurrency(&self) -> usize {
        self.max_concurrency
    }

    pub(crate) fn max_attempt_count(&self) -> usize {
        self.max_attempt_count
    }

    pub(crate) fn max_prompt_chars(&self) -> usize {
        self.max_prompt_chars
    }

    pub(crate) fn cached_input_tokens(&self) -> usize {
        self.cached_input_tokens.load(Ordering::Relaxed)
    }

    pub(crate) fn restore_cached_input_tokens(&self, tokens: usize) {
        self.cached_input_tokens
            .fetch_add(tokens, Ordering::Relaxed);
    }

    pub(crate) async fn track_cached_input_tokens<F>(future: F) -> (F::Output, usize)
    where
        F: Future,
    {
        TASK_CACHED_INPUT_TOKENS
            .scope(AtomicUsize::new(0), async move {
                let output = future.await;
                let cached = TASK_CACHED_INPUT_TOKENS.with(|tokens| tokens.load(Ordering::Relaxed));
                (output, cached)
            })
            .await
    }

    #[cfg(test)]
    pub(crate) fn with_max_attempt_count(mut self, value: usize) -> Self {
        self.max_attempt_count = value.max(1);
        self
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
        // Do not reuse a pooled connection across thousands of sequential
        // reviews. A fresh client makes each retry independent of a stale
        // provider socket and gives the watchdog a clean request boundary.
        let client = build_http_client(client_timeout())?;
        let (content, input_tokens, output_tokens, cached_input_tokens) =
            llm_response::try_call_raw(&client, &self.config, self.api_key.as_ref(), prompt)
                .await?;
        self.cached_input_tokens
            .fetch_add(cached_input_tokens, Ordering::Relaxed);
        let _ = TASK_CACHED_INPUT_TOKENS.try_with(|tokens| {
            tokens.fetch_add(cached_input_tokens, Ordering::Relaxed);
        });
        Ok((content, input_tokens, output_tokens))
    }

    async fn call_once(
        &self,
        prompt: &str,
        schema: ResponseSchema,
    ) -> Result<(Option<Value>, usize, usize), String> {
        if prompt.len() > self.max_prompt_chars {
            return Err(format!(
                "LLM prompt contains {} characters, exceeding the configured safe limit of {}; reduce the method batch size or raise SNIFF_LLM_CONTEXT_TOKENS/SNIFF_LLM_MAX_PROMPT_CHARS for a provider that supports it",
                prompt.len(),
                self.max_prompt_chars
            ));
        }
        llm_call::execute_call(self, prompt, schema).await
    }

    pub async fn call(
        &self,
        prompt: &str,
        schema: ResponseSchema,
    ) -> Result<(Option<serde_json::Value>, usize, usize), String> {
        llm_consensus::call_with_consensus(self, prompt, schema).await
    }

    pub(crate) async fn call_single(
        &self,
        prompt: &str,
        schema: ResponseSchema,
    ) -> Result<(Option<serde_json::Value>, usize, usize), String> {
        self.call_once(prompt, schema).await
    }
}

fn max_concurrency() -> usize {
    let configured = env::var("SNIFF_LLM_MAX_CONCURRENCY")
        .or_else(|_| env::var("LLM_MAX_CONCURRENCY"))
        .ok();
    parse_max_concurrency(configured.as_deref())
}

fn parse_max_concurrency(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(1, 8))
        .unwrap_or(4)
}

fn max_prompt_chars() -> usize {
    let explicit = env::var("SNIFF_LLM_MAX_PROMPT_CHARS").ok();
    let context = env::var("SNIFF_LLM_CONTEXT_TOKENS").ok();
    parse_max_prompt_chars(explicit.as_deref(), context.as_deref())
}

fn parse_max_prompt_chars(explicit: Option<&str>, context: Option<&str>) -> usize {
    if let Some(parsed) = explicit.and_then(|value| value.trim().parse::<usize>().ok()) {
        return parsed.max(4_096);
    }
    let context_tokens = context
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_CONTEXT_TOKENS);
    context_tokens
        .saturating_sub(RESERVED_OUTPUT_TOKENS)
        .max(4_096)
        .saturating_mul(CONSERVATIVE_CHARS_PER_TOKEN)
}

fn client_timeout() -> Duration {
    env::var("SNIFF_LLM_CLIENT_TIMEOUT_SECS")
        .or_else(|_| env::var("SNIFF_LLM_REQUEST_TIMEOUT_SECS"))
        .or_else(|_| env::var("LLM_CLIENT_TIMEOUT_SECS"))
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(600))
}

fn build_http_client(timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .http1_only()
        .pool_max_idle_per_host(0)
        .connect_timeout(timeout)
        .read_timeout(timeout)
        .timeout(timeout)
        .build()
        .map_err(|err| format!("failed to build LLM HTTP client: {err}"))
}

#[cfg(test)]
#[path = "tests/llm_impl.rs"]
mod tests;
