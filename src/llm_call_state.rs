use super::super::llm_retry;
use super::super::llm_text;
use super::ResponseSchema;
use super::{LLMClient, llm_call_policy};
use std::io::Write;
use std::time::Duration;

pub(super) struct CallState {
    last_err: String,
    current_prompt: String,
    repair_count: usize,
    attempt_count: usize,
    same_prompt_retry_count: usize,
    max_attempt_count: usize,
    max_same_prompt_retry_count: usize,
    input_tokens: usize,
    output_tokens: usize,
}

impl CallState {
    fn new(prompt: &str) -> Self {
        Self {
            last_err: String::new(),
            current_prompt: prompt.to_string(),
            repair_count: 0,
            attempt_count: 0,
            same_prompt_retry_count: 0,
            max_attempt_count: llm_retry::max_attempts(),
            max_same_prompt_retry_count: llm_retry::max_same_prompt_retries(),
            input_tokens: 0,
            output_tokens: 0,
        }
    }
}

async fn acquire_call_permit(
    client: &LLMClient,
) -> Result<tokio::sync::SemaphorePermit<'_>, String> {
    client.acquire_permit().await
}

async fn apply_outcome(
    state: &mut CallState,
    outcome: llm_call_policy::CallOutcome,
    attempt: usize,
) -> Result<Option<(Option<serde_json::Value>, usize, usize)>, String> {
    match outcome {
        llm_call_policy::CallOutcome::Return(result) => Ok(Some(result)),
        llm_call_policy::CallOutcome::RetrySamePrompt => {
            state.same_prompt_retry_count += 1;
            eprintln!(
                "  LLM returned no usable response; retrying the same request ({}/{})",
                state.same_prompt_retry_count, state.max_same_prompt_retry_count
            );
            Ok(None)
        }
        llm_call_policy::CallOutcome::RetryWithRepair(new_prompt) => {
            state.current_prompt = new_prompt;
            state.same_prompt_retry_count = 0;
            state.repair_count += 1;
            Ok(None)
        }
        llm_call_policy::CallOutcome::SleepThenRetry => {
            if attempt < state.max_attempt_count {
                let sleep_sec = std::cmp::min(30, 1 << (attempt - 1));
                tokio::time::sleep(Duration::from_secs(sleep_sec)).await;
            }
            Ok(None)
        }
        llm_call_policy::CallOutcome::Fatal(err) => Err(err),
    }
}

async fn run_call_attempt(
    client: &LLMClient,
    prompt: &str,
    schema: ResponseSchema,
    state: &mut CallState,
) -> Result<Option<(Option<serde_json::Value>, usize, usize)>, String> {
    state.attempt_count += 1;
    if state.attempt_count > 1 {
        eprintln!(
            "  LLM request attempt {}/{}",
            state.attempt_count, state.max_attempt_count
        );
    }

    let (outcome, attempt_err, input_tokens, output_tokens) = llm_call_policy::classify_attempt(
        client,
        prompt,
        &state.current_prompt,
        schema,
        state.attempt_count,
        state.max_attempt_count,
        state.same_prompt_retry_count,
        state.max_same_prompt_retry_count,
    )
    .await?;
    state.input_tokens += input_tokens;
    state.output_tokens += output_tokens;
    if !attempt_err.is_empty() {
        state.last_err = attempt_err;
    }

    match outcome {
        llm_call_policy::CallOutcome::Return((result, _, _)) => {
            Ok(Some((result, state.input_tokens, state.output_tokens)))
        }
        outcome => apply_outcome(state, outcome, state.attempt_count).await,
    }
}

fn finish_call(state: &CallState) -> Result<(Option<serde_json::Value>, usize, usize), String> {
    eprintln!(
        "  LLM skip after {} attempts ({} repair retries): {}",
        state.attempt_count,
        state.repair_count,
        llm_text::truncate_for_log(&state.last_err, 120)
    );
    let _ = std::io::stderr().flush();
    Err(state.last_err.clone())
}

pub(super) async fn execute_call(
    client: &LLMClient,
    prompt: &str,
    schema: ResponseSchema,
) -> Result<(Option<serde_json::Value>, usize, usize), String> {
    if client.api_key.is_none() {
        return Err("LLM path is unavailable: missing API key".to_string());
    }

    let mut state = CallState::new(prompt);
    let _permit = match acquire_call_permit(client).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  LLM semaphore error: {}", e);
            return Err(format!("LLM semaphore error: {}", e));
        }
    };

    while state.attempt_count < state.max_attempt_count {
        if let Some(result) = run_call_attempt(client, prompt, schema, &mut state).await? {
            return Ok(result);
        }
    }

    finish_call(&state)
}
