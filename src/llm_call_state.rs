use super::super::llm_retry;
use super::ResponseSchema;
use super::{LLMClient, llm_call_policy};
use std::time::{Duration, Instant};

pub(super) struct CallState {
    last_err: String,
    current_prompt: String,
    repair_count: usize,
    attempt_count: usize,
    same_prompt_retry_count: usize,
    max_attempt_count: usize,
    max_same_prompt_retry_count: usize,
    max_repair_count: usize,
    input_tokens: usize,
    output_tokens: usize,
}

impl CallState {
    fn new(prompt: &str, max_attempt_count: usize, schema: ResponseSchema) -> Self {
        let max_repair_count = if matches!(
            schema,
            ResponseSchema::MethodIntentBatchReview | ResponseSchema::SemanticMethodBatchReview
        ) {
            1
        } else {
            llm_retry::max_format_repairs()
        };
        Self {
            last_err: String::new(),
            current_prompt: prompt.to_string(),
            repair_count: 0,
            attempt_count: 0,
            same_prompt_retry_count: 0,
            max_attempt_count,
            max_same_prompt_retry_count: llm_retry::max_same_prompt_retries(),
            max_repair_count,
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
            Ok(None)
        }
        llm_call_policy::CallOutcome::RetryWithRepair(new_prompt) => {
            if state.repair_count >= state.max_repair_count {
                return Err(format!(
                    "LLM response format remained invalid after {} repair attempts; last error: {}",
                    state.repair_count, state.last_err
                ));
            }
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
        if std::env::var_os("SNIFF_DEBUG_LLM").is_some() {
            eprintln!(
                "[llm-debug] attempt={} error={}",
                state.attempt_count, state.last_err
            );
        }
    }

    match outcome {
        llm_call_policy::CallOutcome::Return((result, _, _)) => {
            Ok(Some((result, state.input_tokens, state.output_tokens)))
        }
        outcome => apply_outcome(state, outcome, state.attempt_count).await,
    }
}

fn finish_call(
    state: &CallState,
    termination: Option<&str>,
) -> Result<(Option<serde_json::Value>, usize, usize), String> {
    let detail = if state.last_err.is_empty() {
        "no provider error was captured"
    } else {
        state.last_err.as_str()
    };
    let reason = termination.unwrap_or("review attempts exhausted");
    Err(format!(
        "LLM {reason} after {} attempts; last error: {detail}",
        state.attempt_count
    ))
}

pub(super) async fn execute_call(
    client: &LLMClient,
    prompt: &str,
    schema: ResponseSchema,
) -> Result<(Option<serde_json::Value>, usize, usize), String> {
    if client.api_key.is_none() {
        return Err("LLM path is unavailable: missing API key".to_string());
    }

    let mut state = CallState::new(prompt, client.max_attempt_count(), schema);
    let retry_budget = llm_retry::retry_budget();
    let retry_deadline = Instant::now() + retry_budget;
    let _permit = match acquire_call_permit(client).await {
        Ok(p) => p,
        Err(e) => {
            return Err(format!("LLM semaphore error: {}", e));
        }
    };

    let mut termination = None;
    while state.attempt_count < state.max_attempt_count {
        let remaining = retry_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            termination = Some(format!(
                "retry budget exhausted after {}s",
                retry_budget.as_secs()
            ));
            break;
        }

        match tokio::time::timeout(
            remaining,
            run_call_attempt(client, prompt, schema, &mut state),
        )
        .await
        {
            Ok(result) => match result {
                Ok(Some(result)) => return Ok(result),
                Ok(None) => {}
                Err(error) => {
                    client.record_failed_usage(state.input_tokens, state.output_tokens);
                    return Err(error);
                }
            },
            Err(_) => {
                termination = Some(format!(
                    "retry budget exhausted after {}s",
                    retry_budget.as_secs()
                ));
                break;
            }
        }
    }

    if termination.is_none() && state.attempt_count >= state.max_attempt_count {
        termination = Some(format!(
            "maximum attempt count ({}) reached",
            state.max_attempt_count
        ));
    }

    client.record_failed_usage(state.input_tokens, state.output_tokens);
    finish_call(&state, termination.as_deref())
}

#[cfg(test)]
mod tests {
    use super::{CallState, finish_call};

    #[test]
    fn exhausted_error_preserves_the_last_provider_error() {
        let state = CallState {
            last_err: "Empty assistant content from Anthropic endpoint".to_string(),
            current_prompt: "prompt".to_string(),
            repair_count: 0,
            attempt_count: 7,
            same_prompt_retry_count: 3,
            max_attempt_count: 128,
            max_same_prompt_retry_count: 3,
            max_repair_count: 3,
            input_tokens: 10,
            output_tokens: 2,
        };

        let err = finish_call(&state, Some("retry budget exhausted after 1s"))
            .expect_err("an exhausted call must fail");
        assert!(err.contains("retry budget exhausted after 1s"));
        assert!(err.contains("after 7 attempts"));
        assert!(err.contains("Empty assistant content"));
    }

    #[tokio::test]
    async fn format_repairs_stop_at_their_own_budget() {
        let mut state = CallState {
            last_err: "missing fields: reviews".to_string(),
            current_prompt: "prompt".to_string(),
            repair_count: 3,
            attempt_count: 4,
            same_prompt_retry_count: 0,
            max_attempt_count: 128,
            max_same_prompt_retry_count: 3,
            max_repair_count: 3,
            input_tokens: 10,
            output_tokens: 2,
        };

        let error = super::apply_outcome(
            &mut state,
            super::llm_call_policy::CallOutcome::RetryWithRepair("repair".to_string()),
            4,
        )
        .await
        .expect_err("a malformed response must not consume the transport retry budget");

        assert!(error.contains("after 3 repair attempts"));
        assert_eq!(state.current_prompt, "prompt");
    }
}
