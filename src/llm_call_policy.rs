use super::super::llm_json;
use super::super::llm_repair;
use super::super::llm_retry::{self, RetryAction};
use super::super::llm_transport;
use super::LLMClient;
use super::ResponseSchema;

pub(super) enum CallOutcome {
    Return((Option<serde_json::Value>, usize, usize)),
    RetrySamePrompt,
    RetryWithRepair(String),
    SleepThenRetry,
    Fatal(String),
}

fn repair_outcome(prompt: &str, content: &str, schema: ResponseSchema, err: &str) -> CallOutcome {
    CallOutcome::RetryWithRepair(llm_repair::build_repair_prompt(
        prompt, content, schema, err,
    ))
}

pub(super) fn retry_action_to_call_outcome(action: RetryAction) -> CallOutcome {
    match action {
        RetryAction::Fatal(err) => CallOutcome::Fatal(err),
        RetryAction::RetrySamePrompt => CallOutcome::RetrySamePrompt,
        RetryAction::RetryWithRepair(new_prompt) => CallOutcome::RetryWithRepair(new_prompt),
        RetryAction::SleepThenRetry => CallOutcome::SleepThenRetry,
    }
}

pub(super) fn classify_successful_response(
    prompt: &str,
    content: String,
    schema: ResponseSchema,
    in_t: usize,
    out_t: usize,
    same_prompt_retry_count: usize,
    max_same_prompt_retry_count: usize,
) -> Result<(CallOutcome, String), String> {
    match llm_json::extract_json_object(&content) {
        Ok(parsed_obj) => match llm_transport::validate_schema(&parsed_obj, schema) {
            Ok(()) => Ok((
                CallOutcome::Return((Some(parsed_obj), in_t, out_t)),
                String::new(),
            )),
            Err(err) => {
                if std::env::var_os("SNIFF_DEBUG_LLM").is_some() {
                    eprintln!(
                        "[llm-debug] schema={} validation={} parsed={}",
                        schema_name(schema),
                        err,
                        parsed_obj
                    );
                }
                let err = err.to_string();
                Ok((repair_outcome(prompt, &content, schema, &err), err))
            }
        },
        Err(err) => {
            if llm_retry::retry_same_prompt_without_repair(&err)
                && same_prompt_retry_count < max_same_prompt_retry_count
            {
                Ok((CallOutcome::RetrySamePrompt, err.to_string()))
            } else {
                let err = err.to_string();
                Ok((repair_outcome(prompt, &content, schema, &err), err))
            }
        }
    }
}

fn schema_name(schema: ResponseSchema) -> &'static str {
    match schema {
        ResponseSchema::MethodReview => "method",
        ResponseSchema::MethodIntentReview => "method_intent",
        ResponseSchema::MethodIntentBatchReview => "method_intent_batch",
        ResponseSchema::SemanticMethodReview => "semantic_method",
        ResponseSchema::SemanticMethodBatchReview => "semantic_method_batch",
        ResponseSchema::ScopedTierReview => "scoped_tier",
        ResponseSchema::CaseSynthesis => "case_synthesis",
        ResponseSchema::FileReview => "file",
        ResponseSchema::RoleClassification => "role",
    }
}

pub(super) fn classify_failed_attempt(
    prompt: &str,
    schema: ResponseSchema,
    err: String,
    _attempt_count: usize,
    _max_attempt_count: usize,
    same_prompt_retry_count: usize,
    max_same_prompt_retry_count: usize,
) -> Result<(CallOutcome, String, usize, usize), String> {
    Ok((
        retry_action_to_call_outcome(llm_retry::classify_error(
            prompt,
            schema,
            &err,
            same_prompt_retry_count,
            max_same_prompt_retry_count,
        )),
        err,
        0,
        0,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn classify_attempt(
    client: &LLMClient,
    prompt: &str,
    current_prompt: &str,
    schema: ResponseSchema,
    attempt_count: usize,
    max_attempt_count: usize,
    same_prompt_retry_count: usize,
    max_same_prompt_retry_count: usize,
) -> Result<(CallOutcome, String, usize, usize), String> {
    let attempt = tokio::time::timeout(
        super::super::llm_retry::attempt_timeout(),
        client.try_call_raw(current_prompt),
    )
    .await;
    let raw_result = match attempt {
        Ok(result) => result,
        Err(_) => Err(format!(
            "LLM attempt watchdog expired after {}s",
            super::super::llm_retry::attempt_timeout().as_secs()
        )),
    };

    match raw_result {
        Ok((content, in_t, out_t)) => {
            let (outcome, error) = classify_successful_response(
                prompt,
                content,
                schema,
                in_t,
                out_t,
                same_prompt_retry_count,
                max_same_prompt_retry_count,
            )?;
            Ok((outcome, error, in_t, out_t))
        }
        Err(err) => classify_failed_attempt(
            prompt,
            schema,
            err,
            attempt_count,
            max_attempt_count,
            same_prompt_retry_count,
            max_same_prompt_retry_count,
        ),
    }
}
