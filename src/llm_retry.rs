use super::ResponseSchema;
use super::llm_repair;
use std::env;

pub(super) enum RetryAction {
    Fatal(String),
    RetrySamePrompt,
    RetryWithRepair(String),
    SleepThenRetry,
}

pub(super) fn max_attempts() -> usize {
    env::var("SNIFF_LLM_MAX_ATTEMPTS")
        .or_else(|_| env::var("LLM_MAX_ATTEMPTS"))
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(32)
}

pub(super) fn max_same_prompt_retries() -> usize {
    env::var("SNIFF_LLM_SAME_PROMPT_RETRIES")
        .or_else(|_| env::var("LLM_SAME_PROMPT_RETRIES"))
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(3)
}

pub(super) fn retry_same_prompt_without_repair(err: &str) -> bool {
    err.contains("No JSON object found")
        || err.contains("Empty assistant content")
        || err.contains("Empty response content")
        || err.contains("error decoding response body")
        || err.contains("Invalid JSON response")
        || err.contains("Timed out reading response body")
        || err.contains("timed out waiting for")
}

pub(super) fn http_status_from_error(err: &str) -> Option<u16> {
    let rest = if let Some(rest) = err.strip_prefix("HTTP ") {
        rest
    } else {
        let idx = err.find("HTTP ")?;
        &err[idx + "HTTP ".len()..]
    };
    let status_text = rest
        .split_once(':')
        .map(|(status, _)| status)
        .unwrap_or(rest);
    let digits: String = status_text
        .trim()
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse::<u16>().ok()
}

pub(super) fn should_retry_http_status(status: u16) -> bool {
    matches!(status, 408 | 409 | 425 | 429 | 500..=599)
}

pub(super) fn is_fatal_http_status(status: u16) -> bool {
    !should_retry_http_status(status)
}

fn classify_http_error(last_err: &str) -> Option<RetryAction> {
    let status = http_status_from_error(last_err)?;
    if is_fatal_http_status(status) {
        return Some(RetryAction::Fatal(last_err.to_string()));
    }
    None
}

fn classify_non_http_error(
    prompt: &str,
    schema: ResponseSchema,
    last_err: &str,
    same_prompt_retry_count: usize,
    max_same_prompt_retry_count: usize,
) -> RetryAction {
    if retry_same_prompt_without_repair(last_err)
        && same_prompt_retry_count < max_same_prompt_retry_count
    {
        return RetryAction::RetrySamePrompt;
    }

    if retry_same_prompt_without_repair(last_err) {
        return RetryAction::RetryWithRepair(llm_repair::build_repair_prompt(
            prompt, "", schema, last_err,
        ));
    }

    RetryAction::SleepThenRetry
}

pub(super) fn classify_error(
    prompt: &str,
    schema: ResponseSchema,
    last_err: &str,
    same_prompt_retry_count: usize,
    max_same_prompt_retry_count: usize,
) -> RetryAction {
    if let Some(action) = classify_http_error(last_err) {
        return action;
    }

    classify_non_http_error(
        prompt,
        schema,
        last_err,
        same_prompt_retry_count,
        max_same_prompt_retry_count,
    )
}

#[cfg(test)]
mod tests {
    use super::{http_status_from_error, is_fatal_http_status, should_retry_http_status};

    #[test]
    fn parses_http_status_from_prefixed_error() {
        assert_eq!(
            http_status_from_error(
                "LLM provider balance is insufficient: HTTP 402: {\"error\":\"Insufficient Balance\"}"
            ),
            Some(402)
        );
    }

    #[test]
    fn parses_http_status_from_plain_http_error() {
        assert_eq!(http_status_from_error("HTTP 429: rate limited"), Some(429));
    }

    #[test]
    fn marks_balance_errors_as_fatal() {
        assert!(is_fatal_http_status(402));
        assert!(!should_retry_http_status(402));
    }

    #[test]
    fn retries_empty_response_content_without_repair() {
        assert!(super::retry_same_prompt_without_repair(
            "Empty response content"
        ));
    }
}
