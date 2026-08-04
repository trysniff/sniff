use super::llm_content;
use super::llm_text::truncate_for_log;
use super::llm_transport::{EndpointKind, endpoint_kind, request_url};
use super::llm_usage;
use crate::config::ResolvedConfig;
use std::env;
use std::time::Duration;

fn configured_timeout(names: &[&str]) -> Duration {
    let secs = names
        .iter()
        .find_map(|name| env::var(name).ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(600);
    Duration::from_secs(secs)
}

fn request_timeout() -> Duration {
    configured_timeout(&[
        "SNIFF_LLM_REQUEST_TIMEOUT_SECS",
        "SNIFF_LLM_CLIENT_TIMEOUT_SECS",
        "LLM_REQUEST_TIMEOUT_SECS",
    ])
}

fn body_timeout() -> Duration {
    configured_timeout(&["SNIFF_LLM_BODY_TIMEOUT_SECS", "LLM_BODY_TIMEOUT_SECS"])
}

pub(super) async fn try_call_raw(
    client: &reqwest::Client,
    config: &ResolvedConfig,
    api_key: Option<&String>,
    prompt: &str,
) -> Result<(String, usize, usize, usize), String> {
    let (payload, mut headers) = super::llm_transport::build_payload(config, prompt);
    let timeout = request_timeout();
    let request_url = request_url(config);
    let endpoint_label = match endpoint_kind(config) {
        EndpointKind::OpenAi => "OpenAI-style",
        EndpointKind::Anthropic => "Anthropic-style",
    };

    if let Some(api_key) = api_key {
        if let Ok(auth_val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", api_key))
        {
            headers.insert(reqwest::header::AUTHORIZATION, auth_val);
        }
        if endpoint_kind(config) == EndpointKind::Anthropic {
            if let Ok(key_val) = reqwest::header::HeaderValue::from_str(api_key) {
                headers.insert("x-api-key", key_val);
            }
            headers.insert(
                "anthropic-version",
                reqwest::header::HeaderValue::from_static("2023-06-01"),
            );
        }
    }

    let request = async {
        if std::env::var_os("SNIFF_DEBUG_LLM").is_some() {
            eprintln!(
                "[llm-debug] request start endpoint={} prompt_chars={} request_timeout_secs={} body_timeout_secs={}",
                request_url,
                prompt.chars().count(),
                timeout.as_secs(),
                body_timeout().as_secs()
            );
        }
        let mut resp = client
            .post(&request_url)
            .headers(headers.clone())
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let status = resp.status();
        if std::env::var_os("SNIFF_DEBUG_LLM").is_some() {
            eprintln!("[llm-debug] response headers status={status}");
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            let snippet = truncate_for_log(&text, 200);
            if status.as_u16() == 402 && text.to_lowercase().contains("insufficient balance") {
                return Err(format!(
                    "LLM provider balance is insufficient at {}: HTTP 402: {}",
                    request_url, snippet
                ));
            }
            return Err(format!(
                "HTTP {} from {}: {}",
                status.as_u16(),
                request_url,
                snippet
            ));
        }

        let body_deadline = tokio::time::Instant::now() + body_timeout();
        let mut body = String::new();
        let data: serde_json::Value = loop {
            let next = tokio::time::timeout_at(body_deadline, resp.chunk())
                .await
                .map_err(|_| {
                    format!(
                        "Timed out reading response body from {endpoint_label} endpoint ({request_url}) before a full JSON object arrived"
                    )
                })?
                .map_err(|e| e.to_string())?;

            let Some(chunk) = next else {
                let snippet = truncate_for_log(&body, 200);
                return Err(format!(
                    "Invalid JSON response from {endpoint_label} endpoint ({request_url}): {snippet}"
                ));
            };

            if std::env::var_os("SNIFF_DEBUG_LLM").is_some() {
                eprintln!("[llm-debug] response chunk bytes={}", chunk.len());
            }
            body.push_str(&String::from_utf8_lossy(&chunk));
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(value) => break value,
                Err(_) if body.len() <= 200_000 => continue,
                Err(_) => {
                    let snippet = truncate_for_log(&body, 200);
                    return Err(format!(
                        "Invalid JSON response from {endpoint_label} endpoint ({request_url}): {snippet}"
                    ));
                }
            }
        };

        if let Some(err) = data.get("error") {
            return Err(format!("API error response: {}", err));
        }

        let (content, in_t, out_t, cached_in_t) = match endpoint_kind(config) {
            EndpointKind::OpenAi => {
                let content = llm_content::openai_content(&data);
                let (in_t, out_t, cached_in_t) = llm_usage::openai_usage(&data, prompt, &content);
                (content, in_t, out_t, cached_in_t)
            }
            EndpointKind::Anthropic => {
                let content = llm_content::anthropic_content(&data);
                let (in_t, out_t, cached_in_t) =
                    llm_usage::anthropic_usage(&data, prompt, &content);
                (content, in_t, out_t, cached_in_t)
            }
        };

        if std::env::var_os("SNIFF_DEBUG_LLM").is_some() {
            eprintln!(
                "[llm-debug] usage input_tokens={in_t} cached_input_tokens={cached_in_t} output_tokens={out_t}"
            );
        }

        if content.trim().is_empty() {
            return Err(format!(
                "Empty assistant content from {endpoint_label} endpoint ({request_url})"
            ));
        }

        if std::env::var_os("SNIFF_DEBUG_LLM_CONTENT").is_some() {
            eprintln!(
                "[llm-debug] assistant content={}",
                truncate_for_log(&content, 800)
            );
        }

        Ok((content, in_t, out_t, cached_in_t))
    };

    match tokio::time::timeout(timeout, request).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "LLM request timed out after {}s waiting for {} response",
            timeout.as_secs(),
            endpoint_label
        )),
    }
}

#[cfg(test)]
#[path = "tests/llm_response.rs"]
mod tests;
