use reqwest::{Client, StatusCode};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, sleep};

use super::{GITHUB_PAGE_SIZE, bounded};

pub(super) async fn fetch_search_page(
    client: &Client,
    github_token: Option<&str>,
    query: &str,
    page: usize,
) -> Result<String, String> {
    let mut last_error = String::new();
    for attempt in 0..4_u32 {
        let mut request = client
            .get("https://api.github.com/search/repositories")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .query(&[
                ("q", query.to_string()),
                ("sort", "created".to_string()),
                ("order", "asc".to_string()),
                ("per_page", GITHUB_PAGE_SIZE.to_string()),
                ("page", page.to_string()),
            ]);
        if let Some(token) = github_token.filter(|token| !token.trim().is_empty()) {
            request = request.bearer_auth(token.trim());
        }
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok());
                let rate_limit_reset = response
                    .headers()
                    .get("x-ratelimit-reset")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok());
                let payload = response
                    .text()
                    .await
                    .map_err(|error| format!("failed to read GitHub search response: {error}"))?;
                if status.is_success() {
                    return Ok(payload);
                }
                if matches!(
                    status,
                    StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
                ) || status.is_server_error()
                {
                    last_error = format!("GitHub returned {status}: {}", bounded(&payload, 512));
                    if attempt < 3 {
                        sleep(Duration::from_secs(retry_delay_seconds(
                            retry_after,
                            rate_limit_reset,
                            attempt,
                        )))
                        .await;
                        continue;
                    }
                }
                return Err(format!(
                    "GitHub search failed with {status}: {}",
                    bounded(&payload, 512)
                ));
            }
            Err(error) if attempt < 3 => {
                last_error = error.to_string();
                sleep(Duration::from_secs(1_u64 << attempt)).await;
            }
            Err(error) => last_error = error.to_string(),
        }
    }
    Err(format!(
        "GitHub search failed after four attempts: {last_error}"
    ))
}

fn retry_delay_seconds(
    retry_after: Option<u64>,
    rate_limit_reset: Option<u64>,
    attempt: u32,
) -> u64 {
    if let Some(delay) = retry_after {
        return delay.clamp(1, 120);
    }
    if let Some(reset) = rate_limit_reset {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        return reset.saturating_sub(now).saturating_add(1).clamp(1, 120);
    }
    (1_u64 << attempt).clamp(1, 120)
}
