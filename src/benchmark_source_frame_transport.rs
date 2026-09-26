use reqwest::{Client, StatusCode, header::HeaderMap};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, sleep};

use super::{GITHUB_PAGE_SIZE, bounded};

struct SearchRateLimitHints {
    retry_after_seconds: Option<u64>,
    reset_at_unix_seconds: Option<u64>,
    remaining_zero: bool,
}

impl SearchRateLimitHints {
    fn from_headers(headers: &HeaderMap) -> Self {
        let numeric = |name| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
        };
        Self {
            retry_after_seconds: numeric("retry-after"),
            reset_at_unix_seconds: numeric("x-ratelimit-reset"),
            remaining_zero: numeric("x-ratelimit-remaining") == Some(0),
        }
    }

    fn wait(&self, attempt: u32, now_unix_seconds: u64) -> Result<Duration, String> {
        let reset_wait = if self.remaining_zero {
            self.reset_at_unix_seconds
                .map(|reset| reset.saturating_sub(now_unix_seconds).saturating_add(1))
                .unwrap_or(0)
        } else {
            0
        };
        let header_wait = reset_wait.max(self.retry_after_seconds.unwrap_or(0));
        if header_wait > 86_400 {
            return Err(
                "GitHub source-frame rate limit wait exceeds one day; the exact page remains open"
                    .to_string(),
            );
        }
        let seconds = if header_wait == 0 {
            60_u64.saturating_mul(1_u64 << attempt).min(3_600)
        } else {
            header_wait
        };
        Ok(Duration::from_secs(seconds.max(1)))
    }
}

fn is_rate_limited(status: StatusCode, hints: &SearchRateLimitHints, payload: &str) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (hints.remaining_zero
                || hints.retry_after_seconds.is_some()
                || serde_json::from_str::<serde_json::Value>(payload)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("message")?
                            .as_str()
                            .map(|message| message.to_ascii_lowercase().contains("rate limit"))
                    })
                    .unwrap_or(false)))
}

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
            .header("Accept-Encoding", "identity")
            .header("Connection", "close")
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
                let hints = SearchRateLimitHints::from_headers(response.headers());
                let payload = match response.text().await {
                    Ok(payload) => payload,
                    Err(error) => {
                        last_error = format!("failed to read GitHub search response: {error:?}");
                        if attempt < 3 {
                            let delay = if status == StatusCode::TOO_MANY_REQUESTS
                                || hints.remaining_zero
                                || hints.retry_after_seconds.is_some()
                            {
                                hints.wait(attempt, unix_now())?
                            } else {
                                Duration::from_secs(1_u64 << attempt)
                            };
                            sleep(delay).await;
                        }
                        continue;
                    }
                };
                if status.is_success() {
                    return Ok(payload);
                }
                let rate_limited = is_rate_limited(status, &hints, &payload);
                if rate_limited || status.is_server_error() {
                    last_error = format!("GitHub returned {status}: {}", bounded(&payload, 512));
                    if attempt < 3 {
                        let delay = if rate_limited {
                            hints.wait(attempt, unix_now())?
                        } else {
                            Duration::from_secs(1_u64 << attempt)
                        };
                        if rate_limited {
                            eprintln!(
                                "GitHub source frame rate limited; waiting {} seconds before retrying the exact page",
                                delay.as_secs()
                            );
                        }
                        sleep(delay).await;
                        continue;
                    }
                }
                return Err(format!(
                    "GitHub search failed with {status}; the exact page remains open: {}",
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
        "GitHub search failed after four attempts; the exact page remains open: {last_error}"
    ))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn only_rate_limited_forbidden_responses_are_retried() {
        let mut headers = HeaderMap::new();
        let hints = SearchRateLimitHints::from_headers(&headers);
        assert!(!is_rate_limited(
            StatusCode::FORBIDDEN,
            &hints,
            r#"{"message":"permission denied"}"#
        ));
        assert!(is_rate_limited(
            StatusCode::FORBIDDEN,
            &hints,
            r#"{"message":"You have exceeded a secondary rate limit."}"#
        ));
        assert!(is_rate_limited(StatusCode::TOO_MANY_REQUESTS, &hints, ""));
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        assert!(is_rate_limited(
            StatusCode::FORBIDDEN,
            &SearchRateLimitHints::from_headers(&headers),
            ""
        ));
    }

    #[test]
    fn rate_limit_wait_respects_reset_and_secondary_backoff() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("1600"));
        headers.insert("retry-after", HeaderValue::from_static("45"));
        let hints = SearchRateLimitHints::from_headers(&headers);
        assert_eq!(hints.wait(0, 1000).unwrap(), Duration::from_secs(601));

        let no_headers = SearchRateLimitHints::from_headers(&HeaderMap::new());
        assert_eq!(no_headers.wait(0, 1000).unwrap(), Duration::from_secs(60));
        assert_eq!(no_headers.wait(2, 1000).unwrap(), Duration::from_secs(240));

        headers.insert("x-ratelimit-reset", HeaderValue::from_static("87402"));
        assert!(
            SearchRateLimitHints::from_headers(&headers)
                .wait(0, 1000)
                .is_err()
        );
    }
}
