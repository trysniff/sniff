use super::{
    HistoricalV3CandidatePageCheckpoint, HistoricalV3CandidatePageRequest, request_body,
    validate_page_checkpoint,
};
use reqwest::{Client, StatusCode, header::HeaderMap};
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, sleep};

pub trait HistoricalV3CandidatePageTransport {
    fn fetch<'a>(
        &'a mut self,
        request: &'a HistoricalV3CandidatePageRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;
}

pub struct GithubHistoricalV3CandidateTransport {
    client: Client,
    token: String,
}

struct RateLimitHints {
    retry_after_seconds: Option<u64>,
    reset_at_unix_seconds: Option<u64>,
    remaining_zero: bool,
}

impl RateLimitHints {
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
                "historical-v3 GitHub rate limit wait exceeds one day; the exact request remains open"
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

fn graphql_rate_limit_error(payload: &[u8], remaining_zero: bool) -> bool {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|value| {
            value.get("errors")?.as_array().map(|errors| {
                errors.iter().any(|error| {
                    remaining_zero
                        || error
                            .get("message")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|message| {
                                message.to_ascii_lowercase().contains("rate limit")
                            })
                })
            })
        })
        .unwrap_or(false)
}

fn is_rate_limited(status: StatusCode, hints: &RateLimitHints, payload: &[u8]) -> bool {
    // GitHub can report primary or secondary GraphQL limits with HTTP 200.
    status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (hints.remaining_zero || hints.retry_after_seconds.is_some()))
        || (status.is_success() && graphql_rate_limit_error(payload, hints.remaining_zero))
}

impl GithubHistoricalV3CandidateTransport {
    pub fn new(token: impl Into<String>) -> Result<Self, String> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err("historical-v3 GitHub token is empty".to_string());
        }
        let client = Client::builder()
            .user_agent("sniff-historical-v3-collector")
            .build()
            .map_err(|error| format!("failed to build historical-v3 GitHub client: {error}"))?;
        Ok(Self { client, token })
    }
}

impl HistoricalV3CandidatePageTransport for GithubHistoricalV3CandidateTransport {
    fn fetch<'a>(
        &'a mut self,
        request: &'a HistoricalV3CandidatePageRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            let body = request_body(request)?;
            let mut last_error = String::new();
            for attempt in 0..4_u32 {
                let response = self
                    .client
                    .post("https://api.github.com/graphql")
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .bearer_auth(self.token.trim())
                    .header("Content-Type", "application/json")
                    .body(body.clone())
                    .send()
                    .await;
                match response {
                    Ok(response) => {
                        let status = response.status();
                        let rate_limit = RateLimitHints::from_headers(response.headers());
                        let payload = match response.bytes().await {
                            Ok(payload) => payload,
                            Err(error) => {
                                last_error = format!(
                                    "failed to read historical-v3 GitHub response: {error}"
                                );
                                if attempt < 3 {
                                    let delay = if status == StatusCode::TOO_MANY_REQUESTS
                                        || rate_limit.remaining_zero
                                        || rate_limit.retry_after_seconds.is_some()
                                    {
                                        let now = SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        rate_limit.wait(attempt, now)?
                                    } else {
                                        Duration::from_secs(1_u64 << attempt)
                                    };
                                    sleep(delay).await;
                                }
                                continue;
                            }
                        };
                        let rate_limited = is_rate_limited(status, &rate_limit, &payload);
                        if status.is_success() && !rate_limited {
                            return Ok(payload.to_vec());
                        }
                        last_error = format!(
                            "GitHub GraphQL returned {status}: {}",
                            bounded(&payload, 512)
                        );
                        let retryable = rate_limited || status.is_server_error();
                        if !retryable {
                            return Err(last_error);
                        }
                        if attempt < 3 {
                            let delay = if rate_limited {
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                rate_limit.wait(attempt, now)?
                            } else {
                                Duration::from_secs(1_u64 << attempt)
                            };
                            if rate_limited {
                                eprintln!(
                                    "historical-v3 GitHub rate limited; waiting {} seconds before retrying the exact request",
                                    delay.as_secs()
                                );
                            }
                            sleep(delay).await;
                        }
                    }
                    Err(error) => {
                        last_error = error.to_string();
                        if attempt < 3 {
                            sleep(Duration::from_secs(1_u64 << attempt)).await;
                        }
                    }
                }
            }
            Err(format!(
                "historical-v3 GitHub request failed after four attempts; the exact request remains open: {last_error}"
            ))
        })
    }
}

pub(super) fn load_page_checkpoint(
    root: &Path,
    request: &HistoricalV3CandidatePageRequest,
) -> Result<Option<HistoricalV3CandidatePageCheckpoint>, String> {
    let path = checkpoint_path(root, &request.request_sha256);
    if path.is_file() {
        let checkpoint = read_checkpoint(&path)?;
        validate_page_checkpoint(request, &checkpoint)?;
        return Ok(Some(checkpoint));
    }
    let pending = pending_path(root, &request.request_sha256);
    if !pending.is_file() {
        return Ok(None);
    }
    match read_checkpoint(&pending).and_then(|checkpoint| {
        validate_page_checkpoint(request, &checkpoint)?;
        Ok(checkpoint)
    }) {
        Ok(checkpoint) => {
            fs::rename(&pending, &path).map_err(|error| {
                format!("failed to recover historical-v3 page checkpoint: {error}")
            })?;
            Ok(Some(checkpoint))
        }
        Err(_) => {
            fs::remove_file(&pending).map_err(|error| {
                format!("failed to clear incomplete historical-v3 page checkpoint: {error}")
            })?;
            Ok(None)
        }
    }
}

pub(super) fn persist_page_checkpoint(
    root: &Path,
    request: &HistoricalV3CandidatePageRequest,
    checkpoint: &HistoricalV3CandidatePageCheckpoint,
) -> Result<(), String> {
    validate_page_checkpoint(request, checkpoint)?;
    let pages = root.join("pages");
    fs::create_dir_all(&pages)
        .map_err(|error| format!("failed to create historical-v3 page directory: {error}"))?;
    let final_path = checkpoint_path(root, &request.request_sha256);
    if final_path.exists() {
        return Err("historical-v3 page checkpoint already exists".to_string());
    }
    let pending_path = pending_path(root, &request.request_sha256);
    if pending_path.exists() {
        fs::remove_file(&pending_path).map_err(|error| {
            format!("failed to clear incomplete historical-v3 page checkpoint: {error}")
        })?;
    }
    let bytes = serde_json::to_vec(checkpoint)
        .map_err(|error| format!("failed to encode historical-v3 page checkpoint: {error}"))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending_path)
        .map_err(|error| format!("failed to create historical-v3 page checkpoint: {error}"))?;
    output
        .write_all(&bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("failed to persist historical-v3 page checkpoint: {error}"))?;
    drop(output);
    fs::rename(&pending_path, &final_path)
        .map_err(|error| format!("failed to publish historical-v3 page checkpoint: {error}"))
}

pub(super) fn read_committed_page_checkpoint(
    root: &Path,
    request_sha256: &str,
) -> Result<HistoricalV3CandidatePageCheckpoint, String> {
    read_checkpoint(&checkpoint_path(root, request_sha256))
}

fn read_checkpoint(path: &Path) -> Result<HistoricalV3CandidatePageCheckpoint, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read historical-v3 page checkpoint: {error}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid historical-v3 page checkpoint: {error}"))
}

fn checkpoint_path(root: &Path, request_sha256: &str) -> PathBuf {
    root.join("pages").join(format!("{request_sha256}.json"))
}

fn pending_path(root: &Path, request_sha256: &str) -> PathBuf {
    root.join("pages").join(format!("{request_sha256}.pending"))
}

fn bounded(bytes: &[u8], limit: usize) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn graphql_200_retries_only_explicit_rate_limit_errors() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        let hints = RateLimitHints::from_headers(&headers);
        assert!(is_rate_limited(
            StatusCode::OK,
            &hints,
            br#"{"data":null,"errors":[{"message":"rate limit exceeded"}]}"#
        ));
        assert!(!is_rate_limited(
            StatusCode::OK,
            &hints,
            br#"{"data":{"search":{"nodes":[]}},"errors":[]}"#
        ));
        assert!(!is_rate_limited(StatusCode::OK, &hints, b"not json"));
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("1"));
        assert!(!is_rate_limited(
            StatusCode::OK,
            &RateLimitHints::from_headers(&headers),
            br#"{"errors":[{"message":"other error"}]}"#
        ));
        assert!(is_rate_limited(
            StatusCode::OK,
            &RateLimitHints::from_headers(&headers),
            br#"{"errors":[{"message":"You have exceeded a secondary rate limit."}]}"#
        ));
        assert!(is_rate_limited(
            StatusCode::TOO_MANY_REQUESTS,
            &RateLimitHints::from_headers(&headers),
            b""
        ));
        assert!(!is_rate_limited(
            StatusCode::FORBIDDEN,
            &RateLimitHints::from_headers(&headers),
            b""
        ));
        headers.insert("retry-after", HeaderValue::from_static("60"));
        assert!(is_rate_limited(
            StatusCode::FORBIDDEN,
            &RateLimitHints::from_headers(&headers),
            b""
        ));
    }

    #[test]
    fn primary_limit_waits_for_reset_even_when_retry_after_is_shorter() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("1600"));
        headers.insert("retry-after", HeaderValue::from_static("45"));
        let hints = RateLimitHints::from_headers(&headers);
        assert_eq!(hints.wait(0, 1000).unwrap(), Duration::from_secs(601));
        assert_eq!(hints.wait(0, 1600).unwrap(), Duration::from_secs(45));
    }

    #[test]
    fn secondary_limit_backs_off_without_headers_but_never_retries_too_early() {
        let hints = RateLimitHints::from_headers(&HeaderMap::new());
        assert_eq!(hints.wait(0, 1000).unwrap(), Duration::from_secs(60));
        assert_eq!(hints.wait(2, 1000).unwrap(), Duration::from_secs(240));

        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("87402"));
        assert!(
            RateLimitHints::from_headers(&headers)
                .wait(0, 1000)
                .is_err()
        );
    }
}
