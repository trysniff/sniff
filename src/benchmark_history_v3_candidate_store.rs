use super::{
    HistoricalV3CandidatePageCheckpoint, HistoricalV3CandidatePageRequest, request_body,
    validate_page_checkpoint,
};
use reqwest::{Client, StatusCode};
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
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
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|value| value.to_str().ok())
                            .and_then(|value| value.parse::<u64>().ok());
                        let rate_limited = response
                            .headers()
                            .get("x-ratelimit-remaining")
                            .and_then(|value| value.to_str().ok())
                            == Some("0");
                        let payload = match response.bytes().await {
                            Ok(payload) => payload,
                            Err(error) => {
                                last_error = format!(
                                    "failed to read historical-v3 GitHub response: {error}"
                                );
                                if attempt < 3 {
                                    sleep(Duration::from_secs(1_u64 << attempt)).await;
                                }
                                continue;
                            }
                        };
                        if status.is_success() {
                            return Ok(payload.to_vec());
                        }
                        last_error = format!(
                            "GitHub GraphQL returned {status}: {}",
                            bounded(&payload, 512)
                        );
                        let retryable = status == StatusCode::TOO_MANY_REQUESTS
                            || status.is_server_error()
                            || (status == StatusCode::FORBIDDEN
                                && (rate_limited || retry_after.is_some()));
                        if !retryable {
                            return Err(last_error);
                        }
                        if attempt < 3 {
                            sleep(Duration::from_secs(
                                retry_after.unwrap_or(1_u64 << attempt).clamp(1, 120),
                            ))
                            .await;
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
