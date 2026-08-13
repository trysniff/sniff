use reqwest::{Client, StatusCode};
use std::error::Error;
use tokio::time::{Duration, sleep};

fn request_error_chain(error: &reqwest::Error) -> String {
    let mut rendered = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        rendered.push_str(": ");
        rendered.push_str(&cause.to_string());
        source = cause.source();
    }
    rendered
}

pub(super) async fn github_metadata(
    client: &Client,
    github_token: Option<&str>,
    api_url: &str,
    repository: &str,
) -> Result<(StatusCode, String), String> {
    let mut last_error = String::new();
    for attempt in 0..4_u32 {
        let mut request = client.get(api_url);
        if let Some(token) = github_token.filter(|token| !token.trim().is_empty()) {
            request = request.bearer_auth(token.trim());
        }
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                if (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
                    && attempt < 3
                {
                    last_error = format!("GitHub returned {status}");
                    sleep(Duration::from_secs(1_u64 << attempt)).await;
                    continue;
                }
                let bytes = response.bytes().await.map_err(|error| {
                    format!("failed to read GitHub metadata for {repository}: {error}")
                })?;
                let payload = String::from_utf8(bytes.to_vec())
                    .map_err(|_| format!("GitHub metadata is not UTF-8 for {repository}"))?;
                return Ok((status, payload));
            }
            Err(error) if attempt < 3 => {
                last_error = request_error_chain(&error);
                sleep(Duration::from_secs(1_u64 << attempt)).await;
            }
            Err(error) => last_error = request_error_chain(&error),
        }
    }
    Err(format!(
        "GitHub metadata request failed for {repository} after four attempts: {last_error}"
    ))
}
