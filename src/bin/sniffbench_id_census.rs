use chrono::Utc;
use clap::Parser;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE, DATE, LINK, RETRY_AFTER, USER_AGENT};
use sniff::benchmark::{
    PublicIdCensusHttpResponse, PublicIdCensusRequest, PublicIdCensusTransport,
    PublicIdCensusTransportError, collect_public_id_census, collect_public_id_census_v2,
    committed_public_id_census_policy, committed_public_id_census_v2_policy,
};
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "sniffbench-id-census", version)]
#[command(about = "Collect or replay the pinned post-August public-ID census")]
struct Args {
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    offline: bool,
    #[arg(long)]
    v2: bool,
}

struct GitHubTransport {
    client: Client,
    token: Option<String>,
    next_at: Option<Instant>,
}

impl GitHubTransport {
    fn new(offline: bool) -> Result<Self, String> {
        let token = if offline {
            None
        } else {
            let token = std::env::var("GITHUB_TOKEN").map_err(|_| {
                "GITHUB_TOKEN is required for live ID census collection".to_string()
            })?;
            if token.trim().is_empty() {
                return Err("GITHUB_TOKEN is empty".to_string());
            }
            Some(token)
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("failed to build GitHub census client: {error}"))?;
        Ok(Self {
            client,
            token,
            next_at: None,
        })
    }

    fn wait_for_budget(&self) {
        if let Some(at) = self.next_at
            && let Some(remaining) = at.checked_duration_since(Instant::now())
        {
            std::thread::sleep(remaining);
        }
    }

    fn decode_response(
        &mut self,
        response: Response,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        let status = response.status().as_u16();
        let header = |name: reqwest::header::HeaderName| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        };
        let link = header(LINK);
        let date = header(DATE);
        let retry_after = header(RETRY_AFTER);
        let remaining = header(reqwest::header::HeaderName::from_static(
            "x-ratelimit-remaining",
        ));
        let reset = header(reqwest::header::HeaderName::from_static(
            "x-ratelimit-reset",
        ));
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                PublicIdCensusTransportError::Other(format!("GitHub response read failed: {error}"))
            })?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(PublicIdCensusTransportError::Other(
                "GitHub response exceeds the census size limit".to_string(),
            ));
        }
        let body = String::from_utf8(bytes).map_err(|error| {
            PublicIdCensusTransportError::Other(format!("GitHub response is not UTF-8: {error}"))
        })?;
        let mut wait = Duration::from_millis(1200);
        if let Some(value) = retry_after {
            let seconds = value.parse::<u64>().map_err(|_| {
                PublicIdCensusTransportError::Other(
                    "GitHub Retry-After is not an integer number of seconds".to_string(),
                )
            })?;
            wait = wait.max(Duration::from_secs(seconds));
        }
        if remaining.as_deref() == Some("0") {
            let reset_at = reset
                .ok_or_else(|| {
                    PublicIdCensusTransportError::Other(
                        "GitHub rate limit reached without a reset time".to_string(),
                    )
                })?
                .parse::<i64>()
                .map_err(|_| {
                    PublicIdCensusTransportError::Other(
                        "GitHub rate reset time is invalid".to_string(),
                    )
                })?;
            let seconds = reset_at.saturating_sub(Utc::now().timestamp()).max(0) as u64;
            wait = wait.max(Duration::from_secs(seconds.saturating_add(1)));
        }
        self.next_at = Some(Instant::now().checked_add(wait).ok_or_else(|| {
            PublicIdCensusTransportError::Other(
                "GitHub rate-limit wait overflows the local clock".to_string(),
            )
        })?);
        Ok(PublicIdCensusHttpResponse {
            status,
            body,
            link,
            date,
            received_at_utc: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        })
    }

    fn send(
        &mut self,
        url: &str,
        body: Option<&str>,
        api_version: Option<&str>,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        let Some(token) = self.token.as_ref() else {
            return Err(PublicIdCensusTransportError::NotSent(
                "offline census has no missing checkpoint to fetch".to_string(),
            ));
        };
        self.wait_for_budget();
        let mut request = if body.is_some() {
            self.client.post(url)
        } else {
            self.client.get(url)
        }
        .header(ACCEPT, "application/vnd.github+json")
        .header(USER_AGENT, "SniffBench-public-ID-census");
        if let Some(version) = api_version {
            request = request
                .header("X-GitHub-Api-Version", version)
                .bearer_auth(token);
        }
        if let Some(body) = body {
            request = request
                .header(CONTENT_TYPE, "application/json")
                .body(body.to_string());
        }
        let response = request.send().map_err(|error| {
            if error.is_timeout() {
                PublicIdCensusTransportError::Timeout
            } else if error.is_connect() {
                PublicIdCensusTransportError::NotSent(format!("GitHub connection failed: {error}"))
            } else {
                PublicIdCensusTransportError::Other(format!("GitHub request failed: {error}"))
            }
        })?;
        self.decode_response(response)
    }
}

impl PublicIdCensusTransport for GitHubTransport {
    fn fetch_public_policy(
        &mut self,
        url: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        self.send(url, None, None)
    }

    fn fetch_exchange(
        &mut self,
        request: &PublicIdCensusRequest,
        url: &str,
        body: Option<&str>,
        api_version: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        if !matches!(
            (request, body),
            (PublicIdCensusRequest::Rest { .. }, None)
                | (PublicIdCensusRequest::Graphql { .. }, Some(_))
        ) {
            return Err(PublicIdCensusTransportError::Other(
                "public-ID census request method or body changed".to_string(),
            ));
        }
        self.send(url, body, Some(api_version))
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("public-ID census failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let mut transport = GitHubTransport::new(args.offline)?;
    if args.v2 {
        let policy = committed_public_id_census_v2_policy()?;
        let manifest = collect_public_id_census_v2(&policy, &args.output, &mut transport)?;
        println!(
            "public-ID census v2 sealed: {} raw exchanges, {} listed, {} resolved in-window, {} crawled null exclusions, {} frames",
            manifest.exchanges.len(),
            manifest.listed_repository_count,
            manifest.resolved_in_window_count,
            manifest.crawled_null_count,
            manifest.frames.len()
        );
    } else {
        let policy = committed_public_id_census_policy()?;
        let manifest = collect_public_id_census(&policy, &args.output, &mut transport)?;
        println!(
            "public-ID census sealed: {} raw exchanges, {} listed repositories, {} in-window repositories, {} frames",
            manifest.exchanges.len(),
            manifest.listed_repository_count,
            manifest.in_window_repository_count,
            manifest.frames.len()
        );
    }
    Ok(())
}
