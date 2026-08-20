use super::history_v2_materialization::{
    materialize_from_url_typed, validate_materialization_request,
};
use super::history_v2_materialization_exclusion::seal_materialization_exclusion;
use super::{
    HistoricalV2Materialization, HistoricalV2MaterializationExclusion,
    HistoricalV2MaterializationExclusionEvidence, HistoricalV2MaterializationExclusionReason,
    HistoricalV2MaterializedRoots, HistoricalV2SlotStage, HistoricalV2SlotStageError,
    HistoricalV2SlotStageErrorKind, HistoricalV2StageResult,
};
use reqwest::{Client, StatusCode};
use std::path::Path;
use std::time::Duration;

const REPOSITORY_PROBE_ATTEMPTS: u32 = 3;
const REPOSITORY_PROBE_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn materialize_historical_v2_repository_typed(
    client: &Client,
    canonical_repository: &str,
    base_revision: &str,
    historical_patch: &str,
    expected_patch_sha256: &str,
    slot_root: &Path,
) -> Result<
    HistoricalV2StageResult<
        (HistoricalV2Materialization, HistoricalV2MaterializedRoots),
        HistoricalV2MaterializationExclusion,
    >,
    HistoricalV2SlotStageError,
> {
    validate_materialization_request(
        canonical_repository,
        base_revision,
        historical_patch,
        expected_patch_sha256,
        slot_root,
    )?;
    let repository_url = format!("https://github.com/{canonical_repository}.git");
    let probe_url = repository_probe_url(canonical_repository);
    match probe_repository(client, &probe_url).await? {
        RepositoryProbeOutcome::Available => materialize_from_url_typed(
            canonical_repository,
            &repository_url,
            base_revision,
            historical_patch,
            expected_patch_sha256,
            slot_root,
        ),
        RepositoryProbeOutcome::Unavailable { status } => {
            let exclusion = seal_materialization_exclusion(
                canonical_repository,
                base_revision,
                expected_patch_sha256,
                HistoricalV2MaterializationExclusionReason::RepositoryUnavailable,
                HistoricalV2MaterializationExclusionEvidence::RepositoryProbe {
                    url: probe_url,
                    status,
                },
            )?;
            Ok(HistoricalV2StageResult::Excluded(exclusion))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepositoryProbeOutcome {
    Available,
    Unavailable { status: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepositoryProbeResponse {
    Available,
    Unavailable,
    Retryable,
}

async fn probe_repository(
    client: &Client,
    url: &str,
) -> Result<RepositoryProbeOutcome, HistoricalV2SlotStageError> {
    let mut last_failure = String::new();
    for attempt in 0..REPOSITORY_PROBE_ATTEMPTS {
        let request = client.get(url).send();
        match tokio::time::timeout(REPOSITORY_PROBE_TIMEOUT, request).await {
            Ok(Ok(response)) => match classify_probe_status(response.status()) {
                RepositoryProbeResponse::Available => {
                    return Ok(RepositoryProbeOutcome::Available);
                }
                RepositoryProbeResponse::Unavailable => {
                    return Ok(RepositoryProbeOutcome::Unavailable {
                        status: response.status().as_u16(),
                    });
                }
                RepositoryProbeResponse::Retryable => {
                    last_failure = format!("repository probe returned {}", response.status());
                }
            },
            Ok(Err(error)) => {
                last_failure = format!("repository probe transport failed: {error}");
            }
            Err(_) => {
                last_failure = format!(
                    "repository probe exceeded its {}-second deadline",
                    REPOSITORY_PROBE_TIMEOUT.as_secs()
                );
            }
        }
        if attempt + 1 < REPOSITORY_PROBE_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(1_u64 << attempt)).await;
        }
    }
    Err(unavailable(format!(
        "historical-v2 repository availability could not be established: {last_failure}"
    )))
}

fn repository_probe_url(canonical_repository: &str) -> String {
    format!("https://github.com/{canonical_repository}.git/info/refs?service=git-upload-pack")
}

fn classify_probe_status(status: StatusCode) -> RepositoryProbeResponse {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND | StatusCode::GONE => {
            RepositoryProbeResponse::Unavailable
        }
        status if status.is_success() => RepositoryProbeResponse::Available,
        _ => RepositoryProbeResponse::Retryable,
    }
}

fn unavailable(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError {
        stage: HistoricalV2SlotStage::Materialization,
        kind: HistoricalV2SlotStageErrorKind::InfrastructureUnavailable,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn only_definitive_smart_git_absence_is_an_exclusion() {
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::NOT_FOUND,
            StatusCode::GONE,
        ] {
            assert_eq!(
                classify_probe_status(status),
                RepositoryProbeResponse::Unavailable
            );
        }
        for status in [
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_REQUEST,
        ] {
            assert_eq!(
                classify_probe_status(status),
                RepositoryProbeResponse::Retryable
            );
        }
        assert_eq!(
            classify_probe_status(StatusCode::OK),
            RepositoryProbeResponse::Available
        );
    }

    #[test]
    fn probe_targets_the_exact_selected_repository() {
        assert_eq!(
            repository_probe_url("trysniff/sniff"),
            "https://github.com/trysniff/sniff.git/info/refs?service=git-upload-pack"
        );
    }

    #[tokio::test]
    async fn retryable_probe_failures_exhaust_the_bounded_attempts() {
        let (url, server) = scripted_server(500, "Internal Server Error", 3);
        let client = Client::builder().build().unwrap();

        let error = probe_repository(&client, &url).await.unwrap_err();
        server.join().unwrap();

        assert_eq!(error.stage, HistoricalV2SlotStage::Materialization);
        assert_eq!(
            error.kind,
            HistoricalV2SlotStageErrorKind::InfrastructureUnavailable
        );
        assert!(error.detail.contains("500 Internal Server Error"));
    }

    #[tokio::test]
    async fn definitive_absence_stops_after_one_probe() {
        let (url, server) = scripted_server(404, "Not Found", 1);
        let client = Client::builder().build().unwrap();

        let outcome = probe_repository(&client, &url).await.unwrap();
        server.join().unwrap();

        assert_eq!(outcome, RepositoryProbeOutcome::Unavailable { status: 404 });
    }

    #[tokio::test]
    async fn invalid_request_fails_before_any_repository_probe() {
        let client = Client::builder().build().unwrap();
        let patch = "patch\n";
        let error = materialize_historical_v2_repository_typed(
            &client,
            "example/repo",
            &"1".repeat(40),
            patch,
            &format!("{:x}", Sha256::digest(patch.as_bytes())),
            Path::new("relative-slot"),
        )
        .await
        .unwrap_err();

        assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    }

    fn scripted_server(
        status: u16,
        reason: &'static str,
        requests: usize,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                stream.flush().unwrap();
            }
        });
        (format!("http://{address}/info/refs"), server)
    }
}
