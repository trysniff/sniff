use super::*;
use crate::benchmark::committed_public_id_census_policy;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sniff-public-id-census-collector-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let Ok(temp) = fs::canonicalize(std::env::temp_dir()) else {
            return;
        };
        let Ok(root) = fs::canonicalize(&self.0) else {
            return;
        };
        if root != temp && root.starts_with(&temp) {
            let _ = fs::remove_dir_all(root);
        }
    }
}

struct FixtureTransport {
    policy_response: PublicIdCensusHttpResponse,
    exchanges: std::collections::VecDeque<PublicIdCensusExchange>,
    policy_calls: usize,
    exchange_calls: usize,
}

impl FixtureTransport {
    fn new(exchanges: Vec<PublicIdCensusExchange>) -> Self {
        let preflight = super::super::replay::tests::preflight_fixture();
        Self {
            policy_response: PublicIdCensusHttpResponse {
                status: preflight.response_status,
                body: preflight.fetched_policy,
                link: None,
                date: None,
                received_at_utc: preflight.fetched_at_utc,
            },
            exchanges: exchanges.into(),
            policy_calls: 0,
            exchange_calls: 0,
        }
    }
}

impl PublicIdCensusTransport for FixtureTransport {
    fn fetch_public_policy(
        &mut self,
        _url: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        self.policy_calls += 1;
        Ok(self.policy_response.clone())
    }

    fn fetch_exchange(
        &mut self,
        request: &PublicIdCensusRequest,
        url: &str,
        body: Option<&str>,
        api_version: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        self.exchange_calls += 1;
        let exchange = self
            .exchanges
            .pop_front()
            .ok_or_else(|| PublicIdCensusTransportError::NotSent("offline".to_string()))?;
        assert_eq!(&exchange.request, request);
        assert_eq!(exchange.request_url, url);
        assert_eq!(exchange.request_body.as_deref(), body);
        assert_eq!(exchange.request_api_version, api_version);
        Ok(PublicIdCensusHttpResponse {
            status: exchange.response_status,
            body: exchange.response_body,
            link: exchange.response_link,
            date: exchange.response_date,
            received_at_utc: exchange.received_at_utc,
        })
    }
}

struct FailingTransport {
    fixture: FixtureTransport,
    failure: PublicIdCensusTransportError,
    exchange_calls: usize,
}

impl FailingTransport {
    fn new(failure: PublicIdCensusTransportError) -> Self {
        Self {
            fixture: FixtureTransport::new(Vec::new()),
            failure,
            exchange_calls: 0,
        }
    }
}

impl PublicIdCensusTransport for FailingTransport {
    fn fetch_public_policy(
        &mut self,
        url: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        self.fixture.fetch_public_policy(url)
    }

    fn fetch_exchange(
        &mut self,
        _request: &PublicIdCensusRequest,
        _url: &str,
        _body: Option<&str>,
        _api_version: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        self.exchange_calls += 1;
        Err(self.failure.clone())
    }
}

#[test]
fn commits_every_exchange_before_sealing_six_frames() {
    let root = TestRoot::new();
    let policy = committed_public_id_census_policy().unwrap();
    let exchanges = super::super::replay::tests::transcript();
    let mut transport = FixtureTransport::new(exchanges.clone());
    let manifest = collect_public_id_census(&policy, &root.0, &mut transport).unwrap();
    assert_eq!(transport.policy_calls, 1);
    assert_eq!(transport.exchange_calls, exchanges.len());
    assert_eq!(manifest.exchanges.len(), exchanges.len());
    assert_eq!(manifest.frames.len(), 6);
    validate_public_id_census_manifest(&manifest, &root.0).unwrap();

    let mut offline = FixtureTransport::new(Vec::new());
    assert_eq!(
        collect_public_id_census(&policy, &root.0, &mut offline).unwrap(),
        manifest
    );
    assert_eq!(offline.policy_calls, 0);
    assert_eq!(offline.exchange_calls, 0);
}

#[test]
fn resumes_after_an_interrupted_request_without_refetching_checkpoints() {
    let root = TestRoot::new();
    let policy = committed_public_id_census_policy().unwrap();
    let exchanges = super::super::replay::tests::transcript();
    let mut first = FixtureTransport::new(exchanges[..3].to_vec());
    assert!(collect_public_id_census(&policy, &root.0, &mut first).is_err());
    assert_eq!(first.exchange_calls, 4);
    assert!(!root.0.join("manifest.json").exists());
    assert!(!root.0.join("frames").exists());
    let mut second = FixtureTransport::new(exchanges[3..].to_vec());
    let manifest = collect_public_id_census(&policy, &root.0, &mut second).unwrap();
    assert_eq!(second.policy_calls, 0);
    assert_eq!(second.exchange_calls, exchanges.len() - 3);
    assert_eq!(manifest.exchanges.len(), exchanges.len());
}

#[test]
fn rejects_wrong_public_policy_before_first_rest_request() {
    let root = TestRoot::new();
    let policy = committed_public_id_census_policy().unwrap();
    let mut transport = FixtureTransport::new(super::super::replay::tests::transcript());
    transport.policy_response.body.push(' ');
    assert!(collect_public_id_census(&policy, &root.0, &mut transport).is_err());
    assert_eq!(transport.policy_calls, 1);
    assert_eq!(transport.exchange_calls, 0);
    assert!(!root.0.join("preflight.json").exists());
    assert!(!root.0.join("frames").exists());
}

#[test]
fn retry_cap_survives_restart_without_an_extra_request() {
    let root = TestRoot::new();
    let policy = committed_public_id_census_policy().unwrap();
    let mut first = FailingTransport::new(PublicIdCensusTransportError::Timeout);
    assert!(collect_public_id_census(&policy, &root.0, &mut first).is_err());
    assert_eq!(first.exchange_calls, 12);
    let mut second = FixtureTransport::new(super::super::replay::tests::transcript());
    assert!(collect_public_id_census(&policy, &root.0, &mut second).is_err());
    assert_eq!(second.exchange_calls, 0);
    assert!(!root.0.join("frames").exists());
}

#[test]
fn uncertain_inflight_request_does_not_repeat_after_restart() {
    let root = TestRoot::new();
    let policy = committed_public_id_census_policy().unwrap();
    let mut first = FailingTransport::new(PublicIdCensusTransportError::Other(
        "response may have been lost".to_string(),
    ));
    assert!(collect_public_id_census(&policy, &root.0, &mut first).is_err());
    assert_eq!(first.exchange_calls, 1);
    let mut second = FixtureTransport::new(super::super::replay::tests::transcript());
    assert!(collect_public_id_census(&policy, &root.0, &mut second).is_err());
    assert_eq!(second.exchange_calls, 0);
}

#[test]
fn completed_root_rejects_uncommitted_frame_file() {
    let root = TestRoot::new();
    let policy = committed_public_id_census_policy().unwrap();
    let mut transport = FixtureTransport::new(super::super::replay::tests::transcript());
    collect_public_id_census(&policy, &root.0, &mut transport).unwrap();
    fs::write(root.0.join("frames/extra.csv"), b"repo,metadata\n").unwrap();
    let mut offline = FixtureTransport::new(Vec::new());
    assert!(collect_public_id_census(&policy, &root.0, &mut offline).is_err());
    assert_eq!(offline.exchange_calls, 0);
}

#[test]
fn atomic_write_never_overwrites_an_existing_checkpoint() {
    let root = TestRoot::new();
    let path = root.0.join("checkpoint.json");
    fs::write(&path, b"first").unwrap();
    assert!(write_new(&path, b"second").is_err());
    assert_eq!(fs::read(path).unwrap(), b"first");
}

#[test]
fn resumes_past_an_orphaned_frame_staging_file() {
    let root = TestRoot::new();
    let policy = committed_public_id_census_policy().unwrap();
    let exchanges = super::super::replay::tests::transcript();
    let mut first = FixtureTransport::new(exchanges[..8].to_vec());
    assert!(collect_public_id_census(&policy, &root.0, &mut first).is_err());
    fs::create_dir(root.0.join("frames")).unwrap();
    fs::write(root.0.join("frames/.sniff-census-orphan"), b"partial").unwrap();
    let mut second = FixtureTransport::new(exchanges[8..].to_vec());
    let manifest = collect_public_id_census(&policy, &root.0, &mut second).unwrap();
    assert_eq!(second.exchange_calls, 1);
    assert_eq!(manifest.exchanges.len(), exchanges.len());
    assert!(!root.0.join("frames/.sniff-census-orphan").exists());
}

#[test]
fn active_collector_lock_prevents_a_second_run() {
    let root = TestRoot::new();
    let policy = committed_public_id_census_policy().unwrap();
    let _lock = super::super::lock::CensusLock::acquire(&root.0.join(".collector.lock")).unwrap();
    let mut transport = FixtureTransport::new(super::super::replay::tests::transcript());
    assert!(collect_public_id_census(&policy, &root.0, &mut transport).is_err());
    assert_eq!(transport.policy_calls, 0);
    assert_eq!(transport.exchange_calls, 0);
}
