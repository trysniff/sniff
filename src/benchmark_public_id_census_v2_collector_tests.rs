use super::*;
use crate::benchmark::release::public_id_census::{
    PublicIdCensusHttpResponse, PublicIdCensusRequest, PublicIdCensusTransportError,
};
use crate::benchmark::release::public_id_census_v2::committed_public_id_census_v2_policy;
use std::collections::VecDeque;
use std::fs;

struct FakeTransport {
    public_bodies: VecDeque<String>,
    exchanges: VecDeque<PublicIdCensusExchange>,
    public_calls: usize,
    source_calls: usize,
    fail_source_at: Option<usize>,
}

impl FakeTransport {
    fn valid(exchanges: Vec<PublicIdCensusExchange>) -> Self {
        Self {
            public_bodies: VecDeque::from([
                include_str!("../sniffbench/historical-v3-id-census-v2/policy.json")
                    .replace("\r\n", "\n"),
                include_str!("../sniffbench/historical-v3-id-census-v2/artifact-contract.json")
                    .replace("\r\n", "\n"),
            ]),
            exchanges: exchanges.into(),
            public_calls: 0,
            source_calls: 0,
            fail_source_at: None,
        }
    }
}

impl PublicIdCensusTransport for FakeTransport {
    fn fetch_public_policy(
        &mut self,
        _url: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        self.public_calls += 1;
        let body = self.public_bodies.pop_front().ok_or_else(|| {
            PublicIdCensusTransportError::Other("unexpected public fetch".to_string())
        })?;
        Ok(PublicIdCensusHttpResponse {
            status: 200,
            body,
            link: None,
            date: None,
            received_at_utc: "2026-09-28T00:00:00Z".to_string(),
        })
    }

    fn fetch_exchange(
        &mut self,
        request: &PublicIdCensusRequest,
        url: &str,
        body: Option<&str>,
        api_version: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        if self.public_calls != 2 {
            return Err(PublicIdCensusTransportError::Other(
                "source sent before both public preflights".to_string(),
            ));
        }
        let index = self.source_calls;
        self.source_calls += 1;
        if self.fail_source_at == Some(index) {
            return Err(PublicIdCensusTransportError::NotSent(
                "synthetic connection loss".to_string(),
            ));
        }
        let expected = self.exchanges.pop_front().ok_or_else(|| {
            PublicIdCensusTransportError::Other("unexpected source call".to_string())
        })?;
        if &expected.request != request
            || expected.request_url != url
            || expected.request_body.as_deref() != body
            || expected.request_api_version != api_version
        {
            return Err(PublicIdCensusTransportError::Other(
                "source request differs from replay".to_string(),
            ));
        }
        Ok(PublicIdCensusHttpResponse {
            status: expected.response_status,
            body: expected.response_body,
            link: expected.response_link,
            date: expected.response_date,
            received_at_utc: expected.received_at_utc,
        })
    }
}

#[test]
fn collector_seals_replay_and_reuses_completed_root_without_network() {
    let root = tempfile::tempdir().unwrap();
    let (policy, _, exchanges, _) = super::super::replay::tests::fixture_transcript();
    let mut transport = FakeTransport::valid(exchanges.clone());
    let manifest = collect_public_id_census_v2(&policy, root.path(), &mut transport).unwrap();
    assert_eq!(transport.public_calls, 2);
    assert_eq!(transport.source_calls, exchanges.len());
    assert!(transport.exchanges.is_empty());
    assert_eq!(manifest.exchanges.len(), exchanges.len());
    assert_eq!(manifest.frames.len(), 6);

    let mut offline = FakeTransport::valid(Vec::new());
    assert_eq!(
        collect_public_id_census_v2(&policy, root.path(), &mut offline).unwrap(),
        manifest
    );
    assert_eq!(offline.public_calls, 0);
    assert_eq!(offline.source_calls, 0);
}

#[test]
fn collector_resumes_only_missing_source_exchanges_after_not_sent_failure() {
    let root = tempfile::tempdir().unwrap();
    let policy = committed_public_id_census_v2_policy().unwrap();
    let (_, _, exchanges, _) = super::super::replay::tests::fixture_transcript();
    let mut first = FakeTransport::valid(exchanges.clone());
    first.fail_source_at = Some(2);
    assert!(collect_public_id_census_v2(&policy, root.path(), &mut first).is_err());
    assert!(root.path().join("raw/00000000.json").is_file());
    assert!(root.path().join("raw/00000001.json").is_file());
    assert!(!root.path().join("raw/00000002.json").exists());

    let mut resumed = FakeTransport::valid(exchanges[2..].to_vec());
    resumed.public_bodies.clear();
    resumed.public_calls = 2;
    let manifest = collect_public_id_census_v2(&policy, root.path(), &mut resumed).unwrap();
    assert_eq!(resumed.source_calls, exchanges.len() - 2);
    assert_eq!(manifest.exchanges.len(), exchanges.len());
}

#[test]
fn collector_does_not_send_source_after_invalid_public_contract() {
    let root = tempfile::tempdir().unwrap();
    let (policy, _, exchanges, _) = super::super::replay::tests::fixture_transcript();
    let mut transport = FakeTransport::valid(exchanges);
    transport.public_bodies[1] = "{}".to_string();
    assert!(collect_public_id_census_v2(&policy, root.path(), &mut transport).is_err());
    assert_eq!(transport.source_calls, 0);
    assert!(!root.path().join("raw").exists());
}

#[test]
fn collector_rejects_wrong_type_retry_directory_before_network() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("attempts"), b"not a directory").unwrap();
    let (policy, _, exchanges, _) = super::super::replay::tests::fixture_transcript();
    let mut transport = FakeTransport::valid(exchanges);
    assert!(collect_public_id_census_v2(&policy, root.path(), &mut transport).is_err());
    assert_eq!(transport.public_calls, 0);
    assert_eq!(transport.source_calls, 0);
}

#[cfg(unix)]
#[test]
fn dangling_raw_checkpoint_symlink_is_rejected_before_source_send() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("raw")).unwrap();
    std::os::unix::fs::symlink(
        root.path().join("missing-checkpoint"),
        root.path().join("raw/00000000.json"),
    )
    .unwrap();
    let (policy, _, exchanges, _) = super::super::replay::tests::fixture_transcript();
    let mut transport = FakeTransport::valid(exchanges);
    assert!(collect_public_id_census_v2(&policy, root.path(), &mut transport).is_err());
    assert_eq!(transport.public_calls, 2);
    assert_eq!(transport.source_calls, 0);
}
