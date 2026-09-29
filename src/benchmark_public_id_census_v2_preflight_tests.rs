use super::*;
use crate::benchmark::release::public_id_census::{
    PublicIdCensusHttpResponse, PublicIdCensusRequest, PublicIdCensusTransportError,
};
use crate::benchmark::release::public_id_census_v2::committed_public_id_census_v2_policy;
use std::collections::VecDeque;

struct FakeTransport {
    bodies: VecDeque<String>,
    fetched_urls: Vec<String>,
    source_calls: usize,
}

impl FakeTransport {
    fn valid() -> Self {
        Self {
            bodies: VecDeque::from([
                include_str!("../sniffbench/historical-v3-id-census-v2/policy.json")
                    .replace("\r\n", "\n"),
                include_str!("../sniffbench/historical-v3-id-census-v2/artifact-contract.json")
                    .replace("\r\n", "\n"),
            ]),
            fetched_urls: Vec::new(),
            source_calls: 0,
        }
    }
}

impl PublicIdCensusTransport for FakeTransport {
    fn fetch_public_policy(
        &mut self,
        url: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        self.fetched_urls.push(url.to_string());
        let body = self
            .bodies
            .pop_front()
            .ok_or(PublicIdCensusTransportError::Other(
                "unexpected public fetch".to_string(),
            ))?;
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
        _request: &PublicIdCensusRequest,
        _url: &str,
        _body: Option<&str>,
        _api_version: &str,
    ) -> Result<PublicIdCensusHttpResponse, PublicIdCensusTransportError> {
        self.source_calls += 1;
        Err(PublicIdCensusTransportError::Other(
            "source request is forbidden during preflight".to_string(),
        ))
    }
}

#[test]
fn both_public_receipts_are_verified_and_reused_without_source_calls() {
    let root = tempfile::tempdir().unwrap();
    let policy = committed_public_id_census_v2_policy().unwrap();
    let mut transport = FakeTransport::valid();
    let first = read_or_fetch_v2_preflights(&policy, root.path(), &mut transport).unwrap();
    assert_eq!(transport.fetched_urls.len(), 2);
    assert_eq!(transport.source_calls, 0);
    assert!(root.path().join("preflight.json").is_file());
    assert!(root.path().join("contract-preflight.json").is_file());

    let mut offline = FakeTransport {
        bodies: VecDeque::new(),
        fetched_urls: Vec::new(),
        source_calls: 0,
    };
    assert_eq!(
        read_or_fetch_v2_preflights(&policy, root.path(), &mut offline).unwrap(),
        first
    );
    assert!(offline.fetched_urls.is_empty());
    assert_eq!(offline.source_calls, 0);
}

#[test]
fn wrong_contract_fails_before_any_source_call_or_contract_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let policy = committed_public_id_census_v2_policy().unwrap();
    let mut transport = FakeTransport::valid();
    transport.bodies[1] = "{}".to_string();
    assert!(read_or_fetch_v2_preflights(&policy, root.path(), &mut transport).is_err());
    assert!(root.path().join("preflight.json").is_file());
    assert!(!root.path().join("contract-preflight.json").exists());
    assert_eq!(transport.source_calls, 0);
}

#[test]
fn wrong_policy_stops_before_contract_fetch_or_source_call() {
    let root = tempfile::tempdir().unwrap();
    let policy = committed_public_id_census_v2_policy().unwrap();
    let mut transport = FakeTransport::valid();
    transport.bodies[0] = "{}".to_string();
    assert!(read_or_fetch_v2_preflights(&policy, root.path(), &mut transport).is_err());
    assert_eq!(transport.fetched_urls.len(), 1);
    assert_eq!(transport.source_calls, 0);
    assert!(!root.path().join("preflight.json").exists());
}
