use super::{
    PUBLIC_ID_CENSUS_V2_PUBLIC_POLICY_SHA256, PublicIdCensusV2Policy,
    validate_public_id_census_v2_policy,
};
use crate::benchmark::release::public_id_census::replay::{
    GraphqlNodeObservation, RestRepository, canonical_name, parse_graphql_observations,
    parse_next_since_for, valid_utc_timestamp, validate_exchange_for_version,
};
use crate::benchmark::release::public_id_census::{
    PublicIdCensusExchange, PublicIdCensusPreflight, PublicIdCensusRequest,
    public_id_census_graphql_body,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound::{Excluded, Unbounded};

pub const PUBLIC_ID_CENSUS_V2_POLICY_COMMIT_SHA: &str = "8ca7dbb872d2dd9e4a60a7ba1f08dd27bc36c6b1";
const MAX_FRAME_BYTES: usize = 512 * 1024 * 1024;
const MAX_TOTAL_FRAME_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusV2NullRecord {
    pub repository_id: u64,
    pub node_id: String,
    pub graphql_exchange_sequence: usize,
    pub batch_index: usize,
    pub error_path: (String, usize),
    pub error_message: String,
    pub crawled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdCensusV2Replay {
    pub frames: BTreeMap<String, Vec<u8>>,
    pub null_ledger: Vec<PublicIdCensusV2NullRecord>,
    pub listed_repository_count: usize,
    pub resolved_in_window_count: usize,
    pub resolved_ineligible_count: usize,
    pub probe_only_null_count: usize,
    pub crawled_null_count: usize,
    pub name_disagreement_count: usize,
    pub lower_boundary_repository_id: u64,
    pub upper_boundary_repository_id: u64,
}

#[derive(Clone)]
struct CachedObservation {
    node_id: String,
    result: GraphqlNodeObservation,
}

struct RestPage {
    repositories: Vec<RestRepository>,
    next_since: Option<u64>,
    received_at_utc: String,
}

struct Witness {
    repository_id: u64,
    created_at: String,
}

pub fn replay_public_id_census_v2_stream<I>(
    policy: &PublicIdCensusV2Policy,
    preflight: &PublicIdCensusPreflight,
    exchanges: I,
) -> Result<PublicIdCensusV2Replay, String>
where
    I: IntoIterator<Item = Result<PublicIdCensusExchange, String>>,
{
    let mut exchanges = exchanges.into_iter();
    let result = replay_public_id_census_v2_with_source(policy, preflight, |_, _, _| {
        exchanges
            .next()
            .ok_or("public-ID census v2 exchange transcript ended early".to_string())?
    })?;
    if exchanges.next().transpose()?.is_some() {
        return Err("public-ID census v2 has trailing exchanges".to_string());
    }
    Ok(result)
}

pub fn replay_public_id_census_v2(
    policy: &PublicIdCensusV2Policy,
    preflight: &PublicIdCensusPreflight,
    exchanges: &[PublicIdCensusExchange],
) -> Result<PublicIdCensusV2Replay, String> {
    replay_public_id_census_v2_stream(policy, preflight, exchanges.iter().cloned().map(Ok))
}

pub(crate) fn replay_public_id_census_v2_with_source<F>(
    policy: &PublicIdCensusV2Policy,
    preflight: &PublicIdCensusPreflight,
    source: F,
) -> Result<PublicIdCensusV2Replay, String>
where
    F: FnMut(
        PublicIdCensusRequest,
        String,
        Option<String>,
    ) -> Result<PublicIdCensusExchange, String>,
{
    validate_public_id_census_v2_policy(policy)?;
    validate_preflight(policy, preflight)?;
    let mut cursor = ReplayCursor {
        policy,
        source,
        sequence: 0,
        last_received_at: preflight.fetched_at_utc.clone(),
        cache: HashMap::new(),
        resolved_times: BTreeMap::new(),
        null_ledger: BTreeMap::new(),
    };
    let start = policy.created_at_or_after_utc.as_str();
    let end = policy.created_before_utc.as_str();

    let mut initial_since = 0_u64;
    let (mut lower, mut lower_witness) = loop {
        let page = cursor.rest(initial_since)?;
        if page.repositories.is_empty() {
            return Err("public-ID census v2 lacks a resolved pre-window witness".to_string());
        }
        let observations = cursor.enrich(&page)?;
        if page.next_since.is_none()
            && !observations.iter().any(|(_, result)| {
                matches!(result, GraphqlNodeObservation::Repository(repository)
                    if repository.created_at.as_str() >= end)
            })
        {
            return Err("public-ID census v2 initial page lacks its next cursor".to_string());
        }
        if let Some((listed, repository)) = observations.iter().find_map(|(listed, result)| {
            if let GraphqlNodeObservation::Repository(repository) = result {
                Some((listed, repository))
            } else {
                None
            }
        }) {
            if repository.created_at.as_str() >= start {
                return Err(
                    "public-ID census v2 first resolved witness is not before window".to_string(),
                );
            }
            break (
                initial_since,
                Witness {
                    repository_id: listed.id,
                    created_at: repository.created_at.clone(),
                },
            );
        }
        initial_since = page
            .next_since
            .ok_or("public-ID census v2 initial all-null page has no next cursor".to_string())?;
    };

    let mut upper = None;
    for exponent in 0..64 {
        let since = 1_u64 << exponent;
        if since <= lower {
            continue;
        }
        match cursor.probe(since)? {
            Some(witness) if witness.created_at.as_str() < start => {
                lower = since;
                lower_witness = witness;
            }
            Some(witness) => {
                upper = Some((since, witness));
                break;
            }
            None => {}
        }
    }
    let (mut upper, _) = upper.ok_or("public-ID census v2 lacks a resolved upper probe")?;
    while upper - lower > 1 {
        let midpoint = lower + (upper - lower) / 2;
        match cursor.probe(midpoint)? {
            Some(witness) if witness.created_at.as_str() < start => {
                lower = midpoint;
                lower_witness = witness;
            }
            Some(_) => upper = midpoint,
            None => break,
        }
    }

    let mut frames = policy
        .languages
        .iter()
        .map(|language| (language.clone(), b"repo,metadata\n".to_vec()))
        .collect::<BTreeMap<_, _>>();
    let mut total_frame_bytes = frames.values().map(Vec::len).sum::<usize>();
    let mut names = HashSet::new();
    let mut seen_ids = HashSet::new();
    let mut listed_repository_count = 0;
    let mut resolved_in_window_count = 0;
    let mut resolved_ineligible_count = 0;
    let mut name_disagreement_count = 0;
    let mut previous_id = None;
    let mut first_crawl = true;
    let upper_boundary_repository_id = loop {
        let page = cursor.rest(lower)?;
        if page.repositories.is_empty() {
            return Err("public-ID census v2 crawl ended before upper time boundary".to_string());
        }
        let observations = cursor.enrich(&page)?;
        if first_crawl {
            if !observations.iter().any(|(listed, result)| {
                listed.id == lower_witness.repository_id
                    && matches!(result, GraphqlNodeObservation::Repository(repository)
                        if repository.created_at == lower_witness.created_at)
            }) {
                return Err("public-ID census v2 lower witness changed during crawl".to_string());
            }
            first_crawl = false;
        }
        let mut crossing_id = None;
        for (listed, result) in observations {
            if !seen_ids.insert(listed.id)
                || previous_id.is_some_and(|previous| listed.id <= previous)
            {
                return Err("public-ID census v2 crawl repeats or reorders an ID".to_string());
            }
            previous_id = Some(listed.id);
            listed_repository_count += 1;
            let repository = match result {
                GraphqlNodeObservation::NotFound { .. } => {
                    cursor
                        .null_ledger
                        .get_mut(&listed.id)
                        .ok_or("public-ID census v2 null has no audit record")?
                        .crawled = true;
                    continue;
                }
                GraphqlNodeObservation::Repository(repository) => repository,
            };
            if repository.created_at.as_str() >= end && crossing_id.is_none() {
                crossing_id = Some(listed.id);
            }
            let name = canonical_name(&repository.name_with_owner)?;
            if canonical_name(&listed.full_name)? != name {
                name_disagreement_count += 1;
            }
            if repository.created_at.as_str() < start || repository.created_at.as_str() >= end {
                continue;
            }
            resolved_in_window_count += 1;
            if repository.created_at.as_str() <= policy.repository_created_after_utc.as_str()
                || (!policy.include_forks && repository.is_fork)
                || (!policy.include_archived && repository.is_archived)
                || (!policy.include_templates && repository.is_template)
                || (!policy.include_mirrors && repository.mirror_url.is_some())
            {
                resolved_ineligible_count += 1;
                continue;
            }
            let Some(language) = repository.primary_language.as_ref() else {
                resolved_ineligible_count += 1;
                continue;
            };
            let Some(frame) = frames.get_mut(&language.name) else {
                resolved_ineligible_count += 1;
                continue;
            };
            if !names.insert(name.clone()) {
                return Err("public-ID census v2 repeats a canonical repository name".to_string());
            }
            let row = format!(
                "github.com/{name},github_repository_id={};created_at={}\n",
                listed.id, repository.created_at
            );
            total_frame_bytes = total_frame_bytes
                .checked_add(row.len())
                .ok_or("public-ID census v2 frame size overflowed")?;
            if total_frame_bytes > MAX_TOTAL_FRAME_BYTES
                || frame.len() + row.len() > MAX_FRAME_BYTES
            {
                return Err("public-ID census v2 frames exceed the memory bound".to_string());
            }
            frame.extend_from_slice(row.as_bytes());
        }
        if let Some(id) = crossing_id {
            break id;
        }
        lower = page.next_since.ok_or(
            "public-ID census v2 page has no next cursor before upper witness".to_string(),
        )?;
    };
    let null_ledger = cursor.null_ledger.into_values().collect::<Vec<_>>();
    let crawled_null_count = null_ledger.iter().filter(|record| record.crawled).count();
    let probe_only_null_count = null_ledger.len() - crawled_null_count;
    Ok(PublicIdCensusV2Replay {
        frames,
        null_ledger,
        listed_repository_count,
        resolved_in_window_count,
        resolved_ineligible_count,
        probe_only_null_count,
        crawled_null_count,
        name_disagreement_count,
        lower_boundary_repository_id: lower_witness.repository_id,
        upper_boundary_repository_id,
    })
}

struct ReplayCursor<'a, F> {
    policy: &'a PublicIdCensusV2Policy,
    source: F,
    sequence: usize,
    last_received_at: String,
    cache: HashMap<u64, CachedObservation>,
    resolved_times: BTreeMap<u64, String>,
    null_ledger: BTreeMap<u64, PublicIdCensusV2NullRecord>,
}

impl<F> ReplayCursor<'_, F>
where
    F: FnMut(
        PublicIdCensusRequest,
        String,
        Option<String>,
    ) -> Result<PublicIdCensusExchange, String>,
{
    fn probe(&mut self, since: u64) -> Result<Option<Witness>, String> {
        let page = self.rest(since)?;
        let first = page
            .repositories
            .first()
            .ok_or("public-ID census v2 boundary probe is empty")?
            .clone();
        let result = self.enrich_subset(std::slice::from_ref(&first), &page.received_at_utc)?;
        if page.next_since.is_none()
            && !page.repositories.iter().any(|repository| {
                self.cache.get(&repository.id).is_some_and(|cached| {
                    cached.node_id == repository.node_id
                        && matches!(&cached.result, GraphqlNodeObservation::Repository(value)
                        if value.created_at.as_str() >= self.policy.created_before_utc.as_str())
                })
            })
        {
            return Err("public-ID census v2 boundary probe lacks its next cursor".to_string());
        }
        match &result[0].1 {
            GraphqlNodeObservation::Repository(repository) => Ok(Some(Witness {
                repository_id: first.id,
                created_at: repository.created_at.clone(),
            })),
            GraphqlNodeObservation::NotFound { .. } => Ok(None),
        }
    }

    fn enrich(
        &mut self,
        page: &RestPage,
    ) -> Result<Vec<(RestRepository, GraphqlNodeObservation)>, String> {
        self.enrich_subset(&page.repositories, &page.received_at_utc)
    }

    fn enrich_subset(
        &mut self,
        listed: &[RestRepository],
        rest_received_at: &str,
    ) -> Result<Vec<(RestRepository, GraphqlNodeObservation)>, String> {
        let unknown = listed
            .iter()
            .filter(|repository| !self.cache.contains_key(&repository.id))
            .cloned()
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            let node_ids = unknown
                .iter()
                .map(|repository| repository.node_id.clone())
                .collect::<Vec<_>>();
            let request = PublicIdCensusRequest::Graphql {
                node_ids: node_ids.clone(),
            };
            let body = public_id_census_graphql_body(&node_ids)?;
            let url = self.policy.metadata_source.clone();
            let (sequence, exchange) =
                self.next(request.clone(), url.clone(), Some(body.clone()))?;
            if exchange.request != request
                || exchange.request_url != url
                || exchange.request_body.as_deref() != Some(body.as_str())
                || exchange.response_link.is_some()
            {
                return Err("public-ID census v2 GraphQL request changed".to_string());
            }
            let observations = parse_graphql_observations(
                &exchange.response_body,
                &node_ids,
                &unknown,
                &exchange.received_at_utc,
                self.policy.require_public_at_enrichment,
            )?;
            for (index, (repository, result)) in unknown.iter().zip(observations).enumerate() {
                if let GraphqlNodeObservation::Repository(value) = &result {
                    if self
                        .resolved_times
                        .range(..repository.id)
                        .next_back()
                        .is_some_and(|(_, previous)| previous > &value.created_at)
                        || self
                            .resolved_times
                            .range((Excluded(repository.id), Unbounded))
                            .next()
                            .is_some_and(|(_, next)| next < &value.created_at)
                    {
                        return Err("public-ID census v2 creation order inverted".to_string());
                    }
                    self.resolved_times
                        .insert(repository.id, value.created_at.clone());
                } else {
                    let message = format!(
                        "Could not resolve to a node with the global id of '{}'.",
                        repository.node_id
                    );
                    self.null_ledger.insert(
                        repository.id,
                        PublicIdCensusV2NullRecord {
                            repository_id: repository.id,
                            node_id: repository.node_id.clone(),
                            graphql_exchange_sequence: sequence,
                            batch_index: index,
                            error_path: ("nodes".to_string(), index),
                            error_message: message,
                            crawled: false,
                        },
                    );
                }
                self.cache.insert(
                    repository.id,
                    CachedObservation {
                        node_id: repository.node_id.clone(),
                        result,
                    },
                );
            }
        }
        listed
            .iter()
            .map(|repository| {
                let cached = self
                    .cache
                    .get(&repository.id)
                    .ok_or("public-ID census v2 omitted metadata")?;
                if cached.node_id != repository.node_id {
                    return Err("public-ID census v2 REST node identity changed".to_string());
                }
                if let GraphqlNodeObservation::Repository(value) = &cached.result
                    && value.created_at.as_str() > rest_received_at
                {
                    return Err("public-ID census v2 REST page predates a repository".to_string());
                }
                Ok((repository.clone(), cached.result.clone()))
            })
            .collect()
    }

    fn rest(&mut self, since: u64) -> Result<RestPage, String> {
        let request = PublicIdCensusRequest::Rest { since };
        let url = format!(
            "{}?per_page={}&since={since}",
            self.policy.source, self.policy.rest_page_size
        );
        let (_, exchange) = self.next(request.clone(), url.clone(), None)?;
        if exchange.request != request
            || exchange.request_url != url
            || exchange.request_body.is_some()
        {
            return Err("public-ID census v2 REST request changed".to_string());
        }
        let repositories: Vec<RestRepository> = serde_json::from_str(&exchange.response_body)
            .map_err(|error| format!("invalid public-ID census v2 REST page: {error}"))?;
        if repositories.len() > self.policy.rest_page_size
            || repositories.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || repositories.first().is_some_and(|first| first.id <= since)
            || repositories.iter().any(|repository| {
                repository.id == 0
                    || repository.node_id.is_empty()
                    || repository.full_name.is_empty()
            })
        {
            return Err("public-ID census v2 REST page is not ordered".to_string());
        }
        let next_since = parse_next_since_for(
            exchange.response_link.as_deref(),
            &self.policy.source,
            self.policy.rest_page_size,
        )?;
        if let Some(next) = next_since
            && repositories.last().map(|repository| repository.id) != Some(next)
        {
            return Err("public-ID census v2 next cursor differs from last ID".to_string());
        }
        Ok(RestPage {
            repositories,
            next_since,
            received_at_utc: exchange.received_at_utc,
        })
    }

    fn next(
        &mut self,
        request: PublicIdCensusRequest,
        url: String,
        body: Option<String>,
    ) -> Result<(usize, PublicIdCensusExchange), String> {
        let exchange = (self.source)(request, url, body)?;
        validate_exchange_for_version(&exchange, &self.policy.api_version)?;
        if exchange.received_at_utc < self.last_received_at
            || exchange
                .failed_attempts
                .first()
                .is_some_and(|attempt| attempt.received_at_utc < self.last_received_at)
        {
            return Err("public-ID census v2 exchange receipts moved backward".to_string());
        }
        self.last_received_at = exchange.received_at_utc.clone();
        let sequence = self.sequence;
        self.sequence += 1;
        Ok((sequence, exchange))
    }
}

fn validate_preflight(
    policy: &PublicIdCensusV2Policy,
    preflight: &PublicIdCensusPreflight,
) -> Result<(), String> {
    valid_utc_timestamp(&preflight.fetched_at_utc)?;
    let expected_url = format!(
        "https://raw.githubusercontent.com/trysniff/sniff/{PUBLIC_ID_CENSUS_V2_POLICY_COMMIT_SHA}/sniffbench/historical-v3-id-census-v2/policy.json"
    );
    if preflight.public_policy_url != expected_url
        || preflight.response_status != 200
        || preflight.fetched_policy_sha256 != PUBLIC_ID_CENSUS_V2_PUBLIC_POLICY_SHA256
        || preflight.fetched_policy_sha256
            != format!("{:x}", Sha256::digest(preflight.fetched_policy.as_bytes()))
    {
        return Err("public-ID census v2 public-policy preflight changed".to_string());
    }
    let fetched: PublicIdCensusV2Policy = serde_json::from_str(&preflight.fetched_policy)
        .map_err(|error| format!("invalid public-ID census v2 preflight policy: {error}"))?;
    if &fetched != policy {
        return Err("public-ID census v2 preflight differs from the typed contract".to_string());
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_public_id_census_v2_replay_tests.rs"]
mod tests;
