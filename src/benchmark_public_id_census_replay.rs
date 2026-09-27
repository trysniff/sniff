use super::{
    PUBLIC_ID_CENSUS_PUBLIC_POLICY_SHA256, PublicIdCensusPolicy, validate_public_id_census_policy,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const PUBLIC_ID_CENSUS_GRAPHQL_QUERY: &str = "query PublicIdCensusNodes($ids:[ID!]!){nodes(ids:$ids){__typename ... on Repository{id databaseId nameWithOwner createdAt primaryLanguage{name} isArchived isFork isTemplate mirrorUrl isPrivate}}}";
pub const PUBLIC_ID_CENSUS_POLICY_COMMIT_SHA: &str = "50c38d47e2d73db748b1a11f1b063b48ca4c5041";
pub const PUBLIC_ID_CENSUS_MAX_FRAME_BYTES: usize = 512 * 1024 * 1024;
const MAX_TOTAL_FRAME_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicIdCensusRequest {
    Rest { since: u64 },
    Graphql { node_ids: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusPreflight {
    pub public_policy_url: String,
    pub fetched_policy: String,
    pub fetched_policy_sha256: String,
    pub fetched_at_utc: String,
    pub response_status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusFailedAttempt {
    pub request: PublicIdCensusRequest,
    pub request_url: String,
    pub request_body: Option<String>,
    pub request_api_version: String,
    pub received_at_utc: String,
    pub response_status: Option<u16>,
    pub response_body: Option<String>,
    pub response_sha256: Option<String>,
    pub transport_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusExchange {
    pub request: PublicIdCensusRequest,
    pub request_url: String,
    pub request_body: Option<String>,
    pub request_api_version: String,
    pub response_status: u16,
    pub response_link: Option<String>,
    pub response_date: Option<String>,
    pub received_at_utc: String,
    pub response_body: String,
    pub response_sha256: String,
    pub failed_attempts: Vec<PublicIdCensusFailedAttempt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdCensusReplay {
    pub frames: BTreeMap<String, Vec<u8>>,
    pub listed_repository_count: usize,
    pub in_window_repository_count: usize,
    pub excluded_repository_count: usize,
    pub name_disagreement_count: usize,
    pub lower_boundary_repository_id: u64,
    pub upper_boundary_repository_id: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct RestRepository {
    id: u64,
    node_id: String,
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct GraphqlResponse {
    data: Option<GraphqlData>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GraphqlData {
    nodes: Vec<Option<GraphqlRepository>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphqlRepository {
    #[serde(rename = "__typename")]
    typename: String,
    id: String,
    database_id: Option<u64>,
    name_with_owner: String,
    created_at: String,
    primary_language: Option<GraphqlLanguage>,
    is_archived: bool,
    is_fork: bool,
    is_template: bool,
    mirror_url: Option<String>,
    is_private: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct GraphqlLanguage {
    name: String,
}

struct RestPage {
    repositories: Vec<RestRepository>,
    next_since: Option<u64>,
    received_at_utc: String,
}

pub fn public_id_census_graphql_body(node_ids: &[String]) -> Result<String, String> {
    if node_ids.is_empty() || node_ids.len() > 100 || node_ids.iter().any(String::is_empty) {
        return Err("public-ID census GraphQL node batch is invalid".to_string());
    }
    serde_json::to_string(&serde_json::json!({
        "query": PUBLIC_ID_CENSUS_GRAPHQL_QUERY,
        "variables": {"ids": node_ids},
    }))
    .map_err(|error| format!("failed to encode public-ID census GraphQL request: {error}"))
}

pub fn replay_public_id_census(
    policy: &PublicIdCensusPolicy,
    preflight: &PublicIdCensusPreflight,
    exchanges: &[PublicIdCensusExchange],
) -> Result<PublicIdCensusReplay, String> {
    replay_public_id_census_stream(policy, preflight, exchanges.iter().cloned().map(Ok))
}

pub fn replay_public_id_census_stream<I>(
    policy: &PublicIdCensusPolicy,
    preflight: &PublicIdCensusPreflight,
    exchanges: I,
) -> Result<PublicIdCensusReplay, String>
where
    I: IntoIterator<Item = Result<PublicIdCensusExchange, String>>,
{
    let mut exchanges = exchanges.into_iter();
    let result = replay_public_id_census_with_source(policy, preflight, |_, _, _| {
        exchanges
            .next()
            .ok_or("public-ID census exchange transcript ended early".to_string())?
    })?;
    if exchanges.next().transpose()?.is_some() {
        return Err("public-ID census has exchanges after the upper time boundary".to_string());
    }
    Ok(result)
}

pub(super) fn replay_public_id_census_with_source<F>(
    policy: &PublicIdCensusPolicy,
    preflight: &PublicIdCensusPreflight,
    source: F,
) -> Result<PublicIdCensusReplay, String>
where
    F: FnMut(
        PublicIdCensusRequest,
        String,
        Option<String>,
    ) -> Result<PublicIdCensusExchange, String>,
{
    validate_public_id_census_policy(policy)?;
    validate_preflight(policy, preflight)?;
    let mut replay = ReplayCursor {
        policy,
        source,
        last_received_at: preflight.fetched_at_utc.clone(),
        probe_cache: HashMap::new(),
    };
    let start = policy.created_at_or_after_utc.as_str();
    let end = policy.created_before_utc.as_str();
    let first = replay
        .probe(0)?
        .ok_or("public-ID census has no initial boundary")?;
    if first.created_at.as_str() >= start {
        return Err("public-ID census initial boundary is not before the window".to_string());
    }
    let mut lower = 0_u64;
    let mut upper = None;
    for exponent in 0..64 {
        let since = 1_u64
            .checked_shl(exponent)
            .ok_or("public-ID census boundary search overflowed")?;
        match replay.probe(since)? {
            Some(repository) if repository.created_at.as_str() < start => lower = since,
            _ => {
                upper = Some(since);
                break;
            }
        }
    }
    let mut upper = upper.ok_or("public-ID census has no upper boundary probe")?;
    while upper - lower > 1 {
        let midpoint = lower + (upper - lower) / 2;
        match replay.probe(midpoint)? {
            Some(repository) if repository.created_at.as_str() < start => lower = midpoint,
            _ => upper = midpoint,
        }
    }
    let lower_witness = replay
        .probe(lower)?
        .ok_or("public-ID census lower boundary disappeared")?;
    let upper_witness = replay
        .probe(upper)?
        .ok_or("public-ID census upper boundary disappeared")?;
    if lower_witness.created_at.as_str() >= start
        || upper_witness.created_at.as_str() < start
        || upper_witness.created_at.as_str() >= end
    {
        return Err(
            "public-ID census boundary witnesses do not straddle the window start".to_string(),
        );
    }

    let mut frames = policy
        .languages
        .iter()
        .map(|language| (language.clone(), b"repo,metadata\n".to_vec()))
        .collect::<BTreeMap<_, _>>();
    let mut total_frame_bytes = frames.values().map(Vec::len).sum::<usize>();
    let mut names = HashSet::new();
    let mut since = lower;
    let mut previous_id = None;
    let mut previous_created_at: Option<String> = None;
    let mut first_crawl = true;
    let mut listed_repository_count = 0;
    let mut in_window_repository_count = 0;
    let mut excluded_repository_count = 0;
    let mut name_disagreement_count = 0;
    let mut saw_upper_witness = false;
    let upper_boundary_repository_id = loop {
        let page = replay.rest(since)?;
        if page.repositories.is_empty() {
            return Err("public-ID census crawl ended before the upper time boundary".to_string());
        }
        let metadata = replay.enrich_page(&page.repositories)?;
        let mut crossing_id = None;
        for (listed, repository) in page.repositories.iter().zip(metadata) {
            if repository.created_at > page.received_at_utc {
                return Err("public-ID census REST page predates a listed repository".to_string());
            }
            if first_crawl {
                if listed.id != lower_witness.id
                    || repository.created_at != lower_witness.created_at
                {
                    return Err("public-ID census lower boundary changed during crawl".to_string());
                }
                first_crawl = false;
            }
            if previous_id.is_some_and(|previous| listed.id <= previous)
                || previous_created_at
                    .as_deref()
                    .is_some_and(|previous| repository.created_at.as_str() < previous)
            {
                return Err("public-ID census creation order changed".to_string());
            }
            previous_id = Some(listed.id);
            previous_created_at = Some(repository.created_at.clone());
            if listed.id == upper_witness.id {
                if repository.created_at != upper_witness.created_at {
                    return Err("public-ID census upper boundary changed during crawl".to_string());
                }
                saw_upper_witness = true;
            }
            listed_repository_count += 1;
            let name = canonical_name(&repository.name_with_owner)?;
            if canonical_name(&listed.full_name)? != name {
                name_disagreement_count += 1;
            }
            if repository.created_at.as_str() >= end && crossing_id.is_none() {
                crossing_id = Some(listed.id);
            }
            if repository.created_at.as_str() < start || repository.created_at.as_str() >= end {
                continue;
            }
            in_window_repository_count += 1;
            if repository.created_at.as_str() <= policy.repository_created_after_utc.as_str()
                || (!policy.include_forks && repository.is_fork)
                || (!policy.include_archived && repository.is_archived)
                || (!policy.include_templates && repository.is_template)
                || (!policy.include_mirrors && repository.mirror_url.is_some())
            {
                excluded_repository_count += 1;
                continue;
            }
            let Some(language) = repository.primary_language.as_ref() else {
                excluded_repository_count += 1;
                continue;
            };
            let Some(frame) = frames.get_mut(&language.name) else {
                excluded_repository_count += 1;
                continue;
            };
            if !names.insert(name.clone()) {
                return Err("public-ID census repeats a canonical repository name".to_string());
            }
            let row = format!(
                "github.com/{name},github_repository_id={};created_at={}\n",
                listed.id, repository.created_at
            );
            total_frame_bytes = total_frame_bytes
                .checked_add(row.len())
                .ok_or("public-ID census frame size overflowed")?;
            if total_frame_bytes > MAX_TOTAL_FRAME_BYTES
                || frame.len() + row.len() > PUBLIC_ID_CENSUS_MAX_FRAME_BYTES
            {
                return Err("public-ID census derived frames exceed the memory bound".to_string());
            }
            frame.extend_from_slice(row.as_bytes());
        }
        if let Some(id) = crossing_id {
            break id;
        }
        since = page
            .next_since
            .ok_or("public-ID census page has no advancing next cursor")?;
    };
    if !saw_upper_witness {
        return Err("public-ID census crawl omitted its probed upper witness".to_string());
    }
    Ok(PublicIdCensusReplay {
        frames,
        listed_repository_count,
        in_window_repository_count,
        excluded_repository_count,
        name_disagreement_count,
        lower_boundary_repository_id: lower_witness.id,
        upper_boundary_repository_id,
    })
}

struct ReplayCursor<'a, F> {
    policy: &'a PublicIdCensusPolicy,
    source: F,
    last_received_at: String,
    probe_cache: HashMap<u64, GraphqlRepository>,
}

impl<F> ReplayCursor<'_, F>
where
    F: FnMut(
        PublicIdCensusRequest,
        String,
        Option<String>,
    ) -> Result<PublicIdCensusExchange, String>,
{
    fn probe(&mut self, since: u64) -> Result<Option<ProbeRepository>, String> {
        let page = self.rest(since)?;
        let Some(first) = page.repositories.first() else {
            return Ok(None);
        };
        let repository = if let Some(cached) = self.probe_cache.get(&first.id) {
            if cached.id != first.node_id {
                return Err("public-ID census probe node identity changed".to_string());
            }
            cached.clone()
        } else {
            let repository = self
                .graphql(
                    std::slice::from_ref(&first.node_id),
                    std::slice::from_ref(first),
                )?
                .into_iter()
                .next()
                .ok_or("public-ID census probe has no GraphQL repository")?;
            self.probe_cache.insert(first.id, repository.clone());
            repository
        };
        if repository.created_at > page.received_at_utc {
            return Err("public-ID census REST probe predates its first repository".to_string());
        }
        Ok(Some(ProbeRepository {
            id: first.id,
            created_at: repository.created_at,
        }))
    }

    fn enrich_page(&mut self, listed: &[RestRepository]) -> Result<Vec<GraphqlRepository>, String> {
        let unknown = listed
            .iter()
            .filter(|repository| !self.probe_cache.contains_key(&repository.id))
            .cloned()
            .collect::<Vec<_>>();
        let fetched = if unknown.is_empty() {
            Vec::new()
        } else {
            let node_ids = unknown
                .iter()
                .map(|repository| repository.node_id.clone())
                .collect::<Vec<_>>();
            self.graphql(&node_ids, &unknown)?
        };
        let mut fetched = fetched.into_iter();
        listed
            .iter()
            .map(|repository| {
                if let Some(cached) = self.probe_cache.get(&repository.id) {
                    if cached.id != repository.node_id {
                        return Err("public-ID census crawl node identity changed".to_string());
                    }
                    Ok(cached.clone())
                } else {
                    fetched
                        .next()
                        .ok_or("public-ID census GraphQL page has missing metadata".to_string())
                }
            })
            .collect()
    }

    fn rest(&mut self, since: u64) -> Result<RestPage, String> {
        let request = PublicIdCensusRequest::Rest { since };
        let url = format!(
            "{}?per_page={}&since={since}",
            self.policy.source, self.policy.rest_page_size
        );
        let exchange = self.next(request.clone(), url.clone(), None)?;
        if exchange.request != request
            || exchange.request_url != url
            || exchange.request_body.is_some()
        {
            return Err("public-ID census REST request changed".to_string());
        }
        validate_exchange(&exchange, self.policy)?;
        let repositories: Vec<RestRepository> = serde_json::from_str(&exchange.response_body)
            .map_err(|error| format!("invalid public-ID census REST page: {error}"))?;
        if repositories.len() > self.policy.rest_page_size
            || repositories.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || repositories
                .first()
                .is_some_and(|repository| repository.id <= since)
            || repositories.iter().any(|repository| {
                repository.id == 0
                    || repository.node_id.is_empty()
                    || repository.full_name.is_empty()
            })
        {
            return Err("public-ID census REST page is not an ordered public-ID page".to_string());
        }
        let next_since = parse_next_since(exchange.response_link.as_deref(), self.policy)?;
        if let Some(next) = next_since {
            if repositories.len() != self.policy.rest_page_size {
                return Err("public-ID census short REST page has a next cursor".to_string());
            }
            if repositories.last().map(|repository| repository.id) != Some(next) {
                return Err("public-ID census next cursor does not match the last ID".to_string());
            }
        }
        Ok(RestPage {
            repositories,
            next_since,
            received_at_utc: exchange.received_at_utc,
        })
    }

    fn graphql(
        &mut self,
        node_ids: &[String],
        listed: &[RestRepository],
    ) -> Result<Vec<GraphqlRepository>, String> {
        let request = PublicIdCensusRequest::Graphql {
            node_ids: node_ids.to_vec(),
        };
        let body = public_id_census_graphql_body(node_ids)?;
        let url = self.policy.metadata_source.clone();
        let exchange = self.next(request.clone(), url.clone(), Some(body.clone()))?;
        if exchange.request != request
            || exchange.request_url != self.policy.metadata_source
            || exchange.request_body.as_deref() != Some(body.as_str())
            || exchange.response_link.is_some()
        {
            return Err("public-ID census GraphQL request changed".to_string());
        }
        validate_exchange(&exchange, self.policy)?;
        let raw: serde_json::Value = serde_json::from_str(&exchange.response_body)
            .map_err(|error| format!("invalid public-ID census GraphQL response: {error}"))?;
        let raw_nodes = raw
            .pointer("/data/nodes")
            .and_then(serde_json::Value::as_array)
            .ok_or("public-ID census GraphQL omitted node array")?;
        for node in raw_nodes {
            let fields = node
                .as_object()
                .ok_or("public-ID census GraphQL node is null or malformed")?;
            if !fields.contains_key("primaryLanguage") || !fields.contains_key("mirrorUrl") {
                return Err("public-ID census GraphQL omitted nullable metadata".to_string());
            }
        }
        let parsed: GraphqlResponse = serde_json::from_value(raw)
            .map_err(|error| format!("invalid public-ID census GraphQL node: {error}"))?;
        if !parsed.errors.is_empty() {
            return Err("public-ID census GraphQL returned partial or failed data".to_string());
        }
        let nodes = parsed
            .data
            .ok_or("public-ID census GraphQL omitted data")?
            .nodes;
        if nodes.len() != node_ids.len() || listed.len() != node_ids.len() {
            return Err("public-ID census GraphQL node count changed".to_string());
        }
        nodes
            .into_iter()
            .zip(node_ids.iter().zip(listed))
            .map(|(node, (node_id, listed))| {
                let repository = node.ok_or("public-ID census GraphQL node is null")?;
                if repository.typename != "Repository"
                    || repository.id != *node_id
                    || repository.database_id != Some(listed.id)
                    || (self.policy.require_public_at_enrichment && repository.is_private)
                {
                    return Err(
                        "public-ID census GraphQL identity or visibility changed".to_string()
                    );
                }
                valid_utc_timestamp(&repository.created_at)?;
                if repository.created_at > exchange.received_at_utc {
                    return Err(
                        "public-ID census repository was created after its GraphQL receipt"
                            .to_string(),
                    );
                }
                canonical_name(&repository.name_with_owner)?;
                Ok(repository)
            })
            .collect()
    }

    fn next(
        &mut self,
        request: PublicIdCensusRequest,
        url: String,
        body: Option<String>,
    ) -> Result<PublicIdCensusExchange, String> {
        let exchange = (self.source)(request, url, body)?;
        if exchange.received_at_utc < self.last_received_at
            || exchange
                .failed_attempts
                .first()
                .is_some_and(|attempt| attempt.received_at_utc < self.last_received_at)
        {
            return Err("public-ID census exchange receipt times moved backward".to_string());
        }
        self.last_received_at = exchange.received_at_utc.clone();
        Ok(exchange)
    }
}

struct ProbeRepository {
    id: u64,
    created_at: String,
}

pub(super) fn validate_exchange(
    exchange: &PublicIdCensusExchange,
    policy: &PublicIdCensusPolicy,
) -> Result<(), String> {
    if exchange.request_api_version != policy.api_version
        || exchange.response_status != 200
        || exchange.response_sha256
            != format!("{:x}", Sha256::digest(exchange.response_body.as_bytes()))
        || exchange.received_at_utc.is_empty()
    {
        return Err(
            "public-ID census exchange metadata or response commitment changed".to_string(),
        );
    }
    valid_utc_timestamp(&exchange.received_at_utc)?;
    if exchange.failed_attempts.len() >= 12 {
        return Err("public-ID census exceeded its committed retry limit".to_string());
    }
    let mut previous_at = None;
    for attempt in &exchange.failed_attempts {
        valid_utc_timestamp(&attempt.received_at_utc)?;
        if attempt.request != exchange.request
            || attempt.request_url != exchange.request_url
            || attempt.request_body != exchange.request_body
            || attempt.request_api_version != exchange.request_api_version
            || previous_at.is_some_and(|previous| previous > attempt.received_at_utc.as_str())
            || attempt.received_at_utc > exchange.received_at_utc
        {
            return Err("public-ID census retry changed request or receipt order".to_string());
        }
        match (
            attempt.response_status,
            attempt.response_body.as_deref(),
            attempt.response_sha256.as_deref(),
            attempt.transport_error.as_deref(),
        ) {
            (None, None, None, Some("timeout")) => {}
            (Some(429 | 500..=599), Some(body), Some(digest), None)
                if digest == format!("{:x}", Sha256::digest(body.as_bytes())) => {}
            _ => {
                return Err(
                    "public-ID census retry is not a committed retryable failure".to_string(),
                );
            }
        }
        previous_at = Some(attempt.received_at_utc.as_str());
    }
    Ok(())
}

pub(super) fn validate_preflight(
    policy: &PublicIdCensusPolicy,
    preflight: &PublicIdCensusPreflight,
) -> Result<(), String> {
    valid_utc_timestamp(&preflight.fetched_at_utc)?;
    let expected_url = format!(
        "https://raw.githubusercontent.com/trysniff/sniff/{PUBLIC_ID_CENSUS_POLICY_COMMIT_SHA}/sniffbench/historical-v3-id-census/policy.json"
    );
    if preflight.public_policy_url != expected_url
        || preflight.response_status != 200
        || preflight.fetched_policy_sha256 != PUBLIC_ID_CENSUS_PUBLIC_POLICY_SHA256
        || preflight.fetched_policy_sha256
            != format!("{:x}", Sha256::digest(preflight.fetched_policy.as_bytes()))
    {
        return Err("public-ID census public-policy preflight changed".to_string());
    }
    let fetched: PublicIdCensusPolicy = serde_json::from_str(&preflight.fetched_policy)
        .map_err(|error| format!("invalid public-ID census preflight policy: {error}"))?;
    if &fetched != policy {
        return Err(
            "public-ID census preflight policy differs from the typed contract".to_string(),
        );
    }
    Ok(())
}

fn valid_utc_timestamp(value: &str) -> Result<(), String> {
    if value.len() != 20
        || !value.ends_with('Z')
        || value.bytes().enumerate().any(|(index, byte)| match index {
            4 | 7 => byte != b'-',
            10 => byte != b'T',
            13 | 16 => byte != b':',
            19 => byte != b'Z',
            _ => !byte.is_ascii_digit(),
        })
    {
        return Err("public-ID census timestamp is not canonical UTC".to_string());
    }
    let number = |start: usize, end: usize| -> Result<u32, String> {
        value[start..end]
            .parse::<u32>()
            .map_err(|_| "public-ID census timestamp has an invalid number".to_string())
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err("public-ID census timestamp is not a real UTC instant".to_string());
    }
    Ok(())
}

fn parse_next_since(
    link: Option<&str>,
    policy: &PublicIdCensusPolicy,
) -> Result<Option<u64>, String> {
    let Some(link) = link else {
        return Ok(None);
    };
    let mut next = None;
    if link.is_empty() {
        return Err("public-ID census Link header is empty".to_string());
    }
    for part in link.split(',') {
        let part = part.trim();
        let (raw_url, rel) = part
            .strip_prefix('<')
            .and_then(|value| value.split_once('>'))
            .ok_or("public-ID census Link header is malformed")?;
        let rel = rel
            .trim()
            .strip_prefix(';')
            .map(str::trim)
            .ok_or("public-ID census Link relation is malformed")?;
        if !matches!(
            rel,
            "rel=\"next\"" | "rel=\"prev\"" | "rel=\"first\"" | "rel=\"last\""
        ) {
            return Err("public-ID census Link relation is unsupported".to_string());
        }
        let url = Url::parse(raw_url)
            .map_err(|error| format!("invalid public-ID census next URL: {error}"))?;
        let expected = Url::parse(&policy.source).map_err(|error| error.to_string())?;
        if url.scheme() != expected.scheme()
            || url.host_str() != expected.host_str()
            || url.path() != expected.path()
            || url.port_or_known_default() != expected.port_or_known_default()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err("public-ID census next URL changes endpoint".to_string());
        }
        if rel != "rel=\"next\"" {
            continue;
        }
        let parameters = url.query_pairs().collect::<Vec<_>>();
        if parameters
            .iter()
            .any(|(key, _)| key != "since" && key != "per_page")
            || parameters.iter().filter(|(key, _)| key == "since").count() != 1
            || parameters
                .iter()
                .filter(|(key, _)| key == "per_page")
                .count()
                > 1
            || parameters
                .iter()
                .find(|(key, _)| key == "per_page")
                .is_some_and(|(_, value)| {
                    value.parse::<usize>().ok() != Some(policy.rest_page_size)
                })
        {
            return Err("public-ID census next URL has unexpected parameters".to_string());
        }
        let cursor = parameters
            .iter()
            .find(|(key, _)| key == "since")
            .and_then(|(_, value)| value.parse::<u64>().ok())
            .ok_or("public-ID census next cursor is invalid")?;
        if next.replace(cursor).is_some() {
            return Err("public-ID census Link header repeats next cursor".to_string());
        }
    }
    Ok(next)
}

fn canonical_name(value: &str) -> Result<String, String> {
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err("public-ID census repository name is not canonicalizable".to_string());
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
#[path = "benchmark_public_id_census_replay_tests.rs"]
pub(crate) mod tests;
