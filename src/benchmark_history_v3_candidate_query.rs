use super::{HistoricalV3CandidateIdentity, HistoricalV3CandidatePageRequest, parse_utc_second};
use serde::{Deserialize, Serialize};

pub(super) const GRAPHQL_QUERY: &str = r#"query HistoricalV3MergedPullRequests($query: String!, $after: String) {
  search(query: $query, type: ISSUE, first: 100, after: $after) {
    issueCount
    pageInfo { hasNextPage endCursor }
    nodes {
      ... on PullRequest {
        number
        createdAt
        updatedAt
        closedAt
        mergedAt
        baseRefOid
        headRefOid
        mergeCommit { oid }
        repository { databaseId nameWithOwner }
      }
    }
  }
}"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParsedCandidatePage {
    pub issue_count: usize,
    pub has_next_page: bool,
    pub end_cursor: Option<String>,
    pub candidates: Vec<HistoricalV3CandidateIdentity>,
}

#[derive(Serialize)]
struct GraphqlBody<'a> {
    query: &'static str,
    variables: GraphqlVariables<'a>,
}

#[derive(Serialize)]
struct GraphqlVariables<'a> {
    query: String,
    after: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlEnvelope {
    data: Option<GraphqlData>,
    #[serde(default)]
    errors: Vec<GraphqlError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlData {
    search: GraphqlSearch,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GraphqlSearch {
    issue_count: usize,
    page_info: GraphqlPageInfo,
    nodes: Vec<GraphqlPullRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GraphqlPageInfo {
    has_next_page: bool,
    end_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GraphqlPullRequest {
    number: u64,
    created_at: String,
    updated_at: String,
    closed_at: Option<String>,
    merged_at: Option<String>,
    base_ref_oid: String,
    head_ref_oid: String,
    merge_commit: Option<GraphqlCommit>,
    repository: GraphqlRepository,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlCommit {
    oid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GraphqlRepository {
    database_id: Option<u64>,
    name_with_owner: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlError {
    message: String,
}

pub(super) fn request_body(request: &HistoricalV3CandidatePageRequest) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&GraphqlBody {
        query: GRAPHQL_QUERY,
        variables: GraphqlVariables {
            query: search_query(request),
            after: request.after_cursor.as_deref(),
        },
    })
    .map_err(|error| format!("failed to encode historical-v3 GraphQL request: {error}"))
}

pub(super) fn parse_candidate_page(
    request: &HistoricalV3CandidatePageRequest,
    response: &[u8],
) -> Result<ParsedCandidatePage, String> {
    let envelope: GraphqlEnvelope = serde_json::from_slice(response)
        .map_err(|error| format!("invalid historical-v3 GraphQL response: {error}"))?;
    if !envelope.errors.is_empty() {
        let messages = envelope
            .errors
            .into_iter()
            .map(|error| error.message)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "historical-v3 GraphQL response contains errors: {messages}"
        ));
    }
    let search = envelope
        .data
        .ok_or_else(|| "historical-v3 GraphQL response has no data".to_string())?
        .search;
    if search.page_info.has_next_page
        && search
            .page_info
            .end_cursor
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err("historical-v3 GraphQL page has no continuation cursor".to_string());
    }
    if !search.page_info.has_next_page && search.page_info.end_cursor.as_deref() == Some("") {
        return Err("historical-v3 GraphQL page has an empty cursor".to_string());
    }

    let range_start = parse_utc_second(&request.partition.merged_at_or_after_utc)?;
    let range_end = parse_utc_second(&request.partition.merged_at_or_before_utc)?;
    let mut candidates = Vec::with_capacity(search.nodes.len());
    for node in search.nodes {
        for timestamp in [&node.created_at, &node.updated_at] {
            parse_utc_second(timestamp)?;
        }
        let closed_at = node
            .closed_at
            .as_deref()
            .ok_or_else(|| "historical-v3 merged PR has no closed timestamp".to_string())?;
        parse_utc_second(closed_at)?;
        let merged_at = node
            .merged_at
            .as_deref()
            .ok_or_else(|| "historical-v3 merged PR has no merge timestamp".to_string())?;
        let merged_second = parse_utc_second(merged_at)?;
        if !(range_start..=range_end).contains(&merged_second) {
            return Err("historical-v3 GraphQL result escaped its UTC partition".to_string());
        }
        if node.repository.database_id != Some(request.partition.repository_id)
            || !node
                .repository
                .name_with_owner
                .eq_ignore_ascii_case(&request.partition.name_with_owner)
        {
            return Err(
                "historical-v3 GraphQL result escaped its repository partition".to_string(),
            );
        }
        let merge_commit = node
            .merge_commit
            .ok_or_else(|| "historical-v3 merged PR has no merge commit".to_string())?;
        candidates.push(HistoricalV3CandidateIdentity {
            language: request.partition.language,
            repository_id: request.partition.repository_id,
            pull_request_number: node.number,
            base_commit: node.base_ref_oid,
            head_commit: node.head_ref_oid,
            merge_commit: merge_commit.oid,
        });
    }
    Ok(ParsedCandidatePage {
        issue_count: search.issue_count,
        has_next_page: search.page_info.has_next_page,
        end_cursor: search.page_info.end_cursor,
        candidates,
    })
}

fn search_query(request: &HistoricalV3CandidatePageRequest) -> String {
    format!(
        "repo:{} is:pr is:merged merged:{}..{} sort:created-asc",
        request.partition.name_with_owner,
        request.partition.merged_at_or_after_utc,
        request.partition.merged_at_or_before_utc,
    )
}
