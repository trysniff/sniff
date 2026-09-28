# Historical v3 public-ID census v2

This is a new, narrower source population for the August 8-14, 2026 UTC
repository-creation window. The v1 public-ID crawl failed on a REST-listed
repository whose GraphQL node was null. Its raw evidence and failure remain
unchanged; no v1 checkpoint may be imported into a v2 root.

The v2 population contains only IDs on the retained, verified crawl pages
that resolve once to a matching, public, non-null GraphQL `Repository`.
An exactly attributable `NOT_FOUND` null on a crawl page is an audited
population exclusion with **unknown creation time**. A null observed only
during boundary discovery is audited as probe evidence, not a cohort
exclusion. Neither is counted as old, outside the week, or a clean negative.
This selection can bias the benchmark; the source cannot prove coverage of
every REST-listed public repository or a historical snapshot. Metadata and
visibility reflect their recorded live observations, not state at creation.

## Traversal and audit

The collector fetches this policy by immutable Git commit and verifies its
exact bytes before the first REST probe. A separate typed v2 artifact contract
must also be publicly SHA-pinned before any live v2 request. Both fetches
must have separate hash-bound receipts; a completed v2 manifest includes
them, sequential raw exchanges, the null ledger, and six replayed frames.
The collector must enforce both preflights **before sending** its first source
request, because response timestamps alone cannot prove request-send order.
The policy and offline artifact contract alone are not a working collector.
The collector writes into a fresh v2 root and commits each REST or GraphQL
request and response before deriving frames.
Every unique REST ID receives at most one GraphQL observation, even when a
probe overlaps a later crawl page. Both resolved and null outcomes are cached
by numeric ID and node ID. An identity mismatch or an ambiguous GraphQL error
fails the entire six-language census.

Starting at `since=0`, enrich each entire returned, verified REST page, following
its next cursor until the first resolved repository is found. It must predate
the window; otherwise the census fails. The cursor of that witness's page is
the initial lower cursor. Earlier all-null pages are probe-only evidence.
For `k=0..63`, exponential search probes `since=2^k`, skipping cursors not
above the current lower cursor. It enriches the first listed ID only. A
resolved repository before the window moves the lower cursor to that probe;
the first resolved repository at or after the window establishes the upper
cursor. A null moves neither bound, and an empty probe fails closed. If no
upper witness is found, the census fails. Binary search probes
`mid=floor(lower+(upper-lower)/2)` while the gap exceeds one. A resolved
first ID moves the appropriate bound. At the first null midpoint, it stops
narrowing and crawls from the last resolved pre-window lower cursor,
retaining a wider range rather than guessing the null's date. An empty
midpoint fails closed.
The crawl follows every verified next cursor and enriches every listed ID
until a retained page contains a **resolved** repository created at or after
August 15. A page of only nulls never establishes an upper boundary. Full
and short nonempty pages may have a next cursor only if it equals the last
listed ID. Every page contains at most 100 IDs; each must be unique, strictly
increasing, and greater than its request cursor. The collector must reject,
not sort or deduplicate, a malformed page. Missing pagination before the
upper witness fails closed.

The only permitted null has exactly one GraphQL error with `type: NOT_FOUND`,
`path: ["nodes", <zero-based batch index>]`, and the exact message
`Could not resolve to a node with the global id of '<requested node ID>'.`.
An error on a non-null node, a missing or duplicate error, or any unrelated
error fails closed. The replay-derived null ledger records each observed null's REST ID, node ID,
GraphQL exchange sequence and batch index, exact `NOT_FOUND` error path and
message, and whether it appeared in the crawl or only a probe. It is
hash-bound to the manifest along with all six frames and separate probe-only
and crawled-null counts. The typed ledger/manifest schemas, exact byte
serialization, and count reconciliation are a required public code gate
before collection, not an implicit choice left to a live run.
Resolved `createdAt` values must be nondecreasing by REST ID. Completeness
within the **resolvable subset** still depends on GitHub's documented
creation ordering for the REST list, including IDs whose metadata is null.
The list is not an atomic snapshot. A distinct downstream protocol must bind
v2's policy hash, manifest, and frame IDs before candidate collection.

Prior-cohort identity and pre-cutoff evidence are a separate scoring gate.
This source policy alone cannot make any agent judgment a human gold label or
authorize an official benchmark score.
