# Historical v3 public-ID census

This is a separately versioned source method for the unchanged August 8-14,
2026 UTC repository-creation window, strictly after the August 7 cutoff. It
replaces the failed GitHub Search source method for **all six languages**; it
does not repair, reinterpret, or resume any Search checkpoint.

The population is repositories observed in GitHub's public ID-ordered list and
still public when GraphQL metadata is resolved. It is **not** an atomic snapshot
of every repository that was public during the historical week. Repositories
deleted, privatized, or made public after their ID cursor passes cannot be
reconstructed by this API. `primaryLanguage` and eligibility flags are taken
at the committed GraphQL observation, not inferred at creation time.

Collection must retain and replay the exact REST cursor chain, boundary probes,
GraphQL batches, response bytes and receipt times. Missing metadata, changed
identity or visibility, malformed pagination, or an unproved time boundary
prevents frame sealing. A new historical-v3 protocol version must bind this
source type explicitly before candidate collection. Search frames and ID-census
frames must not be mixed under the same cohort claim.

## Traversal contract

All probes and crawl pages use `GET /repositories?per_page=100&since=<id>` at
the pinned API version. A probe resolves the first listed repository's
`createdAt` through GraphQL. Probe `since=0` first and require its first
repository to predate the window. Then probe `since=2^k` for increasing
nonnegative integers `k` until the first repository is in or after the window
(an empty result is an upper bound). Binary-search integer `since` values
between the last before-window lower bound and the first upper bound, with
`mid=floor((lower+upper)/2)`, until `upper=lower+1`. The final lower probe must
still have a before-window first repository; the upper probe must have a
nonempty first repository at or after the start and before the window end.
The first crawl page uses `since=lower`, so its first repository is the
retained lower-boundary witness.

Follow the verified `rel="next"` `since` cursor for each page. Every listed ID
must be unique, strictly increasing, and greater than its request cursor;
every next cursor must equal the last listed ID. A previously committed
boundary-probe GraphQL observation is reused when its ID occurs in the crawl;
the other IDs on the page are enriched in their original order. This is one
metadata observation per ID, not a fresh observation of every crawled page.
Require one non-null public `Repository` per requested node, positional node-ID
and numeric ID matches, no GraphQL errors, and nondecreasing UTC `createdAt` across the
whole crawl. A null `primaryLanguage` or a language outside the six named
languages is counted as an ineligible repository, never silently assigned.
The same applies to forks, archived repositories, mirrors, and templates.
The first page containing a repository at or after August 15 is retained and
enriched as the upper-boundary witness; traversal stops only after that page.

Raw REST and GraphQL request identities, response bytes, status, `Link` header,
receipt time, and retries are committed before frames are emitted. Transport
timeouts, 429s, and 5xx responses may retry the **same** request at most 12
times; a semantic error (including missing or mismatched metadata) ends the
census without a frame. Offline replay must reproduce all six ID-ordered CSV
frames and exclusion counts byte for byte. Prior-cohort disjointness is a
separate, unfinished proof gate: the current prior-identity seal records names,
not immutable repository IDs or checked creation-time bounds for every prior
partition. The strict creation-time cutoff is sufficient only after those
prior bounds are verified from pinned evidence. A canonical-name filter is
conservative but cannot prove disjointness when repositories are renamed or
names are reused. Do not score real v3 candidate reviews until this gate is
closed. Before the first REST probe, the collector must fetch this policy
from an immutable public Git commit, verify its exact bytes and SHA-256 against
the pinned public hash and typed contract, and retain that
preflight receipt. GitHub's documented creation ordering is an assumption of
the boundary proof; an observed inversion fails closed, while live visibility
changes remain an explicitly disclosed limitation.
