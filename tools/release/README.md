# Development Candidate Bundles

The `Release candidates` workflow builds native `sniff` executables for
Linux, macOS, and Windows on x64 and ARM64. Each artifact contains one ZIP,
`SHA256SUMS`, an identical manifest sidecar, and an identical SPDX sidecar.
The archive contains the executable, manifest, dependency inventory, install
instructions, and license notices. Candidate names contain the source commit
so an unreleased build cannot be confused with the published crate version.

Pull requests that change the workflow or packaging tools build unsigned
previews. A manual run on `main` additionally creates GitHub attestations for
the six archives and manifest sidecars after every native build and extracted
binary smoke test succeeds. The workflow does not create a release or publish
a crate. Final release qualification is a separate step.

Download the artifact for your architecture from its Actions run. Verify its
GitHub attestation, then verify and extract it using the source commit's tool:

```console
gh attestation verify ARCHIVE.zip --repo trysniff/sniff \
  --signer-workflow trysniff/sniff/.github/workflows/release-candidates.yml \
  --source-ref refs/heads/main --source-digest SOURCE_COMMIT \
  --deny-self-hosted-runners
python tools/release/bundle.py verify --archive ARCHIVE.zip \
  --target TARGET --commit SOURCE_COMMIT --extract NEW_DIRECTORY
```

Choose the expected full source commit from the trusted workflow run, not an
unverified manifest. The checksum file checks transport integrity; the GitHub attestation
establishes which workflow and source produced the archive. Verification
rejects changed files, mismatched sidecars, unexpected files, traversal paths,
duplicate entries, unsafe permissions, oversized archives, and an existing
extraction directory. Python 3.11 or newer is required for the verifier.

The SPDX document describes the Cargo dependency graph filtered for the
target, with normal, build, and development relationships and registry archive
checksums from `Cargo.lock`. It includes an executable file checksum. It is a
source dependency inventory, not a complete inventory of libraries linked into
the binary. `manifest.json` also records the lockfile hash and `rustc -vV`.

Offline smoke checks execute `--version`, `--help`, `--estimate`, and `status`
from the extracted archive in a temporary fixture outside the source checkout.
They remove Sniff/provider environment configuration and disable dotenv loading
for the estimate. They do not contact a model or run a review.
