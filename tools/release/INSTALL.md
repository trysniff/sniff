# Sniff Development Candidate

This archive contains a development build of Sniff. Read `manifest.json` for
its source commit, version, target, compiler, and file hashes. The version
alone does not identify the candidate; released versions are tagged separately.

Extract the archive and run `bin/sniff --help` (`bin/sniff.exe --help` on
Windows). Put the executable in a directory on your PATH to use `sniff`.

Normal scans require the compiler semantic indexers for the repository's
languages. Run `sniff doctor PATH` to inspect the requirements, then
`sniff indexers install PATH` to install the pinned providers. Host
toolchains and sandbox requirements still apply. Read the README at the
source commit listed in the manifest for configuration and supported targets.

A normal scan sends source code to the configured model provider. Offline
commands such as `sniff --estimate PATH`, `sniff status PATH`, and
`sniff doctor PATH` do not review code with a model. `doctor --probe` does.

`sbom.spdx.json` inventories the resolved Cargo source dependencies, including
build and development dependencies. It does not claim that each listed
dependency is linked into the executable. License notices are included.

Check SHA256SUMS and verify the archive's GitHub attestation before installing:

```console
gh attestation verify ARCHIVE.zip --repo trysniff/sniff \
  --signer-workflow trysniff/sniff/.github/workflows/release-candidates.yml \
  --source-ref refs/heads/main --source-digest SOURCE_COMMIT \
  --deny-self-hosted-runners
```

Candidate artifacts are available from the workflow run that built them.
Build provenance is issued for trusted manual runs on `main`; pull request
artifacts are unsigned previews.

Use the full source commit from the trusted workflow run for `SOURCE_COMMIT`.
