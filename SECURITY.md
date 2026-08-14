# Security Policy

## Reporting a vulnerability

Please do not disclose security vulnerabilities in a public issue.

Use GitHub's private vulnerability reporting for this repository when it is
enabled. Include the affected version or commit, reproduction steps, impact,
and any relevant logs with secrets removed.

If private reporting is unavailable, open a minimal issue asking for a private
contact channel without including the vulnerability details.

## Scope

Security reports are especially useful for:

- API-key or source-code leakage
- unsafe handling of scan paths or generated reports
- unintended network requests or endpoint use
- vulnerabilities in the CLI or its dependencies
- failures that cause Sniff to produce a misleading partial report
- failures that allow repository-controlled commands to escape proof isolation

Sniff sends source code to the LLM endpoint configured by the user. This is an
intentional part of the tool's design. Users should review the provider,
retention policy, and endpoint before scanning private repositories.

Never commit `.env` files or API keys. Use `.env.example` as the configuration
template.

Repository tests and differential probes are opt-in through explicit argv in
`sniff.config.toml`. Sniff runs them only from temporary snapshots through the
platform sandbox worker; it does not invoke a shell or guess a test command.
If the platform sandbox is unavailable, proof is left unresolved rather than
executed on the host. Windows users must provide a hardened executable through
`SNIFF_SANDBOX_RUNNER`. Sniff invokes it without a shell as:
`runner --root <snapshot> --workdir <relative-dir> --timeout-ms <limit> -- <program> <args...>`.
The runner is responsible for enforcing filesystem, network, process, CPU, and
memory isolation before launching the final command.

Target-repository `.env` files cannot configure `SNIFF_SANDBOX_RUNNER`, internal
Gradle launcher variables, process paths, cache locations, language-tool homes,
or proxy variables. Put those execution controls in the trusted working-directory
process environment instead; dotenv files are never trusted for execution
controls.
