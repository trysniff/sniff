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

Sniff sends source code to the LLM endpoint configured by the user. This is an
intentional part of the tool's design. Users should review the provider,
retention policy, and endpoint before scanning private repositories.

Never commit `.env` files or API keys. Use `.env.example` as the configuration
template.
