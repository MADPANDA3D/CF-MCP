# Support

## Public support

Use GitHub Issues for reproducible bugs, public-safe documentation corrections,
and focused feature proposals. Before opening an issue, review:

- [README](README.md)
- [tool catalog](docs/tool-catalog.md)
- [endpoint coverage](docs/endpoint-coverage.md)
- [operator runbook](docs/operator-runbook.md)
- [security model](docs/security-model.md)

Include:

- release version or full source commit
- Python and Docker/Compose versions when relevant
- access mode: `standalone` or `portal`
- tool name and minimal synthetic input shape
- safe `/health` fields and the exact sanitized error type
- the smallest provider-free reproduction available

## Never post

Do not include:

- Cloudflare API tokens, service bearer tokens, Portal grants, or resolved
  authorization headers
- `.env`, secret-store exports, screenshots of credentials, or copied CI
  environments
- account IDs, zone IDs, resource IDs, customer data, or raw provider
  responses
- production domains, IP addresses, filesystem paths, proxy configuration,
  internal tickets, agent memory, or private logs

Replace sensitive material with explicit placeholders such as
`<CLOUDFLARE_API_TOKEN>` or `<ZONE_ID>`.

## Cloudflare product support

This repository cannot resolve Cloudflare account access, billing, API token
creation, quota, product availability, service incidents, or provider-policy
questions. Use [Cloudflare Support](https://www.cloudflare.com/support/) or
the relevant official Cloudflare documentation for those matters.

## Security

Report vulnerabilities privately through [SECURITY.md](SECURITY.md), not a
public issue.

Support is best-effort and has no guaranteed response or resolution SLA.
