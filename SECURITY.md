# Security policy

## Supported versions

The v1.0.0 source contract is a release candidate. Until its exact tag workflow
publishes the matching GitHub Release, security fixes target current `main` and
no hosted release availability is implied. After publication succeeds, fixes
target the latest hosted release and current `main`; older releases may not
receive backports.

## Report privately

Use **Security → Report a vulnerability** in this GitHub repository. Include:

- the affected version or full commit SHA
- access mode: `standalone` or `portal`
- a minimal reproduction using synthetic credentials and resources
- expected behavior, observed behavior, and practical impact
- any safe mitigation you have already tested

If private vulnerability reporting is unavailable, open a minimal issue asking
the maintainers for a private contact channel. Do not include the
vulnerability, exploit, credential, Cloudflare identifier, provider response,
private URL, or sensitive log material in that issue.

High-value reports include:

- service-authentication or startup-mode bypass
- Cloudflare API token or Portal grant exposure
- missing/forged Portal tenant admission, trusted-broker tenant overwrite
  bypass, or cross-tenant approval use
- cross-request credential confusion or provider-token persistence
- outbound origin, redirect, pinned method/path, Bearer-auth proof,
  required-provider-header, endpoint-policy, or JSON-media admission escape
- request/success-contract admission bypass involving a missing, empty, or bare
  object JSON schema, omitted required body, no explicit 2xx, or ambiguous
  non-204/205 bodyless success
- a catalog-only or high-risk operation becoming executable unexpectedly
- write/destructive classification or external approval-attestation bypass
- approval forgery, bare-payload/blind-signing acceptance, cross-principal or
  cross-credential use, expiry bypass, or replay
- automatic replay or retry of a mutation
- unbounded request/provider/MCP output handling
- unsafe redaction, logging, Host, or browser-Origin behavior

## Safe research

- Use Cloudflare accounts, zones, tokens, and resources you own or are
  authorized to assess.
- Use least-privilege tokens, synthetic data, and the smallest practical
  request volume.
- Do not purchase, top up, register, transfer, delete, rotate credentials, or
  change account ownership without explicit authorization.
- Do not test a public deployment or another person's credential.
- Repository tests must remain provider-free.

If a real credential is exposed, revoke or rotate it through its issuer, then
report the source and affected version privately. Removing a file, commit, or
repository does not revoke a credential.

## Disclosure

Please allow maintainers time to reproduce, fix, verify, and release a
correction before public disclosure. Coordination depends on severity and fix
availability; no fixed response-time SLA is promised.
