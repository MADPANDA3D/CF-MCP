# Cloudflare MCP Security Model

This document defines the release-candidate trust boundary for catalog version
`2026.07.19.3`. It is an operating model, not a guarantee that every deployment
environment is secure.

## Trust boundaries

```text
trusted operator or broker issuer
  |  MCP_APPROVAL_SIGNING_KEY (never available to the agent)
  |  externally signed, expiring one-use mutation attestation
  v
MCP client or trusted broker
  |  mode-specific service credential
  |  broker-derived tenant partition (Portal mode)
  |  request-scoped Cloudflare API token
  |  signed attestation for an ordinary mutation only
  v
trusted TLS / loopback / private proxy
  |  authenticated, bounded MCP request
  v
MADPANDA3D Cloudflare MCP
  |  pinned method/path, policy-admitted, non-retried HTTPS request
  v
https://api.cloudflare.com/client/v4
```

Five controls are independent:

1. **Network trust** determines who can reach the service.
2. **Service authentication** determines who may invoke MCP.
3. **Cloudflare BYOK authorization** determines which provider resources that
   request may access.
4. **Operation policy** permanently excludes catalog-only and high-risk generic
   operations.
5. **External mutation approval** admits one exact ordinary mutation attempt.

Passing one boundary does not grant the others. An annotation, Cloudflare token,
service credential, approval signature, or Portal decision cannot weaken the
server's permanent high-risk denial.

## Startup access modes

`MCP_MODE` must be exactly `standalone` or `portal`. Startup fails closed when
the selected mode has no valid, non-placeholder service credential.

| Mode | Required service proof | Intended caller |
|---|---|---|
| `standalone` | `Authorization: Bearer <MCP_ACCESS_TOKEN>` | Independent MCP client or trusted local gateway |
| `portal` | Matching `X-MADPANDA-PORTAL-GRANT` and broker-derived tenant header | Trusted MAD MCP Portal broker |

There is no public, anonymous, or request-switchable mode. A restart is required
to change modes. `/mcp` service authentication is enforced before the request
body is parsed.

Portal service authentication requires both proofs on every MCP request. The
tenant header name is configured by `MCP_TENANT_ID_HEADER` and defaults to
`x-madpanda-user-id`. A trusted broker must discard any client-supplied value
and inject the tenant derived from its authenticated session. The tenant is not
authorization: it neither validates Portal access nor grants Cloudflare
permissions. It partitions the service-principal fingerprint used by the
process-local approval ledger, so a preview and approved retry must use the same
broker-derived tenant value as well as the same live process.

`GET /health` is intentionally unauthenticated for routing and container
readiness. It reports safe configuration values, presence booleans, mode,
tool/catalog counts, and release identity. It must never return a service token,
Portal grant, provider token, approval signing key, approval attestation,
account ID, or zone ID.

## Request-scoped Cloudflare BYOK

Provider calls require `x-cloudflare-api-token` on the active request. The
runtime has no supported Cloudflare token environment fallback, does not write
provider credentials to disk, and does not return them in tool output.

Optional `x-cloudflare-account-id` and `x-cloudflare-zone-id` values are request
hints. They may guide navigation or token verification, but they are not
authorization, are not persisted, and do not automatically replace IDs in a
provider path. Mutation approvals bind the provider token and both hints through
a secret-free provider fingerprint.

The Cloudflare token exists in request and process memory while a call is active.
Operators must treat process memory, crash dumps, tracing, and debug snapshots as
sensitive.

## Fixed provider boundary

The advanced dispatcher is not a generic proxy. It enforces:

- HTTPS to `api.cloudflare.com` on the standard port
- the `/client/v4` API prefix
- `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`
- an exact method/path match in the pinned OpenAPI snapshot
- proof that the operation accepts this client's fixed Bearer API-token model
- no required provider request headers that the dispatcher cannot construct
- no URL credentials, custom port, fragment, query-in-path, traversal, or empty
  path segments
- no caller-supplied provider headers
- redirects disabled
- one outbound attempt with no automatic retry

The provider base URL is fixed in source. A deployment environment cannot
redirect the Cloudflare token to another host through a base-URL override.

Method/path presence is not full request-schema validation. The dispatcher
checks the pinned method/path, reviewed endpoint policy, permitted JSON media,
required request-body presence, and structural bounds. It does not validate
arbitrary query keys or JSON body fields against every OpenAPI parameter or
request-body schema. Cloudflare is the field-level schema authority, and callers
must treat provider validation errors as authoritative.

## Endpoint transport and policy boundary

The pinned schema contains 3,148 operations:

| Classification | Count |
|---|---:|
| Read | 1,499 |
| Write | 1,201 |
| Destructive | 448 |

| Coverage status | Count |
|---|---:|
| JSON-transport callable | 2,356 |
| Catalog-only | 792 |

Catalog-only reason counts are:

- 41 with unsupported request media
- 103 with unsupported successful-response media
- 2 requiring provider request headers the fixed dispatcher cannot accept
- 87 without evidence that the fixed Bearer API-token client is compatible
- 127 with no reviewable JSON request schema
- 49 with no explicit 2xx response contract
- 15 with ambiguous non-204/205 bodyless success contracts
- 120 with no reviewable successful JSON schema
- 114 blocked by force-catalog reviewed operation-policy overrides
- 263 with credential-sensitive request or successful-response schemas

There are 117 reviewed overrides in total; 114 force catalog-only status. Of
those, 87 are exact credential-capable contexts whose generic field shapes are
not safely distinguishable from ordinary data, including arbitrary outbound
header maps, signing values, and temporary privileged URLs.

These reason counts overlap when one operation has more than one blocker.

The contract checks are deliberately fail-closed. A JSON request or successful
response must have a reviewable schema; missing, empty, and bare object schemas
do not prove which fields or sensitive values may cross the boundary. Runtime
also enforces OpenAPI's required-body presence bit. Without an explicit 2xx
contract, the dispatcher cannot establish which response is successful. Only
`204` and `205` are accepted as implicitly bodyless; any other successful status
must declare response content. None of these checks claim full field-schema
validation.

The fixed provider client sends a Bearer API token and does not accept arbitrary
caller-supplied provider headers. Operations without pinned compatibility
evidence, or that require additional provider headers, remain catalog-only
instead of relying on an unsafe authentication or transport assumption.

Supported request bodies are JSON objects or arrays using
`application/json`, `application/merge-patch+json`, or
`application/scim+json` only when the operation advertises that media type.
Multipart, form, file, binary, streaming, and unsafe protocol-upgrade operations
are not coerced into JSON.

The generator recursively inspects request parameters/bodies and successful
response bodies/headers through local references, composition, arrays, and maps.
Explicit `x-sensitive`, `format: password`, credential-like `writeOnly`, the
pinned DNSSEC `privkey` contract, and strong credential value semantics such as
unmarked `stream_key`, license or pairing keys, card/payment fields, invoice
documents, and signed upload, download, or debugger URLs force
credential-high-risk `catalog_only` classification. The ledger contains 263
sensitive-schema operations: 104 with request findings, 206 with successful-
response findings, and 172 with credential-semantic signals; these counts
overlap. Exact reviewed overrides separately handle the 87 credential-capable
contexts, misleading HTTP method semantics, and reviewed side-effecting GETs.

In particular,
`GET /accounts/{account_id}/cni/interconnects/{icon}/loa` generates a Letter of
Authorization document despite its read-shaped method. Policy classifies it as
a write, flags it as a side-effecting GET, and forces it catalog-only. Output
redaction remains a defense-in-depth safeguard; it cannot make a
credential-sensitive or response-contract-indeterminate operation admissible.

Exact transport review also forces
`GET /accounts/{account_id}/email-security/investigate` catalog-only because its
`202` flow requires a `Location` response header the dispatcher omits. The
`POST`, `PATCH`, and `DELETE`
`/accounts/{account_id}/teamnet/routes/network/{ip_network_encoded}` operations
are catalog-only because their encoded CIDR slash conflicts with the path
normalizer's traversal defense.

`callable` is only a transport claim. It does not mean an operation is safe,
free, reversible, admitted by policy, permitted by the BYOK token, or executable
through the generic dispatcher.

## Permanent high-risk denial

The ledger flags 469 high-risk operations. Risk flags overlap:

- 405 credential-related
- 25 account-administration
- 18 billing or commerce
- 23 reviewed side-effecting GETs

Every high-risk operation is permanently blocked from generic execution before
any provider attempt. This includes credential lifecycle, credential-returning,
account-administration, billing, commerce, and reviewed side-effecting-GET
operations. There is no `MCP_ALLOW_HIGH_RISK_OPERATIONS` setting, deterministic
confirmation phrase, hidden route, or approval-attestation override.

Endpoint-specific support for any such operation would require a separate
curated tool, least-privilege input contract, safe output projection, accounting
or admission controls where applicable, focused tests, and a new public review.

## Ordinary mutation approval

Ordinary reads need service authentication and request-scoped BYOK but no
mutation approval. Ordinary write and destructive operations use an externally
signed, expiring, one-use approval flow.

### Issuance

An ordinary mutation request without `x-mcp-approval-attestation` is checked
against the pinned method/path inventory, JSON-media boundary, and endpoint
policy, requires request-scoped BYOK, and makes no provider call. The server
places a secret-free pending record in its bounded in-memory ledger and returns:

- a public canonical `approval_payload`
- the operation ID and canonical request SHA-256
- a random challenge and five-minute expiry encoded in the payload
- `approval_header: x-mcp-approval-attestation`

The pending record binds that challenge to fingerprints of the authenticated
service principal and Cloudflare BYOK context plus the exact operation and
request digest. It stores neither raw credential nor request body.

### External review and signing

A trusted operator or broker reviews the operation and exact request outside
the agent's execution context. The issuer must assemble one JSON object with
exactly `approval_payload`, `method`, `path`, `query`, `body`, and
`content_type`, review every value, and pass that document on standard input to
`scripts/sign_approval.py`. The script independently recomputes the pinned
operation identity and canonical request digest before signing. The
symmetric `MCP_APPROVAL_SIGNING_KEY` is configured in the verifier and trusted
issuer contexts, but it must remain unavailable to the MCP client and agent.
The MCP runtime exposes no signing route or tool.

The included `scripts/sign_approval.py` is an operator-side convenience, not an
agent capability. It must never be used to sign a bare `approval_payload` or an
agent-produced document without independent review. If an agent can read the
key, invoke the trusted signer, or cause arbitrary review JSON to be signed,
the external-approval boundary has failed.

When the signing key is blank, ordinary mutations return
`mutation_approval_unavailable`; the deployment remains effectively read-only
while ordinary reads continue to work.

### Verification and consumption

Before expiry, the caller repeats the exact request with:

- the same authenticated service credential and access mode
- the same broker-derived tenant value in Portal mode
- the same Cloudflare token, account hint, and zone hint
- the same method, normalized path, query, body, and selected content type
- `x-mcp-approval-attestation: <SIGNED_ATTESTATION>`

The server verifies the signature and every stored binding, then atomically
consumes the approval **before** attempting Cloudflare. Unknown, expired,
replayed, malformed, cross-principal, cross-provider, cross-operation,
cross-request, or cross-process attestations fail closed.

Consumption authorizes one provider attempt, not a successful outcome. The
attestation cannot be reused if Cloudflare times out, the connection fails, or
the provider returns an error. Reconcile provider state with a safe read before
requesting and approving another mutation attempt.

### Process-local ledger and scaling caveat

The ledger is bounded to 2,048 pending approvals and 32 pending approvals per
principal. Pending and recently consumed challenge hashes are pruned after
expiry. State exists only in memory in one Python process:

- restart or replacement invalidates pending approvals
- a preview and follow-up must reach the same process
- one-use atomicity is process-local, not distributed
- another replica rejects an unknown challenge rather than forwarding it

Use a single replica for mutation-capable deployments. Sticky routing can make a
multi-replica preview flow reach its issuer, but it does not provide a shared
ledger or distributed one-use guarantee. A future multi-replica mutation design
requires a shared atomic store and a separate security review.

## Request and response controls

Production-oriented defaults provide:

- explicit Host allowlisting; wildcard hosts fail startup validation
- browser-Origin rejection unless an explicit origin allowlist is configured
- a 128 KiB MCP request limit, bounded by an 8 MiB hard maximum
- a 64 KiB provider-response default, bounded by a 240 KiB hard maximum
- a 1 MiB complete MCP-response default, bounded by a 2 MiB hard maximum
- provider timeout bounded from 1 through 120 seconds
- non-root container execution, read-only root filesystem, dropped Linux
  capabilities, `no-new-privileges`, bounded PIDs, memory, and CPU

Startup enforces this cross-limit invariant:

```text
MCP_RESPONSE_BODY_MAX_BYTES >=
  (MCP_PROVIDER_RESPONSE_MAX_BYTES * 8) + 32,768
```

The expansion allowance and reserved envelope space prevent an accepted
provider-body limit from being incompatible with the complete MCP response
limit after JSON encoding, redaction, and protocol wrapping. An invalid limit
combination fails startup rather than truncating successful output later.

Provider responses are streamed only to the configured provider bound. Declared
or observed oversize bodies, non-JSON bodies, invalid JSON, unsupported response
media, and responses that exceed the bound after redaction are omitted rather
than returned partially.

Ordinary read results may include the redacted provider body. Mutation results
always set `response=null`, even when Cloudflare returned JSON, and return a
compact outcome envelope containing execution state, HTTP status,
`cloudflare_success`, operation metadata, consumed-approval state, bounded
response metadata, and a generic error classification. This avoids returning
new credentials or arbitrary mutation output through the generic tool.

Secret-key fields and common bearer/token patterns are redacted recursively for
read responses. Redaction is defense in depth, not a data-loss-prevention
guarantee. Cloudflare may return confidential configuration, logs, identifiers,
personal data, or provider errors in arbitrary fields. Treat all provider output
as sensitive and untrusted.

## Retry and outcome ambiguity

The server performs one provider attempt and never automatically retries.
Approval is consumed before that attempt. A timeout or transport error does not
prove that Cloudflare made no change. Reconcile provider state with a safe read
before manually starting a new approval flow.

## Deployment and immutable releases

The source-build manifests `docker-compose.yml` and
`docker-compose.portal.yml` build `cloudflare-mcp:local-source`. Verified release
deployments use `docker-compose.release.yml` or
`docker-compose.portal.release.yml`; those manifests contain no `build` section,
take only `MCP_RELEASE_DIGEST` as their release-identity input, set
`pull_policy: always`, and run only:

```text
ghcr.io/madpanda3d/cloudflare-mcp-server@sha256:<MCP_RELEASE_DIGEST>
```

The build SHA and source fingerprint are baked into the image during the
release build; the release manifests do not accept runtime overrides for them.
`MCP_IMAGE_REFERENCE` is derived from `MCP_RELEASE_DIGEST` and set to that same
immutable reference. Normal service credentials remain required. The release
workflow targets `linux/amd64`. Never substitute a mutable tag for the digest
recorded in the matching GitHub Release.

The tag workflow can build and push only a run-scoped candidate while the clean
canonical source remains private. After candidate scan, the package owner makes
only that GHCR package public; the same digest must then pass anonymous pull,
Compose, and smoke gates. The source repository becomes public only after the
image gate, enabling exact-SHA public Verify/CodeQL admission. Stable tags are
not attached yet: GitHub-signed package and image attestations are created only
after that public admission gate. Stable tags are then attached by digest
without rebuilding and the GitHub Release is created last. Python artifacts are
fixed to the tagged commit epoch and built twice to prove deterministic bytes.
Until that workflow succeeds, this source contract does not assert that hosted
release artifacts exist.

TLS, firewalling, trusted proxy configuration, connection/rate limits, host
hardening, secret storage, signing-key isolation, and log sanitation remain
operator responsibilities. The standalone profile binds to loopback. The Portal
profile exposes a private container port and expects an existing private
network.

## Operator verification order

Before any provider smoke test:

1. Confirm invalid, placeholder, or incomplete startup configuration fails
   closed.
2. Confirm health contains no credential, signing-key, attestation, or provider
   identifier values.
3. Confirm missing and incorrect service credentials—and missing, invalid, or
   duplicate Portal tenant headers—are rejected before MCP request parsing.
4. Confirm unapproved browser-Origin traffic is rejected.
5. Confirm all six tools are visible and only five are default agent-ready.
6. Confirm local navigation works without a Cloudflare token.
7. Confirm provider execution rejects missing BYOK.
8. Confirm alternate origins, redirects, unknown operations, and catalog-only
   operations fail closed.
9. Confirm all high-risk generic operations return permanent denial without a
   provider call.
10. Confirm an ordinary mutation issues an approval payload without a provider
    call, rejects unsigned or changed requests, accepts one correctly bound
    external attestation based on independently reviewed exact-request JSON,
    consumes it before the attempt, and rejects replay or cross-tenant use.
11. Confirm read responses respect both limits and mutation responses omit the
    provider body.

Only then use a dedicated least-privilege token for a separately approved,
narrow read. Do not begin certification with a write, deletion, credential
change, purchase, top-up, domain action, or account-administration call.

## Reporting vulnerabilities

Follow [SECURITY.md](../SECURITY.md). Do not publish exploit details, tokens,
provider data, signing material, attestations, or deployment topology in a
public issue.
