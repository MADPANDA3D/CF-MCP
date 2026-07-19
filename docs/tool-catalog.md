# Cloudflare MCP Tool Catalog

This is the complete six-tool protocol surface for catalog version
`2026.07.19.3`. The exact runtime descriptor is available through
`get_tool_usage`; the complete deterministic catalog is available through
`list_capabilities(include_descriptors=true)`.

## Agent-ready navigation

### `check_configuration`

Reports the selected access mode, service-auth readiness, request-scoped BYOK
presence, fixed provider origin, safe request/response limits, mutation-approval
availability, and the permanently blocked high-risk policy without returning
credential values.

Input:

- `verify_cloudflare_token` — default `false`; when `true`, performs one
  read-only Cloudflare user-token or account-token verification request

The optional account ID hint helps select the account-token verification route.
Live verification needs `x-cloudflare-api-token`; the local readiness check does
not.

### `list_capabilities`

Returns catalog identity, tier counts, safety guidance, and common workflows.

Input:

- `include_descriptors` — default `false`; when `true`, includes every complete
  descriptor and the deterministic descriptor hash

This tool never contacts Cloudflare.

### `get_endpoint_coverage`

Searches the pinned 3,148-operation endpoint inventory.

Inputs:

- `feature_area` — optional case-insensitive feature/tag filter
- `method` — optional `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`
- `path_contains` — optional case-insensitive path substring
- `classification` — optional `read`, `write`, or `destructive`
- `limit` — 1 through 200; default 50
- `offset` — zero-based pagination offset

Results include media types, `callable` or `catalog_only` status,
classification, Bearer-auth evidence, required provider headers/body, request
and success contract state, high-risk state, overlapping risk flags, reviewed
policy, and operation identity. This tool never contacts Cloudflare.

### `get_tool_usage`

Resolves a native tool name, canonical `cloudflare.<tool>` identity, or
documented alias. It returns the exact descriptor plus use, setup, side-effect,
safety-gate, and follow-up guidance. This tool never contacts Cloudflare.

### `find_tools`

Performs deterministic local search over names, aliases, titles, descriptions,
and categories.

Inputs:

- `query` — required natural-language, category, alias, or tool-name text
- `categories` — optional exact category filters
- `include_legacy` — default `false`; enables the advanced dispatcher result
- `limit` — 1 through 25; default 8

This tool never contacts Cloudflare.

## Advanced legacy execution

### `cloudflare_api_request`

Evaluates or executes one operation from the pinned Cloudflare schema.

Inputs:

- `method` — `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`
- `path` — a path relative to `/client/v4`, such as `/zones`, with real IDs
  substituted; a full `https://api.cloudflare.com/client/v4/...` URL is also
  accepted
- `query` — optional provider query object
- `body` — JSON object or array; optional unless the pinned OpenAPI operation
  marks its request body required
- `content_type` — optional operation-admitted `application/json`,
  `application/merge-patch+json`, or `application/scim+json`
- `timeout_seconds` — 1 through 120; default 30
- `max_response_bytes` — 4,096 through 245,760 bytes; default 100,000 and
  further capped by `MCP_PROVIDER_RESPONSE_MAX_BYTES`, whose deployment default
  is 65,536 bytes

Approval is an HTTP-header control, not a tool argument. The retired
`confirm_write`, request-digest, phrase, and global high-risk-toggle parameters
are not part of this contract.

Behavior:

- ordinary reads execute once after service authentication, BYOK, pinned
  method/path, Bearer-auth compatibility, required-header, admitted JSON-media,
  required-body, success-contract, and endpoint-policy checks
- an ordinary mutation without an attestation returns a five-minute public
  `approval_payload` and makes no provider call
- mutation execution requires the unchanged request, the same service
  principal and BYOK context, and an externally signed
  `x-mcp-approval-attestation`
- the server verifies and atomically consumes a valid approval before making
  exactly one provider attempt; expiry, replay, binding mismatch, or a different
  process fails closed
- all 469 high-risk operations are permanently blocked from generic execution;
  no configuration or attestation can enable them
- all 792 catalog-only operations remain non-callable
- reads may return a secret-redacted, size-bounded provider body; mutations
  always omit the provider body and return only a compact outcome envelope
- requests use the fixed Cloudflare origin, disabled redirects, request-scoped
  BYOK, bounded JSON responses, and no automatic retries

The dispatcher does not validate arbitrary query keys or JSON body fields
against Cloudflare's complete parameter/request schemas. Cloudflare remains the
field-level authority. For a mutation, the trusted issuer must review the exact
query and body before signing rather than treating `callable` as field-schema
validation.

The inventory contains 2,356 JSON-transport-callable and 792 catalog-only
operations, classified as 1,499 read, 1,201 write, and 448 destructive. Its 469
high-risk operations carry overlapping flags: 405 credential-related, 25
account-administration, 18 billing or commerce, and 23 reviewed side-effecting
GET flags. All 263 schema-sensitive operations are catalog-only: 104 have
request findings, 206 have successful-response findings, and 172 carry strong
credential-semantic signals for capability URLs, keys, payment fields, or
invoice documents. The 117 reviewed overrides include 114 force-catalog entries
and 87 exact credential-capable endpoint contexts. Counts overlap. `callable`
describes admission to the generic transport; high-risk policy is a separate
permanent execution denial.

Admission also fails closed for 2 operations requiring provider request headers
the dispatcher cannot accept, 87 without Bearer API-token compatibility
evidence, 127 with no reviewable JSON request schema, 49 with no explicit 2xx
response, 15 with ambiguous non-204/205 bodyless success, and 120 with no
reviewable successful JSON schema. Missing, empty, and bare object schemas are
not treated as field contracts. Runtime enforces a required request body's
presence; Cloudflare remains responsible for full field validation.

The reviewed
`GET /accounts/{account_id}/cni/interconnects/{icon}/loa` operation is classified
as a write, flagged as a side-effecting GET, and forced catalog-only because it
generates a Letter of Authorization document.

`GET /accounts/{account_id}/email-security/investigate` is catalog-only because
its `202` workflow requires a `Location` response header the generic dispatcher
omits. The `POST`, `PATCH`, and `DELETE`
`/accounts/{account_id}/teamnet/routes/network/{ip_network_encoded}` operations
are catalog-only because their encoded CIDR slash conflicts with the path
normalizer's traversal defense.

The tool's broad `destructiveHint=true` is intentional. One protocol descriptor
cannot truthfully represent the differing risk of all 3,148 operations. Agents
must use the per-operation ledger and runtime policy result for the actual risk.

## Header requirements

| Call class | Service auth | Cloudflare BYOK | Approval attestation |
|---|---|---|---|
| Local navigation | Selected mode credential | Not required | Not required |
| Live token verification | Selected mode credential | `x-cloudflare-api-token` | Not required |
| Ordinary provider read | Selected mode credential | `x-cloudflare-api-token` | Not required |
| Ordinary mutation approval request | Selected mode credential | `x-cloudflare-api-token` | Omit to receive `approval_payload` |
| Ordinary mutation execution | Same selected-mode principal | Same `x-cloudflare-api-token` and hints | `x-mcp-approval-attestation` |
| High-risk or catalog-only operation | Authenticated request is rejected | No provider execution | Cannot override denial |

In Portal mode, “selected mode credential” means both the matching
`X-MADPANDA-PORTAL-GRANT` and the broker-controlled tenant header configured by
`MCP_TENANT_ID_HEADER`. The broker strips/overwrites client tenant input. Tenant
partitions approval principals and must remain the same for preview/retry, but
is not authorization.

`x-cloudflare-account-id` and `x-cloudflare-zone-id` are optional request hints.
They do not grant access or replace path IDs. Because mutation approvals bind
their provider fingerprint, changing either hint invalidates an issued approval.

## Trusted approval issuer

`MCP_APPROVAL_SIGNING_KEY` is a deployment secret shared only by the verifier
and a separately controlled trusted issuer. It is not a request header and must
never be exposed to the MCP client, agent context, logs, tool output, or source
control. The MCP runtime exposes no signing tool or signing route.

The repository's `scripts/sign_approval.py` is an operator convenience for a
trusted, isolated issuer context. It accepts one exact JSON object on standard
input containing only `approval_payload`, `method`, `path`, `query`, `body`, and
`content_type`; it recomputes the pinned operation and canonical request digest
before reading the signing key from that issuer's environment and signing. It
refuses bare-payload signing. An agent that can invoke the signer, supply an
unreviewed document, or read its key can approve its own mutations, which
defeats the control.

The approval ledger is in-memory and process-local. Mutation-capable deployments
should run a single replica. Sticky routing is required if an operator accepts
the limitations of multiple replicas, but it is not a substitute for a shared,
atomic distributed ledger.

For operation-level details, use the
[endpoint coverage ledger](endpoint-coverage.md). For trust boundaries,
response limits, and retry semantics, read
[the security model](security-model.md).
