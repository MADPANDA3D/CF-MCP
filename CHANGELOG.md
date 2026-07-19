# Changelog

All notable public releases will be documented here.

## Unreleased

- No user-facing changes beyond the v1.0.0 release candidate below.

## 1.0.0 release candidate - 2026-07-19

This section describes the source and tag-ready contract. It does not assert
that the `v1.0.0` tag, GitHub Release, or public GHCR digest already exists.

- Prepared the Python FastMCP server for independent public use under the MIT
  License.
- Added startup-selected authenticated `standalone` and `portal` modes; there
  is no unauthenticated MCP mode. Portal calls require both the service grant
  and a broker-derived tenant header. The broker strips or overwrites client
  tenant input; tenant partitions approval principals but is not authorization.
- Standardized request-scoped Cloudflare BYOK through
  `x-cloudflare-api-token` with no provider-token environment fallback.
- Kept the six-tool protocol surface: five local agent-navigation tools and one
  advanced legacy JSON dispatcher.
- Pinned the endpoint inventory to Cloudflare api-schemas commit
  `aefa753f1190c85866f65dcc7f348e18c7a1ca4a` and recorded its BSD-3-Clause
  attribution. Policy `2026.07.19.3` assigns deterministic bounded fallback
  identities to the 49 operations without a usable upstream `operationId`.
- Finalized endpoint policy `2026.07.19.3`: 2,356 reviewed pinned
  JSON-transport operations are callable and 792 are catalog-only in the
  3,148-operation snapshot, classified as 1,499 read, 1,201 write, and 448
  destructive. Admission now requires Bearer API-token compatibility evidence,
  no unsupported required provider headers, reviewable JSON
  request/success schemas, required-body presence, and an explicit 2xx response.
  Missing, empty, and bare object schemas fail closed; only `204`/`205` may be
  implicitly bodyless. Overlapping catalog-only reason counts include 41
  unsupported-request-media, 103 unsupported-success-media, 2
  required-provider-header, 87 incompatible-auth, 127 unreviewable-request,
  49 no-explicit-2xx, 15 ambiguous-bodyless-success, 120
  unreviewable-success-schema, and 114 reviewed-override operations. Recursive
  request and successful-response inspection forces all 263 sensitive-schema
  operations to fail closed, including 172 with strong credential semantics for
  capability URLs, keys, payment fields, and invoice documents. The final ledger
  has 117 reviewed overrides, 114 forced catalog-only overrides, and 469
  high-risk operations; its risk-flag counts overlap.
- Reclassified the reviewed
  `GET /accounts/{account_id}/cni/interconnects/{icon}/loa` operation as a write,
  flagged it as a side-effecting GET, and forced it catalog-only because it
  generates a Letter of Authorization document.
- Forced the email-security investigation `202` workflow catalog-only because
  continuation requires a `Location` response header the generic dispatcher
  omits, and forced the three encoded-CIDR teamnet route operations catalog-only
  because their encoded slash conflicts with path-traversal normalization.
- Replaced deterministic confirmation fields with externally signed, expiring,
  principal/provider/request-bound one-use mutation approvals. High-risk generic
  execution is permanently blocked. The trusted signer accepts only six-field
  exact-request review JSON, recomputes the operation/request binding, and
  refuses bare-payload signing.
- Clarified that generic admission enforces pinned method/path, endpoint policy,
  and allowed JSON media, not complete query/body field-schema validation;
  Cloudflare remains authoritative for those fields and issuers review the exact
  mutation request.
- Added fixed Cloudflare origin enforcement, a cross-layer response-size
  invariant, compact mutation outcome envelopes, and no automatic provider
  retries.
- Added public-safe deployment, Portal, security, provenance, support, and
  contribution documentation.
- Hardened release publication around a fixed-epoch deterministic double package
  build and a run-scoped candidate image created while source remains private.
  The GHCR package becomes public first for exact-digest anonymous/Compose/smoke
  gates, source becomes public afterward for exact-SHA Verify/CodeQL admission,
  GitHub-signed package/image attestations run after that public admission gate,
  stable tags are promoted by digest without rebuilding, and the GitHub Release
  is created last. The workflow intentionally does not publish to PyPI.

Before the exact tag workflow succeeds, use the source tree and local
verification instructions; hosted artifacts are not implied. After it succeeds,
the matching GitHub Release, attached checksums, and recorded immutable GHCR
digest become the authoritative v1.0.0 availability record.
