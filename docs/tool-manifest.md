# Cloudflare MCP ToolManifest

## Identity

| Field | Value |
|---|---|
| Schema version | `1.0.0` |
| Service ID | `cloudflare` |
| Catalog and reviewed-policy version | `2026.07.19.3` |
| Native tools | 6 |
| Descriptor identity | Deterministic SHA-256 reported by the exact runtime |

`list_capabilities(include_descriptors=true)` is the provider-owned source of
truth for the runtime contract. It returns the complete ordered descriptor
catalog and its deterministic `descriptorHash`. A release record pins the hash
from its exact build; this document does not guess a candidate hash.

## Tier contract

| Tier | Count | Discovery behavior |
|---|---:|---|
| `agent_ready` | 5 | Returned by default task discovery |
| `legacy` | 1 | Returned only when advanced discovery includes legacy tools |
| `hidden` | 0 | None |
| **Total** | **6** | All six remain visible through MCP `tools/list` |

The legacy entry is `cloudflare_api_request`. It is intentionally excluded
from `find_tools` defaults because one dispatcher spans read, write,
destructive, billable, credential, account-administration, and reviewed
side-effecting-GET risks.

## Standard navigation

| Tool | Role |
|---|---|
| `check_configuration` | Reports mode, safe limit values, request readiness, approval availability, and permanent high-risk policy without returning credentials |
| `find_tools` | Searches and ranks the local provider-owned catalog |
| `get_endpoint_coverage` | Filters the pinned ledger with auth, header/body, request/success-contract, coverage, and risk metadata |
| `get_tool_usage` | Resolves one native, canonical, or documented alias identity and its safety gates |
| `list_capabilities` | Returns compact counts or the complete descriptor catalog |

These calls require only the selected mode's service-auth context and remain
local, except an explicit `check_configuration(verify_cloudflare_token=true)`
call. In Portal mode that context is both the matching grant and the
broker-controlled tenant header; the broker strips/overwrites client tenant
input. The tenant partitions approval principals but is not authorization. Any
provider execution requires a request-scoped
`x-cloudflare-api-token` header.

## Advanced dispatcher contract

`cloudflare_api_request` accepts one method, path, optional query, optional JSON
body, and optional supported JSON content type. It rejects:

- operations absent from the pinned schema
- the 792 operations marked `catalog_only`
- every high-risk operation, even when its transport status is `callable`
- non-Cloudflare origins, redirects, URL-embedded query strings, and path
  traversal
- non-JSON request bodies or caller-supplied provider headers
- oversized, non-JSON, invalid JSON, or unsupported provider responses

Admission validates pinned method/path identity, Bearer API-token compatibility,
absence of unsupported required provider headers, reviewed endpoint policy,
supported JSON media, required-body presence, and reviewable request/success
contracts. It does not validate arbitrary query keys or JSON body fields against
Cloudflare's complete schemas; Cloudflare remains authoritative for field-level
validation.

The endpoint ledger contains:

| Classification | Count |
|---|---:|
| Read | 1,499 |
| Write | 1,201 |
| Destructive | 448 |
| **Total** | **3,148** |

| Coverage status | Count |
|---|---:|
| JSON-transport callable | 2,356 |
| Catalog-only | 792 |

Catalog-only reason counts include 41 unsupported-request-media operations, 103
unsupported-success-response-media operations, 2 required-provider-header
operations, 87 without Bearer API-token compatibility evidence, 127 with no
reviewable JSON request schema, 49 with no explicit 2xx, 15 with ambiguous
non-204/205 bodyless success, 120 with no reviewable successful JSON schema, 114
force-catalog reviewed policy overrides, and 263 credential-sensitive request or
successful-response schemas. Reasons overlap.

The registry has 117 reviewed overrides in total, including 87 exact
credential-capable contexts. Sensitive-schema counts are 104 request, 206
successful-response, and 172 credential-semantic signal operations; these cover
capability URLs, keys, payment fields, and invoice documents. The ledger flags
469 high-risk operations: 405 credential-related, 25 account-administration, 18
billing or commerce, and 23 reviewed side-effecting GETs. Risk flags overlap, so
their counts do not sum to the high-risk total.

Missing, empty, and bare object request/success schemas are not reviewable field
contracts. Runtime enforces OpenAPI required-body presence, but Cloudflare still
validates arbitrary fields. Every operation needs an explicit 2xx response, and
only `204`/`205` are accepted as implicitly bodyless. The reviewed
`GET /accounts/{account_id}/cni/interconnects/{icon}/loa` operation generates a
Letter of Authorization document, so policy classifies it as a write, flags it
as a side-effecting GET, and forces it catalog-only.

Exact overrides also keep
`GET /accounts/{account_id}/email-security/investigate` catalog-only because its
`202` continuation requires a `Location` header the dispatcher omits, and keep
the `POST`, `PATCH`, and `DELETE`
`/accounts/{account_id}/teamnet/routes/network/{ip_network_encoded}` operations
catalog-only because their encoded CIDR slash conflicts with the path
normalizer's traversal defense.

`callable` is a transport statement, not permission to execute. All high-risk
generic execution is permanently blocked in source. There is no startup toggle,
phrase, attestation, or Portal policy that can enable it.

## External one-use approval contract

Ordinary reads require service authentication and request-scoped Cloudflare
BYOK but no mutation approval. Ordinary write and destructive operations
require the same BYOK plus an externally signed, expiring, one-use approval:

1. Call the exact mutation without `x-mcp-approval-attestation`.
2. The server makes no provider call and returns `approval_required`, a public
   `approval_payload`, the operation identity, request digest, expiry, and the
   required header name.
3. A trusted operator or broker creates one exact review JSON object containing
   only `approval_payload`, `method`, `path`, `query`, `body`, and
   `content_type`, reviews every field and intended effect, and supplies that
   document to `scripts/sign_approval.py` or an equivalent trusted issuer. The
   issuer recomputes the operation and request digest before signing; bare
   payload signing is forbidden. `MCP_APPROVAL_SIGNING_KEY` must remain
   unavailable to the agent.
4. Repeat the unchanged request before its five-minute expiry with the same
   authenticated service principal, the same broker-derived tenant in Portal
   mode, the same Cloudflare BYOK and account/zone hints, and
   `x-mcp-approval-attestation: <SIGNED_ATTESTATION>`.
5. The server verifies the signature and exact principal, provider, operation,
   and request bindings, then atomically consumes the approval before making
   one non-retried provider attempt.

Changing the method, normalized path, query, JSON body, selected content type,
service credential, broker-derived Portal tenant, provider credential, account
hint, zone hint, or operation invalidates the approval. Expired, replayed,
unknown, or cross-process
attestations fail closed. If `MCP_APPROVAL_SIGNING_KEY` is blank, ordinary
mutations remain read-only-disabled while ordinary reads still work.

The pending/consumed approval ledger stores secret-free fingerprints and is
bounded, in-memory, and process-local. A preview and its approved follow-up must
reach the same live process. Use a single replica for mutation-capable
deployments; sticky routing may preserve usability but does not create a
distributed approval ledger.

## Descriptor contents

Every descriptor contains:

- native and canonical identities plus bounded compatibility aliases
- title, full description, category, tier, and deprecation metadata
- complete input and output JSON schemas
- `readOnlyHint`, `destructiveHint`, `openWorldHint`, and
  `idempotentHint` where true
- confirmation metadata, documentation URL, navigation role, catalog version,
  and descriptor hash

Annotations communicate intended behavior; they are not authorization.
Service authentication, request-scoped BYOK, permanent high-risk denial,
external approval issuance, one-use consumption, and provider-side permissions
remain separate boundaries.

## Safe discovery sequence

1. Call `check_configuration` without live token verification.
2. Call `find_tools` for the desired workflow.
3. Call `get_tool_usage` for the complete selected descriptor.
4. Call `get_endpoint_coverage` to confirm method, path, transport status,
   classification, risk flags, and reviewed policy.
5. Stop if the operation is catalog-only or high-risk.
6. For an ordinary mutation, obtain its server-issued approval payload, build
   and independently review the exact six-field request JSON, have a trusted
   external issuer recompute and sign that binding, and submit the attestation
   before expiry.

Use `list_capabilities(include_descriptors=true)` only for full contract audit,
admission, or publication.

## Build and change control

Source builds report their configured `MCP_BUILD_SHA`,
`MCP_SOURCE_FINGERPRINT`, and `MCP_IMAGE_REFERENCE`. The build SHA and source
fingerprint are baked into release images. Immutable release deployments use
`docker-compose.release.yml` or `docker-compose.portal.release.yml`, take only
`MCP_RELEASE_DIGEST` as release identity, pull
`ghcr.io/madpanda3d/cloudflare-mcp-server@sha256:<digest>`, and report that same
digest reference through `/health` and ToolManifest output.

A tool addition, removal, rename, schema change, annotation change, alias
change, tier change, approval change, or endpoint-policy change requires
synchronized updates to:

- `src/cloudflare_mcp/tool_manifest.py`
- provider-free contract tests
- [the tool catalog](tool-catalog.md)
- [the endpoint ledger](endpoint-coverage.md), when coverage changes
- README counts and changelog

The runtime, health output, Portal catalog, tests, generated inventory, and
public documentation must agree before release.
