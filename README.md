<div align="center">
<h1>🐼 MADPANDA3D Cloudflare MCP</h1>
<pre>
+------------------------------------------------------------------------+
|       .--.   .--.        MADPANDA3D // CLOUDFLARE MCP                  |
|      /    \_/    \       6 TOOLS // 3,148 OPERATIONS                   |
|     |   /\   /\   |      DUAL MODE // REQUEST-SCOPED BYOK             |
|     |  (o)   (o)  |      FASTMCP // PYTHON 3.12 // SELF-HOSTED        |
|      \     ^     /       PINNED CATALOG // JSON MEDIA // NO RETRIES    |
|       '.___.'           REVIEWED POLICY // FAIL-CLOSED                 |
+------------------------------------------------------------------------+
</pre>
<p>An independent, security-conscious FastMCP server for discovering and<br>
executing reviewed Cloudflare REST operations with credentials you control.</p>
<p>
<a href="https://github.com/MADPANDA3D/CF-MCP/actions/workflows/ci.yml"><img alt="Verify" src="https://github.com/MADPANDA3D/CF-MCP/actions/workflows/ci.yml/badge.svg"></a>
<a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-ff2d55.svg"></a>
<img alt="Python 3.12 and 3.13" src="https://img.shields.io/badge/python-3.12%20%7C%203.13-3776ab?logo=python&amp;logoColor=white">
<img alt="MCP tools: 6" src="https://img.shields.io/badge/MCP%20tools-6-111827">
<img alt="Access modes: 2" src="https://img.shields.io/badge/access%20modes-2-22c55e">
</p>
</div>

## The contract

MADPANDA3D Cloudflare MCP exposes exactly **six protocol-visible tools**:

- **Five agent-ready navigation tools** explain configuration, search the
  catalog, filter endpoint coverage, and return exact descriptors. They are
  local unless `check_configuration` is explicitly asked to verify a token.
- **One advanced legacy dispatcher**, `cloudflare_api_request`, executes one
  reviewed Cloudflare REST operation at a time through a fixed provider origin.

The checked-in endpoint inventory accounts for **3,148 operations** from a
pinned Cloudflare api-schemas snapshot. Reviewed policy `2026.07.19.3` makes
**2,356 callable** and leaves **792 catalog-only** because their authentication,
required provider headers, media types, request/success contracts, exact policy
overrides, or credential-sensitive schemas fall outside the generic dispatcher
boundary. Catalog-only does not mean hidden: agents can inspect those operations
and the exclusion reason, but the dispatcher rejects execution.

The server is streamable HTTP at `/mcp`, exposes presence-only health metadata
at `/health`, stores no Cloudflare credential, and does not turn a deployment
into a public or unauthenticated Cloudflare endpoint.

## Choose an access mode

`MCP_MODE` is selected at startup. Changing it requires a restart; no tool can
change the running mode.

| Mode | Intended use | Service credential | Cloudflare credential |
|---|---|---|---|
| `standalone` | Independent self-hosting | `Authorization: Bearer <MCP_ACCESS_TOKEN>` | `x-cloudflare-api-token` on each provider request |
| `portal` | Optional MAD MCP Portal routing | Matching `X-MADPANDA-PORTAL-GRANT` **and** broker-derived tenant header | The broker forwards `x-cloudflare-api-token` per authorized request |

There is no unauthenticated MCP mode. The service credential controls access
to this server; the Cloudflare token separately controls provider permissions.
Portal mode also requires the header named by `MCP_TENANT_ID_HEADER` (default
`x-madpanda-user-id`) on every MCP request. The broker must remove any
client-supplied value and inject its own authenticated tenant identity. That
identity partitions process-local approval principals; it is not authorization
and never replaces Portal access control or Cloudflare token permissions.

## Request-scoped Cloudflare BYOK

Both modes use the same provider headers:

| Header | Required | Purpose |
|---|---:|---|
| `x-cloudflare-api-token` | Provider calls | Least-privilege Cloudflare API token for this request |
| `x-cloudflare-account-id` | Optional | Account-scope hint used by navigation and token verification |
| `x-cloudflare-zone-id` | Optional | Zone-scope hint used by navigation and workflows |
| `x-mcp-approval-attestation` | Approved mutation retry only | Short-lived one-use proof issued by a trusted operator or broker |

Account and zone headers are hints, not authorization and not automatic path
substitution. Provider paths still need the correct explicit resource IDs, and
Cloudflare remains the authority for token permissions.

In Portal mode, the broker-controlled tenant header is mandatory service-auth
context, not a provider header. Clients must never be allowed to select or
forward that value directly.

There is deliberately no Cloudflare token environment fallback. Never place a
provider token in `.env`, Compose, an image layer, a URL, an issue, a screenshot,
or copied client configuration. Supply it through the MCP client's protected
secret/header facility for the active request.

## Five-minute standalone deployment

Prerequisites: Git, Python 3.12 or 3.13, `uv`, Docker Engine with Compose v2,
and a Cloudflare API token with only the permissions required for your intended
operations.

```sh
git clone https://github.com/MADPANDA3D/CF-MCP.git
cd CF-MCP
python3 scripts/init_runtime_env.py --mode standalone
```

The initializer creates ignored `.env` mode `0600`, generates independent
service and mutation-approval secrets, never overwrites an existing file, and
never prints a secret. Review only the non-secret routing values:

```dotenv
MCP_MODE=standalone
MCP_ALLOWED_HOSTS=localhost,127.0.0.1
MCP_HOST_PORT=8000
```

Do not put the Cloudflare token in this file. Start the loopback-only profile:

```sh
docker compose --env-file .env -f docker-compose.yml config --quiet
docker compose --env-file .env -f docker-compose.yml up -d --build
docker compose --env-file .env -f docker-compose.yml ps
curl --fail http://127.0.0.1:8000/health
```

Expected safe health fields include:

```json
{
  "status": "healthy",
  "service": "cloudflare-mcp",
  "tool_count": 6,
  "configuration": {
    "mode": "standalone",
    "provider_credentials_mode": "per_request_byok"
  }
}
```

`/health` reports mode, readiness, bounds, and release/catalog identity without
returning a service token, Portal grant, Cloudflare token, account ID, or zone
ID.

## Connect an MCP client

Client formats differ, but the logical HTTP configuration is:

```json
{
  "mcpServers": {
    "cloudflare": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp",
      "headers": {
        "Authorization": "Bearer ${MCP_ACCESS_TOKEN}",
        "x-cloudflare-api-token": "${CLOUDFLARE_API_TOKEN}",
        "x-cloudflare-account-id": "${OPTIONAL_CLOUDFLARE_ACCOUNT_ID}",
        "x-cloudflare-zone-id": "${OPTIONAL_CLOUDFLARE_ZONE_ID}"
      }
    }
  }
}
```

`${...}` means “load this value from the client's protected secret or
environment facility.” It is not universal interpolation syntax. Omit optional
headers when they are not needed, and never commit resolved values.

The five navigation tools need only the selected service-auth header. Provider
execution and optional live token verification also need
`x-cloudflare-api-token`. Mutation-capable clients additionally need a trusted
per-request mechanism to inject a short-lived `x-mcp-approval-attestation`
after an operator or broker approves the preview. If the client cannot inject a
one-request header, use the server as read-only.

## Tools

| Tool | Tier | Provider call | Behavior |
|---|---|---:|---|
| `check_configuration` | `agent_ready` | Optional | Reports secret-safe readiness; verifies a token only when explicitly requested |
| `list_capabilities` | `agent_ready` | No | Returns compact catalog counts or the complete deterministic ToolManifest |
| `get_endpoint_coverage` | `agent_ready` | No | Filters the pinned 3,148-operation inventory; results include coverage, auth, required-header/body, contract, and risk metadata |
| `get_tool_usage` | `agent_ready` | No | Resolves one native, canonical, or documented alias to its exact descriptor and usage contract |
| `find_tools` | `agent_ready` | No | Searches the local catalog; advanced legacy results are opt-in |
| `cloudflare_api_request` | `legacy` | Yes | Previews or executes one pinned method/path JSON operation through the guarded advanced path |

All six tools remain protocol-visible for compatibility. Default task
discovery returns the five agent-ready tools; callers must deliberately include
the advanced legacy tier to select the dispatcher.

## Endpoint coverage

The generated inventory is pinned to Cloudflare's official
[`api-schemas`](https://github.com/cloudflare/api-schemas) repository:

| Identity | Value |
|---|---|
| Upstream commit | `aefa753f1190c85866f65dcc7f348e18c7a1ca4a` |
| Source snapshot SHA-256 | `6c141cf38b45a514fcba04d322d43916eaba179a4442c8d91afaf5e7a66c8f1f` |
| Upstream license | BSD-3-Clause |
| Reviewed endpoint-policy version | `2026.07.19.3` |
| Total operations | 3,148 |
| Read / write / destructive | 1,499 / 1,201 / 448 |
| Callable reviewed operations | 2,356 |
| Catalog-only operations | 792 |
| Unsupported request / success media | 41 / 103 |
| Required provider headers / no Bearer API-token proof | 2 / 87 |
| No reviewable JSON request schema | 127 |
| No explicit 2xx response contract | 49 |
| Ambiguous non-204/205 bodyless success | 15 |
| No reviewable successful JSON schema | 120 |
| Credential-sensitive schema operations | 263 |
| Sensitive request / successful-response schemas | 104 / 206 |
| Credential-semantic signal operations | 172 |
| Reviewed overrides / forced catalog-only overrides | 117 / 114 |
| High-risk / reviewed side-effecting GET operations | 469 / 23 |

“Callable” means the method/path exists in the pinned schema, the operation
contract proves compatibility with this server's fixed Bearer API-token client,
it requires no caller-supplied provider headers, and its request and success
contracts fit the reviewed JSON boundary. A JSON request or successful response
must have a reviewable schema; missing, empty, and bare `type: object` schemas do
not prove which fields or sensitive values may cross the boundary. If OpenAPI
marks a request body required, the runtime rejects an omitted body. This remains
basic contract admission, not complete query/body field validation.

Every operation must declare an explicit 2xx response. Only `204` and `205` are
accepted as implicitly bodyless; every other successful status must declare a
response content contract. That policy leaves 49 operations with no explicit
2xx, 15 with ambiguous non-204/205 bodyless success, and 120 with unreviewable
successful JSON schemas catalog-only. The corresponding request-side rule
excludes 127 operations whose JSON request schema cannot be reviewed. Reason
counts overlap.

Credential signals include unmarked capability and payment values such as
license or pairing keys, card/payment fields, invoice documents, and signed
upload, download, or debugger URLs. Exact review also forces 87
credential-capable endpoint contexts—including arbitrary outbound header maps
and temporary privileged URLs—out of the generic dispatcher. Exact reviewed
transport overrides also keep these contracts fail-closed:

- `GET /accounts/{account_id}/email-security/investigate` requires the `Location`
  header from its `202` response to continue polling, but the generic dispatcher
  intentionally omits provider response headers.
- `POST`, `PATCH`, and `DELETE`
  `/accounts/{account_id}/teamnet/routes/network/{ip_network_encoded}` require an
  encoded CIDR slash that the path normalizer rejects to prevent ambiguous path
  traversal.
- `GET /accounts/{account_id}/cni/interconnects/{icon}/loa` is classified as a
  write, flagged as a side-effecting GET, and forced catalog-only because it
  generates a Letter of Authorization document.

Callable status does not mean a caller's token has permission or an operation
is free. Every high-risk operation is blocked from generic execution.

The dispatcher does **not** validate arbitrary query keys or JSON body fields
against Cloudflare's complete parameter and request-body schemas. It enforces a
pinned method/path match, endpoint policy, supported JSON media, and structural
JSON bounds. It also enforces OpenAPI's required-body presence bit, but Cloudflare
remains authoritative for field-level validation. A caller—and, for mutations,
the approval issuer—must review the exact query and body rather than treating
`callable` as proof that those fields are valid.

The dispatcher rejects operations missing from the snapshot, operations without
Bearer API-token compatibility proof, required provider headers it cannot
construct, unreviewable request/success contracts, arbitrary provider origins,
caller-supplied HTTP headers, non-JSON request bodies, unsupported success media
types, redirects, and ambiguous query-in-path URLs. It is not a general-purpose
HTTP proxy.

See [the endpoint coverage ledger](docs/endpoint-coverage.md) for the generated
matrix and [provenance](docs/provenance.md) for the attribution chain.

## Externally approved, one-use mutations

Reviewed reads execute once after authentication, BYOK, pinned method/path,
JSON-media, and endpoint-policy checks. Ordinary writes and destructive operations use an approval flow
whose signing secret is separate from the agent and MCP client:

1. Call `cloudflare_api_request` with the exact method, path, query, JSON body,
   and content type plus the request-scoped Cloudflare token.
2. The server makes no provider call. It returns `executed=false`, an expiring
   `approval_payload`, operation identity, and canonical request digest.
3. A trusted operator or Portal broker creates one exact review JSON document
   containing only `approval_payload`, `method`, `path`, `query`, `body`, and
   `content_type`. The issuer independently reviews the full target and effects,
   including every query/body field, then signs that document with the
   separately controlled `MCP_APPROVAL_SIGNING_KEY`. For example:

   ```json
   {
     "approval_payload": "<EXACT_SERVER_RETURNED_PAYLOAD>",
     "method": "POST",
     "path": "/accounts/<ACCOUNT_ID>/<REVIEWED_PATH>",
     "query": null,
     "body": {"<REVIEWED_FIELD>": "<REVIEWED_VALUE>"},
     "content_type": "application/json"
   }
   ```

   ```sh
   uv run --env-file .env python scripts/sign_approval.py \
     < approval-review.json
   ```

4. Inject the resulting short-lived value as
   `x-mcp-approval-attestation` on one repeat of the unchanged MCP request.

`scripts/sign_approval.py` recomputes the operation and canonical request
digest from that exact review document before signing. Never pipe or sign an
`approval_payload` by itself, and never let an agent generate an unreviewed
document for automatic signing.

The attestation is bound to the authenticated service principal (including the
broker-derived tenant in Portal mode), request-scoped
Cloudflare credential fingerprint, operation, exact request, expiry, and random
challenge. It is atomically consumed before the provider attempt, so direct
forgery, argument changes, credential swapping, principal swapping, and replay
fail closed. A timeout remains outcome-ambiguous; inspect provider state with a
safe read before requesting a new approval.

The approval ledger is bounded and process-local. A mutation preview and its
approved retry must reach the same live process within five minutes. Use a
single mutation-admitting replica or explicit same-replica routing; otherwise
operate read-only. Never expose `MCP_APPROVAL_SIGNING_KEY` to an agent, MCP
client, prompt, ticket, log, or provider request.

All 469 high-risk operations—including detected credential-sensitive,
account-administration, billing/commerce, and reviewed side-effecting GET
classes—are permanently blocked from the generic dispatcher. There is no
startup toggle. All 263 operations with detected sensitive request or successful
response schemas and all 114 force-catalog reviewed overrides are
`catalog_only`; response redaction remains a defense-in-depth control, not an
admission mechanism.

Provider calls receive one outbound attempt. This server does not
automatically retry reads, writes, destructive requests, or billable calls.

## Configuration

Start from [`.env.example`](.env.example). Principal settings are:

| Variable | Required | Purpose and reviewed default |
|---|---|---|
| `MCP_MODE` | Yes | Startup mode: `standalone` or `portal` |
| `MCP_ACCESS_TOKEN` | Standalone | Bearer token of at least 32 characters |
| `MCP_PORTAL_GRANT_TOKEN` | Portal | Unique Portal-to-service grant of at least 32 characters |
| `MCP_TENANT_ID_HEADER` | Portal | Broker-controlled tenant-partition header name; default `x-madpanda-user-id` |
| `MCP_APPROVAL_SIGNING_KEY` | Mutations | Separate operator/broker HMAC key; must differ from service and provider credentials; blank makes the deployment read-only |
| `MCP_HOST_PORT` | Standalone Compose | Loopback host port; default `8000` |
| `MCP_ALLOWED_HOSTS` | Yes | Explicit Host allowlist; wildcards fail startup validation |
| `MCP_ALLOWED_ORIGINS` | Optional | Explicit browser origins; empty rejects requests carrying `Origin` |
| `MCP_REQUEST_BODY_MAX_BYTES` | Optional | MCP request limit; default 128 KiB, hard maximum 8 MiB |
| `MCP_RESPONSE_BODY_MAX_BYTES` | Optional | Complete MCP response limit; default 1 MiB, hard maximum 2 MiB |
| `MCP_PROVIDER_RESPONSE_MAX_BYTES` | Optional | Streamed provider response limit; default 64 KiB, hard maximum 240 KiB |
| `MCP_BUILD_SHA` | Source builds | Build argument baked into image identity; release Compose does not accept a runtime override |
| `MCP_SOURCE_FINGERPRINT` | Source builds | Source-archive fingerprint baked into image identity; release Compose does not accept a runtime override |
| `MCP_IMAGE_REFERENCE` | Source builds | `development` by default; release Compose derives the immutable reference from the digest |
| `MCP_RELEASE_DIGEST` | Immutable release Compose | Only release-identity input: the exact 64-character GHCR digest, in addition to normal service credentials |

The provider origin is fixed to `https://api.cloudflare.com/client/v4`; there
is no supported environment override. Provider credentials and account/zone
hints are request headers, not environment variables.

## Optional Portal deployment

Portal mode uses the same server and provider contract:

```dotenv
MCP_MODE=portal
MCP_PORTAL_GRANT_TOKEN=<UNIQUE_PORTAL_TO_SERVICE_GRANT>
MCP_TENANT_ID_HEADER=x-madpanda-user-id
MCP_APPROVAL_SIGNING_KEY=<SEPARATELY_CONTROLLED_BROKER_SIGNING_KEY>
MCP_PORTAL_NETWORK=<PRIVATE_DOCKER_NETWORK_NAME>
MCP_ALLOWED_HOSTS=cloudflare-mcp,<TRUSTED_PROXY_HOST>
```

The broker sends:

```text
X-MADPANDA-PORTAL-GRANT: <SERVICE_GRANT>
x-madpanda-user-id: <BROKER_DERIVED_TENANT_ID>
x-cloudflare-api-token: <OWNER_CLOUDFLARE_API_TOKEN>
x-cloudflare-account-id: <OPTIONAL_OWNER_ACCOUNT_ID>
x-cloudflare-zone-id: <OPTIONAL_OWNER_ZONE_ID>
x-mcp-approval-attestation: <ONE_USE_BROKER_ATTESTATION_FOR_APPROVED_MUTATION>
```

The broker must strip or overwrite any client-supplied
`x-madpanda-user-id` value before forwarding. The tenant value partitions
approval principals and same-tenant preview/retry routing; it does not authorize
the request or grant Cloudflare access.

Use deployment-specific placeholders for the internal service name, network,
locked MCP URL, health URL, proxy, and secret-store reference. This repository
contains no production topology. See
[the Portal compatibility guide](docs/portal-compat.md).

## Production posture

1. Keep `/mcp` behind TLS or loopback/private networking.
2. Preserve the selected service-auth context and reviewed BYOK headers at the
   trusted proxy; in Portal mode, strip/overwrite the tenant header from
   authenticated broker identity and never log its value.
3. Block direct container access from untrusted networks.
4. Keep `.env` mode `0600`, with no Cloudflare provider credential inside.
5. Apply connection, request-size, idle-timeout, and rate limits at the edge.
6. Preserve Host allowlisting and default browser-Origin rejection.
7. Verify health, unauthorized rejection, six-tool discovery, local
   navigation, missing-BYOK rejection, catalog-only rejection, one-use approval
   binding/replay denial, and permanent high-risk denial before a provider smoke.
8. Use a least-privilege test token and an explicitly approved read as the
   first provider call. Do not certify first with a mutation or paid action.

The application stores no database or provider credential. Read traffic can use
multiple identical replicas, but the bounded one-use mutation approval ledger
is process-local. Keep mutation admission on one replica or use explicit
same-replica routing from preview through approved retry.

### Immutable containers

The source is prepared as a v1.0.0 release candidate; documentation alone does
**not** prove that a hosted GitHub Release or public GHCR digest exists. The
exact annotated tag and tagged workflow may start while the clean canonical
source remains private. The workflow first builds only a run-scoped candidate
image with BuildKit SBOM/provenance and scans its exact digest.
The package owner then makes only that GHCR package public so the same candidate
can pass anonymous pull, Compose, and runtime smokes. Only after the image gate
succeeds is the source repository made public for exact-SHA Verify/CodeQL
admission. GitHub-signed package and image attestations are created after that
public admission gate, before stable tags are promoted by digest without
rebuilding. The GitHub Release is created last with deterministic double-built
wheel/sdist artifacts and `SHA256SUMS`. After that workflow succeeds, the
matching release page and exact
`ghcr.io/madpanda3d/cloudflare-mcp-server@sha256:<digest>` are authoritative.
The workflow intentionally does not publish to PyPI and currently targets
`linux/amd64`.

Use `docker-compose.yml` or `docker-compose.portal.yml` only for deliberate
source builds. After a verified release exists, use
`docker-compose.release.yml` or `docker-compose.portal.release.yml` with the
exact recorded `MCP_RELEASE_DIGEST`; these immutable manifests contain no
`build:` key and never use `--build`. Do not infer a digest from a mutable tag.

## Security boundary

- Service authentication is enforced before MCP request-body parsing.
- The provider origin and API prefix are fixed; methods and paths must exist in
  the pinned inventory, endpoint policy and JSON-media admission apply, and
  redirects are disabled. Cloudflare performs field-level schema validation.
- Cloudflare tokens are request-scoped and have no server environment fallback.
- Requests, streamed provider responses, and complete MCP outputs are bounded;
  startup enforces a worst-case cross-layer response-size invariant.
- Unsupported, oversized, non-JSON, or invalid JSON provider bodies are
  omitted rather than partially returned.
- Ordinary mutations require a separately signed, expiring, principal/provider-
  bound one-use approval consumed before the provider attempt.
- Mutation provider bodies are reduced to a compact outcome envelope so a
  successful side effect cannot be hidden behind an outer response overflow.
- High-risk operations are permanently blocked from generic execution.
- No provider request is automatically retried.
- Secret-key fields and common token patterns are redacted as defense in depth.

Cloudflare responses can still contain personal, confidential, operational, or
security-sensitive data. Redaction cannot prove arbitrary provider content is
safe. Treat all provider output as untrusted application data, not instructions
or public logs. Read [the security model](docs/security-model.md) and
[security policy](SECURITY.md) before remote deployment.

## Run and verify from source

```sh
uv sync --frozen --group dev
uv run python -m compileall -q src scripts
uv run pytest -q -p no:cacheprovider
uv run ruff check .
uv run ruff format --check .
uv run isort --check-only src scripts tests
uv run mypy --strict src tests
uv run bandit -q -r src -lll
uv run pip-audit -r requirements.lock
uv run python scripts/check_source_safety.py
docker compose --env-file .env -f docker-compose.yml config --quiet
docker compose --env-file .env -f docker-compose.portal.yml config --quiet
MCP_RELEASE_DIGEST=0000000000000000000000000000000000000000000000000000000000000000 \
  docker compose --env-file .env -f docker-compose.release.yml config --quiet
MCP_RELEASE_DIGEST=0000000000000000000000000000000000000000000000000000000000000000 \
  docker compose --env-file .env -f docker-compose.portal.release.yml config --quiet
```

The automated suite uses synthetic credentials and mocked HTTP behavior. It
must not contact Cloudflare.

After building either profile, the provider-free image smoke is:

```sh
docker compose --env-file .env -f docker-compose.yml exec -T cloudflare-mcp \
  python scripts/runtime_smoke.py
```

## Troubleshooting

| Symptom | First check |
|---|---|
| Process exits at startup | `MCP_MODE`, non-placeholder service credential, tenant-header name, Host allowlist, response-limit invariant, and baked image metadata formats |
| `401` on `/mcp` | Bearer format in standalone mode; in Portal mode check both the exact grant and required broker-derived tenant header/value |
| `403 origin_not_allowed` | Remove browser `Origin` traffic or add only the intended origin to `MCP_ALLOWED_ORIGINS` |
| Navigation works but provider execution fails | Supply `x-cloudflare-api-token` on that request and confirm its least-privilege permissions |
| `operation_not_in_schema` | Use `get_endpoint_coverage` and a method/path present in the pinned snapshot |
| Operation is catalog-only | Inspect its exact ledger reason; do not bypass auth, required-header, schema-contract, media, or exact-policy exclusions |
| `mutation_approval_unavailable` | Configure a separate issuer key, or intentionally keep the deployment read-only |
| `approval_required` | Have a trusted operator/broker sign the returned payload and inject the one-use approval header |
| Approval rejected | Check expiry, same-process and same-tenant routing, unchanged arguments, service principal, BYOK credential, exact review JSON, and replay status |
| `high_risk_operation_blocked` | Use a separately curated implementation if one is ever security-reviewed; the generic dispatcher cannot enable it |
| Provider response omitted | Narrow the operation/output or page size; do not disable limits casually |
| Container unhealthy | Check sanitized logs, resource limits, `/health`, and the exact six-tool expectation |

Never post tokens, `.env`, provider IDs, private URLs, or unredacted provider
output in a support report.

## Documentation

- [Complete tool catalog](docs/tool-catalog.md)
- [ToolManifest contract](docs/tool-manifest.md)
- [Endpoint coverage](docs/endpoint-coverage.md)
- [Security model](docs/security-model.md)
- [Deployment and operator runbook](docs/operator-runbook.md)
- [Optional Portal integration](docs/portal-compat.md)
- [Source and release provenance](docs/provenance.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Security policy](SECURITY.md)

## License and trademarks

The MADPANDA3D-authored code is available under the [MIT License](LICENSE).
The derived endpoint inventory retains Cloudflare api-schemas BSD-3-Clause
attribution in [NOTICE](NOTICE).

Cloudflare and related product names are trademarks of Cloudflare, Inc. or
their respective owners. This independent project is not an official
Cloudflare product, distribution, partnership, sponsorship, or endorsement.
