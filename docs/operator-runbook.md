# Cloudflare MCP Operator Runbook

This runbook covers an independent source deployment and the optional Portal
profile. Every value in angle brackets is a placeholder. Never place a
Cloudflare provider token in the server `.env` file.

## Prerequisites

- Docker Engine with Compose v2
- Git and `curl`
- Python 3.12 or 3.13 plus `uv` for local source verification
- a trusted TLS reverse proxy or private network for any non-loopback client
- a least-privilege Cloudflare API token stored in the MCP client's or broker's
  protected secret facility

## Verify source before deployment

For a release, check out the exact stable tag and compare its commit with the
release record. Then run the provider-free gates:

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
MCP_RELEASE_DIGEST=<64_HEX_IMAGE_DIGEST> \
  docker compose --env-file .env -f docker-compose.release.yml config --quiet
MCP_RELEASE_DIGEST=<64_HEX_IMAGE_DIGEST> \
  docker compose --env-file .env -f docker-compose.portal.release.yml config --quiet
```

For either release command, `MCP_RELEASE_DIGEST` is the only release-identity
input. Build SHA and source fingerprint are baked into the image during
publication and the release manifests do not accept runtime overrides for them.

These checks use synthetic credentials and mocked HTTP behavior. A provider
smoke is a separate, explicitly authorized step.

## Standalone deployment

### 1. Create configuration

```sh
python3 scripts/init_runtime_env.py --mode standalone
```

This creates an ignored mode-`0600` file with separate random service and
mutation-approval secrets, prints no secret, and never overwrites an existing
`.env`.

Set at least:

```dotenv
MCP_MODE=standalone
MCP_HOST_PORT=8000
MCP_ALLOWED_HOSTS=localhost,127.0.0.1
MCP_ALLOWED_ORIGINS=
MCP_BUILD_SHA=development
MCP_SOURCE_FINGERPRINT=development
```

Keep the generated `MCP_APPROVAL_SIGNING_KEY` unavailable to agents and clients,
and never reuse the service grant, Bearer token, or Cloudflare token as that
key. Blanking it intentionally makes provider execution read-only. Keep the
Cloudflare token out of this file.

### 2. Build and start

```sh
docker compose --env-file .env -f docker-compose.yml config --quiet
docker compose --env-file .env -f docker-compose.yml up -d --build
docker compose --env-file .env -f docker-compose.yml ps
curl --fail --silent --show-error http://127.0.0.1:8000/health
```

The standalone profile publishes only to loopback by default. Keep it there
unless an explicit firewall and proxy design requires otherwise.

For a verified immutable release, set only the exact `MCP_RELEASE_DIGEST` as
release identity, then use `docker-compose.release.yml` without `--build`.
Normal service credentials are still required. The manifest pulls only
`ghcr.io/madpanda3d/cloudflare-mcp-server@sha256:<digest>`.

### 3. Run the provider-free image smoke

```sh
docker compose --env-file .env -f docker-compose.yml exec -T cloudflare-mcp \
  python scripts/runtime_smoke.py
```

The smoke verifies health and build identity, auth-before-body rejection,
browser-Origin rejection, exact six-tool discovery, local navigation, and
missing-BYOK rejection. It must not contact Cloudflare.

### 4. Connect a client

Use `http://127.0.0.1:8000/mcp` for a same-host client. Supply the standalone
bearer token and request-scoped `x-cloudflare-api-token` through the client's
protected secret/header facility. Optional account and zone hints belong in
the same request-scoped header configuration.

Use TLS before crossing a host boundary.

Mutation-capable clients must support trusted, per-request injection of
`x-mcp-approval-attestation`. A client limited to static headers is read-only.

## Optional Portal deployment

Portal mode is service-to-service. It expects an existing private Docker
network and a trusted broker that injects the authorized owner's Cloudflare
credential per request.

Set:

```dotenv
MCP_MODE=portal
MCP_PORTAL_GRANT_TOKEN=<UNIQUE_PORTAL_TO_SERVICE_GRANT>
MCP_TENANT_ID_HEADER=x-madpanda-user-id
MCP_APPROVAL_SIGNING_KEY=<SEPARATELY_CONTROLLED_BROKER_SIGNING_KEY>
MCP_PORTAL_NETWORK=<PRIVATE_DOCKER_NETWORK_NAME>
MCP_ALLOWED_HOSTS=cloudflare-mcp,<TRUSTED_PROXY_HOST>
MCP_ALLOWED_ORIGINS=
MCP_BUILD_SHA=<FULL_SOURCE_COMMIT_SHA>
MCP_SOURCE_FINGERPRINT=<SHA256_OF_EXACT_SOURCE_ARCHIVE>
```

Then validate the already-approved network and start the Portal profile:

```sh
docker network inspect <PRIVATE_DOCKER_NETWORK_NAME>
docker compose --env-file .env -f docker-compose.portal.yml config --quiet
docker compose --env-file .env -f docker-compose.portal.yml up -d --build
docker compose --env-file .env -f docker-compose.portal.yml ps
docker compose --env-file .env -f docker-compose.portal.yml exec -T cloudflare-mcp \
  python scripts/runtime_smoke.py
```

The Portal profile exposes port 8000 only to the selected Docker network. It
does not publish a host port. Configure the broker using
[portal-compat.md](portal-compat.md).

Every Portal MCP request requires both the matching grant and the
broker-controlled tenant header. At the trust boundary, strip or overwrite any
client-supplied tenant value and inject the identity derived from the
authenticated Portal session. The tenant partitions approval principals and
same-tenant preview/retry routing; it does not authorize the request or grant
Cloudflare permissions.

## Reverse-proxy requirements

- Terminate TLS with a certificate valid for the client-facing hostname.
- Preserve the selected service-auth context. In Portal mode, strip or
  overwrite any client-supplied tenant header, then forward the grant and the
  tenant derived from the authenticated broker session.
- Forward the three documented Cloudflare BYOK/hint headers only from trusted
  clients or the trusted broker; never log their values. Accept the separate
  one-use approval header only from the trusted approval path.
- Preserve MCP streaming/session response headers even though the server uses
  stateless JSON responses.
- Set request-size, connection, idle-timeout, and rate-limit policies that do
  not exceed server bounds.
- Restrict direct access to the container port.
- Send a Host value included in `MCP_ALLOWED_HOSTS`.
- Do not add broad CORS. Requests carrying `Origin` are rejected unless that
  exact origin is explicitly allowlisted.

## Health and readiness

`GET /health` is the only unauthenticated readiness endpoint. Check at least:

- `status` is `healthy`
- `service` is `cloudflare-mcp`
- `tool_count` is `6`
- mode matches the intended startup profile
- catalog, descriptor, build, source, and image fields match the approved
  deployment identity
- endpoint policy is `2026.07.19.3`, with 3,148 inventoried, 2,356 callable,
  792 catalog-only, and all 469 high-risk operations permanently blocked
- no-Bearer-proof, required-provider-header, unreviewable request/success-schema,
  no-explicit-2xx, and ambiguous non-204/205 bodyless-success operations remain
  catalog-only; required request bodies fail when omitted
- the reviewed LOA-generating GET, `Location`-dependent `202` continuation, and
  encoded-CIDR path operations remain catalog-only
- configuration fields report credential presence only, never values
- mutation approval configuration and byte limits match the approved deployment
- high-risk execution reports `permanently_blocked`

A healthy process does not prove Cloudflare credentials, token permissions,
provider availability, account access, quota, pricing, or a specific operation.
Those properties are request-specific.

## First provider verification

After provider-free checks pass:

1. Create or select a dedicated least-privilege test token.
2. Approve one narrow read and its target account/zone.
3. Call `check_configuration` locally first.
4. Optionally call it again with `verify_cloudflare_token=true` and the token
   header.
5. Use `get_endpoint_coverage` for the intended read.
6. Execute the read once. Confirm it is not retried and returned data is
   handled as sensitive.

Do not certify first with a mutation, credential operation, account action,
purchase, billing call, top-up, domain action, or deletion.

## Mutation operation procedure

1. Find the exact operation and inspect `classification`, `coverage_status`,
   Bearer-auth evidence, required provider headers/body, request/success-contract
   state, `high_risk`, and `risk_flags`.
2. Confirm the token has only the required provider permissions.
3. Submit the exact dispatcher arguments plus request-scoped BYOK without an
   approval attestation.
4. Verify the result says `executed=false` and records no provider status.
5. Create one exact review JSON object containing only `approval_payload`,
   `method`, `path`, `query`, `body`, and `content_type`. Review every value,
   the operation identity, request digest, target, and effects with the
   approving user. Cloudflare—not this generic dispatcher—remains authoritative
   for query/body field schemas.
6. In a trusted issuer context, sign that exact review document:

   ```sh
   uv run --env-file .env python scripts/sign_approval.py \
     < approval-review.json
   ```

   The script recomputes the pinned operation and canonical request digest and
   refuses bare-payload signing. Never blindly sign an `approval_payload` or an
   agent-produced review document.
7. Repeat the unchanged request once, on the same live process and same
   broker-derived tenant in Portal mode, with the resulting value in
   `x-mcp-approval-attestation`.
8. If the result is ambiguous or times out, read provider state before any
   manual retry.

The proof is bound to the service principal (including the broker-derived
tenant in Portal mode), BYOK fingerprint, request,
operation, random challenge, and five-minute expiry, then consumed before the
provider attempt. Never provide the signing key to an agent. High-risk
operations have no startup opt-in and remain blocked by the generic dispatcher.

## Upgrade procedure

1. Read release notes for tool, catalog, schema, mode, and environment changes.
2. Fetch the exact release tag or immutable image digest from the release.
3. Verify source/package checksums and available attestations.
4. Back up the current configuration through the normal secret-management
   process without exporting provider tokens.
5. Run provider-free tests and Compose validation against the candidate.
6. Build or pull the candidate without replacing the running instance.
7. Start it on an isolated loopback port or private network.
8. Run health and `runtime_smoke.py`.
9. Verify catalog version and descriptor hash before switching routing.
10. Observe auth failures, latency, restarts, bounds, and error types before a
    separately approved provider read.

Do not infer a package namespace or digest from a mutable tag. Use the exact
identity in the release record after a package exists.

For v1.0.0, source readiness does not prove hosted availability. The tag
workflow fixes `SOURCE_DATE_EPOCH` to the commit time, builds the wheel and
source archive twice, and requires identical bytes. It publishes only a
run-scoped GHCR candidate first while the clean source can remain private.
After candidate scan, the package owner makes only that GHCR package public so
anonymous pull, Compose, and smoke gates can pass. The source repository is made
public only after the image gate for exact-SHA Verify/CodeQL admission. Stable
tags are not attached until GitHub-signed package and image attestations are
created after that public admission gate. Stable tags are then attached to the
same digest without rebuilding and the GitHub Release is created last. Before
the workflow succeeds, use source verification only. After it succeeds, the
matching GitHub Release and exact digest are authoritative. No PyPI publication
is part of this flow.

## Rollback procedure

1. Stop routing new calls to the failed candidate.
2. Restore the previous verified tag or release digest and its matching
   configuration contract.
3. Run provider-free health and runtime smoke.
4. Verify the previous catalog and descriptor identity.
5. Restore routing and monitor.
6. Preserve sanitized logs and exact build identities for diagnosis.

Rollback cannot reverse a Cloudflare-side mutation already accepted by the
provider. Reconcile provider state separately.

## Troubleshooting

| Symptom | First checks |
|---|---|
| Process exits during startup | `MCP_MODE`, selected token length, tenant-header name, Host allowlist, and baked image metadata formats |
| `401` on `/mcp` | Standalone Bearer formatting; in Portal mode verify both the exact grant and the required broker-derived tenant header/value |
| Host or Origin rejected | `MCP_ALLOWED_HOSTS`, proxy Host preservation, and intentional `MCP_ALLOWED_ORIGINS` |
| Local navigation works but provider call fails | Request-scoped Cloudflare token, token status, and least-privilege permissions |
| Account-token verification fails | Supply the matching optional account ID hint |
| Operation absent or catalog-only | Use the pinned coverage ledger; do not bypass the JSON transport boundary |
| Approval unavailable | Configure a separately controlled issuer key, or keep the deployment read-only |
| Approval rejected | Check signature, expiry, same-process and same-tenant routing, unchanged exact review JSON/request, service principal, BYOK, and replay state |
| High-risk operation rejected | Expected generic-dispatcher policy; there is no enable toggle |
| Provider output omitted | Narrow result size/media; do not raise bounds casually |
| Timeout or transport error | Read provider state before any manual retry |
| Container unhealthy | `/health`, expected tool count, sanitized logs, and CPU/memory/PID limits |
| Portal cannot connect | Private network name, service membership, broker route, and Host allowlist |

If diagnostic output may contain credentials or provider data, redact it before
sharing. Follow [SUPPORT.md](../SUPPORT.md) for public reports and
[SECURITY.md](../SECURITY.md) for vulnerabilities.
