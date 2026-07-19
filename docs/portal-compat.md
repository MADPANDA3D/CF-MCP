# MAD MCP Portal Compatibility

Portal support is optional. The same Cloudflare MCP runtime operates as an
independent standalone server; Portal mode changes only service-to-service
authentication and network placement. Cloudflare authorization remains
request-scoped BYOK in both modes.

## Required runtime contract

```dotenv
MCP_MODE=portal
MCP_PORTAL_GRANT_TOKEN=<UNIQUE_SERVICE_GRANT_OF_AT_LEAST_32_CHARACTERS>
MCP_TENANT_ID_HEADER=x-madpanda-user-id
MCP_APPROVAL_SIGNING_KEY=<SEPARATELY_CONTROLLED_BROKER_SIGNING_KEY>
MCP_PORTAL_NETWORK=<PRIVATE_DOCKER_NETWORK_NAME>
MCP_ALLOWED_HOSTS=cloudflare-mcp,<TRUSTED_PROXY_HOST>
MCP_ALLOWED_ORIGINS=
```

Startup fails if Portal mode has no valid grant or the configured tenant-header
name is invalid. Every MCP request then requires both the matching grant and a
valid broker-derived tenant value in the configured header. The grant
authenticates the broker to this MCP service; it is not a Cloudflare credential
and must be unique to the service and environment. The tenant partitions
approval principals but is not authorization and grants no Cloudflare access.
The approval signing key is a second trust boundary: it must differ from both
the Portal service grant and every provider credential, and must be unavailable
to the agent-facing execution path.

## Broker-to-provider headers

| Header | Required | Source |
|---|---:|---|
| `X-MADPANDA-PORTAL-GRANT` | Every MCP call | Portal secret store; fixed for this service/environment |
| `x-madpanda-user-id` | Every MCP call | Broker-derived tenant identity; header name is configurable with `MCP_TENANT_ID_HEADER` |
| `x-cloudflare-api-token` | Provider calls and optional live verification | Authorized owner's request-scoped secret context |
| `x-cloudflare-account-id` | Optional | Authorized owner's account hint |
| `x-cloudflare-zone-id` | Optional | Authorized owner's zone hint |
| `x-mcp-approval-attestation` | One approved mutation retry | Portal approval service; externally signed, short-lived, and one use |

The broker must not place these values in a registry record, URL, job payload,
ticket, trace, analytics event, or log. At its trust boundary it must remove or
overwrite any client-supplied tenant header and inject the tenant derived from
the authenticated Portal session. It should inject provider headers only after
authenticating the owner and authorizing the specific connection.

The five agent-ready navigation tools need the Portal grant **and tenant
header**, but no Cloudflare token unless `check_configuration` requests live
token verification. `cloudflare_api_request` needs the two-part Portal service
context plus the request-scoped provider token.

## Generic registry example

Field names vary by broker. A public-safe logical record looks like:

```yaml
service_id: cloudflare
transport: streamable-http
mcp_url: http://<CLOUDFLARE_MCP_SERVICE>:8000/mcp
health_url: http://<CLOUDFLARE_MCP_SERVICE>:8000/health
auth:
  kind: broker-service-context
  grant_header: X-MADPANDA-PORTAL-GRANT
  grant_secret_ref: <PORTAL_SECRET_REFERENCE>
  tenant_header: x-madpanda-user-id
  tenant_source: authenticated-owner
  client_tenant_policy: strip-and-overwrite
provider_credentials:
  kind: request-scoped-headers
  required:
    - x-cloudflare-api-token
  optional:
    - x-cloudflare-account-id
    - x-cloudflare-zone-id
mutation_approval:
  kind: external-one-use-attestation
  header: x-mcp-approval-attestation
  signing_key_ref: <SEPARATE_APPROVAL_SIGNING_KEY_REFERENCE>
  ttl_seconds: 300
catalog:
  source: list_capabilities
  pin: <APPROVED_CATALOG_VERSION_AND_DESCRIPTOR_HASH>
```

Use internal service discovery or a private TLS-protected endpoint. The public
repository intentionally contains no production hostname, IP address,
filesystem path, proxy target, tenant ID, network name, or secret reference.

## Catalog admission

The provider-owned ToolManifest is authoritative. On admission or upgrade, the
Portal should:

1. Authenticate with the service grant and a broker-derived tenant header.
2. Call `list_capabilities(include_descriptors=true)` without a Cloudflare
   token.
3. Verify catalog version, six native tools, tier counts, and deterministic
   descriptor hash against the approved deployment record.
4. Store descriptors and release identities, never provider credentials.
5. Use `find_tools` for default agent discovery and `get_tool_usage` for the
   exact selected descriptor.
6. Exclude the legacy dispatcher from default agent selection.
7. Preserve native tool names when invoking the service; canonical names and
   aliases are discovery compatibility only.

Do not hard-code a stale tool list. Reject an unreviewed descriptor-hash change
even when HTTP health succeeds.

## Operation and approval policy

Before routing the advanced dispatcher, the Portal should:

1. Use `get_endpoint_coverage` to confirm the method/path exists.
2. Reject `catalog_only` operations.
3. Surface classification, high-risk state, risk flags, Bearer-auth evidence,
   required provider headers/body, request/success-contract state, media types,
   and provider side effects to the authorized user.
4. Reject every high-risk operation; the generic dispatcher has no enable
   toggle. Sensitive-schema and other reviewed operations are policy-forced
   `catalog_only`; any remaining high-risk operation that is merely
   JSON-transport callable in the ledger is still permanently denied by runtime
   policy.
5. Submit ordinary mutation arguments plus request-scoped BYOK without an
   approval header to obtain the no-provider-call preview.
6. After explicit user/operator approval, construct the exact review JSON with
   `approval_payload`, `method`, `path`, `query`, `body`, and `content_type`.
   Independently review every field, then sign that document in a trusted broker
   context whose signing key is never available to the agent or MCP client.
7. Repeat the unchanged call once on the same live provider process, injecting
   the resulting value as `x-mcp-approval-attestation`, with the same
   broker-derived tenant header, before its five-minute expiry.

Portal policy may require additional human approval, allowlists, or deny rules.
It must never weaken service authentication, provider token scope, pinned
method/path, Bearer-auth proof, required-header/body, request/success-contract,
endpoint-policy, or JSON-media checks, one-use approval binding, permanent
high-risk denial, response bounds, or no-retry behavior.
The generic dispatcher does not validate arbitrary query/body fields against
the complete Cloudflare schema; Cloudflare remains authoritative, and the
issuer must review the exact request. Approval is bound to the tenant-partitioned
service principal, BYOK fingerprint, operation, exact canonical request,
expiry, and random challenge; it is consumed before the provider attempt.

The approval ledger is process-local. Portal routing must keep preview and
approved retry on the same tenant and live replica, or designate a single
mutation-admitting replica. Read traffic may scale independently.

### Attestation wire format

The preview's `approval_payload` is canonical base64url JSON and is the value
ultimately signed unchanged. The issuer must first validate it against the
independently reviewed exact-request JSON. After that validation, the wire
signature is HMAC-SHA-256 over the ASCII bytes
`cloudflare-mcp-approval-v1\0<approval_payload>`, encodes the signature as
unpadded base64url, and sends `<approval_payload>.<signature>` in
`x-mcp-approval-attestation`. `scripts/sign_approval.py` is the executable
reference implementation: it accepts the six-field review JSON on standard
input, recomputes the operation and request digest, and refuses bare-payload
signing. The broker must never accept an agent-supplied attestation as evidence
of approval, blindly sign an agent-produced document, or expose the signing key
to the agent.

Treat timeouts and transport failures as outcome-ambiguous for mutations. Do
not automatically replay them; reconcile Cloudflare state with a safe read.

## Error handling

The broker may relay normalized error types needed for recovery, but must
sanitize:

- service grants and bearer tokens
- Cloudflare API tokens
- account, zone, and provider resource identifiers not needed by the caller
- credential-bearing URLs or query values
- provider response bodies containing personal or confidential data
- private topology and secret-store references

Authentication failures—including a missing or invalid tenant partition—should
remain distinguishable from missing BYOK,
unknown operation, catalog-only transport, approval required/replayed, high-risk
blocked, provider permission, quota, and bounded-response errors without
revealing the rejected value.

## Portal deployment

The checked-in `docker-compose.portal.yml` expects an existing private network:

```sh
docker network inspect <PRIVATE_DOCKER_NETWORK_NAME>
docker compose --env-file .env -f docker-compose.portal.yml config --quiet
docker compose --env-file .env -f docker-compose.portal.yml up -d --build
docker compose --env-file .env -f docker-compose.portal.yml ps
docker compose --env-file .env -f docker-compose.portal.yml exec -T cloudflare-mcp \
  python scripts/runtime_smoke.py
```

The profile exposes the application port only to that network. Broker routing,
TLS, rate limits, secret storage, and deployment identity remain operator
responsibilities.

`docker-compose.portal.yml` is the source-build profile. A verified release must
use `docker-compose.portal.release.yml` with the exact `MCP_RELEASE_DIGEST` and
without `--build`; the immutable profile contains no build definition.

## Admission checklist

- [ ] Exact source, package, or immutable image identity is verified.
- [ ] Catalog version, descriptor hash, native count, and tier counts match.
- [ ] Endpoint policy is `2026.07.19.3`: 3,148 inventoried, 2,356 callable,
      792 catalog-only.
- [ ] Operations without Bearer API-token proof, operations requiring unsupported
      provider headers, and operations with unreviewable request/success schemas
      remain catalog-only; required request bodies fail when omitted.
- [ ] Only `204`/`205` may be implicitly bodyless; no-explicit-2xx and ambiguous
      other-bodyless-success operations remain catalog-only.
- [ ] The reviewed LOA-generating GET, `Location`-dependent `202` continuation,
      and encoded-CIDR path operations remain catalog-only.
- [ ] Portal mode refuses startup without its unique grant.
- [ ] The broker strips/overwrites client tenant input and injects only the
      authenticated tenant identity.
- [ ] Missing or incorrect grants and missing, invalid, or duplicate tenant
      headers are rejected before MCP parsing.
- [ ] Browser-Origin traffic is rejected by default.
- [ ] Host allowlist contains only intended private service/proxy names.
- [ ] Five local navigation tools work without Cloudflare credentials.
- [ ] Provider calls fail without request-scoped `x-cloudflare-api-token`.
- [ ] No provider token environment fallback exists.
- [ ] Alternate origins, redirects, unknown paths, and catalog-only operations
      fail closed.
- [ ] Mutations preview without a provider call; the issuer signs only
      independently reviewed exact-request JSON; unsigned, changed, expired,
      cross-tenant/principal/BYOK, wrong-process, and replayed approvals fail
      closed.
- [ ] All 469 high-risk operations are permanently blocked.
- [ ] Request, provider-response, and complete MCP-response limits are active.
- [ ] Provider-free runtime smoke passes before any Cloudflare call.

After admission, use a dedicated least-privilege token for a separately
authorized narrow read. Do not certify first with a mutation, credential
change, purchase, billing action, domain operation, or account administration.
