# Source and Release Provenance

This project tracks separate identities for source, endpoint specification,
reviewed endpoint policy, Python package, MCP contract, and container artifacts.
None substitutes for the others.

## Cloudflare schema reference

The checked-in endpoint inventory is derived deterministically from the official
Cloudflare api-schemas OpenAPI source.

| Field | Value |
|---|---|
| Repository | <https://github.com/cloudflare/api-schemas> |
| File | `openapi.json` |
| Pinned commit | `aefa753f1190c85866f65dcc7f348e18c7a1ca4a` |
| Snapshot SHA-256 | `6c141cf38b45a514fcba04d322d43916eaba179a4442c8d91afaf5e7a66c8f1f` |
| OpenAPI version | `3.0.3` |
| API title/version | Cloudflare API `4.0.0` |
| License | BSD-3-Clause |
| Total operations | 3,148 |
| JSON-transport callable | 2,356 |
| Catalog-only | 792 |
| Reviewed endpoint-policy version | `2026.07.19.3` |
| Generated JSON SHA-256 | `8f684b02740d4f3ec8973ea202b4a1e3c949b6260995dec7f36a753073b77d96` |
| Generated Markdown SHA-256 | `ff86704835f635d7adab1864127d39df24791df443e8d82969d966eed2cbb12e` |

The pinned upstream license is linked and reproduced in [NOTICE](../NOTICE).
Cloudflare retains its copyright and trademark rights. This repository's MIT
License covers MADPANDA3D-authored code; it does not relicense upstream source.

## Generated endpoint inventory

`scripts/build_endpoint_coverage.py` consumes the exact pinned OpenAPI file and
generates:

- `src/cloudflare_mcp/data/endpoint_coverage.json`
- `docs/endpoint-coverage.md`

Generation records source identity, method/path, operation ID, feature area,
request/success media types, classification, overlapping risk flags, reviewed
policy overrides, auditable schema-sensitivity findings, and callable or
catalog-only status. The source OpenAPI file itself is not copied into the
repository.

Policy `2026.07.19.3` also guarantees an approval-safe operation identity for
every row. Forty-nine pinned upstream operations have no usable `operationId`;
for those, the generator emits a deterministic
`generated-<method>-<path-slug>-<16-hex-sha256>` fallback, bounded to 256
characters. The suffix hashes the exact method and path template, generation
fails if any identity is blank or oversized, and regeneration from the pinned
schema must reproduce the same values.

The deterministic summary is:

| Dimension | Count |
|---|---:|
| Read | 1,499 |
| Write | 1,201 |
| Destructive | 448 |
| Callable | 2,356 |
| Catalog-only | 792 |
| Required provider request headers | 2 |
| No Bearer API-token compatibility evidence | 87 |
| No reviewable JSON request schema | 127 |
| No explicit 2xx response contract | 49 |
| Ambiguous non-204/205 bodyless success | 15 |
| No reviewable successful JSON schema | 120 |
| Credential-sensitive schema | 263 |
| Sensitive request schema | 104 |
| Sensitive successful-response schema | 206 |
| Credential-semantic signal | 172 |
| Reviewed overrides | 117 |
| Force-catalog reviewed overrides | 114 |
| High-risk | 469 |

Catalog-only reason counts are 41 unsupported-request-media operations, 103
unsupported-success-response-media operations, 2 operations requiring provider
request headers, 87 without Bearer API-token compatibility evidence, 127 with no
reviewable JSON request schema, 49 with no explicit 2xx, 15 with ambiguous
non-204/205 bodyless success, 120 with no reviewable successful JSON schema, 114
force-catalog reviewed policy overrides, and 263 credential-sensitive request
or successful-response schemas. Reasons overlap.

The 117 reviewed overrides include 87 exact credential-capable endpoint contexts
for arbitrary header maps, signing values, and privileged capability URLs.
Schema findings include 172 operations with strong credential semantics covering
keys, payment fields, invoice documents, and upload, download, signed, or
debugger URLs. High-risk flags overlap: 405 credential-related, 25
account-administration, 18 billing or commerce, and 23 reviewed side-effecting
GETs.

Request and response contracts fail closed unless their JSON schemas are
reviewable; missing, empty, and bare object schemas do not establish a bounded
field contract. Runtime enforces OpenAPI's required-body presence bit, but not
arbitrary field schemas. Every operation must declare a 2xx response. Only `204`
and `205` are accepted as implicitly bodyless; every other successful status
must declare content. The pinned contract must also prove compatibility with the
fixed Bearer API-token client and require no extra provider headers.

Exact policy treats
`GET /accounts/{account_id}/cni/interconnects/{icon}/loa` as a write,
side-effecting GET, and forced catalog-only operation because it generates a
Letter of Authorization document. It also forces
`GET /accounts/{account_id}/email-security/investigate` catalog-only because its
`202` continuation depends on a `Location` response header the dispatcher omits.
The `POST`, `PATCH`, and `DELETE`
`/accounts/{account_id}/teamnet/routes/network/{ip_network_encoded}` operations
are catalog-only because the encoded CIDR slash is incompatible with the path
normalizer's traversal defense.

“Callable” is a local JSON-transport claim, not a policy-admission claim. Every
high-risk operation remains permanently blocked from generic execution even
when the inventory records its transport as callable. Provider behavior,
availability, pricing, permissions, and terms remain controlled by Cloudflare
and may change independently.

The inventory does not make the dispatcher a complete OpenAPI field validator.
Runtime enforces pinned method/path identity, reviewed endpoint policy, allowed
JSON media, and structural bounds. Arbitrary query keys and JSON body fields are
ultimately validated by Cloudflare; callers and mutation issuers must review the
exact request rather than infer field validity from `callable` status.

## Release identity chain

| Layer | Identity | Authority |
|---|---|---|
| Source | Full Git commit SHA | Exact stable release tag in this repository |
| Source archive | SHA-256 of `git archive --format=tar <COMMIT>` | Release build record and image-baked `source_fingerprint` |
| Schema | Pinned upstream commit plus source SHA-256 | Generated endpoint inventory and this document |
| Reviewed policy | Catalog version `2026.07.19.3` plus schema admission and exact override registry | Generated endpoint inventory and source review |
| Python package | Version plus wheel/source-archive checksums | Artifacts attached to the matching GitHub Release |
| MCP contract | Catalog version plus deterministic descriptor hash | ToolManifest from the exact build |
| Container | `ghcr.io/madpanda3d/cloudflare-mcp-server@sha256:<digest>` | Matching GitHub Release after publication |
| Runtime | Build SHA, source fingerprint, immutable image reference, catalog, descriptor hash | `/health` and local capability output |

A mutable branch, package filename, image tag, or `latest` reference is not an
immutable release identity.

## Public source boundary

The publishable repository contains source, tests, deterministic dependency
metadata, generic deployment templates, documentation, and community policy. It
must not contain:

- Cloudflare API tokens, service access tokens, Portal grants, approval signing
  keys, or signed attestations
- real `.env` files, secret-store exports, or credential-bearing client config
- production hostnames, IP addresses, filesystem paths, proxy configuration,
  tenant identifiers, or network topology
- private tickets, agent transcripts, operator reports, runtime logs, backups,
  approval ledgers, or provider response data

Examples use inert placeholders. CI checks the public-source boundary and scans
the complete publishable history before tests or release publication.

## Dependency and build provenance

- Runtime dependencies are hash-locked in `requirements.lock`.
- The development environment is locked in `uv.lock`.
- The container base and build tooling are pinned by immutable version or digest
  in `Dockerfile`.
- Third-party GitHub Actions and security scanners are pinned to reviewed
  commits or image digests.
- CI runs provider-free syntax, type, unit, ToolManifest/schema, approval,
  source-safety, dependency, four-variant Compose, image, and dual-mode runtime
  checks.

Review lockfile, base-image, generator, endpoint-policy, approval-contract, and
workflow changes as supply-chain or public-contract changes. Regenerate
deliberately and require the complete verification pipeline.

## Tool contract provenance

Tool descriptors are generated from the registered native tools and
`src/cloudflare_mcp/tool_manifest.py`. The descriptor hash covers the ordered
contract, including names, schemas, annotations, categories, tiers, aliases,
approval metadata, and documentation identity.

Release review must reconcile:

- registered native count: six
- tier counts: five agent-ready, one legacy, zero hidden
- catalog version `2026.07.19.3` and exact-build descriptor hash
- [complete tool catalog](tool-catalog.md)
- [endpoint coverage ledger](endpoint-coverage.md)
- README, changelog, health output, and provider-free tests

A descriptor-hash change is a contract change even when the package version or
HTTP route did not change.

## Release artifacts and registry

This source tree is a v1.0.0 release candidate. Its documentation does not, by
itself, assert that a public GitHub Release or immutable GHCR digest exists. The
configured release destinations are:

- OCI image: `ghcr.io/madpanda3d/cloudflare-mcp-server`
- Python wheel:
  `madpanda_cloudflare_mcp-<version>-py3-none-any.whl`
- Python source archive: `madpanda_cloudflare_mcp-<version>.tar.gz`
- package checksum manifest: `SHA256SUMS`

Before the tagged workflow succeeds, operators must treat those destinations as
planned rather than available. After it succeeds, the Python artifacts and
checksum manifest are attached to the matching GitHub Release; the workflow
does not publish to PyPI. The OCI candidate is built with BuildKit SBOM and
provenance metadata, scanned at its exact digest, made public independently of
source visibility, and anonymously pulled before the source-public admission
gate. GitHub-signed package and image attestations are created only after the
source is public and exact-SHA Verify/CodeQL admission passes, then stable tags
are promoted and the GitHub Release advertises the artifacts last. The workflow
currently targets `linux/amd64`.

## Immutable release Compose

Development and source verification use `docker-compose.yml` or
`docker-compose.portal.yml`, which build `cloudflare-mcp:local-source`.
Production release deployment uses:

- `docker-compose.release.yml` for standalone mode
- `docker-compose.portal.release.yml` for Portal mode

The release manifests contain no `build` section. Their only release-identity
input is:

- `MCP_RELEASE_DIGEST` — the exact 64-character digest from the GitHub Release

They set `pull_policy: always`, run
`ghcr.io/madpanda3d/cloudflare-mcp-server@sha256:<MCP_RELEASE_DIGEST>`, and set
`MCP_IMAGE_REFERENCE` to the identical immutable reference. This prevents a
production Compose invocation from silently rebuilding local source or
substituting a mutable tag. Build SHA and source fingerprint are baked into the
image at build time and are not accepted as release-Compose runtime overrides;
normal mode-specific service credentials still apply.

## Conditional release procedure

The v1.0.0 tag-driven workflow is configured to:

1. Require annotated `v1.0.0` at the exact protected `main` tip with a matching
   package version while the clean canonical source repository remains private.
2. Re-run source, type, security, dependency, Compose, and provider-free gates
   from the exact tag.
3. Fix `SOURCE_DATE_EPOCH` to the tagged commit, build the wheel and source
   archive twice, require byte-identical outputs and strict archive contents,
   and record SHA-256 checksums for the staged artifacts.
4. Compute the exact-source fingerprint and publish only a reusable,
   run-scoped candidate image from the private source repository with SBOM and
   maximum build provenance.
5. Resolve, identity-check, and scan that exact candidate digest. If the new
   package is private, stop at the anonymous gate; the package owner makes only
   `cloudflare-mcp-server` public and reruns the failed image job against the
   same candidate.
6. Require anonymous candidate/digest access, prove stable tags are absent or
   already identical, validate immutable Compose, and smoke the anonymously
   pulled digest in standalone and Portal modes.
7. After the image gate succeeds, make the clean source repository public,
   require successful exact-SHA public Verify and CodeQL admission, and only
   then create GitHub-signed package and image attestations.
8. Recheck each stable destination and attach `1.0.0`, `1.0`, `1`, and `latest`
   to the verified digest without rebuilding.
9. Create or repair the matching GitHub Release last, attaching the exact
   Python artifacts and `SHA256SUMS`.

Operators must use the exact `name@sha256:<digest>` from the release. Do not
infer a digest from a mutable tag or repository name, and do not copy a
placeholder from documentation.

## Local verification

```sh
git rev-parse HEAD
git archive --format=tar HEAD | sha256sum
uv sync --frozen --group dev
uv run python -m compileall -q src scripts
uv run pytest -q -p no:cacheprovider
uv run ruff check .
uv run ruff format --check .
uv run isort --check-only src scripts tests
uv run mypy --strict src tests
uv run bandit -q -r src/cloudflare_mcp -lll
uv run pip-audit --requirement requirements.lock
uv run python scripts/check_source_safety.py
docker compose --env-file .env -f docker-compose.yml config --quiet
docker compose --env-file .env -f docker-compose.portal.yml config --quiet
```

To validate immutable Compose locally without claiming a release, use a
synthetic digest:

```sh
export MCP_RELEASE_DIGEST=0000000000000000000000000000000000000000000000000000000000000000
docker compose -f docker-compose.release.yml config --quiet
docker compose -f docker-compose.portal.release.yml config --quiet
```

These checks use synthetic credentials and identities and must not contact
Cloudflare. Verify future package checksums and image attestations against the
exact release subjects using the tooling documented by the release platform.

## Trademark statement

Cloudflare and related product names are trademarks of Cloudflare, Inc. or their
respective owners. MADPANDA3D Cloudflare MCP is an independent open-source
integration and is not an official Cloudflare product, distribution,
partnership, sponsorship, or endorsement.
