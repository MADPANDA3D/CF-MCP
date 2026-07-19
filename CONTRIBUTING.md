# Contributing

Thanks for improving MADPANDA3D Cloudflare MCP.

## Before coding

- Search existing issues before opening a new one.
- Discuss behavior-changing or broad-surface work before implementation.
- Preserve the six-tool protocol contract unless a proposal updates the
  ToolManifest, endpoint ledger, public documentation, and tests together.
- Prefer a focused native tool over expanding the advanced JSON dispatcher.
- Never add real credentials, provider identifiers, production domains, host
  paths, private topology, tickets, agent memory, or operator evidence.

## Development

Python 3.12 or 3.13 and `uv` are the supported development path.

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
```

Tests must use synthetic credentials and mocked provider behavior. They must
not contact Cloudflare, mutate a real account, consume paid services, or depend
on a private deployment.

Use semantic commits:

```text
fix(auth): reject missing request BYOK token
docs(deploy): clarify standalone reverse proxy
test(approval): reject replay and cross-principal mutation proofs
```

## Contract and coverage changes

Any tool addition, removal, rename, annotation change, input/output schema
change, alias change, or tier change must update:

1. `src/cloudflare_mcp/tool_manifest.py`
2. the implementation and provider-free tests
3. [the tool catalog](docs/tool-catalog.md)
4. [the endpoint ledger](docs/endpoint-coverage.md)
5. README counts and changelog

Any endpoint snapshot change must pin the upstream commit, record the source
SHA-256 and license, regenerate artifacts deterministically, and explain count
or risk-classification changes. Do not describe an operation as callable only
because it appears in OpenAPI; the JSON transport and security gates must also
support it.

## Pull requests

A pull request should include:

- what changed and why
- affected tools, endpoint classes, and risk boundary
- exact verification commands and results
- configuration or documentation changes
- confirmation that no live provider call, real credential, or real approval secret was used

Keep changes narrow and preserve compatibility deliberately.

## Security reports

Do not open a public issue for a suspected vulnerability or exposed
credential. Follow [SECURITY.md](SECURITY.md).

By contributing, you agree that your contribution is licensed under the
[MIT License](LICENSE).
