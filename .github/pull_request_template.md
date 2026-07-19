## What changed

Describe the smallest behavior or documentation change.

## Why

Explain the user or agent problem this resolves.

## Verification

- [ ] `uv sync --frozen --group dev`
- [ ] `uv run python -m compileall -q src scripts`
- [ ] `uv run pytest -q -p no:cacheprovider`
- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] `uv run isort --check-only src scripts tests`
- [ ] `uv run mypy --strict src tests`
- [ ] `uv run bandit -q -r src -lll`
- [ ] `uv run pip-audit -r requirements.lock`
- [ ] `uv run python scripts/check_source_safety.py`
- [ ] Standalone and Portal Compose files validate
- [ ] Provider-free Docker smoke passes in both access modes
- [ ] Tool count, catalog, docs, and endpoint coverage remain synchronized
- [ ] No real credential, provider identifier, private path, topology, ticket, agent memory, or runtime evidence is included

## Security boundary

State any change to authentication, request-scoped BYOK, schema coverage,
operation risk, external approval, retries, output bounds, or provider origin. Write
`none` when unchanged.
