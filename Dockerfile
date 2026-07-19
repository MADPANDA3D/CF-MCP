# linux/amd64 Python 3.12.13 slim-bookworm pin. Update the digest deliberately.
FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    UV_PROJECT_ENVIRONMENT=/opt/cloudflare-mcp

WORKDIR /build

RUN mkdir /tmp/uv \
    && python -m pip download --no-cache-dir --no-deps --only-binary=:all: \
      --dest /tmp/uv uv==0.11.29 \
    && echo "eec03a8b63d55915694db3af4e91324b39ced49e2aeac7af37851c7eb3f470ea  /tmp/uv/uv-0.11.29-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl" \
      | sha256sum --check --strict \
    && python -m pip install --no-cache-dir --no-deps /tmp/uv/*.whl \
    && rm -rf /tmp/uv

COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src

RUN uv sync --frozen --no-dev --no-editable \
    && rm -rf /root/.cache /tmp/*


# Keep project build tooling and project source files out of the runtime image.
FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ARG BUILD_SHA=development
ARG SOURCE_FINGERPRINT=development
ARG IMAGE_VERSION=1.0.0

LABEL org.opencontainers.image.title="MADPANDA3D Cloudflare MCP" \
      org.opencontainers.image.description="Dual-mode, request-scoped BYOK Cloudflare MCP provider" \
      org.opencontainers.image.source="https://github.com/MADPANDA3D/CF-MCP" \
      org.opencontainers.image.revision="${BUILD_SHA}" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      com.madpanda.source-fingerprint="${SOURCE_FINGERPRINT}"

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /home/app \
      --shell /usr/sbin/nologin app \
    && test "$(id -u app)" = "10001" \
    && test "$(id -g app)" = "10001"

WORKDIR /app

COPY --from=builder --chown=10001:10001 /opt/cloudflare-mcp /opt/cloudflare-mcp
COPY --chown=10001:10001 scripts/runtime_smoke.py ./scripts/runtime_smoke.py
COPY LICENSE NOTICE /usr/share/licenses/madpanda-cloudflare-mcp/
RUN chmod 0444 /usr/share/licenses/madpanda-cloudflare-mcp/LICENSE \
    /usr/share/licenses/madpanda-cloudflare-mcp/NOTICE

ENV PATH="/opt/cloudflare-mcp/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MCP_MODE=standalone \
    MCP_BUILD_SHA="${BUILD_SHA}" \
    MCP_SOURCE_FINGERPRINT="${SOURCE_FINGERPRINT}" \
    MCP_IMAGE_REFERENCE=development \
    MCP_EXPECTED_TOOL_COUNT=6 \
    MCP_REQUEST_BODY_MAX_BYTES=131072 \
    MCP_RESPONSE_BODY_MAX_BYTES=1048576 \
    MCP_PROVIDER_RESPONSE_MAX_BYTES=65536

EXPOSE 8000
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import json,os,urllib.request; o=urllib.request.build_opener(urllib.request.ProxyHandler({})); r=o.open('http://127.0.0.1:8000/health',timeout=3); b=r.read(65537); r.close(); p=json.loads(b); raise SystemExit(0 if len(b)<=65536 and p.get('status')=='healthy' and p.get('tool_count')==int(os.environ['MCP_EXPECTED_TOOL_COUNT']) else 1)"]

CMD ["cloudflare-mcp"]
