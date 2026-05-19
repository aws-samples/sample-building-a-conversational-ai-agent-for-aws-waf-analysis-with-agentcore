FROM --platform=linux/arm64 ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache --extra serve --no-install-project

COPY agent.py ./
COPY tools/ ./tools/
COPY scripts/ ./scripts/
COPY references/ ./references/

EXPOSE 8080

CMD ["uv", "run", "--no-project", "python", "agent.py", "--serve"]
