FROM --platform=linux/arm64 ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache --extra serve --no-install-project

COPY agent.py ./
COPY tools/ ./tools/

# Pre-download JA4 database (avoids 120s cold-start delay)
RUN uv run python -c "from tools.ja4 import _update_index; _update_index()" || true

EXPOSE 8080

CMD ["uv", "run", "python", "agent.py", "--serve"]
