FROM --platform=linux/arm64 ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --no-cache --extra serve || uv sync --no-cache --extra serve

COPY agent.py ./
COPY tools/ ./tools/

EXPOSE 8080

CMD ["uv", "run", "python", "agent.py", "--serve"]
