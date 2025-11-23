FROM python:3.11-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY --from=ghcr.io/astral-sh/uv:latest /uvx /usr/local/bin/uvx

WORKDIR /app

# Copy uv project files
COPY pyproject.toml .
COPY uv.lock* ./

# Install dependencies with uv (much faster!)
RUN uv sync --frozen --no-dev

RUN uv run playwright install chromium --with-deps

# Copy application code
COPY app/ ./app/

# Run with uv
ENTRYPOINT ["uv", "run", "app/main.py"]
