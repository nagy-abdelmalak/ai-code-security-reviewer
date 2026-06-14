# syntax=docker/dockerfile:1.7

# --- Stage 1: dependencies + project install ---
FROM python:3.12-slim AS builder

# Prevent uv from downloading its own Python; use the system one from the base image.
ENV UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Pin uv version for reproducibility (update intentionally)
COPY --from=ghcr.io/astral-sh/uv:0.5.0 /uv /uvx /bin/

WORKDIR /app

# Install dependencies first for better layer caching
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Now copy the project and install it
COPY app ./app
RUN uv sync --frozen --no-dev


# --- Stage 2: minimal runtime ---
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

# ADR-007: non-root user for container isolation
RUN useradd --create-home --uid 1000 appuser

WORKDIR /app

# Copy app and pre-built virtual environment from builder
COPY --from=builder --chown=appuser:appuser /app /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8000"]