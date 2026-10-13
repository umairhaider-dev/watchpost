# syntax=docker/dockerfile:1

# ---- build: resolve dependencies into a virtualenv ---------------------------
FROM python:3.12-slim AS build

COPY --from=ghcr.io/astral-sh/uv:0.11.16 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app

# Dependencies first so code changes do not invalidate this layer.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# ---- runtime -----------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN groupadd --system --gid 10001 watchpost \
    && useradd --system --uid 10001 --gid watchpost --no-create-home watchpost \
    && mkdir -p /data/uploads /data/watch \
    && chown -R watchpost:watchpost /data

WORKDIR /app

COPY --from=build /opt/venv /opt/venv
COPY alembic.ini ./
COPY alembic ./alembic

USER watchpost

EXPOSE 8000

CMD ["uvicorn", "watchpost.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
