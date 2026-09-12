# Контекст сборки — корень суперпроекта (там же лежит platform-auth-sdk):
#   docker build -f policy-service/Dockerfile .
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.8.0 /uv /usr/local/bin/uv
WORKDIR /app/policy-service
COPY platform-auth-sdk /app/platform-auth-sdk
COPY policy-service/pyproject.toml policy-service/uv.lock policy-service/README.md ./
RUN uv sync --frozen --no-dev --no-install-project

FROM python:3.12-slim AS runtime

RUN useradd --create-home --uid 10001 policy
WORKDIR /app/policy-service
COPY --from=builder /app /app
COPY policy-service/alembic.ini ./
COPY policy-service/migrations ./migrations
COPY policy-service/src ./src
COPY policy-service/authz ./authz
COPY policy-service/pyproject.toml policy-service/README.md ./
ENV PATH="/app/policy-service/.venv/bin:$PATH" \
    PYTHONPATH="/app/policy-service/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER policy
EXPOSE 8030
CMD ["uvicorn", "policy_service.app:app", "--host", "0.0.0.0", "--port", "8030"]
