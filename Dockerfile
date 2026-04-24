FROM astral/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

WORKDIR /app
COPY pyproject.toml README.md ./
COPY mcp_server ./mcp_server
RUN uv venv /opt/venv && \
    uv pip install --python /opt/venv/bin/python --no-cache .

FROM python:3.12-slim

COPY --from=builder /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

WORKDIR /app
COPY . .

ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "uvicorn mcp_server.app:create_app --factory --host 0.0.0.0 --port ${PORT} --log-level info"]
