.PHONY: install sync test lint format-check typecheck audit check run run-github run-polymarket docker-build docker-smoke deploy

SERVICE_NAME ?= mcp-oauth-service
REGION ?= europe-west1
PROJECT ?=
MCP_APP ?= examples.echo_server:build_app
IMAGE ?= mcp-oauth-template:local

install sync:
	uv sync --frozen --all-groups

test:
	uv run pytest -q

lint:
	uv run ruff check .

format-check:
	uv run ruff format --check .

typecheck:
	uv run ty check

audit:
	uv run pip-audit --local

check: lint format-check typecheck test audit

run:
	MCP_AUTH_MODE=demo MCP_APP=$(MCP_APP) uv run python -m mcp_server

run-github:
	MCP_APP=examples.github_oauth_server:build_app uv run python -m mcp_server

run-polymarket:
	MCP_APP=examples.polymarket_server:build_app uv run python -m mcp_server

docker-build:
	docker build --tag $(IMAGE) .

docker-smoke: docker-build
	uv run python scripts/smoke_container.py $(IMAGE)

deploy:
	MCP_APP=$(MCP_APP) ./deploy.sh $(SERVICE_NAME) $(REGION) $(PROJECT)
