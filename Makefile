.PHONY: install test run deploy lint

SERVICE_NAME ?= mcp-oauth-service
REGION       ?= europe-west1

install:
	uv pip install -e ".[dev]"

test:
	pytest tests/ -v --tb=short

run:
	uvicorn mcp_server.app:create_app --factory --reload --port 8080

# Run Polymarket example
run-polymarket:
	uvicorn examples.polymarket_server:app --reload --port 8080

deploy:
	chmod +x deploy.sh
	./deploy.sh $(SERVICE_NAME) $(REGION)

lint:
	ruff check mcp_server/ tests/ examples/ --fix
