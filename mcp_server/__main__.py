"""Run a selected import-safe MCP application factory with Uvicorn."""

from __future__ import annotations

import os

import uvicorn

DEFAULT_APP = "examples.echo_server:build_app"


def main() -> None:
    """Start exactly one ASGI worker for the configured MCP application."""
    uvicorn.run(
        os.getenv("MCP_APP", DEFAULT_APP),
        factory=True,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8080")),
        workers=1,
        log_level=os.getenv("LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
