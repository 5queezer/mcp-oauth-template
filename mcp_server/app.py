"""
MCP OAuth Server -- App Factory.

Uses the FastMCP Starlette app as the root application and adds OAuth routes
to it, so FastMCP's lifespan (session manager) works correctly.

Usage:
  from mcp_server.app import create_app
  app = create_app()

Or for a custom service:
  from mcp_server.app import create_app
  from mcp_server.auth import StaticPasswordProvider
  import fastmcp

  mcp = fastmcp.FastMCP("polymarket")

  @mcp.tool()
  def get_markets(keyword: str) -> list[dict]:
      ...

  app = create_app(mcp=mcp, provider=StaticPasswordProvider("s3cr3t"))
"""

import os
import logging

from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .auth import ClientStore, SingleUserProvider, StaticPasswordProvider, TokenStore
from .oauth_routes import make_oauth_routes

logger = logging.getLogger(__name__)


def create_app(
    mcp=None,
    provider=None,
    base_url: str | None = None,
    title: str = "MCP OAuth Server",
    instructions: str | None = None,
):
    """
    App factory. Returns a Starlette app (from FastMCP) with:
      - OAuth 2.1 AS routes (/.well-known, /authorize, /token, /revoke)
      - MCP HTTP transport at /mcp (Bearer-protected via middleware)
      - CORS for claude.ai

    Args:
        mcp:          fastmcp.FastMCP instance. If None, a stub is used.
        provider:     AuthProvider instance. Defaults to env-driven selection.
        base_url:     Public URL used in OAuth metadata.
                      Falls back to BASE_URL env var, then http://localhost:8080.
        title:        OpenAPI / service title.
        instructions: Text shown as the server description card in claude.ai.
                      Ignored when mcp is provided (set it on the FastMCP
                      instance directly instead).
    """
    _base_url = base_url or os.getenv("BASE_URL", "http://localhost:8080")
    _provider = provider or _default_provider()
    _store = TokenStore()
    _client_store = ClientStore()
    _mcp = mcp or _stub_mcp(instructions=instructions)

    resource_metadata_url = f"{_base_url.rstrip('/')}/.well-known/oauth-protected-resource"

    # Bearer middleware for /mcp (raw ASGI middleware)
    class BearerMiddleware:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http" or not scope["path"].startswith("/mcp"):
                return await self.app(scope, receive, send)

            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode()

            if not auth_header.lower().startswith("bearer "):
                resp = JSONResponse(
                    {"error": "invalid_token", "error_description": "Bearer token required"},
                    status_code=401,
                    headers={"WWW-Authenticate": f'Bearer resource_metadata="{resource_metadata_url}"'},
                )
                return await resp(scope, receive, send)

            token_str = auth_header[7:]
            entry = _store.validate_token(token_str)
            if entry is None:
                resp = JSONResponse(
                    {"error": "invalid_token", "error_description": "Token expired or unknown"},
                    status_code=401,
                    headers={"WWW-Authenticate": f'Bearer resource_metadata="{resource_metadata_url}"'},
                )
                return await resp(scope, receive, send)

            return await self.app(scope, receive, send)

    # Build the MCP Starlette app with middleware baked in
    app = _mcp.http_app(
        path="/mcp",
        middleware=[
            Middleware(CORSMiddleware,
                allow_origins=["https://claude.ai", "https://api.claude.ai"],
                allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
                allow_headers=["Authorization", "Content-Type"],
                allow_credentials=True,
            ),
            Middleware(BearerMiddleware),
        ],
    )

    # Add OAuth routes and health to the MCP app's router
    oauth_routes = make_oauth_routes(
        store=_store,
        client_store=_client_store,
        provider=_provider,
        base_url=_base_url,
    )

    async def health(request: Request):
        return JSONResponse({"status": "ok", "base_url": _base_url})

    for route in oauth_routes:
        app.routes.insert(0, route)
    app.routes.insert(0, Route("/health", health, methods=["GET"]))

    logger.info("MCP OAuth server ready at %s", _base_url)
    return app


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _default_provider():
    pw = os.getenv("ADMIN_PASSWORD")
    if pw:
        logger.info("Using StaticPasswordProvider (ADMIN_PASSWORD set)")
        return StaticPasswordProvider(pw)
    logger.warning(
        "No ADMIN_PASSWORD set -- SingleUserProvider active. "
        "Protect /authorize at network level."
    )
    return SingleUserProvider()


def _stub_mcp(instructions: str | None = None):
    import fastmcp

    mcp = fastmcp.FastMCP("stub", instructions=instructions)

    @mcp.tool()
    def ping() -> str:
        """Health check tool."""
        return "pong"

    return mcp
