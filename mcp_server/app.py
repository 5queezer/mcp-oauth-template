"""Build a Starlette application around FastMCP's authenticated HTTP transport."""

from fastmcp import FastMCP
from fastmcp.server.http import StarletteWithLifespan
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


def create_app(
    mcp: FastMCP,
    *,
    allow_anonymous: bool = False,
    cors_origins: list[str] | None = None,
) -> StarletteWithLifespan:
    """Serve ``mcp`` at /mcp using its native authentication and lifespan.

    Anonymous access requires deliberate opt-in. HTTP requests are stateless,
    so tools read the current request's identity rather than a session's cached
    identity. Configure persistent OAuth storage on the auth provider itself.
    """
    if mcp.auth is None and not allow_anonymous:
        raise ValueError("Configure mcp.auth or explicitly allow anonymous demo access")

    origins = cors_origins if cors_origins is not None else ["https://claude.ai"]
    app = mcp.http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        allowed_origins=origins,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "MCP-Protocol-Version",
            "Mcp-Session-Id",
            "Last-Event-ID",
        ],
        expose_headers=["WWW-Authenticate", "Mcp-Session-Id", "MCP-Protocol-Version"],
    )

    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    app.routes.append(Route("/health", health, methods=["GET"]))
    return app
