"""A minimal tool demonstrating the template's application factory."""

from fastmcp import FastMCP
from fastmcp.server.http import StarletteWithLifespan

from mcp_server import auth_from_env, create_app


def build_app() -> StarletteWithLifespan:
    """Require GitHub OAuth unless MCP_AUTH_MODE=demo is explicitly set."""
    auth = auth_from_env()
    mcp = FastMCP("echo", auth=auth, instructions="Echo text to verify the MCP connection.")

    @mcp.tool()
    def echo(text: str) -> str:
        """Return the supplied text."""
        return text

    return create_app(mcp, allow_anonymous=auth is None)
