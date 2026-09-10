"""Read the authenticated identity from FastMCP's current request."""

from fastmcp.server.dependencies import get_access_token


def get_current_sub() -> str | None:
    """Return the caller's stable subject, or None outside authenticated requests."""
    token = get_access_token()
    return token.subject if token is not None else None
