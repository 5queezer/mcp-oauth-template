"""
Per-request identity context.

BearerMiddleware sets `current_sub` from the validated access token before
awaiting the downstream app; tool code reads it via `get_current_sub()` to
find out who is calling. Resets in a `finally` so a ContextVar token leak
can't bleed one user's identity into another's request.

Why a ContextVar instead of reading the Request: FastMCP dispatches tools
through its own transport. By the time a `@mcp.tool()` function runs, the
Starlette Request is no longer in scope, but the asyncio Task's context
vars are — so this is how we carry the caller's sub through.
"""

from contextvars import ContextVar
from typing import Optional

# Default None so tools that run outside an authenticated request (e.g. in
# tests) get a well-defined "no user" signal rather than a LookupError.
current_sub: ContextVar[Optional[str]] = ContextVar("current_sub", default=None)


def get_current_sub() -> Optional[str]:
    """Return the authenticated subject for the current request, or None."""
    return current_sub.get()
