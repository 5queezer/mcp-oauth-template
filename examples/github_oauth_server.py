"""GitHub tools using the authenticated caller's upstream OAuth credential.

Run with MCP_APP=examples.github_oauth_server:build_app. Required environment
configuration is documented in README.md. The read:user grant allows profile
and public repository reads; this example does not request private repo access.
"""

from typing import Annotated, Any

import httpx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.http import StarletteWithLifespan
from pydantic import Field

from mcp_server import auth_from_env, create_app

GITHUB_API = "https://api.github.com"
Limit = Annotated[int, Field(ge=1, le=100)]


def whoami() -> dict[str, Any]:
    """Return the caller's stable GitHub ID and public profile."""
    access = get_access_token()
    if access is None:
        raise ToolError("GitHub authentication is required")
    return {
        "id": access.subject,
        "login": access.claims.get("login"),
        "name": access.claims.get("name"),
        "email": access.claims.get("email"),
    }


async def _repositories(path: str, limit: int) -> list[dict[str, Any]]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    access = get_access_token()
    if access is None:
        raise ToolError("GitHub authentication is required")
    params: dict[str, str | int] = {"per_page": limit}
    if path == "/user/repos":
        params.update({"visibility": "public", "sort": "updated"})
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"{GITHUB_API}{path}",
                headers={
                    "Authorization": f"Bearer {access.token}",
                    "Accept": "application/vnd.github+json",
                },
                params=params,
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as exc:
        raise ToolError(f"GitHub request failed (HTTP {exc.response.status_code})") from None
    except httpx.RequestError:
        raise ToolError("GitHub is unavailable; try again later") from None
    except ValueError:
        raise ToolError("GitHub returned an invalid JSON response") from None
    if not isinstance(data, list) or any(not isinstance(repo, dict) for repo in data):
        raise ToolError("GitHub returned an unexpected repository response")
    return [
        {
            "full_name": repo.get("full_name"),
            "description": repo.get("description"),
            "url": repo.get("html_url"),
            "stars": repo.get("stargazers_count"),
        }
        for repo in data[:limit]
        if repo.get("private") is False
    ]


async def list_my_repos(limit: Limit = 20) -> list[dict[str, Any]]:
    """List the caller's public repositories, ordered by most recently updated."""
    return await _repositories("/user/repos", limit)


async def get_starred(limit: Limit = 20) -> list[dict[str, Any]]:
    """List repositories starred by the caller, most recent first."""
    return await _repositories("/user/starred", limit)


def build_app() -> StarletteWithLifespan:
    """Build an authenticated GitHub MCP application without import-time work."""
    auth = auth_from_env()
    if auth is None:
        raise ValueError("The GitHub example requires GitHub authentication")
    mcp = FastMCP(
        "github-oauth",
        auth=auth,
        instructions="Read the caller's GitHub profile, public repositories and starred repositories.",
    )
    for tool in (whoami, list_my_repos, get_starred):
        mcp.tool(tool)
    return create_app(mcp)
