# Migrate from 0.2.x to 0.3.0

Version 0.3.0 removes the project-owned authorization server and adopts FastMCP's native GitHub provider. Existing authorization codes, clients, bearer tokens, password configuration, and GitHub sessions do not migrate. MCP clients must connect again after the upgrade.

## Replace removed APIs

The following names no longer exist:

- `TokenStore` and `ClientStore`
- `AuthProvider`, `SingleUserProvider`, and `StaticPasswordProvider`
- `current_sub`
- the custom OAuth routes and HTML templates

Construct authentication through `auth_from_env()` and pass it to FastMCP:

```python
from fastmcp import FastMCP
from starlette.applications import Starlette

from mcp_server import auth_from_env, create_app, get_current_sub


def build_app() -> Starlette:
    auth = auth_from_env()
    mcp = FastMCP("my-service", auth=auth)

    @mcp.tool()
    def identity() -> dict[str, str | None]:
        return {"subject": get_current_sub()}

    return create_app(mcp, allow_anonymous=auth is None)
```

The `create_app` API is now:

```text
create_app(mcp: FastMCP, *, allow_anonymous: bool = False,
           cors_origins: list[str] | None = None)
```

It rejects a FastMCP server without authentication unless the caller sets `allow_anonymous=True`.

## Change the environment

| 0.2.x | 0.3.0 |
| --- | --- |
| No auth setting meant implicit single-user access | `MCP_AUTH_MODE=github` is the default |
| `ADMIN_PASSWORD` | Removed and rejected at startup |
| `GITHUB_ALLOWED_LOGINS` | `GITHUB_ALLOWED_USER_IDS` with numeric GitHub IDs |
| Custom `/auth/github/callback` | Native `/auth/callback` |
| Module-level `app` object | Import-safe `build_app()` factory selected by `MCP_APP` |

For local anonymous testing, set `MCP_AUTH_MODE=demo`. Treat this as unauthenticated access. Public deployments should use GitHub mode.

The GitHub configuration requires `BASE_URL`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `GITHUB_ALLOWED_USER_IDS`. `BASE_URL` must contain an HTTPS origin without a path, query, fragment, or credentials. Loopback HTTP remains available for local development.

Replace login names with the immutable numeric `id` values from GitHub's user API. The value returned by `get_current_sub()` is now that numeric ID.

## Update GitHub tools

FastMCP associates each request with the caller's verified upstream GitHub credential. Remove project-owned session lookups. Use FastMCP's current access-token dependency only at the outbound API boundary:

```python
from fastmcp.server.dependencies import get_access_token


def github_bearer() -> str:
    access = get_access_token()
    if access is None:
        raise RuntimeError("GitHub authentication is required")
    return access.token
```

Do not return or log this value. The provider requests only `read:user`, so migrate tools that require private repository access to a separate reviewed application and scope policy.

## Update GitHub OAuth app and clients

Change the OAuth app callback from `/auth/github/callback` to `/auth/callback`. FastMCP now presents downstream consent and owns client registration, authorization state, PKCE, and token binding.

The GitHub provider does not advertise a local token-revocation route. Users can revoke the OAuth app grant in GitHub. One-hour access-token expiry, revocation, server restarts, and storage loss may require an MCP client reconnect.

## Update deployment

The container now runs `python -m mcp_server` and selects `MCP_APP`, which defaults to `examples.echo_server:build_app`. Export a `module:factory` from custom services. The Dockerfile copies only the `mcp_server` and `examples` packages, so add custom factories to one of those packages or extend its explicit copy steps.

For a first Cloud Run deployment, place the GitHub client secret in Secret Manager and set `GITHUB_CLIENT_SECRET_REF` to its `secret:version` reference. The deployment script preserves existing environment variables and secret bindings during later updates.

FastMCP's default encrypted file store lives under `FASTMCP_HOME`; the image sets it to `/data/fastmcp`. Cloud Run does not preserve that filesystem across restarts, scale-to-zero, or revisions. Version 0.3.0 configures one maximum instance for steady-state operation, but rollouts can overlap revisions and production scaling still requires shared, durable, encrypted storage.
