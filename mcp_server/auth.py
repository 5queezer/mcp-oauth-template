"""GitHub authorization policy on top of FastMCP's maintained OAuth provider."""

import os
import re
from collections.abc import Collection
from urllib.parse import urlsplit

from fastmcp.server.auth.providers.github import GitHubProvider
from key_value.aio.protocols import AsyncKeyValue
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationParams,
    AuthorizeError,
    RegistrationError,
)
from mcp.shared.auth import OAuthClientInformationFull


def _safe_http_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        _ = parsed.port
        return bool(
            parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and "#" not in url
            and (
                parsed.scheme == "https"
                or (
                    parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                )
            )
        )
    except ValueError:
        return False


class GitHubAuthProvider(GitHubProvider):
    """Require an allowed immutable GitHub user ID on every bearer request.

    Native OAuth handles consent, PKCE, client binding and encrypted local
    storage. An injected ``encrypted_storage`` must already encrypt its values;
    FastMCP does not wrap custom backends. Environment changes require restart.
    """

    def __init__(
        self,
        *,
        allowed_user_ids: Collection[str],
        client_id: str,
        client_secret: str,
        base_url: str,
        encrypted_storage: AsyncKeyValue | None = None,
    ) -> None:
        ids = frozenset(allowed_user_ids)
        if not ids or any(not re.fullmatch(r"[1-9][0-9]*", uid) for uid in ids):
            raise ValueError("At least one positive numeric GitHub user ID is required")
        if (
            not _safe_http_url(base_url)
            or urlsplit(base_url).path not in {"", "/"}
            or "?" in base_url
        ):
            raise ValueError(
                "BASE_URL must be an HTTPS origin (or loopback HTTP), without a path, query or fragment"
            )
        if not client_id.strip() or not client_secret.strip():
            raise ValueError("GitHub client ID and secret are required")
        self.allowed_user_ids = ids
        self.github_client_id = client_id
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url.rstrip("/"),
            required_scopes=["read:user"],
            require_authorization_consent=True,
            cache_ttl_seconds=None,
            fastmcp_access_token_expiry_seconds=3600,
            client_storage=encrypted_storage,
            forward_resource=False,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        access = await super().load_access_token(token)
        return access if access and access.subject in self.allowed_user_ids else None

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        # Disable the upstream-app-ID compatibility shortcut: downstream clients
        # must register or provide a verified Client ID Metadata Document.
        if client_id == self.github_client_id:
            return None
        return await super().get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.redirect_uris or any(
            not _safe_http_url(str(uri)) for uri in client_info.redirect_uris
        ):
            raise RegistrationError(
                "invalid_redirect_uri",
                "Register an HTTPS or loopback HTTP callback without credentials or fragments",
            )
        await super().register_client(client_info)

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if not _safe_http_url(str(params.redirect_uri)):
            raise AuthorizeError("invalid_request", "Invalid redirect URI")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge or ""):
            raise AuthorizeError("invalid_request", "A valid S256 PKCE challenge is required")
        return await super().authorize(client, params)


def auth_from_env() -> GitHubAuthProvider | None:
    """Load GitHub auth by default; only MCP_AUTH_MODE=demo permits anonymous access."""
    if "ADMIN_PASSWORD" in os.environ:
        raise ValueError(
            "ADMIN_PASSWORD is no longer supported; configure GitHub OAuth and remove the legacy variable"
        )
    mode = os.getenv("MCP_AUTH_MODE", "github")
    if mode == "demo":
        return None
    if mode != "github":
        raise ValueError("MCP_AUTH_MODE must be github or demo")

    def required(name: str) -> str:
        value = os.getenv(name, "").strip()
        if not value:
            raise ValueError(f"{name} is required for GitHub OAuth")
        return value

    base_url = required("BASE_URL")
    client_id = required("GITHUB_CLIENT_ID")
    client_secret = required("GITHUB_CLIENT_SECRET")
    ids = required("GITHUB_ALLOWED_USER_IDS").split(",")
    return GitHubAuthProvider(
        allowed_user_ids={uid.strip() for uid in ids},
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
    )
