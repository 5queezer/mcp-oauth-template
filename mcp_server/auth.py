"""
OAuth 2.1 PKCE Auth Layer for MCP Servers.

Single-user mode: /authorize issues code directly (no login form).
Multi-user mode: subclass AuthProvider and override authenticate().
"""

import hashlib
import base64
import secrets
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from fastapi import Request

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class AuthCode:
    challenge: str          # S256 code_challenge from client
    redirect_uri: str
    state: str
    sub: str                # authenticated subject, carried forward to token
    expires: float = field(default_factory=lambda: time.time() + 300)


@dataclass
class AccessToken:
    sub: str                # user/service identifier
    expires: float = field(default_factory=lambda: time.time() + 3600)


# ---------------------------------------------------------------------------
# PKCE Helpers
# ---------------------------------------------------------------------------

def verify_pkce(verifier: str, challenge: str) -> bool:
    """SHA-256 PKCE verification (RFC 7636 §4.6)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return secrets.compare_digest(computed, challenge)


# ---------------------------------------------------------------------------
# Auth Provider (swap this for multi-user)
# ---------------------------------------------------------------------------

class AuthProvider(ABC):
    """
    Override this to plug in your identity logic.
    Single-user default: always grants access.
    Multi-user: validate credentials, return subject string or None.
    """

    @abstractmethod
    def authenticate(self, request: Request, credentials: dict[str, str]) -> Optional[str]:
        """
        Return subject (user id / name) or None if auth fails.

        Args:
            request:     The underlying Starlette Request. Advanced providers
                         may read headers, cookies, or upstream session state
                         from this to make auth decisions.
            credentials: Merged dict of /authorize query params plus any POST
                         form fields (e.g. "password"). Simple providers can
                         look at this alone.

        Example (upstream OAuth / session cookie):
            def authenticate(self, request, credentials):
                sess = request.cookies.get("session")
                return self._resolve_session(sess)
        """
        ...


class SingleUserProvider(AuthProvider):
    """
    No login UI. /authorize immediately issues a code.
    Safe when your Cloud Run service is not publicly guessable
    or you protect /authorize with VPN / IP allowlist.
    """
    def authenticate(self, request: Request, credentials: dict[str, str]) -> Optional[str]:
        return "local-user"


class StaticPasswordProvider(AuthProvider):
    """
    Password-gated single-user mode. On GET /authorize the server renders a
    password form; the submitted password is passed in `credentials`.
    Good for single-user deployments that want minimal friction.
    """
    def __init__(self, password: str):
        self._password = password

    def authenticate(self, request: Request, credentials: dict[str, str]) -> Optional[str]:
        provided = credentials.get("password", "")
        if secrets.compare_digest(provided, self._password):
            return "admin"
        return None


# ---------------------------------------------------------------------------
# Token Store (swap for Redis/SQLite in production)
# ---------------------------------------------------------------------------

class TokenStore:
    def __init__(self):
        self._codes: dict[str, AuthCode] = {}
        self._tokens: dict[str, AccessToken] = {}

    # -- Auth codes --

    def create_code(self, challenge: str, redirect_uri: str, state: str, sub: str) -> str:
        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthCode(
            challenge=challenge,
            redirect_uri=redirect_uri,
            state=state,
            sub=sub,
        )
        self._gc_codes()
        return code

    def consume_code(self, code: str) -> Optional[AuthCode]:
        entry = self._codes.pop(code, None)
        if entry and time.time() < entry.expires:
            return entry
        return None

    # -- Access tokens --

    def create_token(self, sub: str) -> str:
        token = secrets.token_urlsafe(48)
        self._tokens[token] = AccessToken(sub=sub)
        return token

    def validate_token(self, token: str) -> Optional[AccessToken]:
        entry = self._tokens.get(token)
        if entry and time.time() < entry.expires:
            return entry
        if entry:
            del self._tokens[token]  # expired -- clean up
        return None

    def revoke_token(self, token: str) -> None:
        self._tokens.pop(token, None)

    # -- GC --

    def _gc_codes(self):
        now = time.time()
        expired = [k for k, v in self._codes.items() if now > v.expires]
        for k in expired:
            del self._codes[k]


# ---------------------------------------------------------------------------
# Client Store (RFC 7591 dynamic registration)
# ---------------------------------------------------------------------------

@dataclass
class OAuthClient:
    client_id: str
    redirect_uris: list[str]
    client_name: str = ""
    issued_at: float = field(default_factory=time.time)


def _validate_redirect_uri(uri: str) -> bool:
    """Allow https everywhere; allow http only for localhost/loopback (dev)."""
    try:
        parsed = urlparse(uri)
    except Exception:
        return False
    if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        return parsed.scheme in ("http", "https")
    return parsed.scheme == "https"


class ClientStore:
    def __init__(self):
        self._clients: dict[str, OAuthClient] = {}

    def register(self, redirect_uris: list[str], client_name: str = "") -> OAuthClient:
        for uri in redirect_uris:
            if not _validate_redirect_uri(uri):
                raise ValueError(f"Invalid redirect_uri: {uri!r} — must be https (or http for localhost)")
        client_id = secrets.token_urlsafe(16)
        client = OAuthClient(
            client_id=client_id,
            redirect_uris=redirect_uris,
            client_name=client_name,
        )
        self._clients[client_id] = client
        return client

    def get(self, client_id: str) -> Optional[OAuthClient]:
        return self._clients.get(client_id)
