"""
GitHub OAuth MCP Server — upstream OAuth as the identity provider.

Demonstrates the template's "multi-user via upstream OAuth" story:
  * Each claude.ai user authenticates through their own GitHub account.
  * The server maintains a whitelist of permitted GitHub logins.
  * Every tool call runs with **that user's** GitHub access token —
    not a shared PAT — so `whoami`, `list_my_repos`, etc. reflect the
    caller's identity, not the server's.

Flow:
    claude.ai → GET /.well-known/oauth-authorization-server
    claude.ai → GET /authorize?code_challenge=…
        (no session cookie → provider.challenge() redirects to github.com)
    github.com → GET {BASE_URL}/auth/github/callback?code=…&state=…
        (we exchange code for token, fetch login, set mcp_session cookie,
         redirect back to /authorize with the original params)
    /authorize → issues OAuth code, claude.ai POSTs /token to get bearer
    claude.ai → POST /mcp with Bearer token → tool call runs with caller's
                GitHub token via get_current_sub() lookup.

Required env vars:
    GITHUB_CLIENT_ID        — from GitHub → Settings → Developer settings
                              → OAuth Apps → New OAuth App
    GITHUB_CLIENT_SECRET    — the paired secret
    GITHUB_ALLOWED_LOGINS   — comma-separated GitHub logins (e.g. "alice,bob")
    BASE_URL                — public URL of this service
                              (local: http://localhost:8080)

Register the OAuth App with:
    Homepage URL:        {BASE_URL}
    Authorization cb URL: {BASE_URL}/auth/github/callback

Deploy:
    gcloud run deploy gh-mcp --source . --region europe-west1 \\
        --set-env-vars BASE_URL=https://…,GITHUB_CLIENT_ID=…,\\
                       GITHUB_CLIENT_SECRET=…,GITHUB_ALLOWED_LOGINS=me,other
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlencode, urlparse

import httpx
import fastmcp
from mcp.types import Icon
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from mcp_server import create_app, get_current_sub
from mcp_server.auth import AuthProvider

logger = logging.getLogger(__name__)

# GitHub mark (Octicons, MIT) as an inline data URI so the connector card in
# claude.ai shows a recognizable logo without depending on external hosting.
_MARK_GITHUB_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
    b'<path fill="currentColor" fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8'
    b'c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49'
    b'-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52'
    b'-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87'
    b'.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36'
    b'-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2'
    b'.27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82'
    b' 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93'
    b'-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>'
    b'</svg>'
)
_ICON_DATA_URI = "data:image/svg+xml;base64," + base64.b64encode(_MARK_GITHUB_SVG).decode()

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com"

SESSION_COOKIE = "mcp_session"
DEFAULT_SESSION_TTL = 30 * 24 * 3600  # 30 days

# ---------------------------------------------------------------------------
# Session store
#
# Keeps two tables:
#   sessions — { session_id: Session }  — per-user post-login state
#   pending_states — { nonce: (return_url, created_at) }
#       one-shot OAuth state values so we can validate the callback
#       and return the user to exactly the /authorize URL they started on.
#
# Both are in-memory; swap for Redis or SQLite in production. Sessions are
# lost on restart, which just forces users through the GitHub flow again.
# ---------------------------------------------------------------------------


@dataclass
class Session:
    login: str
    github_token: str
    expires: float


class SessionStore:
    """In-memory session + pending-state store for the GitHub OAuth example."""

    # State nonces expire in 10 minutes; that's the longest any reasonable
    # user should take bouncing through GitHub's login page.
    STATE_TTL = 600

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        # pending_states maps nonce -> (return_url, created_at)
        self.pending_states: dict[str, tuple[str, float]] = {}

    # -- sessions --

    def create(self, login: str, github_token: str, ttl: int = DEFAULT_SESSION_TTL) -> str:
        """Create a session, return its opaque id (used as the cookie value)."""
        session_id = secrets.token_urlsafe(32)
        self._sessions[session_id] = Session(
            login=login,
            github_token=github_token,
            expires=time.time() + ttl,
        )
        self._gc_sessions()
        return session_id

    def get(self, session_id: str) -> Optional[Session]:
        """Return the session if present and unexpired, else None (deletes expired row)."""
        entry = self._sessions.get(session_id)
        if entry is None:
            return None
        if time.time() >= entry.expires:
            del self._sessions[session_id]
            return None
        return entry

    def get_by_login(self, login: str) -> Optional[Session]:
        """Find a live session for a login (used by tools to map sub → token)."""
        now = time.time()
        for entry in self._sessions.values():
            if entry.login == login and now < entry.expires:
                return entry
        return None

    # -- pending oauth state --

    def put_state(self, return_url: str) -> str:
        """Mint a one-shot state nonce bound to a post-login return URL."""
        nonce = secrets.token_urlsafe(24)
        self.pending_states[nonce] = (return_url, time.time())
        self._gc_states()
        return nonce

    def consume_state(self, nonce: str) -> Optional[str]:
        """Validate and remove a state nonce. Returns the return URL or None.

        Second lookup always returns None — this enforces one-shot semantics
        and defeats replay of a captured state value.
        """
        # Defense-in-depth: use compare_digest to rule out timing oracles on
        # the lookup key. Practical impact is small (dict lookup is already
        # constant-ish) but it's basically free to get right.
        for key in list(self.pending_states.keys()):
            if secrets.compare_digest(key, nonce):
                return_url, created = self.pending_states.pop(key)
                if time.time() - created > self.STATE_TTL:
                    return None
                return return_url
        return None

    # -- gc --

    def _gc_sessions(self) -> None:
        now = time.time()
        for k in [k for k, v in self._sessions.items() if now >= v.expires]:
            del self._sessions[k]

    def _gc_states(self) -> None:
        now = time.time()
        for k in [k for k, (_, ts) in self.pending_states.items() if now - ts > self.STATE_TTL]:
            del self.pending_states[k]


# ---------------------------------------------------------------------------
# GitHub auth provider
# ---------------------------------------------------------------------------


class GitHubOAuthProvider(AuthProvider):
    """
    Authenticate MCP users via GitHub.

    authenticate() checks for a valid `mcp_session` cookie pointing to a live
    session whose login is still in allowed_logins (re-checked every request
    so the allowlist can shrink without waiting for sessions to expire).

    challenge() kicks off the GitHub OAuth dance when there's no cookie yet —
    the user bounces out to github.com, then to our /auth/github/callback,
    which sets the cookie and redirects back to /authorize.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        allowed_logins: set[str],
        sessions: SessionStore,
        base_url: str,
    ) -> None:
        if not client_id or not client_secret:
            raise ValueError("GitHub client_id and client_secret are required")
        self.client_id = client_id
        self.client_secret = client_secret
        self.allowed_logins = allowed_logins
        self.sessions = sessions
        self.base_url = base_url.rstrip("/")

    def authenticate(self, request: Request, credentials: dict[str, str]) -> Optional[str]:
        sid = request.cookies.get(SESSION_COOKIE)
        if not sid:
            return None
        session = self.sessions.get(sid)
        if session is None:
            return None
        # Re-check the allowlist every request: if we remove "alice" from
        # GITHUB_ALLOWED_LOGINS, she loses access immediately even if her
        # cookie is still technically valid.
        if session.login not in self.allowed_logins:
            return None
        return session.login

    def challenge(self, request: Request, credentials: dict[str, str]) -> Optional[Response]:
        # Stash the original /authorize URL (with all its PKCE params) so
        # the callback can bounce the user back here after GitHub login.
        return_url = str(request.url)
        # Only accept same-origin return URLs. If someone crafted a request
        # with a weird Host header, don't let us become an open redirect.
        if not _is_safe_return_url(return_url, self.base_url):
            return_url = f"{self.base_url}/authorize"

        state = self.sessions.put_state(return_url)
        params = {
            "client_id": self.client_id,
            "redirect_uri": f"{self.base_url}/auth/github/callback",
            "scope": "read:user",
            "state": state,
            # allow_signup=false is a small UX touch: we're an allowlist-only
            # server, no point letting randoms create accounts from our page.
            "allow_signup": "false",
        }
        return RedirectResponse(f"{GITHUB_AUTHORIZE}?{urlencode(params)}", status_code=302)


def _is_safe_return_url(url: str, base_url: str) -> bool:
    """True iff url is a same-origin URL within our service."""
    try:
        u = urlparse(url)
        b = urlparse(base_url)
    except Exception:
        return False
    # Scheme + host must match; path is free.
    return (u.scheme, u.netloc) == (b.scheme, b.netloc) and u.path.startswith("/")


# ---------------------------------------------------------------------------
# Callback handler
#
# Factored out as a pure function so tests can inject a fake httpx client.
# ---------------------------------------------------------------------------


async def _handle_callback(
    code: str,
    state: str,
    sessions: SessionStore,
    allowed_logins: set[str],
    client_id: str,
    client_secret: str,
    base_url: str,
    http_client: httpx.AsyncClient,
) -> Response:
    """Process GitHub's OAuth callback. Pure w.r.t. injectable http_client."""
    if not code or not state:
        return JSONResponse({"error": "missing code or state"}, status_code=400)

    return_url = sessions.consume_state(state)
    if return_url is None:
        return JSONResponse({"error": "invalid or expired state"}, status_code=400)

    # Exchange code for an access token.
    token_resp = await http_client.post(
        GITHUB_TOKEN,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": f"{base_url.rstrip('/')}/auth/github/callback",
        },
        headers={"Accept": "application/json"},
    )
    if token_resp.status_code != 200:
        # Don't leak GitHub's error body to the client; log server-side.
        logger.warning("GitHub token exchange failed: %s", token_resp.status_code)
        return JSONResponse({"error": "github token exchange failed"}, status_code=502)
    payload = token_resp.json()
    github_token = payload.get("access_token")
    if not github_token:
        logger.warning("GitHub response missing access_token: keys=%s", list(payload.keys()))
        return JSONResponse({"error": "github did not issue a token"}, status_code=502)

    # Look up the user.
    user_resp = await http_client.get(
        f"{GITHUB_API}/user",
        headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
        },
    )
    if user_resp.status_code != 200:
        logger.warning("GitHub /user failed: %s", user_resp.status_code)
        return JSONResponse({"error": "failed to fetch github user"}, status_code=502)
    user = user_resp.json()
    login = user.get("login")
    if not login:
        return JSONResponse({"error": "github user missing login"}, status_code=502)

    if login not in allowed_logins:
        # Fail closed: don't leak presence/absence of a session. We do echo
        # the login so the user knows which account to switch to if they
        # authenticated with the wrong one.
        logger.info("Rejected GitHub login %r (not in allowlist)", login)
        return JSONResponse({"error": "user not allowed", "login": login}, status_code=403)

    session_id = sessions.create(login=login, github_token=github_token)

    # Secure cookie only when the service is actually on https. For local
    # dev over http, browsers drop Secure cookies and the flow breaks.
    is_https = base_url.startswith("https://")
    resp = RedirectResponse(return_url, status_code=302)
    resp.set_cookie(
        SESSION_COOKIE,
        session_id,
        max_age=DEFAULT_SESSION_TTL,
        httponly=True,
        secure=is_https,
        samesite="lax",
        path="/",
    )
    return resp


# ---------------------------------------------------------------------------
# MCP tools — each runs as the caller, using *their* GitHub token
# ---------------------------------------------------------------------------

# Module-level session store. Shared by the provider and the tools; in a
# multi-process deployment you'd back this with Redis so every worker sees
# the same sessions.
_SESSIONS = SessionStore()


def _caller_session() -> Optional[Session]:
    """Map the authenticated sub (a GitHub login) back to their session."""
    sub = get_current_sub()
    if sub is None:
        return None
    return _SESSIONS.get_by_login(sub)


mcp = fastmcp.FastMCP(
    "github-oauth",
    instructions=(
        "GitHub MCP bridge with per-user OAuth. Tools operate using the "
        "caller's own GitHub access token. Each claude.ai user logs in "
        "through GitHub the first time they connect."
    ),
    website_url="https://github.com/5queezer/mcp-oauth-template",
    icons=[Icon(src=_ICON_DATA_URI, mimeType="image/svg+xml", sizes=["any"])],
)


@mcp.tool()
def whoami() -> dict:
    """
    Return the authenticated GitHub user's login, name, and email.
    Uses the caller's own token.
    """
    session = _caller_session()
    if session is None:
        return {"error": "no github token for current user"}
    with httpx.Client(timeout=10) as client:
        r = client.get(
            f"{GITHUB_API}/user",
            headers={"Authorization": f"Bearer {session.github_token}"},
        )
        r.raise_for_status()
        u = r.json()
    return {"login": u.get("login"), "name": u.get("name"), "email": u.get("email")}


@mcp.tool()
def list_my_repos(limit: int = 20) -> list[dict]:
    """
    List the caller's most recently updated repos.

    Args:
        limit: max repos to return (GitHub caps per-page at 100)
    """
    session = _caller_session()
    if session is None:
        return [{"error": "no github token for current user"}]
    with httpx.Client(timeout=10) as client:
        r = client.get(
            f"{GITHUB_API}/user/repos",
            headers={"Authorization": f"Bearer {session.github_token}"},
            params={"per_page": min(limit, 100), "sort": "updated"},
        )
        r.raise_for_status()
        repos = r.json()
    return [
        {
            "full_name": x.get("full_name"),
            "private": x.get("private"),
            "description": x.get("description"),
            "updated_at": x.get("updated_at"),
            "stars": x.get("stargazers_count"),
        }
        for x in repos[:limit]
    ]


@mcp.tool()
def get_starred(limit: int = 20) -> list[dict]:
    """
    List the repos the caller has starred (most recent first).
    """
    session = _caller_session()
    if session is None:
        return [{"error": "no github token for current user"}]
    with httpx.Client(timeout=10) as client:
        r = client.get(
            f"{GITHUB_API}/user/starred",
            headers={"Authorization": f"Bearer {session.github_token}"},
            params={"per_page": min(limit, 100)},
        )
        r.raise_for_status()
        starred = r.json()
    return [
        {
            "full_name": x.get("full_name"),
            "description": x.get("description"),
            "stars": x.get("stargazers_count"),
            "language": x.get("language"),
        }
        for x in starred[:limit]
    ]


# ---------------------------------------------------------------------------
# App assembly
# ---------------------------------------------------------------------------


def _env_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} env var is required")
    return value


def build_app():
    base_url = os.getenv("BASE_URL", "http://localhost:8080")
    client_id = _env_required("GITHUB_CLIENT_ID")
    client_secret = _env_required("GITHUB_CLIENT_SECRET")
    allowed = {
        s.strip()
        for s in _env_required("GITHUB_ALLOWED_LOGINS").split(",")
        if s.strip()
    }
    if not allowed:
        raise RuntimeError("GITHUB_ALLOWED_LOGINS must list at least one login")

    provider = GitHubOAuthProvider(
        client_id=client_id,
        client_secret=client_secret,
        allowed_logins=allowed,
        sessions=_SESSIONS,
        base_url=base_url,
    )

    app = create_app(
        mcp=mcp,
        provider=provider,
        base_url=base_url,
        title="GitHub OAuth MCP",
    )

    # Wire in the GitHub OAuth callback route. Same pattern create_app()
    # uses for /health: insert at the front of the router so it beats the
    # catch-all MCP transport.
    async def callback(request: Request):
        code = request.query_params.get("code", "")
        state = request.query_params.get("state", "")
        async with httpx.AsyncClient(timeout=10) as http_client:
            return await _handle_callback(
                code=code,
                state=state,
                sessions=_SESSIONS,
                allowed_logins=allowed,
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
                http_client=http_client,
            )

    app.routes.insert(0, Route("/auth/github/callback", callback, methods=["GET"]))
    return app


# Only build at import time if the env is fully populated — keeps the module
# importable for tests (which construct their own provider).
if all(os.getenv(k) for k in ("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "GITHUB_ALLOWED_LOGINS")):
    app = build_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(build_app(), host="0.0.0.0", port=8080, log_level="info")
