"""
Tests for examples/github_oauth_server.py.

We exercise:
  * GitHubOAuthProvider.authenticate — cookie + allowlist logic
  * GitHubOAuthProvider.challenge — redirect shape
  * SessionStore — TTL, one-shot state
  * _handle_callback — happy path + disallowed-login path, with a
    handwritten fake httpx client (no respx dependency)

Run: pytest tests/test_github_oauth.py -v
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from starlette.requests import Request

from examples.github_oauth_server import (
    GITHUB_API,
    GITHUB_TOKEN,
    SESSION_COOKIE,
    GitHubOAuthProvider,
    SessionStore,
    _handle_callback,
    _is_safe_return_url,
)

BASE_URL = "http://localhost:8080"


# ---------------------------------------------------------------------------
# Request builder
# ---------------------------------------------------------------------------


def make_request(cookies: dict | None = None, url: str = f"{BASE_URL}/authorize?x=1") -> Request:
    """Build a minimal Starlette Request for provider tests."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    headers: list[tuple[bytes, bytes]] = []
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers.append((b"cookie", cookie_str.encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": parsed.path,
        "raw_path": parsed.path.encode(),
        "query_string": parsed.query.encode(),
        "headers": headers,
        "scheme": parsed.scheme,
        "server": (parsed.hostname, parsed.port or 80),
    }
    return Request(scope)


def make_provider(allowed: set[str], sessions: SessionStore | None = None) -> GitHubOAuthProvider:
    return GitHubOAuthProvider(
        client_id="gh_client",
        client_secret="gh_secret",
        allowed_logins=allowed,
        sessions=sessions or SessionStore(),
        base_url=BASE_URL,
    )


# ---------------------------------------------------------------------------
# authenticate()
# ---------------------------------------------------------------------------


def test_authenticate_no_cookie_returns_none():
    provider = make_provider({"alice"})
    assert provider.authenticate(make_request(), {}) is None


def test_authenticate_expired_session_returns_none():
    sessions = SessionStore()
    sid = sessions.create("alice", "gh_tok", ttl=1)
    # Force expiry without sleeping: reach into the store.
    sessions._sessions[sid].expires = time.time() - 1
    provider = make_provider({"alice"}, sessions=sessions)
    assert provider.authenticate(make_request({SESSION_COOKIE: sid}), {}) is None


def test_authenticate_valid_cookie_allowed_login_returns_sub():
    sessions = SessionStore()
    sid = sessions.create("alice", "gh_tok")
    provider = make_provider({"alice", "bob"}, sessions=sessions)
    assert provider.authenticate(make_request({SESSION_COOKIE: sid}), {}) == "alice"


def test_authenticate_valid_cookie_disallowed_login_returns_none():
    """Allowlist shrinks after session was created → access revoked immediately."""
    sessions = SessionStore()
    sid = sessions.create("alice", "gh_tok")
    provider = make_provider({"bob"}, sessions=sessions)  # alice removed
    assert provider.authenticate(make_request({SESSION_COOKIE: sid}), {}) is None


# ---------------------------------------------------------------------------
# challenge()
# ---------------------------------------------------------------------------


def test_challenge_returns_redirect_to_github():
    provider = make_provider({"alice"})
    resp = provider.challenge(make_request(), {})
    assert resp is not None
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://github.com/login/oauth/authorize")
    assert "client_id=gh_client" in location
    assert "state=" in location
    assert "scope=read%3Auser" in location


def test_challenge_rejects_hostile_return_url():
    """A request with a mismatched host should still produce a safe state."""
    provider = make_provider({"alice"})
    req = make_request(url="http://evil.example.com/authorize?x=1")
    resp = provider.challenge(req, {})
    assert resp is not None
    # The state must point to our own base_url, not the attacker's.
    state = resp.headers["location"].split("state=")[1].split("&")[0]
    return_url = provider.sessions.consume_state(state)
    assert return_url is not None
    assert return_url.startswith(BASE_URL)


# ---------------------------------------------------------------------------
# SessionStore
# ---------------------------------------------------------------------------


def test_session_store_ttl_expiry():
    s = SessionStore()
    sid = s.create("alice", "tok", ttl=1)
    s._sessions[sid].expires = time.time() - 1  # force expiry
    assert s.get(sid) is None


def test_session_store_live_session_ok():
    s = SessionStore()
    sid = s.create("alice", "tok", ttl=60)
    entry = s.get(sid)
    assert entry is not None
    assert entry.login == "alice"
    assert entry.github_token == "tok"


def test_pending_state_one_shot():
    s = SessionStore()
    nonce = s.put_state(f"{BASE_URL}/authorize?code_challenge=abc")
    # First consume: ok.
    url = s.consume_state(nonce)
    assert url == f"{BASE_URL}/authorize?code_challenge=abc"
    # Second consume: gone.
    assert s.consume_state(nonce) is None


def test_pending_state_expiry():
    s = SessionStore()
    nonce = s.put_state(f"{BASE_URL}/authorize")
    # Backdate creation past TTL.
    s.pending_states[nonce] = (s.pending_states[nonce][0], time.time() - s.STATE_TTL - 1)
    assert s.consume_state(nonce) is None


def test_is_safe_return_url():
    assert _is_safe_return_url(f"{BASE_URL}/authorize?x=1", BASE_URL)
    assert not _is_safe_return_url("https://evil.com/authorize", BASE_URL)
    assert not _is_safe_return_url("http://localhost:9999/authorize", BASE_URL)


# ---------------------------------------------------------------------------
# _handle_callback — with a fake http_client
# ---------------------------------------------------------------------------


def _make_transport(responses: dict[str, httpx.Response]) -> httpx.MockTransport:
    """Route GET/POST by URL prefix to a canned Response."""

    def handler(request: httpx.Request) -> httpx.Response:
        for prefix, resp in responses.items():
            if str(request.url).startswith(prefix):
                return resp
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    return httpx.MockTransport(handler)


async def _callback_happy_path():
    sessions = SessionStore()
    nonce = sessions.put_state(f"{BASE_URL}/authorize?code_challenge=abc&state=xyz")
    transport = _make_transport({
        GITHUB_TOKEN: httpx.Response(200, json={"access_token": "gh_user_token"}),
        f"{GITHUB_API}/user": httpx.Response(200, json={"login": "alice", "id": 1}),
    })
    async with httpx.AsyncClient(transport=transport) as http_client:
        resp = await _handle_callback(
            code="the_code",
            state=nonce,
            sessions=sessions,
            allowed_logins={"alice"},
            client_id="cid",
            client_secret="csec",
            base_url=BASE_URL,
            http_client=http_client,
        )
    return resp, sessions


def test_callback_happy_path_sets_cookie_and_redirects():
    resp, sessions = asyncio.run(_callback_happy_path())
    assert resp.status_code == 302
    assert resp.headers["location"] == f"{BASE_URL}/authorize?code_challenge=abc&state=xyz"
    set_cookie = resp.headers["set-cookie"]
    assert SESSION_COOKIE in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=lax" in set_cookie.lower()
    # http base_url → Secure must NOT be set
    assert "secure" not in set_cookie.lower()
    live = sessions.get_by_login("alice")
    assert live is not None
    assert live.github_token == "gh_user_token"


async def _callback_disallowed():
    sessions = SessionStore()
    nonce = sessions.put_state(f"{BASE_URL}/authorize")
    transport = _make_transport({
        GITHUB_TOKEN: httpx.Response(200, json={"access_token": "gh_user_token"}),
        f"{GITHUB_API}/user": httpx.Response(200, json={"login": "eve"}),
    })
    async with httpx.AsyncClient(transport=transport) as http_client:
        resp = await _handle_callback(
            code="the_code",
            state=nonce,
            sessions=sessions,
            allowed_logins={"alice"},
            client_id="cid",
            client_secret="csec",
            base_url=BASE_URL,
            http_client=http_client,
        )
    return resp, sessions


def test_callback_disallowed_login_returns_403():
    resp, sessions = asyncio.run(_callback_disallowed())
    assert resp.status_code == 403
    body = resp.body.decode()
    assert "eve" in body
    assert "set-cookie" not in {k.lower() for k in resp.headers.keys()}
    assert sessions.get_by_login("eve") is None


async def _callback_invalid_state():
    sessions = SessionStore()
    transport = _make_transport({})  # no requests should be made
    async with httpx.AsyncClient(transport=transport) as http_client:
        return await _handle_callback(
            code="c",
            state="nonsense",
            sessions=sessions,
            allowed_logins={"alice"},
            client_id="cid",
            client_secret="csec",
            base_url=BASE_URL,
            http_client=http_client,
        )


def test_callback_invalid_state_rejected():
    resp = asyncio.run(_callback_invalid_state())
    assert resp.status_code == 400


async def _callback_https():
    sessions = SessionStore()
    https_base = "https://mcp.example.com"
    nonce = sessions.put_state(f"{https_base}/authorize")
    transport = _make_transport({
        GITHUB_TOKEN: httpx.Response(200, json={"access_token": "t"}),
        f"{GITHUB_API}/user": httpx.Response(200, json={"login": "alice"}),
    })
    async with httpx.AsyncClient(transport=transport) as http_client:
        return await _handle_callback(
            code="c",
            state=nonce,
            sessions=sessions,
            allowed_logins={"alice"},
            client_id="cid",
            client_secret="csec",
            base_url=https_base,
            http_client=http_client,
        )


def test_callback_https_sets_secure_cookie():
    resp = asyncio.run(_callback_https())
    assert resp.status_code == 302
    assert "secure" in resp.headers["set-cookie"].lower()
