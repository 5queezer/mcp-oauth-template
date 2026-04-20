"""
Tests for MCP OAuth template.
Run: pytest tests/ -v
"""

import base64
import hashlib
import secrets
import pytest
from starlette.testclient import TestClient

from mcp_server.auth import (
    SingleUserProvider,
    StaticPasswordProvider,
    TokenStore,
    ClientStore,
    verify_pkce,
)
from mcp_server.app import create_app
from mcp_server.templates import render_login


REDIRECT_URI = "https://claude.ai/callback"


# ---------------------------------------------------------------------------
# PKCE Unit Tests
# ---------------------------------------------------------------------------

def make_pkce_pair():
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def test_pkce_valid():
    verifier, challenge = make_pkce_pair()
    assert verify_pkce(verifier, challenge)


def test_pkce_wrong_verifier():
    _, challenge = make_pkce_pair()
    assert not verify_pkce("wrong_verifier", challenge)


def test_pkce_tampered_challenge():
    verifier, _ = make_pkce_pair()
    assert not verify_pkce(verifier, "tampered_challenge")


# ---------------------------------------------------------------------------
# TokenStore Unit Tests
# ---------------------------------------------------------------------------

def test_token_store_full_flow():
    store = TokenStore()
    verifier, challenge = make_pkce_pair()

    code = store.create_code(
        challenge=challenge,
        redirect_uri=REDIRECT_URI,
        state="xyz",
        sub="test-user",
    )

    entry = store.consume_code(code)
    assert entry is not None
    assert entry.challenge == challenge

    # Code should be consumed (single-use)
    assert store.consume_code(code) is None


def test_token_store_invalid_token():
    store = TokenStore()
    assert store.validate_token("nonexistent") is None


def test_token_store_revoke():
    store = TokenStore()
    verifier, challenge = make_pkce_pair()
    code = store.create_code(challenge, REDIRECT_URI, "", "test-user")
    store.consume_code(code)  # consume so we can issue token

    token = store.create_token("user")
    assert store.validate_token(token) is not None

    store.revoke_token(token)
    assert store.validate_token(token) is None


# ---------------------------------------------------------------------------
# ClientStore Unit Tests
# ---------------------------------------------------------------------------

def test_client_store_register_and_get():
    cs = ClientStore()
    client = cs.register(redirect_uris=[REDIRECT_URI], client_name="test")
    assert client.client_id
    assert client.redirect_uris == [REDIRECT_URI]

    fetched = cs.get(client.client_id)
    assert fetched is not None
    assert fetched.client_id == client.client_id


def test_client_store_unknown_id():
    cs = ClientStore()
    assert cs.get("nonexistent") is None


# ---------------------------------------------------------------------------
# Integration Tests (Full OAuth Flow)
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    app = create_app(title="Test MCP")
    return TestClient(app, raise_server_exceptions=True)


def _register_client(client) -> str:
    """Register a client and return its client_id."""
    resp = client.post(
        "/register",
        json={"redirect_uris": [REDIRECT_URI], "client_name": "test-client"},
    )
    assert resp.status_code == 201
    return resp.json()["client_id"]


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_oauth_metadata(client):
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    data = resp.json()
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "registration_endpoint" in data
    assert "S256" in data["code_challenge_methods_supported"]


def test_protected_resource_metadata(client):
    resp = client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    data = resp.json()
    assert "resource" in data
    assert "authorization_servers" in data
    assert len(data["authorization_servers"]) == 1


def test_register_client(client):
    resp = client.post(
        "/register",
        json={"redirect_uris": [REDIRECT_URI], "client_name": "my-app"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "client_id" in data
    assert data["redirect_uris"] == [REDIRECT_URI]
    assert data["token_endpoint_auth_method"] == "none"


def test_register_missing_redirect_uris(client):
    resp = client.post("/register", json={"client_name": "no-uris"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


def test_authorize_unknown_client(client):
    verifier, challenge = make_pkce_pair()
    resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "unknown-client-id",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": REDIRECT_URI,
            "state": "s",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client"


def test_authorize_unregistered_redirect_uri(client):
    client_id = _register_client(client)
    verifier, challenge = make_pkce_pair()
    resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": "https://attacker.example.com/callback",
            "state": "s",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def _full_pkce_flow(client, password: str | None = None) -> str:
    """Helper: runs full PKCE flow (with registration), returns access token.

    If `password` is given, performs the POST-login step expected when a
    StaticPasswordProvider is active.
    """
    client_id = _register_client(client)
    verifier, challenge = make_pkce_pair()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REDIRECT_URI,
        "state": "test123",
    }

    # Step 1: /authorize (GET)
    resp = client.get("/authorize", params=params, follow_redirects=False)

    if password is not None:
        # Password provider: GET returns login page, POST with password redirects.
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        resp = client.post(
            "/authorize",
            params=params,
            data={"password": password},
            follow_redirects=False,
        )

    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "code=" in location
    assert "state=test123" in location

    code = location.split("code=")[1].split("&")[0]

    # Step 2: /token
    resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    return data["access_token"]


def test_full_oauth_flow(client):
    token = _full_pkce_flow(client)
    assert len(token) > 10


def test_mcp_requires_bearer(client):
    resp = client.post("/mcp", json={})
    assert resp.status_code == 401
    www_auth = resp.headers.get("www-authenticate", "")
    assert "resource_metadata" in www_auth


def test_mcp_with_expired_token(client):
    """Expired/revoked tokens must be rejected with 401."""
    token = _full_pkce_flow(client)
    # Revoke the token first
    client.post("/revoke", data=f"token={token}")
    resp = client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {token}"},
        json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
    )
    assert resp.status_code == 401


def test_code_single_use(client):
    """Auth codes must be consumed exactly once."""
    client_id = _register_client(client)
    verifier, challenge = make_pkce_pair()
    resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": REDIRECT_URI,
            "state": "",
        },
        follow_redirects=False,
    )
    code = resp.headers["location"].split("code=")[1].split("&")[0]

    # First exchange: success
    r1 = client.post("/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
    })
    assert r1.status_code == 200

    # Second exchange: fail
    r2 = client.post("/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
    })
    assert r2.status_code == 400
    assert r2.json()["error"] == "invalid_grant"


def test_wrong_verifier_rejected(client):
    client_id = _register_client(client)
    _, challenge = make_pkce_pair()
    resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": REDIRECT_URI,
            "state": "",
        },
        follow_redirects=False,
    )
    code = resp.headers["location"].split("code=")[1].split("&")[0]

    r = client.post("/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": "wrong_verifier_that_will_fail",
    })
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_token_rfc6749_error_format(client):
    """Token endpoint errors must use RFC 6749 format, not FastAPI detail."""
    r = client.post("/token", data={
        "grant_type": "client_credentials",  # unsupported
        "code": "x",
        "code_verifier": "x",
    })
    assert r.status_code == 400
    body = r.json()
    assert "error" in body
    assert "detail" not in body


# ---------------------------------------------------------------------------
# Password login page (StaticPasswordProvider)
# ---------------------------------------------------------------------------

@pytest.fixture
def pw_client():
    app = create_app(
        title="Test MCP",
        provider=StaticPasswordProvider("s3cr3t"),
    )
    return TestClient(app, raise_server_exceptions=True)


def _pw_register(pw_client) -> str:
    resp = pw_client.post(
        "/register",
        json={"redirect_uris": [REDIRECT_URI], "client_name": "pw-client"},
    )
    assert resp.status_code == 201
    return resp.json()["client_id"]


def test_password_get_renders_login_form(pw_client):
    client_id = _pw_register(pw_client)
    _, challenge = make_pkce_pair()
    resp = pw_client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": REDIRECT_URI,
            "state": "xyz",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    assert 'action="/authorize"' in body
    assert 'method="post"' in body
    assert 'name="code_challenge"' in body
    assert f'value="{challenge}"' in body
    assert 'type="password"' in body


def test_password_post_correct_redirects(pw_client):
    client_id = _pw_register(pw_client)
    _, challenge = make_pkce_pair()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REDIRECT_URI,
        "state": "s1",
    }
    resp = pw_client.post(
        "/authorize",
        params=params,
        data={"password": "s3cr3t"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    loc = resp.headers["location"]
    assert loc.startswith(REDIRECT_URI)
    assert "code=" in loc
    assert "state=s1" in loc


def test_password_post_wrong_shows_error(pw_client):
    client_id = _pw_register(pw_client)
    _, challenge = make_pkce_pair()
    resp = pw_client.post(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": REDIRECT_URI,
            "state": "s1",
        },
        data={"password": "wrong"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "Invalid password" in resp.text
    assert 'type="password"' in resp.text


def test_password_post_missing_code_challenge_400(pw_client):
    client_id = _pw_register(pw_client)
    resp = pw_client.post(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "code_challenge_method": "S256",
            "redirect_uri": REDIRECT_URI,
            "state": "s",
        },
        data={"password": "s3cr3t"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_single_user_get_still_redirects(client):
    """SingleUserProvider (default) must not render HTML — short-circuits to 302."""
    client_id = _register_client(client)
    _, challenge = make_pkce_pair()
    resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": REDIRECT_URI,
            "state": "s",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "text/html" not in resp.headers.get("content-type", "")


def test_login_page_escapes_hostile_state():
    """Injected state must not produce raw <script> in the rendered form."""
    evil = '"><script>alert(1)</script>'
    html = render_login(
        title="Test",
        params={
            "response_type": "code",
            "code_challenge": "abc",
            "code_challenge_method": "S256",
            "redirect_uri": REDIRECT_URI,
            "state": evil,
        },
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html or "&quot;&gt;&lt;script&gt;" in html


def test_full_oauth_flow_with_password(pw_client):
    """End-to-end: GET shows form → POST password → /token → access token."""
    token = _full_pkce_flow(pw_client, password="s3cr3t")
    assert len(token) > 10
