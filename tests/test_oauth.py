"""Regressions for the native OAuth integration, including browser consent."""

from urllib.parse import parse_qs, urlsplit

import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

from mcp_server import GitHubAuthProvider, create_app, get_current_sub
from tests.conftest import (
    BASE_URL,
    begin_authorization,
    call_tool,
    issue_code,
    mint_token,
    register,
)


def test_discovery_describes_the_actual_resource(oauth_client):
    denied = oauth_client.post("/mcp", json={})
    assert denied.status_code == 401
    assert "resource_metadata=" in denied.headers["www-authenticate"]
    resource = oauth_client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert resource["resource"] == f"{BASE_URL}/mcp"
    metadata = oauth_client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["issuer"] == f"{BASE_URL}/"
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert "revocation_endpoint" not in metadata
    assert oauth_client.post("/revoke").status_code == 404


@pytest.mark.parametrize(
    "payload", [None, [], 7, {"redirect_uris": []}, {"redirect_uris": "https://client.example/cb"}]
)
def test_malformed_registration_is_a_client_error(oauth_client, payload):
    response = oauth_client.post("/register", json=payload)
    assert response.status_code == 400
    assert "error" in response.json()


@pytest.mark.parametrize(
    "redirect",
    [
        "http://evil.example/cb",
        "https://",
        "https://client.example/cb#fragment",
        "https://user:secret@client.example/cb",
        "javascript:alert(1)",
    ],
)
def test_unsafe_registration_rejected(oauth_client, redirect):
    response = oauth_client.post("/register", json={"redirect_uris": [redirect]})
    assert response.status_code == 400


@pytest.mark.parametrize("client_id", ["", "unknown", "github-app-id"])
def test_missing_or_unregistered_client_never_receives_code(oauth_client, client_id):
    response = oauth_client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": "https://attacker.invalid/cb",
            "response_type": "code",
            "code_challenge": "a" * 43,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "location" not in response.headers


def test_callback_must_match_registered_client(oauth_client):
    client_id = register(oauth_client)
    response = oauth_client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": "https://other.example/cb",
            "response_type": "code",
            "code_challenge": "a" * 43,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "location" not in response.headers


def test_consent_is_required_again_for_same_client(oauth_client):
    client_id, _, _, page = begin_authorization(oauth_client)
    assert "Test client" in page.text
    assert "client.example" in page.text
    _, _, _, second_page = begin_authorization(oauth_client, client_id=client_id)
    assert second_page.status_code == 200
    assert "csrf_token" in second_page.text


def test_consent_post_requires_the_approving_browser(oauth_client, github_http):
    _, _, fields, _ = begin_authorization(oauth_client)
    oauth_client.cookies.clear()
    response = oauth_client.post(
        "/consent", data={**fields, "action": "approve"}, follow_redirects=False
    )
    assert response.status_code in {400, 403}
    assert not github_http.calls


def test_upstream_callback_requires_browser_binding(oauth_client, github_http):
    _, _, fields, _ = begin_authorization(oauth_client)
    response = oauth_client.post(
        "/consent", data={**fields, "action": "approve"}, follow_redirects=False
    )
    state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
    oauth_client.cookies.clear()
    response = oauth_client.get("/auth/callback", params={"state": state, "code": "101"})
    assert response.status_code == 403
    assert not github_http.calls


@pytest.mark.parametrize("state", ["a+b", "a&other=1", "a#b", "a%26b"])
def test_complete_pkce_flow_preserves_opaque_state(oauth_client, state):
    response = oauth_client.post("/token", data=issue_code(oauth_client, state=state))
    assert response.status_code == 200, response.text
    assert response.json()["expires_in"] <= 3600
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert not response.json()["access_token"].startswith("upstream-")


def test_code_cannot_be_redeemed_by_another_client(oauth_client):
    form = issue_code(oauth_client)
    form["client_id"] = register(oauth_client)
    response = oauth_client.post("/token", data=form)
    assert response.status_code in {400, 401}
    assert "access_token" not in response.json()


def test_code_is_single_use(oauth_client):
    form = issue_code(oauth_client)
    assert oauth_client.post("/token", data=form).status_code == 200
    assert oauth_client.post("/token", data=form).status_code in {400, 401}


@pytest.mark.parametrize("verifier", ["wrong", "é" * 43])
def test_invalid_verifier_returns_client_error(oauth_client, verifier):
    form = issue_code(oauth_client)
    form["code_verifier"] = verifier
    response = oauth_client.post("/token", data=form)
    assert response.status_code in {400, 401}


def test_each_bearer_uses_its_own_github_identity(oauth_client):
    alice = mint_token(oauth_client, user="101")
    bob = mint_token(oauth_client, user="202")
    for token, subject in [(alice, "101"), (bob, "202"), (alice, "101")]:
        response = call_tool(oauth_client, token)
        assert response.status_code == 200, response.text
        assert response.json()["result"]["content"][0]["text"] == subject
        assert "upstream-" not in response.text


def test_allowlist_is_enforced_on_already_issued_token(oauth_client, github_provider):
    token = mint_token(oauth_client, user="101")
    github_provider.allowed_user_ids = frozenset({"202"})
    assert call_tool(oauth_client, token).status_code == 401


def test_disallowed_github_account_cannot_call_tools(oauth_client):
    token = mint_token(oauth_client, user="303")
    assert call_tool(oauth_client, token).status_code == 401


def test_revoking_upstream_authorization_invalidates_mcp_access(oauth_client, github_http):
    token = mint_token(oauth_client)
    assert call_tool(oauth_client, token).status_code == 200
    github_http.revoked.add("upstream-101")
    assert call_tool(oauth_client, token).status_code == 401


def test_github_tokens_are_encrypted_at_rest(oauth_client, tmp_path):
    mint_token(oauth_client)
    files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert files
    assert all(b"upstream-101" not in p.read_bytes() for p in files)


def test_wrong_resource_never_receives_authorization_code(oauth_client):
    response = oauth_client.get(
        "/authorize",
        params={
            "client_id": register(oauth_client),
            "redirect_uri": "https://client.example/callback",
            "response_type": "code",
            "code_challenge": "a" * 43,
            "code_challenge_method": "S256",
            "resource": "https://different-server.example/mcp",
        },
        follow_redirects=False,
    )
    assert response.status_code in {302, 400}
    if response.status_code == 302:
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["error"] == ["invalid_target"]
        assert "code" not in query


def test_callback_state_cannot_be_replayed(oauth_client):
    _, _, fields, _ = begin_authorization(oauth_client)
    consent = oauth_client.post(
        "/consent", data={**fields, "action": "approve"}, follow_redirects=False
    )
    state = parse_qs(urlsplit(consent.headers["location"]).query)["state"][0]
    params = {"state": state, "code": "101"}
    assert (
        oauth_client.get("/auth/callback", params=params, follow_redirects=False).status_code == 302
    )
    assert (
        oauth_client.get("/auth/callback", params=params, follow_redirects=False).status_code == 400
    )


def test_encrypted_storage_survives_app_recreation(oauth_client):
    token = mint_token(oauth_client)
    provider = GitHubAuthProvider(
        client_id="github-app-id",
        client_secret="test-github-app-secret",
        base_url=BASE_URL,
        allowed_user_ids={"101"},
    )
    server = FastMCP("restarted", auth=provider)

    @server.tool()
    def identity() -> str | None:
        return get_current_sub()

    with TestClient(create_app(server), base_url=BASE_URL) as restarted:
        response = call_tool(restarted, token)
        assert response.status_code == 200, response.text
        assert response.json()["result"]["content"][0]["text"] == "101"


def test_expired_native_access_token_is_denied(oauth_client, github_provider):
    token = mint_token(oauth_client)
    claims = github_provider.jwt_issuer.verify_token(token)
    expired = github_provider.jwt_issuer.issue_access_token(
        client_id=claims["client_id"], scopes=["read:user"], jti=claims["jti"], expires_in=-120
    )
    assert call_tool(oauth_client, expired).status_code == 401


@pytest.mark.parametrize(
    ("challenge", "method"),
    [
        ("", "S256"),
        ("a" * 42, "S256"),
        ("a" * 44, "S256"),
        ("+" * 43, "S256"),
        ("é" * 43, "S256"),
        ("a" * 43, "plain"),
    ],
)
def test_authorize_rejects_invalid_pkce_challenge(oauth_client, challenge, method):
    response = oauth_client.get(
        "/authorize",
        params={
            "client_id": register(oauth_client),
            "redirect_uri": "https://client.example/callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": method,
        },
        follow_redirects=False,
    )
    assert response.status_code in {302, 400}, response.text
    if response.status_code == 302:
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert "error" in query
        assert "code" not in query
