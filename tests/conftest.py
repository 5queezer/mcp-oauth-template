"""Local OAuth fixtures: only GitHub's HTTP boundary is mocked."""

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import fastmcp
import httpx2
import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

from mcp_server import GitHubAuthProvider, create_app, get_current_sub

BASE_URL = "http://localhost:8080"
CALLBACK = "https://client.example/callback"


class HiddenFields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("type") == "hidden" and values.get("name"):
            self.fields[values["name"]] = values.get("value", "")


@dataclass
class GitHubHTTP:
    revoked: set[str] = field(default_factory=set)
    calls: list[tuple[str, str]] = field(default_factory=list)

    async def send(self, request):
        url = request.url
        self.calls.append((request.method, str(url)))
        if url.host == "github.com" and url.path == "/login/oauth/access_token":
            form = parse_qs(request.content.decode())
            assert form.get("code_verifier"), "Upstream exchange must use PKCE too"
            code = form["code"][0]
            assert code in {"101", "202", "303"}, code
            return httpx2.Response(
                200,
                request=request,
                json={
                    "access_token": f"upstream-{code}",
                    "token_type": "bearer",
                    "scope": "read:user",
                },
            )
        if url.host == "api.github.com":
            token = request.headers.get("authorization", "").removeprefix("Bearer ")
            if token in self.revoked:
                return httpx2.Response(401, request=request, json={"message": "Bad credentials"})
            uid = token.removeprefix("upstream-")
            assert uid in {"101", "202", "303"}, "Unexpected upstream credential"
            payload = {"id": int(uid), "login": f"user-{uid}", "name": f"User {uid}", "email": None}
            if url.path == "/user":
                return httpx2.Response(
                    200, request=request, json=payload, headers={"X-OAuth-Scopes": "read:user"}
                )
            if url.path == "/user/repos":
                return httpx2.Response(
                    200, request=request, json=[], headers={"X-OAuth-Scopes": "read:user"}
                )
        raise AssertionError(f"Unexpected external request: {request.method} {url}")


@pytest.fixture
def github_http(monkeypatch):
    backend = GitHubHTTP()

    async def send(client, request, **kwargs):
        return await backend.send(request)

    monkeypatch.setattr(httpx2.AsyncClient, "send", send)
    return backend


@pytest.fixture
def github_provider(monkeypatch, tmp_path, github_http):
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path)
    return GitHubAuthProvider(
        client_id="github-app-id",
        client_secret="test-github-app-secret",
        base_url=BASE_URL,
        allowed_user_ids={"101", "202"},
    )


@pytest.fixture
def oauth_client(github_provider):
    server = FastMCP("OAuth test", auth=github_provider)

    @server.tool()
    def identity() -> str | None:
        return get_current_sub()

    with TestClient(create_app(server), base_url=BASE_URL) as client:
        yield client


def register(client: TestClient, redirect_uri: str = CALLBACK) -> str:
    response = client.post(
        "/register",
        json={
            "redirect_uris": [redirect_uri],
            "client_name": "Test client",
            "token_endpoint_auth_method": "none",
            "scope": "read:user",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


def begin_authorization(
    client: TestClient, *, client_id: str | None = None, state: str = "opaque-state"
):
    client_id = client_id or register(client)
    verifier = secrets.token_urlsafe(32)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    params = {
        "client_id": client_id,
        "redirect_uri": CALLBACK,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": f"{BASE_URL}/mcp",
        "scope": "read:user",
        "state": state,
    }
    response = client.get("/authorize", params=params, follow_redirects=False)
    assert response.status_code == 302, response.text
    consent_url = response.headers["location"]
    assert consent_url.startswith(f"{BASE_URL}/consent?")
    page = client.get(consent_url)
    assert page.status_code == 200, page.text
    parser = HiddenFields()
    parser.feed(page.text)
    return client_id, verifier, parser.fields, page


def issue_code(
    client: TestClient, *, user: str = "101", state: str = "opaque-state"
) -> dict[str, str]:
    client_id, verifier, fields, _ = begin_authorization(client, state=state)
    response = client.post("/consent", data={**fields, "action": "approve"}, follow_redirects=False)
    assert response.status_code in {302, 303}, response.text
    upstream = urlsplit(response.headers["location"])
    assert upstream.hostname == "github.com"
    query = parse_qs(upstream.query)
    response = client.get(
        "/auth/callback", params={"state": query["state"][0], "code": user}, follow_redirects=False
    )
    assert response.status_code == 302, response.text
    callback = urlsplit(response.headers["location"])
    assert f"{callback.scheme}://{callback.netloc}{callback.path}" == CALLBACK
    result = parse_qs(callback.query)
    assert result.get("state") == [state]
    return {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": result["code"][0],
        "code_verifier": verifier,
        "redirect_uri": CALLBACK,
        "resource": f"{BASE_URL}/mcp",
    }


def mint_token(client: TestClient, **kwargs) -> str:
    response = client.post("/token", data=issue_code(client, **kwargs))
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def call_tool(
    client: TestClient, token: str, name: str = "identity", arguments: dict | None = None
):
    return client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
    )
