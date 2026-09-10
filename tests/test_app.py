"""Exercise the actual HTTP transport and its authentication boundary."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from starlette.testclient import TestClient

from mcp_server import create_app, get_current_sub


class UserTokens(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        if token not in {"alice-token", "bob-token"}:
            return None
        return AccessToken(
            token=token,
            client_id="test-client",
            scopes=[],
            subject=token.removesuffix("-token"),
        )


def identity_server() -> FastMCP:
    server = FastMCP("identity-test", auth=UserTokens())

    @server.tool()
    def identity() -> str | None:
        return get_current_sub()

    return server


def call_identity(client: TestClient, user: str) -> str:
    response = client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {user}-token",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "identity", "arguments": {}},
        },
    )
    assert response.status_code == 200, response.text
    assert "mcp-session-id" not in response.headers
    return response.json()["result"]["content"][0]["text"]


def test_unprotected_server_requires_explicit_opt_in():
    with pytest.raises(ValueError, match="auth"):
        create_app(FastMCP("unprotected"))


def test_demo_health_and_no_fake_oauth_routes():
    with TestClient(create_app(FastMCP("demo"), allow_anonymous=True)) as client:
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/.well-known/oauth-authorization-server").status_code == 404


def test_invalid_bearer_denied():
    with TestClient(create_app(identity_server())) as client:
        for headers in ({}, {"Authorization": "Bearer invalid"}):
            response = client.post("/mcp", headers=headers, json={})
            assert response.status_code == 401
            assert response.headers["www-authenticate"].startswith("Bearer")


def test_identity_tracks_each_request_and_does_not_leak():
    with TestClient(create_app(identity_server())) as client:
        assert call_identity(client, "alice") == "alice"
        assert call_identity(client, "bob") == "bob"
        assert call_identity(client, "alice") == "alice"
        assert get_current_sub() is None


def test_concurrent_users_keep_their_identity():
    with TestClient(create_app(identity_server())) as client:
        users = ["alice", "bob"] * 5
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda user: call_identity(client, user), users))
        assert results == users


def test_cors_supports_protocol_headers_for_allowed_origin():
    with TestClient(create_app(identity_server(), cors_origins=["https://claude.ai"])) as client:
        response = client.options(
            "/mcp",
            headers={
                "Origin": "https://claude.ai",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": (
                    "authorization,content-type,mcp-protocol-version,mcp-session-id"
                ),
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "https://claude.ai"
        response = client.post("/mcp", headers={"Origin": "https://claude.ai"}, json={})
        assert response.status_code == 401
        assert (
            "www-authenticate" in response.headers.get("access-control-expose-headers", "").lower()
        )


def test_cors_rejects_unconfigured_origin():
    with TestClient(create_app(identity_server())) as client:
        response = client.options(
            "/mcp",
            headers={
                "Origin": "https://untrusted.invalid",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert "access-control-allow-origin" not in response.headers
