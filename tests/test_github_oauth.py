"""The shipped GitHub tools must use the current user's upstream credential."""

import httpx
import pytest
from starlette.testclient import TestClient

from examples import github_oauth_server
from tests.conftest import BASE_URL, call_tool, mint_token


def test_github_example_rejects_anonymous_mode(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_MODE", "demo")
    with pytest.raises(ValueError, match="GitHub"):
        github_oauth_server.build_app()


def test_github_tools_use_the_authenticated_users_token(monkeypatch, github_provider):
    monkeypatch.setattr(github_oauth_server, "auth_from_env", lambda: github_provider)
    original_client = httpx.AsyncClient
    seen_tokens = []

    def handler(request):
        token = request.headers["authorization"]
        seen_tokens.append(token)
        assert request.url.params["per_page"] == "2"
        assert request.url.path in {"/user/repos", "/user/starred"}
        if request.url.path == "/user/repos":
            assert request.url.params["visibility"] == "public"
        return httpx.Response(
            200,
            json=[
                {
                    "full_name": "owner/repo",
                    "private": False,
                    "description": None,
                    "html_url": "https://github.com/owner/repo",
                    "stargazers_count": 3,
                },
                {"full_name": "owner/private-repo", "private": True},
            ],
        )

    monkeypatch.setattr(
        github_oauth_server.httpx,
        "AsyncClient",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    with TestClient(github_oauth_server.build_app(), base_url=BASE_URL) as client:
        tokens = {uid: mint_token(client, user=uid) for uid in ["101", "202"]}
        for uid, token in tokens.items():
            response = call_tool(client, token, "whoami")
            assert response.status_code == 200
            assert response.json()["result"]["isError"] is False
            assert f"user-{uid}" in response.text
            assert "upstream-" not in response.text
            for name in ["list_my_repos", "get_starred"]:
                response = call_tool(client, token, name, {"limit": 2})
                assert response.json()["result"]["isError"] is False
                assert "owner/repo" in response.text
                assert "private-repo" not in response.text
                assert seen_tokens[-1] == f"Bearer upstream-{uid}"
                assert "upstream-" not in response.text
        for limit in [0, -1, 101]:
            before = len(seen_tokens)
            response = call_tool(client, tokens["101"], "list_my_repos", {"limit": limit})
            assert response.json()["result"]["isError"] is True
            assert len(seen_tokens) == before


def test_upstream_error_does_not_expose_credentials(monkeypatch, github_provider):
    monkeypatch.setattr(github_oauth_server, "auth_from_env", lambda: github_provider)
    original_client = httpx.AsyncClient
    transport = httpx.MockTransport(lambda request: httpx.Response(403, json={"message": "denied"}))
    monkeypatch.setattr(
        github_oauth_server.httpx,
        "AsyncClient",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )
    with TestClient(github_oauth_server.build_app(), base_url=BASE_URL) as client:
        token = mint_token(client)
        response = call_tool(client, token, "list_my_repos")
        assert response.json()["result"]["isError"] is True
        assert "upstream-" not in response.text
        assert "403" in response.text
