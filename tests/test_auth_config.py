"""Configuration must never accidentally open access."""

import pytest

from mcp_server.auth import GitHubAuthProvider, auth_from_env


@pytest.fixture(autouse=True)
def clean_auth_env(monkeypatch, tmp_path):
    import fastmcp

    for key in (
        "MCP_AUTH_MODE",
        "BASE_URL",
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "GITHUB_ALLOWED_USER_IDS",
        "ADMIN_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path)


def test_missing_configuration_fails_closed():
    with pytest.raises(ValueError, match="BASE_URL"):
        auth_from_env()


def test_demo_must_be_explicit(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_MODE", "demo")
    assert auth_from_env() is None


def test_unknown_mode_is_not_anonymous(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_MODE", "gitub")
    with pytest.raises(ValueError, match="MCP_AUTH_MODE"):
        auth_from_env()


def test_obsolete_password_is_not_silently_ignored(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_MODE", "demo")
    monkeypatch.setenv("ADMIN_PASSWORD", "legacy-secret")
    with pytest.raises(ValueError, match="ADMIN_PASSWORD"):
        auth_from_env()


@pytest.mark.parametrize("ids", [set(), {"alice"}, {"0"}, {"-2"}, {"  "}])
def test_allowed_ids_must_be_nonempty_positive_numbers(ids):
    with pytest.raises(ValueError, match="user ID"):
        GitHubAuthProvider(
            allowed_user_ids=ids,
            client_id="github-app-id",
            client_secret="github-app-secret",
            base_url="http://localhost:8080",
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://public.example",
        "https://",
        "https:callback",
        "https://user:secret@example.com",
        "https://example.com/prefix",
        "https://example.com?tenant=a",
        "https://example.com/#fragment",
    ],
)
def test_invalid_public_url_rejected(url):
    with pytest.raises(ValueError, match="BASE_URL"):
        GitHubAuthProvider(
            allowed_user_ids={"101"},
            client_id="app-id",
            client_secret="app-secret",
            base_url=url,
        )


def test_github_config_uses_stable_ids(monkeypatch):
    for key, value in {
        "BASE_URL": "http://localhost:8080/",
        "GITHUB_CLIENT_ID": "app-id",
        "GITHUB_CLIENT_SECRET": "app-secret",
        "GITHUB_ALLOWED_USER_IDS": "101, 202",
    }.items():
        monkeypatch.setenv(key, value)
    provider = auth_from_env()
    assert isinstance(provider, GitHubAuthProvider)
    assert provider.allowed_user_ids == frozenset({"101", "202"})
    assert provider.required_scopes == ["read:user"]
