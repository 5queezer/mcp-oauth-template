from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = REPO_ROOT / "deploy.sh"


@pytest.fixture
def fake_gcloud(tmp_path: Path) -> tuple[dict[str, str], Path]:
    """Simulate service discovery and IAM failures without contacting Google Cloud."""
    executable = tmp_path / "gcloud"
    log = tmp_path / "gcloud.log"
    deployed = tmp_path / "deployed"
    executable.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["GCLOUD_LOG"]).open("a") as log:
    log.write(" ".join(args) + "\\n")
deployed = Path(os.environ["GCLOUD_DEPLOYED"])
exists = os.getenv("GCLOUD_SERVICE_EXISTS") == "1" or deployed.exists()
if args == ["config", "get-value", "project"]:
    print("configured-project")
elif args[:3] == ["run", "services", "describe"]:
    error = os.getenv("GCLOUD_DESCRIBE_ERROR") or ("PERMISSION_DENIED: caller lacks permission" if os.getenv("GCLOUD_DESCRIBE_FAILS") == "1" else None)
    if error:
        print("ERROR: (gcloud.run.services.describe) " + error, file=sys.stderr)
        sys.exit(7 if os.getenv("GCLOUD_DESCRIBE_ERROR") else 1)
    if not exists:
        print(f"ERROR: (gcloud.run.services.describe) Cannot find service [{args[3]}]", file=sys.stderr)
        sys.exit(1)
    url = os.getenv("GCLOUD_SERVICE_URL", "https://canonical-service-uc.a.run.app")
    if args[-1].startswith("value(") and "MCP_AUTH_MODE" in args[-1]:
        mode = os.getenv("GCLOUD_AUTH_MODE", os.getenv("GCLOUD_DEPLOYED_AUTH_MODE", ""))
        print("" if mode == "__missing__" else mode)
    elif args[-1] == "value(status.url)":
        print(url)
    else:
        mode = os.getenv("GCLOUD_AUTH_MODE", os.getenv("GCLOUD_DEPLOYED_AUTH_MODE", "github")) or "__missing__"
        env = [] if mode == "__missing__" else [{"name": "MCP_AUTH_MODE", "value": mode}]
        print(json.dumps({"status": {"url": url}, "spec": {"template": {"spec": {"containers": [{"env": env}]}}}}))
elif args[:3] == ["run", "services", "get-iam-policy"]:
    if os.getenv("GCLOUD_IAM_GET_ERROR"):
        print("Cannot read IAM policy", file=sys.stderr)
        sys.exit(8)
    bindings = [{"role": "roles/run.invoker", "members": ["allUsers"]}] if os.getenv("GCLOUD_PUBLIC_IAM") == "1" else []
    print(json.dumps({"bindings": bindings}))
elif args[:3] in (["run", "services", "remove-iam-policy-binding"], ["run", "services", "add-iam-policy-binding"]):
    if os.getenv("GCLOUD_IAM_WRITE_ERROR"):
        print("Cannot update IAM policy", file=sys.stderr)
        sys.exit(9)
elif args[:2] == ["run", "deploy"]:
    if not exists and "--no-traffic" in args:
        print("--no-traffic not supported when creating a new service.", file=sys.stderr)
        sys.exit(1)
    deployed.touch()
"""
    )
    executable.chmod(0o755)
    environment: dict[str, str] = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "GCLOUD_LOG": str(log),
        "GCLOUD_DEPLOYED": str(deployed),
    }
    for name in (
        "MCP_AUTH_MODE",
        "MCP_APP",
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET_REF",
        "GITHUB_ALLOWED_USER_IDS",
    ):
        environment.pop(name, None)
    return environment, log


def _run_deploy(environment: dict[str, str], *arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the real deployment script with the supplied fake Cloud SDK environment."""
    return subprocess.run(
        ["bash", str(DEPLOY_SCRIPT), *arguments],
        cwd=REPO_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def test_existing_service_preserves_configuration_and_selects_application(
    fake_gcloud: tuple[dict[str, str], Path],
) -> None:
    """Update the selected factory without replacing unrelated environment or secret bindings."""
    environment, log = fake_gcloud
    environment["GCLOUD_SERVICE_EXISTS"] = "1"

    result = _run_deploy(
        environment,
        "technical-mcp",
        "europe-west1",
        "explicit-project",
        "examples.polymarket_server:build_app",
    )

    assert result.returncode == 0, result.stderr
    commands = log.read_text().splitlines()
    deploy = next(command for command in commands if command.startswith("run deploy "))
    assert "--project explicit-project" in deploy
    assert "--region europe-west1" in deploy
    assert "--source ." in deploy
    assert "--max-instances 1" in deploy
    assert "--allow-unauthenticated" not in deploy
    assert "--update-env-vars" in deploy
    assert "BASE_URL=https://canonical-service-uc.a.run.app" in deploy
    assert "MCP_APP=examples.polymarket_server:build_app" in deploy
    assert "--set-env-vars" not in deploy
    assert "--set-secrets" not in deploy
    assert any(
        "services update-traffic" in command and "--to-latest" in command for command in commands
    )


def test_new_service_bootstraps_privately_then_uses_discovered_url(
    fake_gcloud: tuple[dict[str, str], Path],
) -> None:
    """Expose a new GitHub service only after its canonical URL and revision are ready."""
    environment, log = fake_gcloud
    environment.update(
        {
            "GITHUB_CLIENT_ID": "client-id",
            "GITHUB_CLIENT_SECRET": "plain-never-pass",
            "GITHUB_CLIENT_SECRET_REF": "github-client-secret:latest",
            "GITHUB_ALLOWED_USER_IDS": "123,456",
        }
    )

    result = _run_deploy(environment, "new-mcp", "us-central1")

    assert result.returncode == 0, result.stderr
    commands = log.read_text().splitlines()
    bootstrap = next(command for command in commands if command.startswith("run deploy "))
    assert "--project configured-project" in bootstrap
    assert "--no-allow-unauthenticated" in bootstrap
    assert "--no-traffic" not in bootstrap
    assert "--max-instances 1" in bootstrap
    assert "BASE_URL=http://127.0.0.1:8080" in bootstrap
    assert "MCP_AUTH_MODE=github" in bootstrap
    assert "MCP_APP=examples.echo_server:build_app" in bootstrap
    assert "GITHUB_ALLOWED_USER_IDS=123,456" in bootstrap
    assert "--update-secrets GITHUB_CLIENT_SECRET=github-client-secret:latest" in bootstrap
    assert "plain-never-pass" not in bootstrap
    update = next(command for command in commands if command.startswith("run services update "))
    assert "--no-traffic" in update
    assert "--max-instances 1" in update
    assert "--update-env-vars" in update
    assert "BASE_URL=https://canonical-service-uc.a.run.app" in update
    assert "--set-env-vars" not in update
    traffic_index = next(
        i for i, command in enumerate(commands) if "services update-traffic" in command
    )
    iam_index = next(
        i for i, command in enumerate(commands) if "services add-iam-policy-binding" in command
    )
    assert traffic_index < iam_index
    assert "--member allUsers" in commands[iam_index]
    assert "--role roles/run.invoker" in commands[iam_index]
    assert "https://canonical-service-uc.a.run.app/mcp" in result.stdout


def test_new_github_service_fails_closed_without_credentials(
    fake_gcloud: tuple[dict[str, str], Path],
) -> None:
    """Reject missing bootstrap credentials before any service can be created."""
    environment, log = fake_gcloud
    for name in (
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET_REF",
        "GITHUB_ALLOWED_USER_IDS",
    ):
        environment.pop(name, None)

    result = _run_deploy(environment, "new-mcp", "us-central1")

    assert result.returncode != 0
    assert "GITHUB_CLIENT_ID" in result.stderr
    assert not any(command.startswith("run deploy ") for command in log.read_text().splitlines())


def test_new_demo_service_requires_explicit_mode(
    fake_gcloud: tuple[dict[str, str], Path],
) -> None:
    """Allow an explicitly selected demo to bootstrap with private invocation settings."""
    environment, log = fake_gcloud
    environment["MCP_AUTH_MODE"] = "demo"

    result = _run_deploy(environment, "demo-mcp", "us-central1")

    assert result.returncode == 0, result.stderr
    bootstrap = next(
        command for command in log.read_text().splitlines() if command.startswith("run deploy ")
    )
    assert "MCP_AUTH_MODE=demo" in bootstrap
    assert "--no-allow-unauthenticated" in bootstrap


def test_existing_demo_service_stays_private(
    fake_gcloud: tuple[dict[str, str], Path],
) -> None:
    """Retain private invocation when updating an existing demo service."""
    environment, log = fake_gcloud
    environment["GCLOUD_SERVICE_EXISTS"] = "1"
    environment["GCLOUD_DEPLOYED_AUTH_MODE"] = "demo"

    result = _run_deploy(environment, "demo-mcp", "us-central1")

    assert result.returncode == 0, result.stderr
    commands = log.read_text().splitlines()
    deploy = next(command for command in commands if command.startswith("run deploy "))
    assert "--no-allow-unauthenticated" in deploy
    assert "--allow-unauthenticated" not in deploy.replace("--no-allow-unauthenticated", "")
    assert not any("add-iam-policy-binding" in command for command in commands)


def test_existing_service_rejects_unsupported_deployed_mode(
    fake_gcloud: tuple[dict[str, str], Path],
) -> None:
    """Refuse an unknown deployed mode instead of guessing its authentication policy."""
    environment, log = fake_gcloud
    environment["GCLOUD_SERVICE_EXISTS"] = "1"
    environment["GCLOUD_DEPLOYED_AUTH_MODE"] = "anonymous"

    result = _run_deploy(environment, "odd-mcp", "us-central1")

    assert result.returncode == 2
    assert "Unsupported MCP_AUTH_MODE" in result.stderr
    assert not any(command.startswith("run deploy ") for command in log.read_text().splitlines())


def test_new_demo_service_never_becomes_publicly_invocable(
    fake_gcloud: tuple[dict[str, str], Path],
) -> None:
    """Never grant anonymous invocation to an application without its own authentication."""
    environment, log = fake_gcloud
    environment["MCP_AUTH_MODE"] = "demo"

    result = _run_deploy(environment, "demo-mcp", "us-central1")

    assert result.returncode == 0, result.stderr
    commands = log.read_text().splitlines()
    assert not any("add-iam-policy-binding" in command for command in commands)
    assert not any("--member allUsers" in command for command in commands)
    assert "stays private" in result.stdout


def test_lookup_failure_does_not_bootstrap_over_an_existing_service(
    fake_gcloud: tuple[dict[str, str], Path],
) -> None:
    """Treat a failed existence lookup as an error rather than permission to bootstrap."""
    environment, log = fake_gcloud
    environment["GCLOUD_DESCRIBE_FAILS"] = "1"

    result = _run_deploy(environment, "technical-mcp", "us-central1")

    assert result.returncode == 1
    assert "Refusing to deploy" in result.stderr
    assert not any(command.startswith("run deploy ") for command in log.read_text().splitlines())


@pytest.mark.parametrize("remote_mode", ["github", "demo", "__missing__"])
def test_existing_service_uses_deployed_mode_for_iam(fake_gcloud, remote_mode):
    """Use remote configuration even when the local shell selects the opposite mode."""
    environment, log = fake_gcloud
    environment.update(
        {
            "GCLOUD_SERVICE_EXISTS": "1",
            "GCLOUD_AUTH_MODE": remote_mode,
            "MCP_AUTH_MODE": "github" if remote_mode == "demo" else "demo",
        }
    )
    result = _run_deploy(environment, "existing-mcp", "europe-west1")
    assert result.returncode == 0, result.stderr
    commands = log.read_text().splitlines()
    deploy = next(command for command in commands if command.startswith("run deploy "))
    if remote_mode == "demo":
        assert "--no-allow-unauthenticated" in deploy
        assert "--allow-unauthenticated" not in deploy
        assert "--invoker-iam-check" in deploy
        assert not any("--member allUsers" in command for command in commands)
    else:
        assert "--allow-unauthenticated" not in deploy
        assert "add-iam-policy-binding" in commands[-1]
        assert "--member allUsers" in commands[-1]
    assert "MCP_AUTH_MODE=" not in deploy


@pytest.mark.parametrize(
    "error",
    [
        "PERMISSION_DENIED: missing run.services.get",
        "UNAVAILABLE: service temporarily unavailable",
        "NOT_FOUND: Project [missing-project] could not be found.",
    ],
)
def test_describe_failure_never_bootstraps_a_service(fake_gcloud, error):
    """Preserve lookup errors even when credentials would permit a bootstrap deployment."""
    environment, log = fake_gcloud
    environment.update(
        {
            "GCLOUD_SERVICE_EXISTS": "1",
            "GCLOUD_DESCRIBE_ERROR": error,
            "GITHUB_CLIENT_ID": "client-id",
            "GITHUB_CLIENT_SECRET_REF": "secret:latest",
            "GITHUB_ALLOWED_USER_IDS": "101",
        }
    )
    result = _run_deploy(environment, "existing-mcp", "europe-west1")
    assert result.returncode == 7
    assert error in result.stderr
    assert all(
        command.startswith(("run services describe ", "config get-value "))
        for command in log.read_text().splitlines()
    )


@pytest.mark.parametrize(
    "mode,url",
    [
        ("unknown", "https://canonical-service-uc.a.run.app"),
        ("github", ""),
    ],
)
def test_unreadable_deployed_config_fails_before_mutation(fake_gcloud, mode, url):
    """Avoid cloud mutations when the canonical URL or authentication mode is unusable."""
    environment, log = fake_gcloud
    environment.update(
        {"GCLOUD_SERVICE_EXISTS": "1", "GCLOUD_AUTH_MODE": mode, "GCLOUD_SERVICE_URL": url}
    )
    result = _run_deploy(environment, "existing-mcp", "europe-west1")
    assert result.returncode != 0
    assert all(
        command.startswith(("run services describe ", "config get-value "))
        for command in log.read_text().splitlines()
    )


def test_existing_public_demo_revokes_invoker_before_deploy(fake_gcloud):
    """Remove public access before deploying another revision of an existing demo."""
    environment, log = fake_gcloud
    environment.update(
        {
            "GCLOUD_SERVICE_EXISTS": "1",
            "GCLOUD_AUTH_MODE": "demo",
            "GCLOUD_PUBLIC_IAM": "1",
        }
    )
    result = _run_deploy(environment, "demo-mcp", "europe-west1")
    assert result.returncode == 0, result.stderr
    commands = log.read_text().splitlines()
    revoke = next(i for i, command in enumerate(commands) if "remove-iam-policy-binding" in command)
    deploy = next(i for i, command in enumerate(commands) if command.startswith("run deploy "))
    assert revoke < deploy
    assert "--member allUsers" in commands[revoke]
    assert "--role roles/run.invoker" in commands[revoke]
    assert "--all" in commands[revoke]
    assert not any("add-iam-policy-binding" in command for command in commands)


@pytest.mark.parametrize(
    "failure,expected", [("GCLOUD_IAM_GET_ERROR", 8), ("GCLOUD_IAM_WRITE_ERROR", 9)]
)
def test_demo_iam_failure_stops_before_deployment(fake_gcloud, failure, expected):
    """Fail before deployment when private invocation cannot be verified or enforced."""
    environment, log = fake_gcloud
    environment.update(
        {
            "GCLOUD_SERVICE_EXISTS": "1",
            "GCLOUD_AUTH_MODE": "demo",
            "GCLOUD_PUBLIC_IAM": "1",
            failure: "1",
        }
    )
    result = _run_deploy(environment, "demo-mcp", "europe-west1")
    assert result.returncode == expected
    assert not any(command.startswith("run deploy ") for command in log.read_text().splitlines())


def test_github_iam_failure_is_reported_after_ready_revision(fake_gcloud):
    """Do not report success when the ready GitHub service cannot be made reachable."""
    environment, log = fake_gcloud
    environment.update({"GCLOUD_SERVICE_EXISTS": "1", "GCLOUD_IAM_WRITE_ERROR": "1"})
    result = _run_deploy(environment, "github-mcp", "europe-west1")
    assert result.returncode == 9
    assert "Cannot update IAM policy" in result.stderr
    commands = log.read_text().splitlines()
    assert "update-traffic" in commands[-2]
    assert "add-iam-policy-binding" in commands[-1]
    assert "Deployed:" not in result.stdout
