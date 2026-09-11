from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = REPO_ROOT / "deploy.sh"


@pytest.fixture
def fake_gcloud(tmp_path: Path) -> tuple[dict[str, str], Path]:
    executable = tmp_path / "gcloud"
    log = tmp_path / "gcloud.log"
    deployed = tmp_path / "deployed"
    executable.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$GCLOUD_LOG"

if [[ "$*" == "config get-value project" ]]; then
  printf '%s\\n' "configured-project"
  exit 0
fi

if [[ "$*" == run\\ services\\ describe* ]]; then
  if [[ "${GCLOUD_DESCRIBE_FAILS:-0}" == "1" ]]; then
    echo "ERROR: (gcloud.run.services.describe) PERMISSION_DENIED: caller lacks permission" >&2
    exit 1
  fi
  if [[ "${GCLOUD_SERVICE_EXISTS:-0}" == "1" || -f "$GCLOUD_DEPLOYED" ]]; then
    if [[ "$*" == *MCP_AUTH_MODE* ]]; then
      printf '%s\\n' "${GCLOUD_DEPLOYED_AUTH_MODE:-}"
    else
      printf '%s\\n' "https://canonical-service-uc.a.run.app"
    fi
    exit 0
  fi
  echo "ERROR: (gcloud.run.services.describe) Cannot find service [unknown]." >&2
  exit 1
fi

if [[ "$*" == run\\ deploy* ]]; then
  if [[ "${GCLOUD_SERVICE_EXISTS:-0}" != "1" && ! -f "$GCLOUD_DEPLOYED" && "$*" == *"--no-traffic"* ]]; then
    echo "--no-traffic not supported when creating a new service." >&2
    exit 1
  fi
  : > "$GCLOUD_DEPLOYED"
fi
"""
    )
    executable.chmod(0o755)
    environment = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "GCLOUD_LOG": str(log),
        "GCLOUD_DEPLOYED": str(deployed),
    }
    return environment, log


def _run_deploy(environment: dict[str, str], *arguments: str) -> subprocess.CompletedProcess[str]:
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
    assert "--allow-unauthenticated" in deploy
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
    environment, log = fake_gcloud
    environment["GCLOUD_DESCRIBE_FAILS"] = "1"

    result = _run_deploy(environment, "technical-mcp", "us-central1")

    assert result.returncode == 1
    assert "Refusing to deploy" in result.stderr
    assert not any(command.startswith("run deploy ") for command in log.read_text().splitlines())
