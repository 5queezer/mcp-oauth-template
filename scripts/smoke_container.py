"""Exercise fail-closed and demo-mode behavior of a built container image."""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import time
import urllib.error
import urllib.request
import uuid

from fastmcp import Client


def _docker(
    *arguments: str, check: bool = True, timeout: float = 30
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        text=True,
        capture_output=True,
        check=check,
        timeout=timeout,
    )


def _wait_for_health(port: int) -> None:
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                body = json.load(response)
                if response.status == 200 and body.get("status") == "ok":
                    return
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.25)
    raise RuntimeError(f"container did not become healthy at {url}")


async def _assert_tool(port: int, expected_tool: str) -> None:
    async with Client(f"http://127.0.0.1:{port}/mcp") as client:
        names = {tool.name for tool in await client.list_tools()}
        if expected_tool == "echo" and "echo" in names:
            result = await client.call_tool("echo", {"text": "container smoke"})
            if result.data != "container smoke":
                raise RuntimeError("container echo tool returned an unexpected result")
    if expected_tool not in names:
        raise RuntimeError(f"expected tool {expected_tool!r}; container exposed {sorted(names)!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--app", default="examples.echo_server:build_app")
    parser.add_argument("--tool", default="echo")
    args = parser.parse_args()

    uid = _docker("run", "--rm", "--entrypoint", "id", args.image, "-u").stdout.strip()
    if not uid.isdigit() or uid == "0":
        raise RuntimeError(f"container must run unprivileged; got UID {uid!r}")

    fail_closed_name = f"mcp-oauth-fail-closed-{uuid.uuid4().hex[:12]}"
    try:
        try:
            fail_closed = _docker(
                "run", "--name", fail_closed_name, args.image, check=False, timeout=15
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                "container stayed running without the required GitHub configuration"
            ) from error
        if fail_closed.returncode == 0:
            raise RuntimeError("container accepted missing GitHub configuration")
        if "required for GitHub OAuth" not in fail_closed.stderr:
            raise RuntimeError("container failed for an unexpected reason:\n" + fail_closed.stderr)
    finally:
        _docker("rm", "--force", fail_closed_name, check=False)

    name = f"mcp-oauth-smoke-{uuid.uuid4().hex[:12]}"
    try:
        _docker(
            "run",
            "--detach",
            "--name",
            name,
            "--publish",
            "127.0.0.1::8080",
            "--env",
            "MCP_AUTH_MODE=demo",
            "--env",
            f"MCP_APP={args.app}",
            args.image,
        )
        mapping = _docker("port", name, "8080/tcp").stdout.strip()
        port = int(mapping.rsplit(":", 1)[1])
        _wait_for_health(port)
        asyncio.run(_assert_tool(port, args.tool))
        _docker("stop", "--time", "10", name)
        state = json.loads(_docker("inspect", name, "--format", "{{json .State}}").stdout)
        if state["Running"] or state["ExitCode"] != 0 or state["OOMKilled"]:
            raise RuntimeError(f"container did not stop cleanly: {state}")
    finally:
        _docker("rm", "--force", name, check=False)


if __name__ == "__main__":
    main()
