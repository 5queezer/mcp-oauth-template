from __future__ import annotations

import importlib
import sys
from typing import Any


def _run_launcher(monkeypatch, **environment: str) -> dict[str, Any]:
    import uvicorn

    captured: dict[str, Any] = {}

    def fake_run(app: str, **kwargs: Any) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    for name in ("MCP_APP", "HOST", "PORT", "LOG_LEVEL"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    launcher = importlib.import_module("mcp_server.__main__")
    launcher.main()
    return captured


def test_launcher_uses_echo_factory_by_default(monkeypatch) -> None:
    captured = _run_launcher(monkeypatch)

    assert captured == {
        "app": "examples.echo_server:build_app",
        "factory": True,
        "host": "127.0.0.1",
        "log_level": "info",
        "port": 8080,
        "workers": 1,
    }


def test_launcher_passes_selected_factory_to_uvicorn_without_importing_it(
    monkeypatch,
) -> None:
    module_name = "application_that_must_not_be_imported"
    sys.modules.pop(module_name, None)

    captured = _run_launcher(
        monkeypatch,
        MCP_APP=f"{module_name}:build_app",
        HOST="127.0.0.1",
        PORT="9090",
        LOG_LEVEL="warning",
    )

    assert captured["app"] == f"{module_name}:build_app"
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 9090
    assert captured["log_level"] == "warning"
    assert module_name not in sys.modules
