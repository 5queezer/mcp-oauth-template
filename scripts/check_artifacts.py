"""Validate wheel/sdist contents and run tests against the built wheel."""

from __future__ import annotations

import argparse
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

REQUIRED_RUNTIME = {
    "mcp_server/__main__.py",
    "mcp_server/app.py",
    "mcp_server/auth.py",
    "examples/echo_server.py",
    "examples/github_oauth_server.py",
    "examples/polymarket_server.py",
}
REQUIRED_SDIST = REQUIRED_RUNTIME | {"LICENSE", "README.md", "pyproject.toml", "uv.lock"}
REQUIRED_SDIST |= {
    ".dockerignore",
    ".gcloudignore",
    ".gitignore",
    "deploy.sh",
    "scripts/check_artifacts.py",
    "scripts/smoke_container.py",
    "tests/__init__.py",
    "tests/conftest.py",
}
FORBIDDEN_PARTS = {".env", ".git", ".omx", ".claude", "__pycache__"}


def _normalise_sdist(names: list[str]) -> set[str]:
    normalised: set[str] = set()
    for name in names:
        parts = Path(name).parts
        if len(parts) > 1:
            normalised.add(Path(*parts[1:]).as_posix())
    return normalised


def _assert_contents(names: set[str], required: set[str], artifact: Path) -> None:
    missing = sorted(required - names)
    if missing:
        raise SystemExit(f"{artifact.name} is missing: {', '.join(missing)}")
    for name in names:
        parts = set(Path(name).parts)
        if parts & FORBIDDEN_PARTS or name.endswith((".pyc", ".pyo")):
            raise SystemExit(f"{artifact.name} contains forbidden path: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    args = parser.parse_args()

    wheels = sorted(args.dist.glob("*.whl"))
    sdists = sorted(args.dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("expected exactly one wheel and one source distribution")

    wheel, sdist = wheels[0].resolve(), sdists[0].resolve()
    with zipfile.ZipFile(wheel) as archive:
        _assert_contents(set(archive.namelist()), REQUIRED_RUNTIME, wheel)
    with tarfile.open(sdist, "r:gz") as archive:
        sdist_names = _normalise_sdist(archive.getnames())
        _assert_contents(sdist_names, REQUIRED_SDIST, sdist)
        if not any(name.startswith("tests/") and name.endswith(".py") for name in sdist_names):
            raise SystemExit(f"{sdist.name} does not contain tests")

        with tempfile.TemporaryDirectory() as temporary_directory:
            archive.extractall(temporary_directory, filter="data")
            temporary_root = Path(temporary_directory)
            source_roots = [path for path in temporary_root.iterdir() if path.is_dir()]
            if len(source_roots) != 1:
                raise SystemExit(f"{sdist.name} must contain exactly one source root")
            source_root = source_roots[0]
            environment = temporary_root / "venv"
            run_root = temporary_root / "run"
            run_root.mkdir()
            constraints = temporary_root / "constraints.txt"
            export = subprocess.run(
                [
                    "uv",
                    "export",
                    "--frozen",
                    "--all-groups",
                    "--no-emit-project",
                    "--output-file",
                    str(constraints),
                ],
                cwd=source_root,
                text=True,
                capture_output=True,
            )
            if export.returncode:
                raise SystemExit("could not export locked constraints:\n" + export.stderr)
            subprocess.run(["uv", "venv", str(environment)], check=True)
            python = environment / "bin" / "python"
            subprocess.run(
                [
                    "uv",
                    "pip",
                    "install",
                    "--python",
                    str(python),
                    "--constraint",
                    str(constraints),
                    str(wheel),
                    "pytest",
                ],
                check=True,
            )
            site_packages = subprocess.run(
                [str(python), "-c", "import site; print(site.getsitepackages()[0])"],
                cwd=run_root,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
            subprocess.run(
                [
                    str(python),
                    "-c",
                    (
                        "from pathlib import Path; import mcp_server, examples.echo_server; "
                        f"root=Path({site_packages!r}).resolve(); "
                        "assert Path(mcp_server.__file__).resolve().is_relative_to(root); "
                        "assert Path(examples.echo_server.__file__).resolve().is_relative_to(root)"
                    ),
                ],
                cwd=run_root,
                check=True,
            )
            subprocess.run(
                [str(python), "-m", "pytest", "-q", str(source_root / "tests")],
                cwd=run_root,
                check=True,
            )


if __name__ == "__main__":
    main()
