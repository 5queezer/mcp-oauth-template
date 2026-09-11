# Contributing

Contributions should keep this repository small, auditable, and useful as a template. Prefer FastMCP's maintained protocol and authentication features over project-owned OAuth machinery.

## Set up the repository

```bash
git clone https://github.com/5queezer/mcp-oauth-template.git
cd mcp-oauth-template
uv sync --frozen --group dev
```

Create a branch from `main`. Keep each change focused and explain any new runtime dependency or public API change in the pull request.

## Validate a change

Run the required local checks:

```bash
make check
```

Changes to packaging or the runtime image should also run:

```bash
uv build
uv run python scripts/check_artifacts.py dist
make docker-smoke
```

Tests must cover externally meaningful behavior. Authentication changes should use the real FastMCP HTTP flow and mock only external services such as GitHub. Keep tests deterministic and free of live credentials.

Update the README and changelog when a change affects setup, configuration, deployment, security behavior, or the public Python API. Document breaking changes in `docs/migration.md`.

## Submit a pull request

Describe the problem, the resulting behavior, and the commands you ran. Call out security assumptions, storage requirements, and validation gaps that a reviewer cannot infer from the diff. CI must pass before merge.

Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md), not a public issue.
