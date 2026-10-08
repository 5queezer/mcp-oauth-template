# Changelog

This project records user-visible changes in this file.

## Unreleased

### Security

- Update locked PyJWT to 2.15.1 and urllib3 to 2.8.0 to resolve `pip-audit` advisories against 2.13.0 and 2.7.0.

### Changed

- Raise the minimum FastMCP to 4.0.11, MCP SDK to 2.3.0, Starlette to 1.7.0, and py-key-value-aio to 0.4.6, and refresh the lockfile.
- Update the pinned dev tools to Ruff 0.16.10, ty 0.0.85, and httpx2 2.13.1.
- Update container images to uv 0.12.23 and the current Python 3.14 slim-bookworm digest; CI now uses uv 0.12.23 and `astral-sh/setup-uv` 10.2.0.
- Group Dependabot version and security updates into one pull request per ecosystem.

## 0.3.1 - 2026-09-14

- Make the README easier to navigate and follow.
- Create a GitHub release from the package version after all main-branch CI jobs pass.
- Skip publication when a release for that version already exists.
- Require successful explicit IAM updates for Cloud Run privacy and public-access changes; deploy-command warnings no longer count as success.
- Stop when deployed authentication configuration cannot be read, and bootstrap only when the named service is absent.
- Declare the pinned `httpx2` test dependency directly.
- Update container images to Python 3.14 and uv 0.12.13.

## 0.3.0 - 2026-09-10

### Security

- Replaced the custom authorization server with FastMCP's maintained GitHub OAuth provider.
- Added downstream client consent and native PKCE, client, redirect, resource, and browser-state binding.
- Enforced a nonempty allowlist of immutable numeric GitHub IDs on each bearer request.
- Kept demo deployments private: public Cloud Run invocation is granted only in GitHub mode, on new and existing services alike.
- Stopped the deployment script when a service lookup fails for any reason other than a missing service, so it cannot bootstrap over a running OAuth deployment.
- Made GitHub authentication the default and required an explicit `demo` mode for anonymous access.

### Changed

- Raised the supported baseline to FastMCP 4.0.3 and Python 3.12 through 3.14.
- Added a locked uv environment and CI checks for lint, formatting, types, tests, dependency advisories, distributions, and the container.
- Added import-safe application factories and made the neutral echo server the container default.
- Reworked the Polymarket example around its public search and market endpoints.
- Set the Cloud Run steady-state maximum to one instance and preserved existing configuration during updates.

### Removed

- Removed the password and implicit single-user modes.
- Removed the project-owned OAuth routes, token/client stores, HTML templates, and request identity context variable.
- Removed mutable GitHub-login allowlists and process-local upstream sessions.

Read [docs/migration.md](docs/migration.md) before upgrading from 0.2.x.

## 0.2.1 - 2026-04-21

- Added the original custom upstream GitHub OAuth example.
- Set the FastMCP 2.13 dependency floor.
