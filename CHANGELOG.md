# Changelog

This project records user-visible changes in this file.

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
