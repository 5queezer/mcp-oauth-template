# mcp-oauth-template

A small Python template for serving a remote [Model Context Protocol](https://modelcontextprotocol.io/) server with FastMCP and GitHub OAuth.

The repository keeps authentication policy in one place, uses FastMCP's maintained [GitHub OAuth provider](https://gofastmcp.com/integrations/github), and ships a container entrypoint that runs a selected application factory. GitHub OAuth is the default. Anonymous access requires `MCP_AUTH_MODE=demo`.

Version 0.3.0 replaces the custom OAuth server from 0.2.x. Existing users should read the [migration guide](docs/migration.md).

## Requirements

- Python 3.12, 3.13, or 3.14
- [uv](https://docs.astral.sh/uv/)
- Docker for the container checks
- Google Cloud CLI for the optional Cloud Run deployment

The committed `uv.lock` defines the tested dependency set. The package metadata allows compatible FastMCP 4.x releases, while CI installs the lockfile with `--frozen` and uv 0.12.12.

## Local quick start

Clone the repository and install the development environment:

```bash
git clone https://github.com/5queezer/mcp-oauth-template.git
cd mcp-oauth-template
uv sync --frozen --group dev
```

Start the neutral echo example in explicit demo mode:

```bash
HOST=127.0.0.1 MCP_AUTH_MODE=demo uv run python -m mcp_server
```

The server listens on `http://localhost:8080`. Its MCP endpoint is `/mcp`, and `curl http://localhost:8080/health` returns a process health check. Demo mode has no application authentication; use it only on a trusted network.

## GitHub OAuth

Create a GitHub OAuth app with these values for local development:

| GitHub setting | Value |
| --- | --- |
| Homepage URL | `http://localhost:8080` |
| Authorization callback URL | `http://localhost:8080/auth/callback` |

Copy the configuration template, add the OAuth app credentials, and list the numeric GitHub user IDs that may connect:

```bash
cp .env.example .env
uv run --env-file .env python -m mcp_server
```

GitHub exposes the immutable numeric ID as the `id` field in `GET https://api.github.com/users/{login}`. Do not use mutable account names in `GITHUB_ALLOWED_USER_IDS`.

The provider requests [`read:user`](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps). That scope supports profile identity and does not grant access to private repositories. The GitHub example limits its repository tools to public data; it never returns the upstream access token.

## Build an application

Export an import-safe `build_app` factory. Construct the auth provider inside the factory so imports, packaging checks, and tooling do not require secrets.

```python
# examples/my_service.py
from fastmcp import FastMCP
from starlette.applications import Starlette

from mcp_server import auth_from_env, create_app, get_current_sub


def build_app() -> Starlette:
    auth = auth_from_env()
    mcp = FastMCP("my-service", auth=auth)

    @mcp.tool()
    def identity() -> dict[str, str | None]:
        return {"subject": get_current_sub()}

    return create_app(mcp, allow_anonymous=auth is None)
```

Select the factory through `MCP_APP`:

```bash
MCP_APP=examples.my_service:build_app uv run --env-file .env python -m mcp_server
```

`auth_from_env()` returns `None` only when `MCP_AUTH_MODE=demo`. The `allow_anonymous` expression above therefore preserves the explicit opt-in. The launcher uses one Uvicorn worker.

The container copies `mcp_server/` and `examples/` instead of the whole build context. Keep custom factories in one of those packages, or add their package to the Dockerfile's explicit copy steps.

The repository includes three factories:

| Factory | Purpose |
| --- | --- |
| `examples.echo_server:build_app` | Deterministic echo smoke test; container default |
| `examples.github_oauth_server:build_app` | Caller identity and public GitHub data with the caller's credential |
| `examples.polymarket_server:build_app` | Read-only Polymarket event and market search |

The GitHub example requires GitHub mode. The other examples may run in demo mode for local testing.

## Public API

```text
create_app(mcp: FastMCP, *, allow_anonymous: bool = False,
           cors_origins: list[str] | None = None)
```

`create_app` serves stateless JSON MCP transport at `/mcp`, adds `/health`, and rejects an MCP server without authentication unless `allow_anonymous=True`. Its default browser CORS origin is `https://claude.ai`; pass the exact origins for other browser clients.

`auth_from_env()` selects the configured auth mode. `GitHubAuthProvider` enforces the numeric-ID allowlist on each bearer request. `get_current_sub()` reads the current request's native subject and returns `None` outside an authenticated request.

Advanced users can construct the provider and supply an alternate store:

```text
GitHubAuthProvider(*, allowed_user_ids: Collection[str], client_id: str,
                   client_secret: str, base_url: str,
                   encrypted_storage: AsyncKeyValue | None = None)
```

FastMCP encrypts its default file store. A store supplied through `encrypted_storage` must encrypt its values before persistence.

Tools that call GitHub can obtain the current upstream credential through FastMCP's `get_access_token()` dependency. Treat `AccessToken.token` as a secret: use it only in the outbound authorization header and keep it out of logs and tool results.

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `MCP_AUTH_MODE` | No | `github` by default; `demo` opts into anonymous access |
| `BASE_URL` | GitHub mode | Public origin, without a path, query, fragment, or credentials |
| `GITHUB_CLIENT_ID` | GitHub mode | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | GitHub mode | GitHub OAuth app client secret |
| `GITHUB_ALLOWED_USER_IDS` | GitHub mode | Comma-separated positive numeric GitHub IDs |
| `MCP_APP` | No | `module:factory`; defaults to `examples.echo_server:build_app` |
| `FASTMCP_HOME` | No | Directory used by FastMCP for encrypted OAuth state |
| `HOST`, `PORT`, `LOG_LEVEL` | No | Uvicorn process settings |

`BASE_URL` must use HTTPS. The provider permits HTTP only for `localhost`, `127.0.0.1`, and `::1`. It rejects the removed `ADMIN_PASSWORD` setting so an obsolete deployment cannot fall through to anonymous access.

The application reads auth configuration when it builds the factory. Restart the local process or create a new service revision after changing the mode, credentials, allowlist, or base URL.

## OAuth and storage model

FastMCP supplies client registration, PKCE, downstream consent, browser-bound state, client and redirect binding, token issuance, and protected-resource discovery. The provider supports Client ID Metadata Documents and Dynamic Client Registration for compatible MCP clients. The locked FastMCP 4.0.3 and MCP SDK 2.2.0 stack negotiates MCP protocol version `2025-11-25` in the repository's HTTP tests. See the current [MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/) for the broader protocol contract.

The server issues one-hour FastMCP access tokens and validates GitHub access without an upstream verification cache. FastMCP stores registrations and token mappings in an encrypted file store under `FASTMCP_HOME` when you do not inject another store. A custom store must provide encryption itself.

GitHub does not expose an OAuth token-revocation endpoint for this provider, so the server does not advertise a local `/revoke` route. Revoke the OAuth app grant from the user's GitHub application settings to invalidate the GitHub credential. Token expiry, revocation, a new revision, or lost local storage may require the MCP client to reconnect; client refresh behavior varies, and this project does not promise an automatic refresh flow.

Dynamic client registration and consent endpoints must remain reachable by MCP clients and browsers. This template does not add ingress rate limits, registration quotas, or storage monitoring. An internet-facing operator should apply abuse controls at the edge and set an operational policy for storage growth and retention.

## Container

Build and smoke-test the image:

```bash
make docker-smoke
```

The image runs `python -m mcp_server` as UID/GID 10001, launches one worker, and sets `FASTMCP_HOME=/data/fastmcp`. Set `MCP_APP` and the auth variables at runtime. The smoke test starts the echo factory in demo mode and checks the health route and MCP tool list.

`/data/fastmcp` is writable container storage. Mount durable storage if the runtime supports it. Cloud Run's container filesystem is ephemeral.

## Cloud Run reference deployment

The script accepts a service, region, optional project, and optional application factory:

```text
./deploy.sh <service-name> <region> [project-id] [module:factory]
```

For a first GitHub deployment, create the secret in Secret Manager and grant the Cloud Run runtime service account access to it. Then run:

```bash
export GITHUB_CLIENT_ID='your-oauth-app-client-id'
export GITHUB_ALLOWED_USER_IDS='12345678,87654321'
export GITHUB_CLIENT_SECRET_REF='github-client-secret:latest'

./deploy.sh my-mcp europe-west1 my-project examples.github_oauth_server:build_app
```

The script creates a private bootstrap revision with a loopback URL, discovers Cloud Run's canonical URL, and updates `BASE_URL` on a new revision before switching traffic. Only then, and only in GitHub mode, does it grant `allUsers` the Cloud Run invoker role. The initial revision uses private IAM because `gcloud` does not support `--no-traffic` when creating a service. MCP clients and browser redirects need public network access; the application enforces GitHub authentication.

After the first deployment, set the GitHub OAuth app homepage to the printed service URL and its callback to `<service-url>/auth/callback`. Existing-service deployments preserve unrelated environment variables and Secret Manager bindings while updating `BASE_URL` and `MCP_APP`.

The script sets a maximum of one instance because its default OAuth store is local to one instance. The limit reduces steady-state concurrency, but Cloud Run rollouts can overlap revisions, and local state still disappears on restart, including after scale-to-zero. The reference script allows scale-to-zero to avoid idle compute charges. Use shared, durable, encrypted storage before enabling scaling or relying on state across revisions. The script does not provision that storage or Secret Manager.

A Cloud Run demo deployment requires `MCP_AUTH_MODE=demo` in the environment before the first deployment. Demo mode has no application authentication, so the script keeps the service private: it deploys with `--no-allow-unauthenticated` and adds no `allUsers` binding. Grant `roles/run.invoker` to named principals to reach it.

Updates to an existing service read the deployed `MCP_AUTH_MODE` and apply the same rule, so a demo service never becomes publicly invocable through a redeploy. If the service lookup fails for any reason other than a missing service, the script stops instead of bootstrapping over a running deployment.

## Client setup

Use the deployed `/mcp` URL in an MCP client that supports remote OAuth. For Claude, follow Anthropic's maintained [custom connector guide](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp): individual users start under Customize > Connectors, while organization administrators use Organization settings.

The repository tests protocol discovery and a real HTTP MCP flow. Maintainers have not run this release against live GitHub OAuth, Claude, or Cloud Run credentials.

## Development

Run the full local quality suite:

```bash
uv sync --frozen --group dev
make check
```

`make check` runs Ruff lint and formatting checks, ty, pytest, and a dependency advisory audit. CI also tests Python 3.12 through 3.14, builds the wheel and source distribution, runs tests from the source archive, checks ShellCheck, and smoke-tests the container.

See [CONTRIBUTING.md](CONTRIBUTING.md) for change guidance, [SECURITY.md](SECURITY.md) for private vulnerability reports, and [CHANGELOG.md](CHANGELOG.md) for release history.

## License

[MIT](LICENSE)
