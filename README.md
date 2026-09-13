# mcp-oauth-template

Build a remote [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server with Python, FastMCP, and GitHub OAuth.

This template keeps authentication policy in one place and uses FastMCP's maintained [GitHub OAuth provider](https://gofastmcp.com/integrations/github).
The container runs the application factory you select.
GitHub OAuth is the default. Anonymous access requires `MCP_AUTH_MODE=demo`.

**Upgrading from 0.2.x?** Version 0.3.0 replaces the custom OAuth server. Read the [migration guide](docs/migration.md) first.

## On this page

- [Requirements](#requirements)
- [Local quick start](#local-quick-start)
- [GitHub OAuth](#github-oauth)
- [Client setup](#client-setup)
- [Build an application](#build-an-application)
- [Configuration](#configuration)
- [Container](#container)
- [Cloud Run reference deployment](#cloud-run-reference-deployment)
- [Public API](#public-api)
- [OAuth and storage model](#oauth-and-storage-model)
- [Development](#development)
- [License](#license)

## Requirements

For local development, install:

- Python 3.12, 3.13, or 3.14
- [uv](https://docs.astral.sh/uv/)

You also need Docker for container checks, or Google Cloud CLI for the optional Cloud Run deployment.

The committed `uv.lock` defines the tested dependencies. Package metadata allows compatible FastMCP 4.x releases.
CI installs the lockfile with `--frozen` and uv 0.12.12.

## Local quick start

### 1. Install the project

```bash
git clone https://github.com/5queezer/mcp-oauth-template.git
cd mcp-oauth-template
uv sync --frozen --group dev
```

### 2. Start the echo example

**Demo mode has no application authentication. Use it only on a trusted network.**

```bash
HOST=127.0.0.1 MCP_AUTH_MODE=demo uv run python -m mcp_server
```

The server listens on `http://localhost:8080`.

### 3. Check the server

Run this command in another terminal:

```bash
curl http://localhost:8080/health
```

| Endpoint | Purpose |
| --- | --- |
| `http://localhost:8080/health` | Process health check |
| `http://localhost:8080/mcp` | MCP client connection |

## GitHub OAuth

### 1. Create a GitHub OAuth app

Use these values for local development:

| GitHub setting | Value |
| --- | --- |
| Homepage URL | `http://localhost:8080` |
| Authorization callback URL | `http://localhost:8080/auth/callback` |

### 2. Configure credentials and allowed users

Copy the configuration template:

```bash
cp .env.example .env
```

Edit `.env`:

- Set `GITHUB_CLIENT_ID` to the OAuth app client ID.
- Set `GITHUB_CLIENT_SECRET` to the OAuth app client secret.
- Set `GITHUB_ALLOWED_USER_IDS` to the comma-separated numeric GitHub IDs of users who may connect.

GitHub returns the immutable numeric ID in the `id` field of `GET https://api.github.com/users/{login}`.
Do not use account names in `GITHUB_ALLOWED_USER_IDS`. Account names can change.

### 3. Start the authenticated server

Stop the demo server first if it still uses port 8080.

```bash
uv run --env-file .env python -m mcp_server
```

### GitHub permissions

The provider requests the [`read:user`](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps) scope for profile identity.
This scope does not grant access to private repositories.
The GitHub example uses public repository data only and never returns the upstream access token.

## Client setup

Connect an MCP client that supports remote OAuth to your server's `/mcp` URL.

For Claude, follow Anthropic's [custom connector guide](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp):

- Individual users start under **Customize > Connectors**.
- Organization administrators use **Organization settings**.

The repository tests protocol discovery and a real HTTP MCP flow.
Maintainers did not test this release with live GitHub OAuth, Claude, or Cloud Run credentials.

## Build an application

### Create a factory

Export a `build_app` factory that callers can import without secrets.
Construct the authentication provider inside the factory. This keeps imports, packaging checks, and tooling independent of secrets.

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

### Run your factory

Select the factory with `MCP_APP`:

```bash
MCP_APP=examples.my_service:build_app uv run --env-file .env python -m mcp_server
```

`auth_from_env()` returns `None` only when `MCP_AUTH_MODE=demo`.
The `allow_anonymous` expression therefore permits anonymous access only in demo mode.
The launcher uses one Uvicorn worker.

The container copies only `mcp_server/` and `examples/` from the build context.
Keep custom factories in one of these packages. For another package, add a copy step to the Dockerfile.

### Included examples

| Factory | Purpose |
| --- | --- |
| `examples.echo_server:build_app` | Deterministic echo smoke test. Container default. |
| `examples.github_oauth_server:build_app` | Caller identity and public GitHub data with the caller's credential |
| `examples.polymarket_server:build_app` | Read-only Polymarket event and market search |

The GitHub example requires GitHub mode. The other examples can use demo mode for local testing.

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `MCP_AUTH_MODE` | No | Defaults to `github`. Use `demo` for anonymous access. |
| `BASE_URL` | GitHub mode | Public origin without a path, query, fragment, or credentials |
| `GITHUB_CLIENT_ID` | GitHub mode | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | GitHub mode | GitHub OAuth app client secret |
| `GITHUB_ALLOWED_USER_IDS` | GitHub mode | Comma-separated positive numeric GitHub IDs |
| `MCP_APP` | No | `module:factory`. Defaults to `examples.echo_server:build_app`. |
| `FASTMCP_HOME` | No | Directory for FastMCP's encrypted OAuth state |
| `HOST`, `PORT`, `LOG_LEVEL` | No | Uvicorn process settings |

`BASE_URL` must use HTTPS. The provider permits HTTP only for `localhost`, `127.0.0.1`, and `::1`.
The provider rejects the removed `ADMIN_PASSWORD` setting. This prevents an obsolete deployment from allowing anonymous access.

The application reads authentication configuration when the factory runs.
Restart the local process after you change the mode, credentials, allowlist, or base URL.
For a deployed service, create a new revision.

## Container

Build and smoke-test the image:

```bash
make docker-smoke
```

The image:

- Runs `python -m mcp_server` as UID/GID 10001.
- Starts one worker.
- Sets `FASTMCP_HOME=/data/fastmcp`.

Set `MCP_APP` and the authentication variables at runtime.
The smoke test starts the echo factory in demo mode. It checks the health route and MCP tool list.

`/data/fastmcp` is writable container storage. Mount durable storage if the runtime supports it.
Cloud Run's container filesystem is temporary.

## Cloud Run reference deployment

### Deploy with GitHub OAuth

The script accepts a service, region, optional project, and optional application factory:

```text
./deploy.sh <service-name> <region> [project-id] [module:factory]
```

Before the first deployment:

1. Create the GitHub client secret in Secret Manager.
2. Grant the Cloud Run runtime service account access to that secret.
3. Set the deployment variables and run the script:

```bash
export GITHUB_CLIENT_ID='your-oauth-app-client-id'
export GITHUB_ALLOWED_USER_IDS='12345678,87654321'
export GITHUB_CLIENT_SECRET_REF='github-client-secret:latest'

./deploy.sh my-mcp europe-west1 my-project examples.github_oauth_server:build_app
```

After the first deployment, update the GitHub OAuth app:

| GitHub setting | Value |
| --- | --- |
| Homepage URL | The service URL printed by the script |
| Authorization callback URL | `<service-url>/auth/callback` |

### Deployment sequence

For a new service, the script:

1. Creates a private bootstrap revision with a loopback URL.
2. Gets Cloud Run's canonical service URL.
3. Updates `BASE_URL` on a new revision before switching traffic.
4. Grants `allUsers` the Cloud Run invoker role only after these steps, and only in GitHub mode.

The initial revision uses private Identity and Access Management (IAM) permissions.
This is necessary because `gcloud` does not support `--no-traffic` when creating a service.
MCP clients and browser redirects need public network access. The application enforces GitHub authentication.

For an existing service, the script updates `BASE_URL` and `MCP_APP`.
It preserves unrelated environment variables and Secret Manager bindings.
GitHub services receive public access through an explicit IAM command after the revision is ready.
If that command fails, the script reports a deployment failure.

### Storage and scaling limits

**Use shared, durable, encrypted storage before you enable scaling or rely on OAuth state across revisions.**

The script limits the service to one instance because the default OAuth store is local to that instance.
This reduces steady-state concurrency, but Cloud Run rollouts can overlap revisions.
Local state disappears on restart, including after scale-to-zero.

The reference script allows scale-to-zero to avoid idle compute charges.
It does not provision shared storage or Secret Manager.

### Private demo deployments

Set `MCP_AUTH_MODE=demo` in your environment before the first demo deployment.
Demo mode has no application authentication.
The script enables invoker IAM checks and removes any existing `allUsers` invoker binding before updating a demo.
IAM read or removal failures stop the script before deployment.

Grant `roles/run.invoker` to named principals who need access.
You can also use an authenticated local proxy:

```bash
gcloud run services proxy my-mcp --region europe-west1 --project my-project --port 8080
```

Connect the MCP client to `http://localhost:8080/mcp` through that proxy.

For existing services, the script reads the service URL and deployed `MCP_AUTH_MODE` together.
The local shell's mode does not override deployed configuration.
Lookup failures and unreadable configuration stop the script. The script preserves the original lookup error status.
Only an error identifying the named service as missing starts bootstrap.
The script does not infer GitHub mode when it cannot read the deployed mode.

## Public API

### Create the HTTP application

```text
create_app(mcp: FastMCP, *, allow_anonymous: bool = False,
           cors_origins: list[str] | None = None)
```

`create_app`:

- Serves stateless JSON MCP transport at `/mcp`.
- Adds the `/health` route.
- Rejects an MCP server without authentication unless `allow_anonymous=True`.

The default browser origin for cross-origin resource sharing (CORS) is `https://claude.ai`.
Pass exact origins through `cors_origins` for other browser clients.

### Read authentication and identity

| API | Behavior |
| --- | --- |
| `auth_from_env()` | Selects the configured authentication mode |
| `GitHubAuthProvider` | Enforces the numeric-ID allowlist on each bearer request |
| `get_current_sub()` | Returns the current request's native subject, or `None` outside an authenticated request |

### Supply a custom OAuth store

```text
GitHubAuthProvider(*, allowed_user_ids: Collection[str], client_id: str,
                   client_secret: str, base_url: str,
                   encrypted_storage: AsyncKeyValue | None = None)
```

FastMCP encrypts its default file store.
A store supplied through `encrypted_storage` must encrypt its values before persistence.

### Call GitHub from a tool

Use FastMCP's `get_access_token()` dependency to get the current upstream credential.
Treat `AccessToken.token` as a secret:

- Use it only in the outbound authorization header.
- Keep it out of logs and tool results.

## OAuth and storage model

### Protocol support

FastMCP provides:

- Client registration and Proof Key for Code Exchange (PKCE).
- Downstream consent and browser-bound state.
- Client and redirect binding.
- Token issuance and protected-resource discovery.

The provider supports Client ID Metadata Documents and Dynamic Client Registration for compatible MCP clients.
The lockfile pins FastMCP 4.0.3 and MCP SDK 2.2.0.
This stack negotiates MCP protocol version `2025-11-25` in the repository's HTTP tests.
See the [MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/) for the broader protocol contract.

### Tokens and persistence

The server issues one-hour FastMCP access tokens.
It checks GitHub access without an upstream verification cache.

By default, FastMCP stores registrations and token mappings in an encrypted file store under `FASTMCP_HOME`.
A custom store must provide encryption itself.

### Revocation and reconnection

GitHub does not expose an OAuth token-revocation endpoint for this provider.
The server therefore does not advertise a local `/revoke` route.
To invalidate a GitHub credential, revoke the OAuth app grant in the user's GitHub application settings.

The MCP client may need to reconnect after token expiry, revocation, a new revision, or loss of local storage.
Client refresh behavior varies. This project does not promise an automatic refresh flow.

### Public-service operations

MCP clients and browsers must be able to reach the dynamic client registration and consent endpoints.
This template does not add ingress rate limits, registration quotas, or storage monitoring.

For an internet-facing service:

- Apply abuse controls at the network edge.
- Set an operational policy for storage growth and retention.

## Development

Run the local quality suite:

```bash
uv sync --frozen --group dev
make check
```

`make check` runs Ruff lint and formatting checks, ty, pytest, and a dependency advisory audit.

CI also:

- Tests Python 3.12 through 3.14.
- Builds the wheel and source distribution.
- Runs tests from the source archive.
- Checks ShellCheck.
- Smoke-tests the container.

| Document | Purpose |
| --- | --- |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Change guidance |
| [SECURITY.md](SECURITY.md) | Private vulnerability reports |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## License

[MIT](LICENSE)
