#!/usr/bin/env bash
# Deploy an MCP application factory to Google Cloud Run.

set -euo pipefail

usage() {
  echo "Usage: ./deploy.sh <service-name> <region> [project-id] [module:factory]" >&2
}

if (( $# < 2 || $# > 4 )); then
  usage
  exit 2
fi

SERVICE_NAME="$1"
REGION="$2"
PROJECT="${3:-$(gcloud config get-value project)}"
MCP_APP="${4:-${MCP_APP:-examples.echo_server:build_app}}"

if [[ -z "$PROJECT" || "$PROJECT" == "(unset)" ]]; then
  echo "A Google Cloud project is required as argument 3 or in gcloud config." >&2
  exit 2
fi

if [[ "$MCP_APP" != *:* ]]; then
  echo "MCP application must use module:factory syntax: $MCP_APP" >&2
  exit 2
fi

for value in "$MCP_APP" "${GITHUB_CLIENT_ID:-}" "${GITHUB_CLIENT_SECRET_REF:-}" "${GITHUB_ALLOWED_USER_IDS:-}"; do
  if [[ "$value" == *"|"* ]]; then
    echo "Deployment values must not contain the reserved '|' delimiter." >&2
    exit 2
  fi
done

describe_service() {
  gcloud run services describe "$SERVICE_NAME" \
    --region "$REGION" \
    --project "$PROJECT" \
    --format "$1"
}

service_url() {
  describe_service "value(status.url)"
}

# The mode the deployed revision actually runs in. An unset variable means the
# application default, which is GitHub authentication.
deployed_auth_mode() {
  describe_service \
    'value(spec.template.spec.containers[0].env.filter("name:MCP_AUTH_MODE").extract("value"))'
}

# Public invocation is only safe when the application authenticates its callers.
# Demo mode has no application authentication, so it stays private.
select_invoker_policy() {
  case "$1" in
    github)
      INVOKER_ARGS=(--allow-unauthenticated)
      PUBLIC_INVOKER=1
      ;;
    demo)
      INVOKER_ARGS=(--no-allow-unauthenticated)
      PUBLIC_INVOKER=0
      ;;
    *)
      echo "Unsupported MCP_AUTH_MODE: $1 (expected github or demo)" >&2
      exit 2
      ;;
  esac
}

common_deploy_args=(
  --source .
  --region "$REGION"
  --project "$PROJECT"
  --platform managed
  --memory 512Mi
  --cpu 1
  --min-instances 0
  --max-instances 1
  --timeout 300
  --quiet
)

echo "Deploying $SERVICE_NAME to $REGION (project: $PROJECT)"

# A lookup that fails for any reason other than a missing service must not be
# read as "this service is new": bootstrapping would reset the environment of a
# running OAuth deployment.
describe_error="$(mktemp)"
trap 'rm -f "$describe_error"' EXIT
describe_status=0
SERVICE_URL="$(service_url 2>"$describe_error")" || describe_status=$?

if (( describe_status != 0 )) \
  && ! grep -qiE 'not ?found|does not exist|cannot find' "$describe_error"; then
  cat "$describe_error" >&2
  echo "Could not determine whether $SERVICE_NAME exists. Refusing to deploy." >&2
  exit 1
fi

if (( describe_status == 0 )) && [[ -z "$SERVICE_URL" ]]; then
  echo "$SERVICE_NAME exists but reports no canonical URL. Refusing to deploy." >&2
  exit 1
fi

if (( describe_status == 0 )); then
  AUTH_MODE="$(deployed_auth_mode 2>/dev/null || true)"
  select_invoker_policy "${AUTH_MODE:-github}"
  echo "Existing service runs in ${AUTH_MODE:-github} mode"

  # Updating selected keys keeps unrelated environment variables and all
  # Secret Manager bindings intact.
  gcloud run deploy "$SERVICE_NAME" \
    "${common_deploy_args[@]}" \
    "${INVOKER_ARGS[@]}" \
    --update-env-vars "^|^BASE_URL=${SERVICE_URL}|MCP_APP=${MCP_APP}"

  gcloud run services update-traffic "$SERVICE_NAME" \
    --region "$REGION" \
    --project "$PROJECT" \
    --to-latest \
    --quiet
else
  AUTH_MODE="${MCP_AUTH_MODE:-github}"
  select_invoker_policy "$AUTH_MODE"
  case "$AUTH_MODE" in
    github)
      : "${GITHUB_CLIENT_ID:?GITHUB_CLIENT_ID is required for a new GitHub-authenticated service}"
      : "${GITHUB_CLIENT_SECRET_REF:?GITHUB_CLIENT_SECRET_REF must name an existing Secret Manager version for a new GitHub-authenticated service}"
      : "${GITHUB_ALLOWED_USER_IDS:?GITHUB_ALLOWED_USER_IDS is required for a new GitHub-authenticated service}"
      auth_env="^|^BASE_URL=http://127.0.0.1:8080|MCP_APP=${MCP_APP}|MCP_AUTH_MODE=github|GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}|GITHUB_ALLOWED_USER_IDS=${GITHUB_ALLOWED_USER_IDS}"
      secret_args=(--update-secrets "GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET_REF}")
      ;;
    demo)
      auth_env="^|^BASE_URL=http://127.0.0.1:8080|MCP_APP=${MCP_APP}|MCP_AUTH_MODE=demo"
      secret_args=()
      ;;
  esac

  # A new service has no canonical URL until it exists. Bootstrap a private,
  # revision with a valid loopback URL, then discover status.url. gcloud does
  # not support --no-traffic when creating a service; IAM keeps it private.
  # Even explicit demo mode is unreachable during this bootstrap.
  gcloud run deploy "$SERVICE_NAME" \
    "${common_deploy_args[@]}" \
    --no-allow-unauthenticated \
    "${secret_args[@]}" \
    --update-env-vars "$auth_env"

  SERVICE_URL="$(service_url)"
  if [[ -z "$SERVICE_URL" ]]; then
    echo "Cloud Run did not return a canonical service URL." >&2
    exit 1
  fi

  # Reuse the ready image and preserve auth configuration while replacing the
  # temporary loopback URL. Traffic stays closed until this revision is ready.
  gcloud run services update "$SERVICE_NAME" \
    --region "$REGION" \
    --project "$PROJECT" \
    --max-instances 1 \
    --no-traffic \
    --update-env-vars "^|^BASE_URL=${SERVICE_URL}|MCP_APP=${MCP_APP}" \
    --quiet

  gcloud run services update-traffic "$SERVICE_NAME" \
    --region "$REGION" \
    --project "$PROJECT" \
    --to-latest \
    --quiet

  if (( PUBLIC_INVOKER == 1 )); then
    # OAuth endpoints must be reachable by browsers and MCP clients. The
    # application itself stays fail-closed on every request.
    gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
      --region "$REGION" \
      --project "$PROJECT" \
      --member allUsers \
      --role roles/run.invoker \
      --quiet >/dev/null
  else
    echo "Demo mode has no application authentication: the service stays private."
    echo "Grant roles/run.invoker to specific principals to reach it."
  fi
fi

echo
echo "Deployed: $SERVICE_URL"
echo "MCP URL: ${SERVICE_URL}/mcp"
echo "Health: ${SERVICE_URL}/health"
