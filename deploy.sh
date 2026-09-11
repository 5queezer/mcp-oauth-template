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

common_deploy_args=(
  --source .
  --region "$REGION"
  --project "$PROJECT"
  --platform managed
  --invoker-iam-check
  --memory 512Mi
  --cpu 1
  --min-instances 0
  --max-instances 1
  --timeout 300
  --quiet
)

echo "Deploying $SERVICE_NAME to $REGION (project: $PROJECT)"

# Read the effective mode from the deployed service, not the operator's local
# shell. A lookup failure must never turn an existing service into a bootstrap.
describe_error_file="$(mktemp)"
trap 'rm -f "$describe_error_file"' EXIT
service_exists=false
if service_data="$(describe_service 'json(status.url,spec.template.spec.containers)' 2>"$describe_error_file")"; then
  service_fields="$(printf '%s' "$service_data" | python3 -c '
import json
import sys
try:
    service = json.load(sys.stdin)
    url = service["status"]["url"]
    environment = service["spec"]["template"]["spec"]["containers"][0].get("env", [])
    modes = [item for item in environment if item.get("name") == "MCP_AUTH_MODE"]
    if len(modes) > 1:
        raise ValueError("duplicate auth mode")
    mode = modes[0].get("value") if modes else "github"
    if mode not in {"github", "demo"}:
        print("Unsupported MCP_AUTH_MODE; a literal github or demo value is required. No changes made.", file=sys.stderr)
        sys.exit(2)
    if not isinstance(url, str) or not url.startswith("https://") or any(c in url for c in "| \r\n"):
        raise ValueError("missing or invalid canonical service URL")
except (ValueError, KeyError, IndexError, TypeError, AttributeError):
    sys.exit("Cannot determine the deployed service URL and MCP_AUTH_MODE; no changes made.")
print(url)
print(mode)
')"
  SERVICE_URL="${service_fields%%$'\n'*}"
  AUTH_MODE="${service_fields#*$'\n'}"
  service_exists=true
else
  describe_status=$?
  describe_error="$(<"$describe_error_file")"
  case "$describe_error" in
    *"Cannot find service [$SERVICE_NAME]"*|*"Service [$SERVICE_NAME] could not be found."*)
      AUTH_MODE="${MCP_AUTH_MODE:-github}"
      ;;
    *)
      echo "Could not read service state. Refusing to deploy; no changes made:" >&2
      cat "$describe_error_file" >&2
      exit "$describe_status"
      ;;
  esac
fi

case "$AUTH_MODE" in
  github) iam_args=() ;;
  demo) iam_args=(--no-allow-unauthenticated) ;;
  *)
    echo "Unsupported MCP_AUTH_MODE (expected github or demo)." >&2
    exit 2
    ;;
esac

if [[ "$service_exists" == true ]]; then
  # Deploy's IAM flags can turn SetIamPolicy errors into warnings. Explicitly
  # revoke public invoker access before updating a demo and propagate failures.
  if [[ "$AUTH_MODE" == demo ]]; then
    iam_policy="$(gcloud run services get-iam-policy "$SERVICE_NAME" \
      --region "$REGION" --project "$PROJECT" --format json)"
    has_public_invoker="$(printf '%s' "$iam_policy" | python3 -c '
import json
import sys
policy = json.load(sys.stdin)
print(any(binding.get("role") == "roles/run.invoker" and "allUsers" in binding.get("members", [])
          for binding in policy.get("bindings", [])))
')"
    if [[ "$has_public_invoker" == True ]]; then
      gcloud run services remove-iam-policy-binding "$SERVICE_NAME" \
        --region "$REGION" \
        --project "$PROJECT" \
        --member allUsers \
        --role roles/run.invoker \
        --all \
        --quiet >/dev/null
    fi
  fi

  # Updating selected keys keeps unrelated environment variables and all
  # Secret Manager bindings intact.
  gcloud run deploy "$SERVICE_NAME" \
    "${common_deploy_args[@]}" \
    "${iam_args[@]}" \
    --update-env-vars "^|^BASE_URL=${SERVICE_URL}|MCP_APP=${MCP_APP}"

  gcloud run services update-traffic "$SERVICE_NAME" \
    --region "$REGION" \
    --project "$PROJECT" \
    --to-latest \
    --quiet
else
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
    *)
      echo "Unsupported MCP_AUTH_MODE: $AUTH_MODE (expected github or demo)" >&2
      exit 2
      ;;
  esac

  # A new service has no canonical URL until it exists. Bootstrap a private
  # revision with a valid loopback URL, then discover status.url. gcloud does
  # not support --no-traffic when creating a service; IAM keeps it private.
  # Even explicit demo mode is unreachable during this bootstrap.
  gcloud run deploy "$SERVICE_NAME" \
    "${common_deploy_args[@]}" \
    --no-allow-unauthenticated \
    "${secret_args[@]}" \
    --update-env-vars "$auth_env"

  SERVICE_URL="$(describe_service 'value(status.url)')"
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

fi

# Publish only after the GitHub-authenticated revision is ready. This explicit
# IAM command fails the script if public access could not be configured.
if [[ "$AUTH_MODE" == github ]]; then
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

echo
echo "Deployed: $SERVICE_URL"
echo "MCP URL: ${SERVICE_URL}/mcp"
echo "Health: ${SERVICE_URL}/health"
