"""
OAuth 2.1 Authorization Server routes (pure Starlette).

Provides:
  GET  /.well-known/oauth-authorization-server
  GET  /.well-known/oauth-protected-resource  (RFC 9728)
  POST /register                               (RFC 7591)
  GET  /authorize
  POST /token
  POST /revoke                                 (RFC 7009)
"""

import logging
from urllib.parse import parse_qs

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route

from .auth import AuthProvider, ClientStore, TokenStore, verify_pkce

logger = logging.getLogger(__name__)

SUPPORTED_METHODS = ["S256"]


def make_oauth_routes(
    store: TokenStore,
    client_store: ClientStore,
    provider: AuthProvider,
    base_url: str,
    scopes_supported: list[str] | None = None,
) -> list[Route]:
    scopes = scopes_supported or ["mcp:tools"]
    base_url = base_url.rstrip("/")

    async def protected_resource_metadata(request: Request):
        return JSONResponse({
            "resource": base_url,
            "authorization_servers": [base_url],
        })

    async def oauth_metadata(request: Request):
        return JSONResponse({
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/authorize",
            "token_endpoint": f"{base_url}/token",
            "revocation_endpoint": f"{base_url}/revoke",
            "registration_endpoint": f"{base_url}/register",
            "code_challenge_methods_supported": SUPPORTED_METHODS,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": scopes,
        })

    async def register(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Malformed JSON body"},
                status_code=400,
            )
        redirect_uris = body.get("redirect_uris", [])
        if not redirect_uris:
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "redirect_uris required"},
                status_code=400,
            )
        try:
            client = client_store.register(
                redirect_uris=redirect_uris,
                client_name=body.get("client_name", ""),
            )
        except ValueError as exc:
            return JSONResponse(
                {"error": "invalid_redirect_uri", "error_description": str(exc)},
                status_code=400,
            )
        return JSONResponse({
            "client_id": client.client_id,
            "client_id_issued_at": int(client.issued_at),
            "redirect_uris": client.redirect_uris,
            "client_name": client.client_name,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
        }, status_code=201)

    async def authorize(request: Request):
        params = request.query_params
        response_type = params.get("response_type", "code")
        client_id = params.get("client_id", "")
        code_challenge = params.get("code_challenge", "")
        code_challenge_method = params.get("code_challenge_method", "S256")
        redirect_uri = params.get("redirect_uri", "")
        state = params.get("state", "")

        if response_type != "code":
            return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
        if code_challenge_method not in SUPPORTED_METHODS:
            return JSONResponse({"error": "invalid_request", "error_description": "only S256 supported"}, status_code=400)
        if not code_challenge:
            return JSONResponse({"error": "invalid_request", "error_description": "code_challenge required"}, status_code=400)
        if not redirect_uri:
            return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri required"}, status_code=400)

        if client_id:
            client = client_store.get(client_id)
            if client is None:
                return JSONResponse({"error": "invalid_client"}, status_code=400)
            if redirect_uri not in client.redirect_uris:
                return JSONResponse(
                    {"error": "invalid_request", "error_description": "redirect_uri not registered"},
                    status_code=400,
                )

        sub = provider.authenticate(request)
        if sub is None:
            return JSONResponse(
                {"error": "authentication_required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        code = store.create_code(
            challenge=code_challenge,
            redirect_uri=redirect_uri,
            state=state,
            sub=sub,
        )
        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}code={code}&state={state}"
        logger.info("Issued auth code for sub=%s", sub)
        return RedirectResponse(location, status_code=302)

    async def token(request: Request):
        body = await request.body()
        form = parse_qs(body.decode(), keep_blank_values=True)
        grant_type = form.get("grant_type", [""])[0]
        code = form.get("code", [""])[0]
        code_verifier = form.get("code_verifier", [""])[0]
        redirect_uri = form.get("redirect_uri", [""])[0]

        if grant_type != "authorization_code":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        auth_code = store.consume_code(code)
        if auth_code is None:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "code expired or unknown"},
                status_code=400,
            )
        if not verify_pkce(code_verifier, auth_code.challenge):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE verification failed"},
                status_code=400,
            )
        if redirect_uri and redirect_uri != auth_code.redirect_uri:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
                status_code=400,
            )

        access_token = store.create_token(auth_code.sub)
        logger.info("Issued access token for sub=%s", auth_code.sub)
        return JSONResponse({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": " ".join(scopes),
        })

    async def revoke(request: Request):
        body = await request.body()
        form = parse_qs(body.decode(), keep_blank_values=True)
        token_value = form.get("token", [""])[0]
        store.revoke_token(token_value)
        return JSONResponse({}, status_code=200)

    return [
        Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
        Route("/register", register, methods=["POST"]),
        Route("/authorize", authorize, methods=["GET"]),
        Route("/token", token, methods=["POST"]),
        Route("/revoke", revoke, methods=["POST"]),
    ]
