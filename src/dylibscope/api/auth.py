from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Optional

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError, PyJWKClient
from jwt.exceptions import PyJWKClientError

_bearer_scheme = HTTPBearer(auto_error=False)
_ASYMMETRIC_ALGORITHMS = ["ES256", "RS256"]


@dataclass(frozen=True)
class CurrentUser:
    """Authenticated Supabase user visible to the API layer."""

    user_id: str
    role: Optional[str] = None
    is_anonymous: bool = False


def _truthy_env(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _env(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _supabase_project_url() -> Optional[str]:
    # SUPABASE_URL is the backend/API env var. VITE_SUPABASE_URL is accepted only
    # to make local development less surprising when users share one .env file.
    return _env("SUPABASE_URL") or _env("VITE_SUPABASE_URL")


def _supabase_jwks_url() -> str:
    explicit_url = _env("SUPABASE_JWKS_URL")
    if explicit_url:
        return explicit_url

    project_url = _supabase_project_url()
    if not project_url:
        raise HTTPException(
            status_code=503,
            detail=(
                "Supabase JWT verification is not configured for asymmetric tokens. "
                "Set SUPABASE_URL or SUPABASE_JWKS_URL on the API service."
            ),
        )

    return project_url.rstrip("/") + "/auth/v1/.well-known/jwks.json"


@lru_cache(maxsize=8)
def _get_jwks_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(jwks_url)


def _decode_asymmetric_supabase_token(token: str, audience: str) -> Dict[str, Any]:
    jwks_url = _supabase_jwks_url()
    client = _get_jwks_client(jwks_url)
    signing_key = client.get_signing_key_from_jwt(token).key

    decode_kwargs: Dict[str, Any] = {
        "key": signing_key,
        "algorithms": _ASYMMETRIC_ALGORITHMS,
        "audience": audience,
    }

    issuer = _env("SUPABASE_JWT_ISSUER")
    project_url = _supabase_project_url()
    if issuer is None and project_url:
        issuer = project_url.rstrip("/") + "/auth/v1"
    if issuer:
        decode_kwargs["issuer"] = issuer

    return jwt.decode(token, **decode_kwargs)


def _decode_hs256_supabase_token(token: str, audience: str) -> Dict[str, Any]:
    jwt_secret = _env("SUPABASE_JWT_SECRET")
    if not jwt_secret:
        raise HTTPException(
            status_code=503,
            detail=(
                "Supabase JWT verification is not configured for HS256 tokens. "
                "Set SUPABASE_JWT_SECRET on the API service."
            ),
        )

    return jwt.decode(
        token,
        jwt_secret,
        algorithms=["HS256"],
        audience=audience,
    )


def _decode_supabase_token(token: str) -> Dict[str, Any]:
    """Decode and verify a Supabase access token.

    Supabase projects may issue legacy HS256 tokens or newer asymmetric
    ES256/RS256 tokens. HS256 tokens are verified with SUPABASE_JWT_SECRET.
    ES256/RS256 tokens are verified against the project's JWKS endpoint.

    Local development may set DYLIBSCOPE_ALLOW_UNVERIFIED_AUTH=1 to exercise
    scoped-dataset logic without configuring Supabase Auth. Do not enable it in
    production.
    """
    audience = os.getenv("SUPABASE_JWT_AUDIENCE", "authenticated")

    if _truthy_env("DYLIBSCOPE_ALLOW_UNVERIFIED_AUTH"):
        return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})

    try:
        header = jwt.get_unverified_header(token)
    except InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid access token: {exc}") from exc

    alg = header.get("alg")
    if alg == "HS256":
        return _decode_hs256_supabase_token(token, audience=audience)

    if alg in _ASYMMETRIC_ALGORITHMS:
        return _decode_asymmetric_supabase_token(token, audience=audience)

    raise HTTPException(status_code=401, detail=f"Invalid access token: unsupported signing algorithm {alg!r}.")


def _user_from_payload(payload: Dict[str, Any]) -> CurrentUser:
    user_id = payload.get("sub")
    if not isinstance(user_id, str) or not user_id:
        raise HTTPException(status_code=401, detail="Invalid access token: missing subject.")

    app_metadata = payload.get("app_metadata") or {}
    if not isinstance(app_metadata, dict):
        app_metadata = {}

    return CurrentUser(
        user_id=user_id,
        role=payload.get("role") if isinstance(payload.get("role"), str) else None,
        is_anonymous=bool(app_metadata.get("is_anonymous")),
    )


def decode_current_user(token: str) -> CurrentUser:
    try:
        return _user_from_payload(_decode_supabase_token(token))
    except HTTPException:
        raise
    except (InvalidTokenError, PyJWKClientError) as exc:
        raise HTTPException(status_code=401, detail=f"Invalid access token: {exc}") from exc


def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> Optional[CurrentUser]:
    if credentials is None:
        return None
    return decode_current_user(credentials.credentials)


def require_current_user(
    user: Optional[CurrentUser] = Depends(get_optional_current_user),
) -> CurrentUser:
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication is required for this endpoint.")
    return user
