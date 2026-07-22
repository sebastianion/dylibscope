from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError

_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    """Authenticated Supabase user visible to the API layer."""

    user_id: str
    role: Optional[str] = None
    is_anonymous: bool = False


def _truthy_env(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _decode_supabase_token(token: str) -> Dict[str, Any]:
    """Decode a Supabase access token.

    Production should set ``SUPABASE_JWT_SECRET`` so tokens are verified before
    their subject is trusted. Local development may set
    ``DYLIBSCOPE_ALLOW_UNVERIFIED_AUTH=1`` to exercise scoped-dataset logic
    without configuring Supabase Auth.
    """
    jwt_secret = os.getenv("SUPABASE_JWT_SECRET")
    audience = os.getenv("SUPABASE_JWT_AUDIENCE", "authenticated")

    if jwt_secret:
        return jwt.decode(
            token,
            jwt_secret,
            algorithms=["HS256"],
            audience=audience,
        )

    if _truthy_env("DYLIBSCOPE_ALLOW_UNVERIFIED_AUTH"):
        return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})

    raise HTTPException(
        status_code=503,
        detail="Supabase JWT verification is not configured. Set SUPABASE_JWT_SECRET on the API service.",
    )


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
    except InvalidTokenError as exc:
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
