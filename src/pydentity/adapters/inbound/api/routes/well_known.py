"""JWKS well-known endpoint for public key discovery."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request, Response
from jwt.algorithms import RSAAlgorithm

from pydentity.adapters.container import get_container

router = APIRouter(tags=["well-known"])


@router.get("/.well-known/jwks.json")
def get_jwks(request: Request) -> Response:
    container = get_container(request)
    public_keys = container.key_store.get_all_public_keys()

    keys: list[dict[str, Any]] = []
    for pk in public_keys:
        jwk = RSAAlgorithm.to_jwk(pk.public_key, as_dict=True)
        jwk["kid"] = pk.kid
        jwk["use"] = "sig"
        jwk["alg"] = pk.algorithm
        keys.append(jwk)

    return Response(
        content=json.dumps({"keys": keys}),
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=3600"},
    )
