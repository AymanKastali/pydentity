"""JWK key pair and public key models for RS256 token signing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
    )


@dataclass(frozen=True, slots=True)
class JWKKeyPair:
    kid: str
    private_key: RSAPrivateKey
    public_key: RSAPublicKey


@dataclass(frozen=True, slots=True)
class JWKPublicKey:
    kid: str
    public_key: RSAPublicKey
    algorithm: str = "RS256"
