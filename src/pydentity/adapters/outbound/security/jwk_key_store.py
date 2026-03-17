"""File-system backed JWK key store for RS256 signing keys."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pydentity.application.models.jwk import JWKKeyPair, JWKPublicKey
from pydentity.application.ports.jwk_key_store import JWKKeyStorePort

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

_log = logging.getLogger(__name__)

_MINIMUM_KEY_SIZE = 2048
_SECURE_FILE_MODE = 0o600


class FileSystemJWKKeyStore(JWKKeyStorePort):
    def __init__(self, *, directory: Path) -> None:
        if not directory.is_dir():
            msg = f"JWK key directory does not exist or is not a directory: {directory}"
            raise ValueError(msg)

        keys: dict[str, JWKKeyPair] = {}

        pem_files = sorted(directory.glob("*.pem"))
        for pem_path in pem_files:
            try:
                key_pair = self._load_key(pem_path)
            except Exception:
                _log.warning("skipping invalid key file: %s", pem_path, exc_info=True)
                continue
            keys[key_pair.kid] = key_pair

        if not keys:
            msg = f"No valid RSA keys found in {directory}"
            raise ValueError(msg)

        self._keys = keys
        # Last key (by sorted filename) is the active signing key
        self._active_kid = list(keys.keys())[-1]
        _log.info(
            "loaded %d RSA key(s), active signing kid=%s",
            len(keys),
            self._active_kid,
        )

    def get_signing_key(self) -> JWKKeyPair:
        return self._keys[self._active_kid]

    def get_all_public_keys(self) -> Sequence[JWKPublicKey]:
        return [
            JWKPublicKey(kid=kp.kid, public_key=kp.public_key)
            for kp in self._keys.values()
        ]

    def get_public_key(self, kid: str) -> JWKPublicKey | None:
        kp = self._keys.get(kid)
        if kp is None:
            return None
        return JWKPublicKey(kid=kp.kid, public_key=kp.public_key)

    @classmethod
    def _load_key(cls, pem_path: Path) -> JWKKeyPair:
        file_mode = pem_path.stat().st_mode & 0o777
        if file_mode > _SECURE_FILE_MODE:
            _log.warning(
                "key file %s has permissions %o (recommended: %o)",
                pem_path,
                file_mode,
                _SECURE_FILE_MODE,
            )

        pem_data = pem_path.read_bytes()
        private_key = load_pem_private_key(pem_data, password=None)

        if not isinstance(private_key, RSAPrivateKey):
            msg = f"{pem_path} is not an RSA private key"
            raise TypeError(msg)

        if private_key.key_size < _MINIMUM_KEY_SIZE:
            msg = (
                f"{pem_path} RSA key is {private_key.key_size} bits"
                f" (minimum {_MINIMUM_KEY_SIZE})"
            )
            raise ValueError(msg)

        public_key = private_key.public_key()
        kid = cls._compute_kid(public_key)

        return JWKKeyPair(kid=kid, private_key=private_key, public_key=public_key)

    @classmethod
    def _compute_kid(cls, public_key: RSAPublicKey) -> str:
        """Compute key ID per RFC 7638 (JWK Thumbprint)."""
        pub_numbers = public_key.public_numbers()

        def _int_to_base64url(n: int) -> str:
            byte_length = (n.bit_length() + 7) // 8
            return (
                base64.urlsafe_b64encode(
                    n.to_bytes(byte_length, byteorder="big"),
                )
                .rstrip(b"=")
                .decode("ascii")
            )

        # Lexicographic order of members: e, kty, n (RFC 7638 Section 3.2)
        thumbprint_input = json.dumps(
            {
                "e": _int_to_base64url(pub_numbers.e),
                "kty": "RSA",
                "n": _int_to_base64url(pub_numbers.n),
            },
            separators=(",", ":"),
            sort_keys=True,
        )

        digest = hashlib.sha256(thumbprint_input.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
