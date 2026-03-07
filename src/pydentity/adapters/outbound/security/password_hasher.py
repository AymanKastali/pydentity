from __future__ import annotations

import hashlib
import hmac
import os

from pydentity.domain.models.value_objects import HashedPassword
from pydentity.domain.ports.password_hasher import PasswordHasherPort

_SALT_LEN = 32
_HASH_LEN = 32
_N = 16384
_R = 8
_P = 1


class ScryptPasswordHasher(PasswordHasherPort):
    async def hash(self, plain: str) -> HashedPassword:
        salt = os.urandom(_SALT_LEN)
        h = hashlib.scrypt(plain.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_HASH_LEN)
        return HashedPassword(value=salt + h)

    async def verify(self, plain: str, hashed: HashedPassword) -> bool:
        stored = hashed.value
        salt = stored[:_SALT_LEN]
        expected = stored[_SALT_LEN:]
        h = hashlib.scrypt(plain.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_HASH_LEN)
        return hmac.compare_digest(h, expected)
