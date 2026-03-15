from __future__ import annotations

import re

from pydentity.domain.exceptions import InvalidEmailAddressError
from pydentity.domain.ports.email_validator import EmailValidatorPort

_EMAIL_LOCAL_RE = re.compile(
    r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*$"
)
_EMAIL_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


class RegexEmailValidator(EmailValidatorPort):
    def validate(self, local_part: str, domain: str) -> None:
        self._ensure_valid_local_part(local_part)
        self._ensure_valid_domain(domain)

    @classmethod
    def _ensure_valid_local_part(cls, local_part: str) -> None:
        if not local_part:
            raise InvalidEmailAddressError(detail=f"invalid local part: {local_part!r}")
        if len(local_part) > 64:
            raise InvalidEmailAddressError(detail="local part exceeds 64 characters")
        if not _EMAIL_LOCAL_RE.match(local_part):
            raise InvalidEmailAddressError(detail=f"invalid local part: {local_part!r}")

    @classmethod
    def _ensure_valid_domain(cls, domain: str) -> None:
        if not domain:
            raise InvalidEmailAddressError(detail=f"invalid domain: {domain!r}")
        if len(domain) > 255:
            raise InvalidEmailAddressError(detail="domain exceeds 255 characters")
        if not _EMAIL_DOMAIN_RE.match(domain):
            raise InvalidEmailAddressError(detail=f"invalid domain: {domain!r}")
