from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.value_objects import EmailAddress

if TYPE_CHECKING:
    from pydentity.domain.ports.email_validator import EmailValidatorPort


class EmailAddressFactory:
    def __init__(self, *, email_validator: EmailValidatorPort) -> None:
        self._email_validator = email_validator

    def create(self, address: str) -> EmailAddress:
        local_part, _, domain = address.partition("@")
        self._email_validator.validate(local_part, domain)
        return EmailAddress(local_part=local_part, domain=domain)
