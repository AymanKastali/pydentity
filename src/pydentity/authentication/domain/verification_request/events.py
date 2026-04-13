from dataclasses import dataclass

from pydentity.authentication.domain.verification_request.value_objects import (
    VerificationFailureReason,
    VerificationRequestId,
    VerificationRequestType,
)
from pydentity.shared_kernel.building_blocks import DomainEvent
from pydentity.shared_kernel.value_objects import AccountId


@dataclass(frozen=True, slots=True)
class VerificationRequestCreated(DomainEvent):
    verification_request_id: VerificationRequestId
    account_id: AccountId
    request_type: VerificationRequestType


@dataclass(frozen=True, slots=True)
class VerificationRequestVerified(DomainEvent):
    verification_request_id: VerificationRequestId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class VerificationRequestFailed(DomainEvent):
    verification_request_id: VerificationRequestId
    account_id: AccountId
    reason: VerificationFailureReason


@dataclass(frozen=True, slots=True)
class VerificationRequestInvalidated(DomainEvent):
    verification_request_id: VerificationRequestId
    account_id: AccountId


@dataclass(frozen=True, slots=True)
class VerificationRequestExpired(DomainEvent):
    verification_request_id: VerificationRequestId
    account_id: AccountId
