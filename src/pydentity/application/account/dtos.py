from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RegisterAccountDTO:
    email: str
    password: str


@dataclass(frozen=True, slots=True)
class VerifyEmailDTO:
    account_id: str
    token: str


@dataclass(frozen=True, slots=True)
class GetCurrentAccountDTO:
    account_id: str


@dataclass(frozen=True, slots=True)
class RegisterAccountResultDTO:
    id: str
    email: str
    status: str


@dataclass(frozen=True, slots=True)
class AccountDTO:
    id: str
    email: str
    status: str
