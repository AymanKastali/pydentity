from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.events.user_events import (
    AccountLocked,
    EmailVerified,
    LoginFailed,
    LoginSucceeded,
    PasswordChanged,
    PasswordReset,
    PasswordResetRequested,
    RoleAssignedToUser,
    RoleRevokedFromUser,
    UserDeactivated,
    UserEmailChanged,
    UserReactivated,
    UserRegistered,
    UserSuspended,
    VerificationTokenReissued,
)
from pydentity.domain.models.base import AggregateRoot
from pydentity.domain.models.enums import UserStatus
from pydentity.domain.models.exceptions import (
    AccountDeactivatedError,
    AccountLockedError,
    AccountNotActiveError,
    EmailAlreadyVerifiedError,
    InvalidCredentialsError,
    PasswordReuseError,
    ResetTokenExpiredError,
    ResetTokenInvalidError,
    RoleAlreadyAssignedError,
    RoleNotAssignedError,
    VerificationTokenExpiredError,
    VerificationTokenInvalidError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.events.base import DomainEvent
    from pydentity.domain.models.policies import AccountLockoutPolicy, PasswordPolicy
    from pydentity.domain.models.value_objects import (
        EmailAddress,
        EmailVerificationToken,
        HashedPassword,
        PasswordResetToken,
        RoleId,
        UserId,
    )


class User(AggregateRoot):
    def __init__(
        self,
        *,
        user_id: UserId,
        email: EmailAddress,
        display_name: str,
        password_hash: HashedPassword,
        status: UserStatus,
        is_email_verified: bool,
        email_verification_token: EmailVerificationToken | None,
        password_reset_token: PasswordResetToken | None,
        failed_login_attempts: int,
        locked_until: datetime | None,
        password_history: list[HashedPassword],
        created_at: datetime,
        role_ids: set[RoleId],
    ) -> None:
        self._id = user_id
        self._email = email
        self._display_name = display_name
        self._password_hash = password_hash
        self._status = status
        self._is_email_verified = is_email_verified
        self._email_verification_token = email_verification_token
        self._password_reset_token = password_reset_token
        self._failed_login_attempts = failed_login_attempts
        self._locked_until = locked_until
        self._password_history = list(password_history)
        self._created_at = created_at
        self._role_ids = set(role_ids)
        self._events: list[DomainEvent] = []

    @staticmethod
    def register(
        user_id: UserId,
        email: EmailAddress,
        display_name: str,
        password_hash: HashedPassword,
        verification_token: EmailVerificationToken,
        created_at: datetime,
    ) -> User:
        if not display_name.strip():
            raise ValueError("display_name cannot be blank")

        user = User(
            user_id=user_id,
            email=email,
            display_name=display_name.strip(),
            password_hash=password_hash,
            status=UserStatus.ACTIVE,
            is_email_verified=False,
            email_verification_token=verification_token,
            password_reset_token=None,
            failed_login_attempts=0,
            locked_until=None,
            password_history=[password_hash],
            created_at=created_at,
            role_ids=set(),
        )

        user._record_event(
            UserRegistered(
                user_id=user_id.value,
                email=email.full_address,
                display_name=user._display_name,
            )
        )
        return user

    @staticmethod
    def _reconstitute(
        user_id: UserId,
        email: EmailAddress,
        display_name: str,
        password_hash: HashedPassword,
        status: UserStatus,
        is_email_verified: bool,
        email_verification_token: EmailVerificationToken | None,
        password_reset_token: PasswordResetToken | None,
        failed_login_attempts: int,
        locked_until: datetime | None,
        password_history: list[HashedPassword],
        created_at: datetime,
        role_ids: set[RoleId],
    ) -> User:
        return User(
            user_id=user_id,
            email=email,
            display_name=display_name,
            password_hash=password_hash,
            status=status,
            is_email_verified=is_email_verified,
            email_verification_token=email_verification_token,
            password_reset_token=password_reset_token,
            failed_login_attempts=failed_login_attempts,
            locked_until=locked_until,
            password_history=password_history,
            created_at=created_at,
            role_ids=role_ids,
        )

    # --- Read-only properties ---

    @property
    def id(self) -> UserId:
        return self._id

    @property
    def email(self) -> EmailAddress:
        return self._email

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def password_hash(self) -> HashedPassword:
        return self._password_hash

    @property
    def status(self) -> UserStatus:
        return self._status

    @property
    def is_email_verified(self) -> bool:
        return self._is_email_verified

    @property
    def email_verification_token(self) -> EmailVerificationToken | None:
        return self._email_verification_token

    @property
    def password_reset_token(self) -> PasswordResetToken | None:
        return self._password_reset_token

    @property
    def failed_login_attempts(self) -> int:
        return self._failed_login_attempts

    @property
    def locked_until(self) -> datetime | None:
        return self._locked_until

    @property
    def password_history(self) -> tuple[HashedPassword, ...]:
        return tuple(self._password_history)

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def role_ids(self) -> frozenset[RoleId]:
        return frozenset(self._role_ids)

    # --- Helpers ---

    def _ensure_active(self) -> None:
        if self._status == UserStatus.DEACTIVATED:
            raise AccountDeactivatedError("Account has been permanently deactivated")
        if self._status != UserStatus.ACTIVE:
            raise AccountNotActiveError(
                f"Account is not active (status={self._status.value})"
            )

    def _ensure_not_locked(self, now: datetime) -> None:
        if self._locked_until is not None and now < self._locked_until:
            raise AccountLockedError(
                f"Account is locked until {self._locked_until.isoformat()}"
            )

    def _check_password_history(
        self, new_hash: HashedPassword, policy: PasswordPolicy
    ) -> None:
        history_window = self._password_history[-policy.history_size :]
        if any(h.value == new_hash.value for h in history_window):
            raise PasswordReuseError(
                f"Cannot reuse any of the last {policy.history_size} passwords"
            )

    # --- Commands ---

    def verify_email(self, token: str, now: datetime) -> None:
        self._ensure_active()

        if self._is_email_verified:
            raise EmailAlreadyVerifiedError("Email is already verified")
        if self._email_verification_token is None:
            raise VerificationTokenInvalidError("No verification token issued")
        if self._email_verification_token.is_expired(now):
            raise VerificationTokenExpiredError("Verification token has expired")
        if not self._email_verification_token.matches(token):
            raise VerificationTokenInvalidError("Verification token does not match")

        self._is_email_verified = True
        self._email_verification_token = None

        self._record_event(EmailVerified(user_id=self._id.value))

    def request_password_reset(self, token: PasswordResetToken) -> None:
        self._ensure_active()

        self._password_reset_token = token

        self._record_event(PasswordResetRequested(user_id=self._id.value))

    def reset_password(
        self,
        token: str,
        new_hash: HashedPassword,
        policy: PasswordPolicy,
        now: datetime,
    ) -> None:
        self._ensure_active()

        if self._password_reset_token is None:
            raise ResetTokenInvalidError("No password reset token issued")
        if self._password_reset_token.is_expired(now):
            self._password_reset_token = None
            raise ResetTokenExpiredError("Password reset token has expired")
        if not self._password_reset_token.matches(token):
            raise ResetTokenInvalidError("Password reset token does not match")

        self._check_password_history(new_hash, policy)

        self._password_hash = new_hash
        self._password_history.append(new_hash)
        self._password_reset_token = None
        self._failed_login_attempts = 0
        self._locked_until = None

        self._record_event(PasswordReset(user_id=self._id.value))

    def change_password(
        self,
        current_hash: HashedPassword,
        new_hash: HashedPassword,
        policy: PasswordPolicy,
    ) -> None:
        self._ensure_active()

        if self._password_hash.value != current_hash.value:
            raise InvalidCredentialsError("Current password does not match")

        self._check_password_history(new_hash, policy)

        self._password_hash = new_hash
        self._password_history.append(new_hash)

        self._record_event(PasswordChanged(user_id=self._id.value))

    def record_failed_login(self, policy: AccountLockoutPolicy, now: datetime) -> None:
        self._ensure_active()

        if self._locked_until is not None and now < self._locked_until:
            raise AccountLockedError(
                f"Account is locked until {self._locked_until.isoformat()}"
            )

        self._failed_login_attempts += 1

        self._record_event(
            LoginFailed(
                user_id=self._id.value,
                failed_attempts=self._failed_login_attempts,
            )
        )

        if self._failed_login_attempts >= policy.max_attempts:
            self._locked_until = now + policy.lockout_duration
            self._record_event(
                AccountLocked(
                    user_id=self._id.value,
                    locked_until=self._locked_until,
                )
            )

    def record_successful_login(self, now: datetime) -> None:
        self._ensure_active()
        self._ensure_not_locked(now)

        self._failed_login_attempts = 0
        self._locked_until = None

        self._record_event(LoginSucceeded(user_id=self._id.value))

    def suspend(self, reason: str) -> None:
        self._ensure_active()

        self._status = UserStatus.SUSPENDED

        self._record_event(
            UserSuspended(
                user_id=self._id.value,
                reason=reason,
            )
        )

    def reactivate(self) -> None:
        if self._status == UserStatus.DEACTIVATED:
            raise AccountDeactivatedError("Cannot reactivate a deactivated account")
        if self._status == UserStatus.ACTIVE:
            raise AccountNotActiveError("Account is already active")

        self._status = UserStatus.ACTIVE

        self._record_event(UserReactivated(user_id=self._id.value))

    def deactivate(self) -> None:
        if self._status == UserStatus.DEACTIVATED:
            raise AccountDeactivatedError("Account is already deactivated")

        self._status = UserStatus.DEACTIVATED

        self._record_event(UserDeactivated(user_id=self._id.value))

    def change_email(
        self,
        new_email: EmailAddress,
        verification_token: EmailVerificationToken,
    ) -> None:
        self._ensure_active()

        old_email = self._email
        self._email = new_email
        self._is_email_verified = False
        self._email_verification_token = verification_token

        self._record_event(
            UserEmailChanged(
                user_id=self._id.value,
                old_email=old_email.full_address,
                new_email=new_email.full_address,
            )
        )

    def reissue_verification_token(self, token: EmailVerificationToken) -> None:
        self._ensure_active()

        if self._is_email_verified:
            raise EmailAlreadyVerifiedError("Email is already verified")

        self._email_verification_token = token

        self._record_event(VerificationTokenReissued(user_id=self._id.value))

    def assign_role(self, role_id: RoleId) -> None:
        self._ensure_active()

        if role_id in self._role_ids:
            raise RoleAlreadyAssignedError(
                f"Role {role_id.value!r} is already assigned to user {self._id.value!r}"
            )

        self._role_ids.add(role_id)

        self._record_event(
            RoleAssignedToUser(
                user_id=self._id.value,
                role_id=role_id.value,
            )
        )

    def revoke_role(self, role_id: RoleId) -> None:
        self._ensure_active()

        if role_id not in self._role_ids:
            raise RoleNotAssignedError(
                f"Role {role_id.value!r} is not assigned to user {self._id.value!r}"
            )

        self._role_ids.discard(role_id)

        self._record_event(
            RoleRevokedFromUser(
                user_id=self._id.value,
                role_id=role_id.value,
            )
        )
