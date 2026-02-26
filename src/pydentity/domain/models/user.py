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
    AccountAlreadyActiveError,
    AccountAlreadyDeactivatedError,
    AccountDeactivatedError,
    AccountNotActiveError,
    EmailAlreadyVerifiedError,
    EmailUnchangedError,
    EmptyValueError,
    RoleAlreadyAssignedError,
    RoleNotAssignedError,
    VerificationTokenExpiredError,
    VerificationTokenInvalidError,
    VerificationTokenNotIssuedError,
)
from pydentity.domain.models.value_objects import (
    Credentials,
    DisplayName,
    EmailVerification,
    FailedLoginAttempts,
    LoginTracking,
    UserId,
)

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.models.value_objects import (
        AccountLockoutPolicy,
        EmailAddress,
        EmailVerificationToken,
        HashedPassword,
        HashedResetToken,
        HashedVerificationToken,
        LockoutExpiry,
        PasswordResetToken,
        RoleId,
    )


class User(AggregateRoot[UserId]):
    def __init__(
        self,
        *,
        user_id: UserId,
        email: EmailAddress,
        display_name: DisplayName,
        status: UserStatus,
        email_verification: EmailVerification,
        credentials: Credentials,
        login_tracking: LoginTracking,
        role_ids: set[RoleId],
    ) -> None:
        super().__init__()
        self._id = user_id
        self._email = email
        self._display_name = display_name
        self._status = status
        self._email_verification = email_verification
        self._credentials = credentials
        self._login_tracking = login_tracking
        self._role_ids = set(role_ids)

    @classmethod
    def register(
        cls,
        user_id: UserId,
        email: EmailAddress,
        display_name: DisplayName,
        password_hash: HashedPassword,
        verification_token: EmailVerificationToken | None = None,
    ) -> User:
        user = cls(
            user_id=user_id,
            email=email,
            display_name=display_name,
            status=UserStatus.ACTIVE,
            email_verification=EmailVerification(
                is_verified=verification_token is None,
                token=verification_token,
            ),
            credentials=Credentials(
                password_hash=password_hash,
                password_reset_token=None,
                password_history=(password_hash,),
            ),
            login_tracking=LoginTracking(
                failed_login_attempts=FailedLoginAttempts(0),
                lockout_expiry=None,
            ),
            role_ids=set(),
        )

        user._record_event(
            UserRegistered(
                user_id=user_id.value,
                email=email.full_address,
                display_name=user._display_name.value,
            )
        )
        return user

    @classmethod
    def _reconstitute(
        cls,
        user_id: UserId,
        email: EmailAddress,
        display_name: DisplayName,
        status: UserStatus,
        email_verification: EmailVerification,
        credentials: Credentials,
        login_tracking: LoginTracking,
        role_ids: set[RoleId],
    ) -> User:
        return cls(
            user_id=user_id,
            email=email,
            display_name=display_name,
            status=status,
            email_verification=email_verification,
            credentials=credentials,
            login_tracking=login_tracking,
            role_ids=role_ids,
        )

    # --- Read-only properties ---

    @property
    def email(self) -> EmailAddress:
        return self._email

    @property
    def display_name(self) -> DisplayName:
        return self._display_name

    @property
    def status(self) -> UserStatus:
        return self._status

    @property
    def email_verification(self) -> EmailVerification:
        return self._email_verification

    @property
    def credentials(self) -> Credentials:
        return self._credentials

    @property
    def login_tracking(self) -> LoginTracking:
        return self._login_tracking

    @property
    def password_hash(self) -> HashedPassword:
        return self._credentials.password_hash

    @property
    def is_email_verified(self) -> bool:
        return self._email_verification.is_verified

    @property
    def email_verification_token(self) -> EmailVerificationToken | None:
        return self._email_verification.token

    @property
    def password_reset_token(self) -> PasswordResetToken | None:
        return self._credentials.password_reset_token

    @property
    def failed_login_attempts(self) -> FailedLoginAttempts:
        return self._login_tracking.failed_login_attempts

    @property
    def lockout_expiry(self) -> LockoutExpiry | None:
        return self._login_tracking.lockout_expiry

    @property
    def password_history(self) -> tuple[HashedPassword, ...]:
        return self._credentials.password_history

    @property
    def role_ids(self) -> frozenset[RoleId]:
        return frozenset(self._role_ids)

    # --- Helpers ---

    def _ensure_active(self) -> None:
        if self._status == UserStatus.DEACTIVATED:
            raise AccountDeactivatedError()
        if self._status != UserStatus.ACTIVE:
            raise AccountNotActiveError(status=self._status)

    # --- Commands ---

    def verify_email(self, token_hash: HashedVerificationToken, now: datetime) -> None:
        self._ensure_active()

        if self._email_verification.is_verified:
            raise EmailAlreadyVerifiedError()
        if self._email_verification.token is None:
            raise VerificationTokenNotIssuedError()
        if self._email_verification.token.is_expired(now):
            raise VerificationTokenExpiredError()
        if not self._email_verification.token.matches(token_hash):
            raise VerificationTokenInvalidError()

        self._email_verification = EmailVerification(is_verified=True, token=None)

        self._record_event(EmailVerified(user_id=self._id.value))

    def request_password_reset(self, token: PasswordResetToken) -> None:
        self._ensure_active()

        self._credentials = self._credentials.with_reset_requested(token)

        self._record_event(PasswordResetRequested(user_id=self._id.value))

    def reset_password(
        self,
        token_hash: HashedResetToken,
        new_hash: HashedPassword,
        now: datetime,
        history_size: int,
    ) -> None:
        self._ensure_active()

        self._credentials = self._credentials.with_password_reset(
            token_hash, new_hash, now, history_size
        )
        self._login_tracking = self._login_tracking.reset()

        self._record_event(PasswordReset(user_id=self._id.value))

    def change_password(
        self,
        new_hash: HashedPassword,
        history_size: int,
    ) -> None:
        self._ensure_active()

        self._credentials = self._credentials.with_new_password(new_hash, history_size)
        self._login_tracking = self._login_tracking.reset()

        self._record_event(PasswordChanged(user_id=self._id.value))

    def record_failed_login(self, policy: AccountLockoutPolicy, now: datetime) -> None:
        self._ensure_active()

        self._login_tracking.ensure_not_locked(now)

        self._login_tracking, new_lockout = self._login_tracking.after_failed_attempt(
            policy, now
        )

        self._record_event(
            LoginFailed(
                user_id=self._id.value,
                failed_attempts=self._login_tracking.failed_login_attempts.value,
            )
        )

        if new_lockout is not None:
            self._record_event(
                AccountLocked(
                    user_id=self._id.value,
                    locked_until=new_lockout.locked_until,
                )
            )

    def record_successful_login(self, now: datetime) -> None:
        self._ensure_active()
        self._login_tracking.ensure_not_locked(now)

        self._login_tracking = self._login_tracking.after_successful_login()

        self._record_event(LoginSucceeded(user_id=self._id.value))

    def suspend(self, reason: str) -> None:
        self._ensure_active()

        stripped_reason = reason.strip()
        if not stripped_reason:
            raise EmptyValueError(field_name="reason")

        self._status = UserStatus.SUSPENDED

        self._record_event(
            UserSuspended(
                user_id=self._id.value,
                reason=stripped_reason,
            )
        )

    def reactivate(self) -> None:
        if self._status == UserStatus.DEACTIVATED:
            raise AccountDeactivatedError()
        if self._status == UserStatus.ACTIVE:
            raise AccountAlreadyActiveError()

        self._status = UserStatus.ACTIVE

        self._record_event(UserReactivated(user_id=self._id.value))

    def deactivate(self) -> None:
        if self._status == UserStatus.DEACTIVATED:
            raise AccountAlreadyDeactivatedError()

        self._status = UserStatus.DEACTIVATED

        self._record_event(UserDeactivated(user_id=self._id.value))

    def change_email(
        self,
        new_email: EmailAddress,
        verification_token: EmailVerificationToken | None = None,
    ) -> None:
        self._ensure_active()

        if new_email == self._email:
            raise EmailUnchangedError()

        old_email = self._email
        self._email = new_email
        self._email_verification = EmailVerification(
            is_verified=verification_token is None,
            token=verification_token,
        )

        self._record_event(
            UserEmailChanged(
                user_id=self._id.value,
                old_email=old_email.full_address,
                new_email=new_email.full_address,
            )
        )

    def reissue_verification_token(self, token: EmailVerificationToken) -> None:
        self._ensure_active()

        if self._email_verification.is_verified:
            raise EmailAlreadyVerifiedError()

        self._email_verification = EmailVerification(is_verified=False, token=token)

        self._record_event(VerificationTokenReissued(user_id=self._id.value))

    def assign_role(self, role_id: RoleId) -> None:
        self._ensure_active()

        if role_id in self._role_ids:
            raise RoleAlreadyAssignedError(role_id=role_id, user_id=self._id)

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
            raise RoleNotAssignedError(role_id=role_id, user_id=self._id)

        self._role_ids.discard(role_id)

        self._record_event(
            RoleRevokedFromUser(
                user_id=self._id.value,
                role_id=role_id.value,
            )
        )
