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
    UserActivated,
    UserDeactivated,
    UserEmailChanged,
    UserReactivated,
    UserRegistered,
    UserSuspended,
    VerificationTokenIssued,
    VerificationTokenReissued,
)
from pydentity.domain.exceptions import (
    AccountAlreadyActiveError,
    AccountAlreadyDeactivatedError,
    AccountAlreadySuspendedError,
    AccountDeactivatedError,
    AccountNotActiveError,
    EmailAlreadyVerifiedError,
    EmailUnchangedError,
    RoleAlreadyAssignedError,
    RoleNotAssignedError,
    VerificationTokenNotIssuedError,
)
from pydentity.domain.guards import verify_params
from pydentity.domain.models.base import AggregateRoot
from pydentity.domain.models.enums import UserStatus
from pydentity.domain.models.value_objects import (
    Credentials,
    EmailAddress,
    EmailVerification,
    FailedLoginAttempts,
    LoginTracking,
    RoleName,
    UserId,
)

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.models.value_objects import (
        AccountLockoutPolicy,
        EmailVerificationToken,
        HashedPassword,
        LockoutExpiry,
        PasswordResetToken,
    )


class User(AggregateRoot[UserId]):
    def __init__(
        self,
        *,
        user_id: UserId,
        email: EmailAddress,
        status: UserStatus,
        email_verification: EmailVerification,
        credentials: Credentials,
        login_tracking: LoginTracking,
        role_names: set[RoleName],
    ) -> None:
        super().__init__()
        verify_params(
            user_id=(user_id, UserId),
            email=(email, EmailAddress),
            status=(status, UserStatus),
            email_verification=(email_verification, EmailVerification),
            credentials=(credentials, Credentials),
            login_tracking=(login_tracking, LoginTracking),
            role_names=(role_names, set),
        )
        self._id = user_id
        self._email = email
        self._status = status
        self._email_verification = email_verification
        self._credentials = credentials
        self._login_tracking = login_tracking
        self._role_names = set(role_names)

    @classmethod
    def create(
        cls,
        *,
        user_id: UserId,
        email: EmailAddress,
        password_hash: HashedPassword,
        verification_token: EmailVerificationToken | None = None,
    ) -> User:
        user = cls(
            user_id=user_id,
            email=email,
            status=UserStatus.PENDING_VERIFICATION
            if verification_token is not None
            else UserStatus.ACTIVE,
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
            role_names=set(),
        )

        user._record_event(UserRegistered(user_id=user_id.value, email=email.address))

        if verification_token is not None:
            user._record_event(
                VerificationTokenIssued(user_id=user_id.value, email=email.address)
            )

        return user

    @classmethod
    def _reconstitute(
        cls,
        user_id: UserId,
        email: EmailAddress,
        status: UserStatus,
        email_verification: EmailVerification,
        credentials: Credentials,
        login_tracking: LoginTracking,
        role_names: set[RoleName],
    ) -> User:
        return cls(
            user_id=user_id,
            email=email,
            status=status,
            email_verification=email_verification,
            credentials=credentials,
            login_tracking=login_tracking,
            role_names=role_names,
        )

    # --- Read-only properties ---

    @property
    def email(self) -> EmailAddress:
        return self._email

    @property
    def status(self) -> UserStatus:
        return self._status

    @property
    def is_active(self) -> bool:
        return self._status == UserStatus.ACTIVE

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
    def role_names(self) -> frozenset[RoleName]:
        return frozenset(self._role_names)

    # --- Helpers ---

    def _ensure_active(self) -> None:
        if self._status != UserStatus.ACTIVE:
            raise AccountNotActiveError(status=self._status)

    def _ensure_not_deactivated(self) -> None:
        if self._status == UserStatus.DEACTIVATED:
            raise AccountDeactivatedError()

    def _ensure_not_already_active(self) -> None:
        if self._status == UserStatus.ACTIVE:
            raise AccountAlreadyActiveError()

    def _ensure_not_already_deactivated(self) -> None:
        if self._status == UserStatus.DEACTIVATED:
            raise AccountAlreadyDeactivatedError()

    def _ensure_email_not_verified(self) -> None:
        if self._email_verification.is_verified:
            raise EmailAlreadyVerifiedError()

    def _ensure_verification_token_issued(self) -> None:
        if self._email_verification.token is None:
            raise VerificationTokenNotIssuedError()

    def _ensure_email_changed(self, new_email: EmailAddress) -> None:
        if new_email == self._email:
            raise EmailUnchangedError()

    def _ensure_role_not_assigned(self, role_name: RoleName) -> None:
        if role_name in self._role_names:
            raise RoleAlreadyAssignedError(role_name=role_name, user_id=self._id)

    def _ensure_role_assigned(self, role_name: RoleName) -> None:
        if role_name not in self._role_names:
            raise RoleNotAssignedError(role_name=role_name, user_id=self._id)

    # --- Commands ---

    def verify_email(self) -> None:
        self._ensure_not_deactivated()
        self._ensure_email_not_verified()
        self._ensure_verification_token_issued()

        self._email_verification = EmailVerification(is_verified=True, token=None)

        if self._status == UserStatus.PENDING_VERIFICATION:
            self._status = UserStatus.ACTIVE
            self._record_event(UserActivated(user_id=self._id.value))

        self._record_event(
            EmailVerified(user_id=self._id.value, email=self._email.address)
        )

    def request_password_reset(self, token: PasswordResetToken) -> None:
        self._ensure_active()

        self._credentials = self._credentials.with_reset_requested(token)

        self._record_event(
            PasswordResetRequested(
                user_id=self._id.value,
                email=self._email.address,
            )
        )

    def reset_password(
        self,
        new_hash: HashedPassword,
        *,
        history_size: int,
    ) -> None:
        self._ensure_active()
        self._credentials = self._credentials.with_password_reset(
            new_hash, history_size
        )
        self._login_tracking = self._login_tracking.reset()
        self._record_event(
            PasswordReset(user_id=self._id.value, email=self._email.address)
        )

    def change_password(self, new_hash: HashedPassword, *, history_size: int) -> None:
        self._ensure_active()
        self._credentials = self._credentials.with_new_password(new_hash, history_size)
        self._login_tracking = self._login_tracking.reset()
        self._record_event(
            PasswordChanged(user_id=self._id.value, email=self._email.address)
        )

    def ensure_can_attempt_login(self, now: datetime) -> HashedPassword:
        """Check preconditions for login and return the stored hash.

        Raises ``AccountNotActiveError`` or ``AccountLockedError`` if the
        user cannot attempt a login right now.
        """
        self._ensure_active()
        self._login_tracking.ensure_not_locked(now)
        return self._credentials.password_hash

    def record_failed_login(self, policy: AccountLockoutPolicy, now: datetime) -> None:
        self._ensure_active()

        self._login_tracking.ensure_not_locked(now)

        self._login_tracking, new_lockout = self._login_tracking.after_failed_attempt(
            policy, now
        )

        self._record_event(
            LoginFailed(
                user_id=self._id.value,
                email=self._email.address,
                failed_attempts=self._login_tracking.failed_login_attempts.value,
            )
        )

        if new_lockout is not None:
            self._record_event(
                AccountLocked(
                    user_id=self._id.value,
                    email=self._email.address,
                    locked_until=new_lockout.locked_until,
                )
            )

    def record_successful_login(self, now: datetime) -> None:
        self._ensure_active()

        self._login_tracking = self._login_tracking.after_successful_login()

        self._record_event(LoginSucceeded(user_id=self._id.value))

    def suspend(self, reason: str) -> None:
        if self._status == UserStatus.SUSPENDED:
            raise AccountAlreadySuspendedError()
        self._ensure_active()
        verify_params(reason=(reason, str))

        self._status = UserStatus.SUSPENDED

        self._record_event(
            UserSuspended(
                user_id=self._id.value,
                email=self._email.address,
                reason=reason.strip(),
            )
        )

    def reactivate(self) -> None:
        self._ensure_not_deactivated()
        self._ensure_not_already_active()

        self._status = UserStatus.ACTIVE

        self._record_event(UserReactivated(user_id=self._id.value))

    def deactivate(self) -> None:
        self._ensure_not_already_deactivated()

        self._status = UserStatus.DEACTIVATED

        self._record_event(
            UserDeactivated(user_id=self._id.value, email=self._email.address)
        )

    def change_email(
        self,
        new_email: EmailAddress,
        verification_token: EmailVerificationToken | None = None,
    ) -> None:
        self._ensure_active()
        self._ensure_email_changed(new_email)

        old_email = self._email
        self._email = new_email
        self._email_verification = EmailVerification(
            is_verified=verification_token is None,
            token=verification_token,
        )

        self._record_event(
            UserEmailChanged(
                user_id=self._id.value,
                old_email=old_email.address,
                new_email=new_email.address,
            )
        )

        if verification_token is not None:
            self._status = UserStatus.PENDING_VERIFICATION
            self._record_event(
                VerificationTokenIssued(user_id=self._id.value, email=new_email.address)
            )

    def reissue_verification_token(self, token: EmailVerificationToken) -> None:
        self._ensure_not_deactivated()
        self._ensure_email_not_verified()

        self._email_verification = EmailVerification(is_verified=False, token=token)

        self._record_event(VerificationTokenReissued(user_id=self._id.value))

    def assign_role(self, role_name: RoleName) -> None:
        self._ensure_not_deactivated()
        self._ensure_role_not_assigned(role_name)

        self._role_names.add(role_name)

        self._record_event(
            RoleAssignedToUser(
                user_id=self._id.value,
                role_name=role_name.value,
            )
        )

    def revoke_role(self, role_name: RoleName) -> None:
        self._ensure_not_deactivated()
        self._ensure_role_assigned(role_name)

        self._role_names.discard(role_name)

        self._record_event(
            RoleRevokedFromUser(
                user_id=self._id.value,
                role_name=role_name.value,
            )
        )
