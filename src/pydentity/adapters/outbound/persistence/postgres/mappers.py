from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.adapters.outbound.persistence.postgres.models import (
    DeviceModel,
    RoleModel,
    SessionModel,
    UserModel,
)

if TYPE_CHECKING:
    from pydentity.domain.models.device import Device
    from pydentity.domain.models.role import Role
    from pydentity.domain.models.session import Session
    from pydentity.domain.models.user import User


# ── user ──────────────────────────────────────────────────────────────────────


def user_to_model(user: User) -> UserModel:
    ev = user.email_verification
    creds = user.credentials
    lt = user.login_tracking

    return UserModel(
        domain_id=user.id.value,
        email=user.email.address,
        status=user.status.value,
        email_verification_is_verified=ev.is_verified,
        # Accessing .value on the Hashed token VOs
        email_verification_token_hash=(
            ev.token.token_hash.value.hex() if ev.token else None
        ),
        email_verification_token_expires_at=(ev.token.expires_at if ev.token else None),
        credentials_password_hash=creds.password_hash.value.hex(),
        credentials_password_reset_token_hash=(
            creds.password_reset_token.token_hash.value.hex()
            if creds.password_reset_token
            else None
        ),
        credentials_password_reset_token_expires_at=(
            creds.password_reset_token.expires_at
            if creds.password_reset_token
            else None
        ),
        # Ensure password history is stored as hex strings for JSON compatibility
        credentials_password_history=[h.value.hex() for h in creds.password_history],
        login_tracking_failed_attempts=lt.failed_login_attempts.value,
        login_tracking_lockout_expiry=(
            lt.lockout_expiry.locked_until if lt.lockout_expiry else None
        ),
    )


def model_to_user(model: UserModel) -> User:
    from pydentity.domain.models.enums import UserStatus
    from pydentity.domain.models.user import User
    from pydentity.domain.models.value_objects import (
        Credentials,
        EmailAddress,
        EmailVerification,
        EmailVerificationToken,
        FailedLoginAttempts,
        HashedPassword,
        HashedResetToken,
        HashedVerificationToken,
        LockoutExpiry,
        LoginTracking,
        PasswordResetToken,
        RoleId,
        UserId,
    )

    ev_token = None
    if (
        model.email_verification_token_hash
        and model.email_verification_token_expires_at
    ):
        ev_token = EmailVerificationToken(
            token_hash=HashedVerificationToken(
                bytes.fromhex(model.email_verification_token_hash)
            ),
            expires_at=model.email_verification_token_expires_at,
        )

    reset_token = None
    if (
        model.credentials_password_reset_token_hash
        and model.credentials_password_reset_token_expires_at
    ):
        reset_token = PasswordResetToken(
            token_hash=HashedResetToken(
                bytes.fromhex(model.credentials_password_reset_token_hash)
            ),
            expires_at=model.credentials_password_reset_token_expires_at,
        )

    return User(
        user_id=UserId(model.domain_id),
        email=EmailAddress.from_string(model.email),
        status=UserStatus(model.status),
        email_verification=EmailVerification(
            is_verified=model.email_verification_is_verified,
            token=ev_token,
        ),
        credentials=Credentials(
            password_hash=HashedPassword(
                bytes.fromhex(model.credentials_password_hash)
            ),
            password_reset_token=reset_token,
            password_history=tuple(
                HashedPassword(bytes.fromhex(h))
                for h in model.credentials_password_history
            ),
        ),
        login_tracking=LoginTracking(
            failed_login_attempts=FailedLoginAttempts(
                model.login_tracking_failed_attempts
            ),
            lockout_expiry=(
                LockoutExpiry(locked_until=model.login_tracking_lockout_expiry)
                if model.login_tracking_lockout_expiry
                else None
            ),
        ),
        role_ids={RoleId(r.domain_id) for r in (model.roles or [])},
    )


# ── role ──────────────────────────────────────────────────────────────────────


def role_to_model(role: Role) -> RoleModel:
    return RoleModel(
        domain_id=role.id.value,
        name=role.name.value,
        description=role.description.value,
        permissions=[f"{p.resource}:{p.action}" for p in role.permissions],
    )


def model_to_role(model: RoleModel) -> Role:
    from pydentity.domain.models.role import Role
    from pydentity.domain.models.value_objects import (
        Permission,
        RoleDescription,
        RoleId,
        RoleName,
    )

    return Role(
        role_id=RoleId(model.domain_id),
        name=RoleName(model.name),
        description=RoleDescription(model.description),
        permissions={
            Permission(resource=p.split(":")[0], action=p.split(":")[1])
            for p in model.permissions
        },
    )


# ── session ───────────────────────────────────────────────────────────────────


def session_to_model(session: Session, user_fk: int, device_fk: int) -> SessionModel:
    return SessionModel(
        domain_id=session.id.value,
        user_fk=user_fk,
        device_fk=device_fk,
        user_domain_id=session.user_id.value,
        device_domain_id=session.device_id.value,
        refresh_token_hash=session.refresh_token_hash.value.hex(),
        refresh_token_family_id=session.refresh_token_family.family_id,
        refresh_token_family_generation=session.refresh_token_family.generation,
        status=session.status.value,
        session_created_at=session.created_at.created_at,
        last_refresh=session.last_refresh.refreshed_at,
        expiry=session.expiry.expires_at,
    )


def model_to_session(model: SessionModel) -> Session:
    from pydentity.domain.models.enums import SessionStatus
    from pydentity.domain.models.session import Session
    from pydentity.domain.models.value_objects import (
        DeviceId,
        HashedRefreshToken,
        RefreshTokenFamily,
        SessionCreatedAt,
        SessionExpiry,
        SessionId,
        SessionLastRefresh,
        UserId,
    )

    return Session(
        session_id=SessionId(model.domain_id),
        user_id=UserId(model.user_domain_id),
        device_id=DeviceId(model.device_domain_id),
        refresh_token_hash=HashedRefreshToken(bytes.fromhex(model.refresh_token_hash)),
        refresh_token_family=RefreshTokenFamily(
            family_id=model.refresh_token_family_id,
            generation=model.refresh_token_family_generation,
        ),
        status=SessionStatus(model.status),
        created_at=SessionCreatedAt(created_at=model.session_created_at),
        last_refresh=SessionLastRefresh(refreshed_at=model.last_refresh),
        expiry=SessionExpiry(expires_at=model.expiry),
    )


# ── device ────────────────────────────────────────────────────────────────────


def device_to_model(device: Device, user_fk: int) -> DeviceModel:
    return DeviceModel(
        domain_id=device.id.value,
        user_fk=user_fk,
        user_domain_id=device.user_id.value,
        name=device.name.value,
        fingerprint=device.fingerprint.value,
        platform=device.platform.value,
        status=device.status.value,
        is_trusted=device.is_trusted,
        last_active=device.last_active.last_active_at,
    )


def model_to_device(model: DeviceModel) -> Device:
    from pydentity.domain.models.device import Device
    from pydentity.domain.models.enums import DevicePlatform, DeviceStatus
    from pydentity.domain.models.value_objects import (
        DeviceFingerprint,
        DeviceId,
        DeviceLastActive,
        DeviceName,
        UserId,
    )

    return Device(
        device_id=DeviceId(model.domain_id),
        user_id=UserId(model.user_domain_id),
        name=DeviceName(model.name),
        fingerprint=DeviceFingerprint(model.fingerprint),
        platform=DevicePlatform(model.platform),
        status=DeviceStatus(model.status),
        is_trusted=model.is_trusted,
        last_active=DeviceLastActive(last_active_at=model.last_active),
    )
