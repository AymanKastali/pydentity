from __future__ import annotations

from pydentity.adapters.outbound.persistence.postgres.models import (
    DeviceModel,
    RoleModel,
    SessionModel,
    UserModel,
)
from pydentity.domain.models.device import Device
from pydentity.domain.models.enums import (
    DevicePlatform,
    DeviceStatus,
    SessionStatus,
    UserStatus,
)
from pydentity.domain.models.role import Role
from pydentity.domain.models.session import Session
from pydentity.domain.models.user import User
from pydentity.domain.models.value_objects import (
    Credentials,
    DeviceFingerprint,
    DeviceId,
    DeviceLastActive,
    DeviceName,
    EmailAddress,
    EmailVerification,
    EmailVerificationToken,
    FailedLoginAttempts,
    HashedPassword,
    HashedRefreshToken,
    HashedResetToken,
    HashedVerificationToken,
    LockoutExpiry,
    LoginTracking,
    PasswordResetToken,
    Permission,
    RefreshTokenFamily,
    RoleDescription,
    RoleId,
    RoleName,
    SessionCreatedAt,
    SessionExpiry,
    SessionId,
    SessionLastRefresh,
    UserId,
)

# ── user ──────────────────────────────────────────────────────────────────────


def user_to_model(user: User) -> UserModel:
    ev = user.email_verification
    creds = user.credentials
    lt = user.login_tracking

    ev_token_hash = ev.token.token_hash.value if ev.token else None
    ev_token_expires_at = ev.token.expires_at if ev.token else None

    credentials_password_hash = creds.password_hash.value
    credentials_reset_token_hash = (
        creds.password_reset_token.token_hash.value
        if creds.password_reset_token
        else None
    )
    credentials_reset_token_expires_at = (
        creds.password_reset_token.expires_at if creds.password_reset_token else None
    )
    credentials_password_history = [h.value for h in creds.password_history]

    login_tracking_failed_attempts = lt.failed_login_attempts.value
    login_tracking_lockout_expiry = (
        lt.lockout_expiry.locked_until if lt.lockout_expiry else None
    )

    return UserModel(
        domain_id=user.id.value,
        email=user.email.address,
        status=user.status.value,
        email_verification_is_verified=ev.is_verified,
        email_verification_token_hash=ev_token_hash,
        email_verification_token_expires_at=ev_token_expires_at,
        credentials_password_hash=credentials_password_hash,
        credentials_password_reset_token_hash=credentials_reset_token_hash,
        credentials_password_reset_token_expires_at=credentials_reset_token_expires_at,
        credentials_password_history=credentials_password_history,
        login_tracking_failed_attempts=login_tracking_failed_attempts,
        login_tracking_lockout_expiry=login_tracking_lockout_expiry,
    )


def model_to_user(model: UserModel) -> User:
    ev_token = (
        EmailVerificationToken(
            token_hash=HashedVerificationToken(model.email_verification_token_hash),
            expires_at=model.email_verification_token_expires_at,
        )
        if model.email_verification_token_hash
        and model.email_verification_token_expires_at
        else None
    )
    email_verification = EmailVerification(
        is_verified=model.email_verification_is_verified,
        token=ev_token,
    )

    reset_token = (
        PasswordResetToken(
            token_hash=HashedResetToken(model.credentials_password_reset_token_hash),
            expires_at=model.credentials_password_reset_token_expires_at,
        )
        if model.credentials_password_reset_token_hash
        and model.credentials_password_reset_token_expires_at
        else None
    )
    credentials = Credentials(
        password_hash=HashedPassword(model.credentials_password_hash),
        password_reset_token=reset_token,
        password_history=tuple(
            HashedPassword(h) for h in model.credentials_password_history
        ),
    )

    lockout_expiry = (
        LockoutExpiry(locked_until=model.login_tracking_lockout_expiry)
        if model.login_tracking_lockout_expiry
        else None
    )
    login_tracking = LoginTracking(
        failed_login_attempts=FailedLoginAttempts(model.login_tracking_failed_attempts),
        lockout_expiry=lockout_expiry,
    )

    role_ids = {RoleId(r.domain_id) for r in (model.roles or [])}

    return User._reconstitute(
        user_id=UserId(model.domain_id),
        email=EmailAddress.from_string(model.email),
        status=UserStatus(model.status),
        email_verification=email_verification,
        credentials=credentials,
        login_tracking=login_tracking,
        role_ids=role_ids,
    )


# ── role ──────────────────────────────────────────────────────────────────────


def role_to_model(role: Role) -> RoleModel:
    permissions = [f"{p.resource}:{p.action}" for p in role.permissions]

    return RoleModel(
        domain_id=role.id.value,
        name=role.name.value,
        description=role.description.value,
        permissions=permissions,
    )


def model_to_role(model: RoleModel) -> Role:
    role_id = RoleId(model.domain_id)
    name = RoleName(model.name)
    description = RoleDescription(model.description)
    permissions = {
        Permission(resource=raw.split(":")[0], action=raw.split(":")[1])
        for raw in model.permissions
    }

    return Role._reconstitute(
        role_id=role_id,
        name=name,
        description=description,
        permissions=permissions,
    )


# ── session ───────────────────────────────────────────────────────────────────


def session_to_model(session: Session, user_fk: int, device_fk: int) -> SessionModel:
    refresh_token_hash = session.refresh_token_hash.value
    refresh_token_family_id = session.refresh_token_family.family_id
    refresh_token_family_generation = session.refresh_token_family.generation
    session_created_at = session.created_at.created_at
    last_refresh = session.last_refresh.refreshed_at
    expiry = session.expiry.expires_at

    return SessionModel(
        domain_id=session.id.value,
        user_fk=user_fk,
        device_fk=device_fk,
        user_domain_id=session.user_id.value,
        device_domain_id=session.device_id.value,
        refresh_token_hash=refresh_token_hash,
        refresh_token_family_id=refresh_token_family_id,
        refresh_token_family_generation=refresh_token_family_generation,
        status=session.status.value,
        session_created_at=session_created_at,
        last_refresh=last_refresh,
        expiry=expiry,
    )


def model_to_session(model: SessionModel) -> Session:
    session_id = SessionId(model.domain_id)
    user_id = UserId(model.user_domain_id)
    device_id = DeviceId(model.device_domain_id)
    refresh_token_hash = HashedRefreshToken(model.refresh_token_hash)
    refresh_token_family = RefreshTokenFamily(
        family_id=model.refresh_token_family_id,
        generation=model.refresh_token_family_generation,
    )
    status = SessionStatus(model.status)
    created_at = SessionCreatedAt(created_at=model.session_created_at)
    last_refresh = SessionLastRefresh(refreshed_at=model.last_refresh)
    expiry = SessionExpiry(expires_at=model.expiry)

    return Session._reconstitute(
        session_id=session_id,
        user_id=user_id,
        device_id=device_id,
        refresh_token_hash=refresh_token_hash,
        refresh_token_family=refresh_token_family,
        status=status,
        created_at=created_at,
        last_refresh=last_refresh,
        expiry=expiry,
    )


# ── device ────────────────────────────────────────────────────────────────────


def device_to_model(device: Device, user_fk: int) -> DeviceModel:
    last_active = device.last_active.last_active_at

    return DeviceModel(
        domain_id=device.id.value,
        user_fk=user_fk,
        user_domain_id=device.user_id.value,
        name=device.name.value,
        fingerprint=device.fingerprint.value,
        platform=device.platform.value,
        status=device.status.value,
        is_trusted=device.is_trusted,
        last_active=last_active,
    )


def model_to_device(model: DeviceModel) -> Device:
    device_id = DeviceId(model.domain_id)
    user_id = UserId(model.user_domain_id)
    name = DeviceName(model.name)
    fingerprint = DeviceFingerprint(model.fingerprint)
    platform = DevicePlatform(model.platform)
    status = DeviceStatus(model.status)
    last_active = DeviceLastActive(last_active_at=model.last_active)

    return Device._reconstitute(
        device_id=device_id,
        user_id=user_id,
        name=name,
        fingerprint=fingerprint,
        platform=platform,
        status=status,
        is_trusted=model.is_trusted,
        last_active=last_active,
    )
