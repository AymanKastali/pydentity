"""Startup seeder for predefined roles and super admin user."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydentity.adapters.config.permissions import PermissionRegistry
from pydentity.domain.factories.role_factory import RoleFactory
from pydentity.domain.models.value_objects import (
    EmailAddress,
    RoleDescription,
    RoleName,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydentity.adapters.config.super_admin import SuperAdminSettings
    from pydentity.domain.ports.identity_generation import IdentityGeneratorPort
    from pydentity.domain.ports.password_hasher import PasswordHasherPort
    from pydentity.domain.ports.unit_of_work import UnitOfWork

logger = logging.getLogger(__name__)

_PREDEFINED_ROLES = PermissionRegistry.PREDEFINED_ROLES


async def seed_roles(
    *,
    uow_factory: Callable[[], UnitOfWork],
) -> None:
    role_factory = RoleFactory()

    async with uow_factory() as uow:
        for name, (description, permissions) in _PREDEFINED_ROLES.items():
            role_name = RoleName(name)
            existing = await uow.roles.find_by_name(role_name)

            if existing is None:
                role = role_factory.create(
                    name=role_name,
                    description=RoleDescription(description),
                )
                for perm in permissions:
                    role.add_permission(perm)
                await uow.roles.upsert(role)
                role.collect_events()
                logger.info(
                    "Seeded role '%s' with %d permissions",
                    name,
                    len(permissions),
                )
            else:
                missing = permissions - existing.permissions
                for perm in missing:
                    existing.add_permission(perm)
                if missing:
                    await uow.roles.upsert(existing)
                    existing.collect_events()
                    logger.info(
                        "Synced %d missing permissions for role '%s'",
                        len(missing),
                        name,
                    )

        await uow.commit()


async def seed_super_admin(
    *,
    uow_factory: Callable[[], UnitOfWork],
    identity_generator: IdentityGeneratorPort,
    password_hasher: PasswordHasherPort,
    password_policy: object,
    super_admin_settings: SuperAdminSettings | None,
) -> None:
    if super_admin_settings is None:
        logger.debug("No super admin settings configured — skipping")
        return

    async with uow_factory() as uow:
        super_admin_role = await uow.roles.find_by_name(
            RoleName(PermissionRegistry.SUPER_ADMIN_ROLE_NAME)
        )
        if super_admin_role is None:
            logger.warning("Super admin role not found — seed roles first")
            return

        existing = await uow.users.find_by_email(
            EmailAddress.from_string(super_admin_settings.email)
        )
        if existing is not None and super_admin_role.name in existing.role_names:
            logger.info("Super admin already exists — skipping")
            return

        from pydentity.domain.models.user import User

        email = EmailAddress.from_string(super_admin_settings.email)
        password_hash = await password_hasher.hash(
            super_admin_settings.password.get_secret_value()
        )
        user_id = identity_generator.new_user_id()

        user = User.create(
            user_id=user_id,
            email=email,
            password_hash=password_hash,
            verification_token=None,
        )
        user.assign_role(super_admin_role.name)
        user.collect_events()

        await uow.users.upsert(user)
        await uow.commit()

    logger.info(
        "Super admin '%s' created — you can now remove the env vars",
        super_admin_settings.email,
    )
