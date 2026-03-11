from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends

from pydentity.adapters.config.permissions import PermissionRegistry as Perms
from pydentity.adapters.container import (
    get_add_permission_to_role,
    get_assign_role_to_user,
    get_change_role_description,
    get_create_role,
    get_remove_permission_from_role,
    get_revoke_role_from_user,
)
from pydentity.adapters.inbound.api.dependencies.auth import require_permissions
from pydentity.adapters.inbound.api.schemas.response import ApiResponse
from pydentity.adapters.inbound.api.schemas.roles import (
    AssignRoleRequest,
    ChangeRoleDescriptionRequest,
    CreateRoleRequest,
    CreateRoleResponse,
    PermissionRequest,
    RevokeRoleRequest,
)
from pydentity.application.dtos.role import (
    AddPermissionToRoleInput,
    AssignRoleToUserInput,
    ChangeRoleDescriptionInput,
    CreateRoleInput,
    RemovePermissionFromRoleInput,
    RevokeRoleFromUserInput,
)
from pydentity.application.models.access_token_claims import AccessTokenClaims

if TYPE_CHECKING:
    from pydentity.application.use_cases.role.add_permission_to_role import (
        AddPermissionToRole,
    )
    from pydentity.application.use_cases.role.assign_role_to_user import (
        AssignRoleToUser,
    )
    from pydentity.application.use_cases.role.change_role_description import (
        ChangeRoleDescription,
    )
    from pydentity.application.use_cases.role.create_role import CreateRole
    from pydentity.application.use_cases.role.remove_permission_from_role import (
        RemovePermissionFromRole,
    )
    from pydentity.application.use_cases.role.revoke_role_from_user import (
        RevokeRoleFromUser,
    )

router = APIRouter(
    prefix="/roles",
    tags=["roles"],
)


@router.post("", status_code=201)
async def create_role(
    body: CreateRoleRequest,
    _claims: Annotated[
        AccessTokenClaims,
        Depends(require_permissions(Perms.ROLES_CREATE)),
    ],
    use_case: CreateRole = Depends(get_create_role),
) -> ApiResponse[CreateRoleResponse]:
    result = await use_case.execute(
        CreateRoleInput(name=body.name, description=body.description)
    )
    return ApiResponse(
        data=CreateRoleResponse(
            name=result.name,
            description=result.description,
        )
    )


@router.patch("/{role_name}/description", status_code=204)
async def change_role_description(
    role_name: str,
    body: ChangeRoleDescriptionRequest,
    _claims: Annotated[
        AccessTokenClaims,
        Depends(require_permissions(Perms.ROLES_UPDATE)),
    ],
    use_case: ChangeRoleDescription = Depends(get_change_role_description),
) -> None:
    await use_case.execute(
        ChangeRoleDescriptionInput(
            role_name=role_name, new_description=body.new_description
        )
    )


@router.post("/{role_name}/permissions", status_code=204)
async def add_permission(
    role_name: str,
    body: PermissionRequest,
    _claims: Annotated[
        AccessTokenClaims,
        Depends(require_permissions(Perms.ROLES_UPDATE)),
    ],
    use_case: AddPermissionToRole = Depends(get_add_permission_to_role),
) -> None:
    await use_case.execute(
        AddPermissionToRoleInput(
            role_name=role_name, resource=body.resource, action=body.action
        )
    )


@router.delete("/{role_name}/permissions", status_code=204)
async def remove_permission(
    role_name: str,
    body: PermissionRequest,
    _claims: Annotated[
        AccessTokenClaims,
        Depends(require_permissions(Perms.ROLES_UPDATE)),
    ],
    use_case: RemovePermissionFromRole = Depends(get_remove_permission_from_role),
) -> None:
    await use_case.execute(
        RemovePermissionFromRoleInput(
            role_name=role_name, resource=body.resource, action=body.action
        )
    )


@router.post("/{role_name}/assign", status_code=204)
async def assign_role(
    role_name: str,
    body: AssignRoleRequest,
    _claims: Annotated[
        AccessTokenClaims,
        Depends(require_permissions(Perms.ROLES_ASSIGN)),
    ],
    use_case: AssignRoleToUser = Depends(get_assign_role_to_user),
) -> None:
    await use_case.execute(
        AssignRoleToUserInput(user_id=body.user_id, role_name=role_name)
    )


@router.post("/{role_name}/revoke", status_code=204)
async def revoke_role(
    role_name: str,
    body: RevokeRoleRequest,
    _claims: Annotated[
        AccessTokenClaims,
        Depends(require_permissions(Perms.ROLES_REVOKE)),
    ],
    use_case: RevokeRoleFromUser = Depends(get_revoke_role_from_user),
) -> None:
    await use_case.execute(
        RevokeRoleFromUserInput(user_id=body.user_id, role_name=role_name)
    )
