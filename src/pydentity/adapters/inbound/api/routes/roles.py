from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends

from pydentity.adapters.container import (
    get_add_permission_to_role,
    get_assign_role_to_user,
    get_change_role_description,
    get_create_role,
    get_remove_permission_from_role,
    get_rename_role,
    get_revoke_role_from_user,
)
from pydentity.adapters.inbound.api.schemas.response import ApiResponse
from pydentity.adapters.inbound.api.schemas.roles import (
    AssignRoleRequest,
    ChangeRoleDescriptionRequest,
    CreateRoleRequest,
    CreateRoleResponse,
    PermissionRequest,
    RenameRoleRequest,
    RevokeRoleRequest,
)
from pydentity.application.dtos.role import (
    AddPermissionToRoleInput,
    AssignRoleToUserInput,
    ChangeRoleDescriptionInput,
    CreateRoleInput,
    RemovePermissionFromRoleInput,
    RenameRoleInput,
    RevokeRoleFromUserInput,
)

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
    from pydentity.application.use_cases.role.rename_role import RenameRole
    from pydentity.application.use_cases.role.revoke_role_from_user import (
        RevokeRoleFromUser,
    )

router = APIRouter(prefix="/roles", tags=["roles"])


@router.post("", status_code=201)
async def create_role(
    body: CreateRoleRequest,
    use_case: CreateRole = Depends(get_create_role),
) -> ApiResponse[CreateRoleResponse]:
    result = await use_case.execute(
        CreateRoleInput(name=body.name, description=body.description)
    )
    return ApiResponse(
        data=CreateRoleResponse(
            role_id=result.role_id,
            name=result.name,
            description=result.description,
        )
    )


@router.patch("/{role_id}/name", status_code=204)
async def rename_role(
    role_id: str,
    body: RenameRoleRequest,
    use_case: RenameRole = Depends(get_rename_role),
) -> None:
    await use_case.execute(RenameRoleInput(role_id=role_id, new_name=body.new_name))


@router.patch("/{role_id}/description", status_code=204)
async def change_role_description(
    role_id: str,
    body: ChangeRoleDescriptionRequest,
    use_case: ChangeRoleDescription = Depends(get_change_role_description),
) -> None:
    await use_case.execute(
        ChangeRoleDescriptionInput(
            role_id=role_id, new_description=body.new_description
        )
    )


@router.post("/{role_id}/permissions", status_code=204)
async def add_permission(
    role_id: str,
    body: PermissionRequest,
    use_case: AddPermissionToRole = Depends(get_add_permission_to_role),
) -> None:
    await use_case.execute(
        AddPermissionToRoleInput(
            role_id=role_id, resource=body.resource, action=body.action
        )
    )


@router.delete("/{role_id}/permissions", status_code=204)
async def remove_permission(
    role_id: str,
    body: PermissionRequest,
    use_case: RemovePermissionFromRole = Depends(get_remove_permission_from_role),
) -> None:
    await use_case.execute(
        RemovePermissionFromRoleInput(
            role_id=role_id, resource=body.resource, action=body.action
        )
    )


@router.post("/{role_id}/assign", status_code=204)
async def assign_role(
    role_id: str,
    body: AssignRoleRequest,
    use_case: AssignRoleToUser = Depends(get_assign_role_to_user),
) -> None:
    await use_case.execute(AssignRoleToUserInput(user_id=body.user_id, role_id=role_id))


@router.post("/{role_id}/revoke", status_code=204)
async def revoke_role(
    role_id: str,
    body: RevokeRoleRequest,
    use_case: RevokeRoleFromUser = Depends(get_revoke_role_from_user),
) -> None:
    await use_case.execute(
        RevokeRoleFromUserInput(user_id=body.user_id, role_id=role_id)
    )
