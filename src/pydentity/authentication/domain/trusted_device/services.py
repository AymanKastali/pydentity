from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydentity.authentication.domain.trusted_device.repository import (
        TrustedDeviceRepository,
    )
    from pydentity.authentication.domain.trusted_device.value_objects import (
        DevicePolicy,
    )
    from pydentity.shared_kernel import AccountId


class EnforceDeviceLimit:
    @classmethod
    async def check(
        cls,
        account_id: AccountId,
        device_repository: TrustedDeviceRepository,
        device_policy: DevicePolicy,
    ) -> None:
        active_count = await device_repository.count_active_by_account_id(account_id)
        device_policy.guard_limit_not_exceeded(active_count)
