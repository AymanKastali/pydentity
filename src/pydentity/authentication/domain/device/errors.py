from pydentity.authentication.domain.device.value_objects import DeviceStatus
from pydentity.shared_kernel.building_blocks import DomainError


class DeviceError(DomainError):
    pass


class DeviceNotActiveError(DeviceError):
    def __init__(self, current_status: DeviceStatus) -> None:
        super().__init__(f"Device must be active, but status is {current_status}.")


class MaxDevicesReachedError(DeviceError):
    def __init__(self, max_devices: int) -> None:
        super().__init__(f"Maximum number of devices ({max_devices}) has been reached.")
