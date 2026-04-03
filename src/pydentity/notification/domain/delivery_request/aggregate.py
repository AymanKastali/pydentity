from typing import TYPE_CHECKING

from pydentity.notification.domain.delivery_request.aggregate_id import (
    DeliveryRequestId,
)
from pydentity.notification.domain.delivery_request.errors import (
    DeliveryRequestContentAlreadyPurgedError,
    DeliveryRequestNotSensitiveError,
)
from pydentity.notification.domain.delivery_request.events import (
    MessageDelivered,
    MessageDeliveryFailed,
)
from pydentity.notification.domain.delivery_request.value_objects import (
    Channel,
    DeliveryStatus,
    MessageContent,
    Recipient,
)
from pydentity.shared_kernel import AggregateRoot

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.shared_kernel import AccountId


class DeliveryRequest(AggregateRoot[DeliveryRequestId]):
    def __init__(
        self,
        request_id: DeliveryRequestId,
        account_id: AccountId,
        recipient: Recipient,
        channel: Channel,
        content: MessageContent | None,
        status: DeliveryStatus,
        attempt_count: int,
        is_sensitive: bool,
    ) -> None:
        super().__init__(request_id)
        self._account_id: AccountId = account_id
        self._recipient: Recipient = recipient
        self._channel: Channel = channel
        self._content: MessageContent | None = content
        self._status: DeliveryStatus = status
        self._attempt_count: int = attempt_count
        self._is_sensitive: bool = is_sensitive

    # --- Creation ---

    @classmethod
    def create(
        cls,
        request_id: DeliveryRequestId,
        account_id: AccountId,
        recipient: Recipient,
        channel: Channel,
        content: MessageContent,
        is_sensitive: bool,
    ) -> DeliveryRequest:
        return cls(
            request_id=request_id,
            account_id=account_id,
            recipient=recipient,
            channel=channel,
            content=content,
            status=DeliveryStatus.PENDING,
            attempt_count=0,
            is_sensitive=is_sensitive,
        )

    # --- Queries ---

    @property
    def account_id(self) -> AccountId:
        return self._account_id

    @property
    def recipient(self) -> Recipient:
        return self._recipient

    @property
    def channel(self) -> Channel:
        return self._channel

    @property
    def content(self) -> MessageContent | None:
        return self._content

    @property
    def status(self) -> DeliveryStatus:
        return self._status

    @property
    def attempt_count(self) -> int:
        return self._attempt_count

    @property
    def is_sensitive(self) -> bool:
        return self._is_sensitive

    # --- Delivery success ---

    def mark_sent(self, now: datetime) -> None:
        self._status.guard_not_sent()
        self._status.guard_not_failed()
        self._increment_attempt_count()
        self._mark_sent()
        self.record_event(
            MessageDelivered(
                occurred_at=now,
                request_id=self._id,
                account_id=self._account_id,
            )
        )

    def _increment_attempt_count(self) -> None:
        self._attempt_count += 1

    def _mark_sent(self) -> None:
        self._status = DeliveryStatus.SENT

    # --- Delivery failure ---

    def record_failed_attempt(self) -> None:
        self._status.guard_not_sent()
        self._status.guard_not_failed()
        self._increment_attempt_count()

    def mark_failed(self, now: datetime) -> None:
        self._status.guard_not_sent()
        self._status.guard_not_failed()
        self._mark_failed()
        self.record_event(
            MessageDeliveryFailed(
                occurred_at=now,
                request_id=self._id,
                account_id=self._account_id,
            )
        )

    def _mark_failed(self) -> None:
        self._status = DeliveryStatus.FAILED

    # --- Content purge ---

    def purge_content(self) -> None:
        self._guard_is_sensitive()
        self._guard_content_not_purged()
        self._content = None

    def _guard_is_sensitive(self) -> None:
        if not self._is_sensitive:
            raise DeliveryRequestNotSensitiveError()

    def _guard_content_not_purged(self) -> None:
        if self._content is None:
            raise DeliveryRequestContentAlreadyPurgedError()
