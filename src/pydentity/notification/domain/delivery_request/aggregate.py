from typing import TYPE_CHECKING

from pydentity.notification.domain.delivery_request.aggregate_id import (
    DeliveryRequestId,
)
from pydentity.notification.domain.delivery_request.errors import (
    DeliveryRequestContentAlreadyPurgedError,
)
from pydentity.notification.domain.delivery_request.events import (
    MessageDelivered,
    MessageDeliveryFailed,
)
from pydentity.notification.domain.delivery_request.value_objects import (
    AttemptCount,
    Channel,
    ContentSensitivity,
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
        attempt_count: AttemptCount,
        sensitivity: ContentSensitivity,
    ) -> None:
        super().__init__(request_id)
        self._account_id: AccountId = account_id
        self._recipient: Recipient = recipient
        self._channel: Channel = channel
        self._content: MessageContent | None = content
        self._status: DeliveryStatus = status
        self._attempt_count: AttemptCount = attempt_count
        self._sensitivity: ContentSensitivity = sensitivity

    # --- Creation ---

    @classmethod
    def create(
        cls,
        request_id: DeliveryRequestId,
        account_id: AccountId,
        recipient: Recipient,
        channel: Channel,
        content: MessageContent,
        sensitivity: ContentSensitivity,
    ) -> DeliveryRequest:
        return cls(
            request_id=request_id,
            account_id=account_id,
            recipient=recipient,
            channel=channel,
            content=content,
            status=DeliveryStatus.PENDING,
            attempt_count=AttemptCount.initialize(),
            sensitivity=sensitivity,
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
    def attempt_count(self) -> AttemptCount:
        return self._attempt_count

    @property
    def sensitivity(self) -> ContentSensitivity:
        return self._sensitivity

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
        self._attempt_count = self._attempt_count.increment()

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
        self._sensitivity.guard_is_sensitive()
        self._guard_content_not_purged()
        self._content = None

    def _guard_content_not_purged(self) -> None:
        if self._content is None:
            raise DeliveryRequestContentAlreadyPurgedError()
