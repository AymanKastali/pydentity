from typing import Self

from pydentity.notification.domain.delivery_request.errors import (
    ContentPurgeRequiresSensitiveError,
    ContentPurgeRequiresSentError,
    DeliveryRequestNotPendingError,
)
from pydentity.notification.domain.delivery_request.events import (
    ContentPurged,
    DeliveryAttemptFailed,
    DeliveryRequestCreated,
    MessageDelivered,
    MessageDeliveryFailed,
)
from pydentity.notification.domain.delivery_request.value_objects import (
    AttemptCount,
    Channel,
    ContentSensitivity,
    DeliveryRequestId,
    DeliveryStatus,
    MessageContent,
    Recipient,
)
from pydentity.shared_kernel.building_blocks import AggregateRoot
from pydentity.shared_kernel.value_objects import AccountId


class DeliveryRequest(AggregateRoot[DeliveryRequestId]):
    def __init__(
        self,
        delivery_request_id: DeliveryRequestId,
        account_id: AccountId,
        recipient: Recipient,
        channel: Channel,
        content: MessageContent | None,
        status: DeliveryStatus,
        attempt_count: AttemptCount,
        sensitivity: ContentSensitivity,
    ) -> None:
        super().__init__(delivery_request_id)
        self._account_id: AccountId = account_id
        self._recipient: Recipient = recipient
        self._channel: Channel = channel
        self._content: MessageContent | None = content
        self._status: DeliveryStatus = status
        self._attempt_count: AttemptCount = attempt_count
        self._sensitivity: ContentSensitivity = sensitivity

    @classmethod
    def create(
        cls,
        delivery_request_id: DeliveryRequestId,
        account_id: AccountId,
        recipient: Recipient,
        channel: Channel,
        content: MessageContent,
        sensitivity: ContentSensitivity,
    ) -> Self:
        request = cls(
            delivery_request_id=delivery_request_id,
            account_id=account_id,
            recipient=recipient,
            channel=channel,
            content=content,
            status=DeliveryStatus.PENDING,
            attempt_count=AttemptCount(0),
            sensitivity=sensitivity,
        )
        request._record_delivery_request_created()
        return request

    def mark_sent(self) -> None:
        self._guard_status_is_pending()
        self._mark_as_sent()
        self._record_message_delivered()

    def record_failed_attempt(self) -> None:
        self._guard_status_is_pending()
        self._increment_attempt_count()
        self._record_delivery_attempt_failed()

    def mark_failed(self) -> None:
        self._guard_status_is_pending()
        self._mark_as_failed()
        self._record_message_delivery_failed()

    def purge_content(self) -> None:
        self._guard_status_is_sent()
        self._guard_sensitivity_is_sensitive()
        self._clear_content()
        self._record_content_purged()

    def _mark_as_sent(self) -> None:
        self._status = DeliveryStatus.SENT

    def _mark_as_failed(self) -> None:
        self._status = DeliveryStatus.FAILED

    def _increment_attempt_count(self) -> None:
        self._attempt_count = AttemptCount(self._attempt_count.value + 1)

    def _clear_content(self) -> None:
        self._content = None

    def _guard_status_is_pending(self) -> None:
        if self._status is not DeliveryStatus.PENDING:
            raise DeliveryRequestNotPendingError(self._status)

    def _guard_status_is_sent(self) -> None:
        if self._status is not DeliveryStatus.SENT:
            raise ContentPurgeRequiresSentError(self._status)

    def _guard_sensitivity_is_sensitive(self) -> None:
        if self._sensitivity is not ContentSensitivity.SENSITIVE:
            raise ContentPurgeRequiresSensitiveError(self._sensitivity)

    def _record_delivery_request_created(self) -> None:
        self.record_event(
            DeliveryRequestCreated(
                delivery_request_id=self._id,
                account_id=self._account_id,
                channel=self._channel,
            )
        )

    def _record_message_delivered(self) -> None:
        self.record_event(
            MessageDelivered(delivery_request_id=self._id, account_id=self._account_id)
        )

    def _record_delivery_attempt_failed(self) -> None:
        self.record_event(
            DeliveryAttemptFailed(
                delivery_request_id=self._id,
                account_id=self._account_id,
                attempt_count=self._attempt_count,
            )
        )

    def _record_message_delivery_failed(self) -> None:
        self.record_event(
            MessageDeliveryFailed(
                delivery_request_id=self._id, account_id=self._account_id
            )
        )

    def _record_content_purged(self) -> None:
        self.record_event(
            ContentPurged(delivery_request_id=self._id, account_id=self._account_id)
        )

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
