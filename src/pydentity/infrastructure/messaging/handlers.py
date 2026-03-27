import logging
from typing import TYPE_CHECKING

from pydentity.domain.account.events import AccountRegistered

if TYPE_CHECKING:
    from pydentity.infrastructure.messaging.event_publisher import (
        InProcessEventPublisher,
    )

logger = logging.getLogger(__name__)


def on_account_registered(event: AccountRegistered) -> None:
    logger.info(
        "Account registered: id=%s email=%s",
        event.account_id,
        event.email,
    )


def register_event_handlers(
    publisher: InProcessEventPublisher,
) -> None:
    publisher.register(AccountRegistered, on_account_registered)
