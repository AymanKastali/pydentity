from datetime import datetime

from pydentity.authentication.domain.identity.aggregate import Identity
from pydentity.authentication.domain.identity.events import IdentityCreated
from pydentity.shared_kernel import IdentityId


class TestIdentityCreate:
    def test_returns_identity_with_id(self, identity_id: IdentityId, now: datetime):
        identity = Identity.create(identity_id, now)
        assert identity.id == identity_id

    def test_records_identity_created_event(
        self, identity_id: IdentityId, now: datetime
    ):
        identity = Identity.create(identity_id, now)
        assert len(identity.events) == 1
        assert isinstance(identity.events[0], IdentityCreated)

    def test_event_contains_identity_id(self, identity_id: IdentityId, now: datetime):
        identity = Identity.create(identity_id, now)
        event = identity.events[0]
        assert isinstance(event, IdentityCreated)
        assert event.identity_id == identity_id

    def test_event_contains_occurred_at(self, identity_id: IdentityId, now: datetime):
        identity = Identity.create(identity_id, now)
        assert identity.events[0].occurred_at == now
