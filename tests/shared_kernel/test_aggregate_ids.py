from uuid import UUID

from pydentity.shared_kernel import AccountId, IdentityId


class TestAccountId:
    def test_stores_uuid(self):
        uuid = UUID("12345678-1234-5678-1234-567812345678")
        account_id = AccountId(value=uuid)
        assert account_id.value == uuid

    def test_equality(self):
        uuid = UUID("12345678-1234-5678-1234-567812345678")
        assert AccountId(value=uuid) == AccountId(value=uuid)

    def test_inequality(self):
        uuid_a = UUID("12345678-1234-5678-1234-567812345678")
        uuid_b = UUID("87654321-4321-8765-4321-876543218765")
        assert AccountId(value=uuid_a) != AccountId(value=uuid_b)


class TestIdentityId:
    def test_stores_uuid(self):
        uuid = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        identity_id = IdentityId(value=uuid)
        assert identity_id.value == uuid

    def test_equality(self):
        uuid = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        assert IdentityId(value=uuid) == IdentityId(value=uuid)
