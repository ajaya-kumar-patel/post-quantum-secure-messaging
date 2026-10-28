
import pytest

from src.prekeys import create_identity_keys
from src.prekey_service import PreKeyService


def test_register_retrieve_verify_and_consume():
    identity_public_key, identity_secret_key = create_identity_keys()
    service = PreKeyService()

    bundle = service.register_prekey(
        "bob",
        "prekey-001",
        identity_secret_key,
    )

    retrieved = service.get_bundle("bob", "prekey-001")
    assert retrieved == bundle

    assert service.verify_bundle(
        retrieved,
        identity_public_key,
    )

    secret_key = service.consume_prekey("bob", "prekey-001")
    assert isinstance(secret_key, bytes)
    assert len(secret_key) > 0

    with pytest.raises(ValueError, match="unavailable"):
        service.get_bundle("bob", "prekey-001")

    with pytest.raises(ValueError, match="expired, missing, or already consumed"):
        service.consume_prekey("bob", "prekey-001")


def test_untrusted_identity_cannot_verify_bundle():
    _, bob_identity_secret_key = create_identity_keys()
    wrong_public_key, _ = create_identity_keys()

    service = PreKeyService()
    bundle = service.register_prekey(
        "bob",
        "prekey-002",
        bob_identity_secret_key,
    )

    with pytest.raises(ValueError, match="Invalid signed prekey bundle"):
        service.verify_bundle(bundle, wrong_public_key)
