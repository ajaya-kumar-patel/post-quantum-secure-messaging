
from dataclasses import replace

import pytest

from src.prekeys import (
    create_identity_keys,
    create_signed_prekey_bundle,
    verify_signed_prekey_bundle,
)


def test_signed_prekey_bundle_verifies():
    identity_public_key, identity_secret_key = create_identity_keys()

    bundle, kem_secret_key = create_signed_prekey_bundle(
        user_id="bob",
        prekey_id="prekey-001",
        identity_secret_key=identity_secret_key,
    )

    assert verify_signed_prekey_bundle(
        bundle,
        identity_public_key,
    ) is True

    # The secret KEM key exists separately and is not in the bundle.
    assert kem_secret_key
    assert not hasattr(bundle, "kem_secret_key")


def test_tampered_prekey_is_rejected():
    identity_public_key, identity_secret_key = create_identity_keys()

    bundle, _ = create_signed_prekey_bundle(
        "bob",
        "prekey-001",
        identity_secret_key,
    )

    modified_key = bytearray(bundle.kem_public_key)
    modified_key[0] ^= 1

    tampered_bundle = replace(
        bundle,
        kem_public_key=bytes(modified_key),
    )

    with pytest.raises(ValueError, match="Invalid signed prekey bundle"):
        verify_signed_prekey_bundle(
            tampered_bundle,
            identity_public_key,
        )


def test_wrong_identity_key_is_rejected():
    _, bob_identity_secret_key = create_identity_keys()
    alice_identity_public_key, _ = create_identity_keys()

    bundle, _ = create_signed_prekey_bundle(
        "bob",
        "prekey-001",
        bob_identity_secret_key,
    )

    with pytest.raises(ValueError, match="Invalid signed prekey bundle"):
        verify_signed_prekey_bundle(
            bundle,
            alice_identity_public_key,
        )
