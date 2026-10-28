
from fastapi.testclient import TestClient

from src.client import send_via_relay, receive_from_relay
from src.main import generate_bob_keys, generate_alice_signing_keys
from src.server.relay import app, _inboxes, _lock


def setup_function():
    with _lock:
        _inboxes.clear()


def test_real_encrypted_message_round_trip_through_relay():
    # Generate recipient's KEM keys and sender's signing keys.
    bob_public_key, bob_secret_key = generate_bob_keys()
    alice_signing_public_key, alice_signing_secret_key = (
        generate_alice_signing_keys()
    )

    original = "Real encrypted message through the relay!"

    with TestClient(app) as client:
        message_id = send_via_relay(
            http_client=client,
            sender_id="alice",
            recipient_id="bob",
            prekey_id="prekey-001",
            recipient_public_key=bob_public_key,
            sender_signing_secret_key=alice_signing_secret_key,
            plaintext=original,
        )

        # Inspect the relay queue: it contains ciphertext, not plaintext.
        with _lock:
            queued = list(_inboxes["bob"])

        assert len(queued) == 1
        assert queued[0]["message_id"] == message_id
        assert queued[0]["ciphertext"] != original
        assert original not in str(queued[0])

        received = receive_from_relay(
            http_client=client,
            recipient_id="bob",
            recipient_secret_key=bob_secret_key,
            trusted_sender_signing_public_key=alice_signing_public_key,
        )

    assert len(received) == 1
    assert received[0]["message_id"] == message_id
    assert received[0]["plaintext"] == original
