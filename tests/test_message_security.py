
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from src.client import (
    receive_from_relay,
    send_via_relay,
    _received_message_ids,
    _received_lock,
)
from src.main import (
    generate_bob_keys,
    generate_alice_signing_keys,
    send_message,
    receive_message,
)
from src.server.relay import app, _inboxes, _seen_message_ids, _lock


def reset_state():
    with _lock:
        _inboxes.clear()
        _seen_message_ids.clear()

    with _received_lock:
        _received_message_ids.clear()


def test_message_round_trip():
    bob_public, bob_secret = generate_bob_keys()
    alice_public, alice_secret = generate_alice_signing_keys()

    message = send_message(
        bob_public,
        alice_secret,
        "Hello Bob",
        sender_id="alice",
        recipient_id="bob",
        prekey_id="prekey-001",
    )

    assert receive_message(bob_secret, alice_public, message) == "Hello Bob"


@pytest.mark.parametrize(
    "field,value",
    [
        ("recipient_id", "mallory"),
        ("message_id", "forged-message-id"),
        ("prekey_id", "forged-prekey"),
        ("ciphertext", b"tampered-ciphertext"),
    ],
)
def test_tampered_message_is_rejected(field, value):
    bob_public, bob_secret = generate_bob_keys()
    alice_public, alice_secret = generate_alice_signing_keys()

    message = send_message(
        bob_public,
        alice_secret,
        "Original message",
        sender_id="alice",
        recipient_id="bob",
        prekey_id="prekey-001",
    )

    modified = replace(message, **{field: value})

    with pytest.raises(ValueError, match="Invalid signature"):
        receive_message(bob_secret, alice_public, modified)


def test_replayed_message_is_rejected():
    reset_state()

    bob_public, bob_secret = generate_bob_keys()
    alice_public, alice_secret = generate_alice_signing_keys()

    with TestClient(app) as client:
        send_via_relay(
            http_client=client,
            sender_id="alice",
            recipient_id="bob",
            prekey_id="prekey-001",
            recipient_public_key=bob_public,
            sender_signing_secret_key=alice_secret,
            plaintext="Replay test",
        )

        first = receive_from_relay(
            http_client=client,
            recipient_id="bob",
            recipient_secret_key=bob_secret,
            trusted_sender_signing_public_key=alice_public,
        )

        assert len(first) == 1
        assert first[0]["plaintext"] == "Replay test"

        # Simulate the same valid envelope being delivered again.
        message = send_message(
            bob_public,
            alice_secret,
            "Second message",
            sender_id="alice",
            recipient_id="bob",
            prekey_id="prekey-001",
            message_id=first[0]["message_id"],
        )

        import base64

        replay_envelope = {
            "sender_id": message.sender_id,
            "recipient_id": message.recipient_id,
            "prekey_id": message.prekey_id,
            "message_id": message.message_id,
            "kem_ciphertext": base64.b64encode(message.kem_ciphertext).decode("ascii"),
            "nonce": base64.b64encode(message.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(message.ciphertext).decode("ascii"),
            "signature": base64.b64encode(message.signature).decode("ascii"),
        }

        # The relay rejects duplicate IDs before redelivery.
        response = client.post("/messages", json=replay_envelope)
        assert response.status_code == 409


def test_client_rejects_already_received_message():
    reset_state()

    bob_public, bob_secret = generate_bob_keys()
    alice_public, alice_secret = generate_alice_signing_keys()

    with TestClient(app) as client:
        message_id = send_via_relay(
            http_client=client,
            sender_id="alice",
            recipient_id="bob",
            prekey_id="prekey-001",
            recipient_public_key=bob_public,
            sender_signing_secret_key=alice_secret,
            plaintext="Client replay test",
        )

        first = receive_from_relay(
            http_client=client,
            recipient_id="bob",
            recipient_secret_key=bob_secret,
            trusted_sender_signing_public_key=alice_public,
        )

        assert first[0]["message_id"] == message_id

        # Simulate the same message being delivered again.
        with _received_lock:
            _received_message_ids.add(("bob", message_id))

        with pytest.raises(ValueError, match="Replay detected"):
            # Re-delivery is simulated by placing the original envelope
            # back into the in-memory inbox.
            with _lock:
                # Reuse the message ID to verify client-side rejection.
                _inboxes["bob"].append({
                    "sender_id": "alice",
                    "recipient_id": "bob",
                    "prekey_id": "prekey-001",
                    "message_id": message_id,
                    "kem_ciphertext": "invalid",
                    "nonce": "invalid",
                    "ciphertext": "invalid",
                    "signature": "invalid",
                })

            receive_from_relay(
                http_client=client,
                recipient_id="bob",
                recipient_secret_key=bob_secret,
                trusted_sender_signing_public_key=alice_public,
            )