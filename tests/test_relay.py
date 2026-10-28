
from fastapi.testclient import TestClient

from src.server.relay import (
    app,
    _inboxes,
    _seen_message_ids,
    _lock,
)


client = TestClient(app)


def reset_relay():
    with _lock:
        _inboxes.clear()
        _seen_message_ids.clear()


def make_envelope(
    message_id="test-message-001",
    sender_id="alice",
    recipient_id="bob",
    ciphertext="encoded-encrypted-message",
):
    return {
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "prekey_id": "prekey-001",
        "message_id": message_id,
        "kem_ciphertext": "test-kem",
        "nonce": "test-nonce",
        "ciphertext": ciphertext,
        "signature": "test-signature",
    }


def test_health_endpoint():
    reset_relay()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_relay_forwards_opaque_envelope():
    reset_relay()
    envelope = make_envelope()

    sent = client.post("/messages", json=envelope)

    assert sent.status_code == 202
    assert sent.json()["message_id"] == envelope["message_id"]

    queued = client.get("/messages/bob")

    assert queued.status_code == 200
    messages = queued.json()["messages"]

    assert len(messages) == 1
    assert messages[0]["sender_id"] == "alice"
    assert messages[0]["recipient_id"] == "bob"
    assert messages[0]["message_id"] == "test-message-001"
    assert messages[0]["ciphertext"] == "encoded-encrypted-message"


def test_retrieval_removes_message_from_queue():
    reset_relay()

    response = client.post(
        "/messages",
        json=make_envelope(
            message_id="test-message-002",
            ciphertext="encrypted-data",
        ),
    )
    assert response.status_code == 202

    first = client.get("/messages/bob")
    second = client.get("/messages/bob")

    assert len(first.json()["messages"]) == 1
    assert len(second.json()["messages"]) == 0


def test_sender_cannot_send_to_themselves():
    reset_relay()

    response = client.post(
        "/messages",
        json=make_envelope(
            message_id="test-message-003",
            sender_id="alice",
            recipient_id="alice",
        ),
    )

    assert response.status_code == 400


def test_duplicate_message_id_is_rejected():
    reset_relay()
    envelope = make_envelope(message_id="duplicate-test-id")

    first = client.post("/messages", json=envelope)
    second = client.post("/messages", json=envelope)

    assert first.status_code == 202
    assert second.status_code == 409

    queued = client.get("/messages/bob")
    assert len(queued.json()["messages"]) == 1
