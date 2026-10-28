
import base64
import httpx

from src.main import Message, send_message, receive_message

from threading import Lock

_received_message_ids: set[tuple[str, str]] = set()
_received_lock = Lock()

def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid Base64 data in message envelope") from exc


def send_via_relay(
    http_client,
    sender_id: str,
    recipient_id: str,
    prekey_id: str,
    recipient_public_key: bytes,
    sender_signing_secret_key: bytes,
    plaintext: str,
) -> str:
    message = send_message(
        recipient_public_key,
        sender_signing_secret_key,
        plaintext,
        sender_id=sender_id,
        recipient_id=recipient_id,
        prekey_id=prekey_id,
    )

    envelope = {
        "sender_id": message.sender_id,
        "recipient_id": message.recipient_id,
        "prekey_id": message.prekey_id,
        "message_id": message.message_id,
        "kem_ciphertext": _encode(message.kem_ciphertext),
        "nonce": _encode(message.nonce),
        "ciphertext": _encode(message.ciphertext),
        "signature": _encode(message.signature),
    }

    response = http_client.post("/messages", json=envelope)
    response.raise_for_status()

    return response.json()["message_id"]


def receive_from_relay(
    http_client,
    recipient_id: str,
    recipient_secret_key: bytes,
    trusted_sender_signing_public_key: bytes,
) -> list[dict]:
    response = http_client.get(f"/messages/{recipient_id}")
    response.raise_for_status()

    results = []

    for envelope in response.json()["messages"]:
        
        replay_key = (recipient_id, envelope["message_id"])

        with _received_lock:
            if replay_key in _received_message_ids:
                raise ValueError("Replay detected: message already received")


        # Reject messages addressed to another recipient.
        if envelope["recipient_id"] != recipient_id:
            raise ValueError("Message recipient mismatch")

        message = Message(
            sender_id=envelope["sender_id"],
            recipient_id=envelope["recipient_id"],
            prekey_id=envelope["prekey_id"],
            message_id=envelope["message_id"],
            kem_ciphertext=_decode(envelope["kem_ciphertext"]),
            nonce=_decode(envelope["nonce"]),
            ciphertext=_decode(envelope["ciphertext"]),
            signature=_decode(envelope["signature"]),
        )

        plaintext = receive_message(
            recipient_secret_key,
            trusted_sender_signing_public_key,
            message,
        )

        with _received_lock:
            if replay_key in _received_message_ids:
                raise ValueError("Replay detected: message already received")

            _received_message_ids.add(replay_key)

        results.append({
            "message_id": message.message_id,
            "sender_id": message.sender_id,
            "plaintext": plaintext,
        })

    return results


def main():
    from src.main import generate_bob_keys, generate_alice_signing_keys

    bob_public_key, bob_secret_key = generate_bob_keys()
    alice_public_key, alice_secret_key = generate_alice_signing_keys()

    with httpx.Client(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        message_id = send_via_relay(
            client,
            sender_id="alice",
            recipient_id="bob",
            prekey_id="demo-prekey",
            recipient_public_key=bob_public_key,
            sender_signing_secret_key=alice_secret_key,
            plaintext="Hello Bob through the relay!",
        )

        print(f"Sent message: {message_id}")

        received = receive_from_relay(
            client,
            recipient_id="bob",
            recipient_secret_key=bob_secret_key,
            trusted_sender_signing_public_key=alice_public_key,
        )

        for item in received:
            print(f"From {item['sender_id']}: {item['plaintext']}")


if __name__ == "__main__":
    main()
