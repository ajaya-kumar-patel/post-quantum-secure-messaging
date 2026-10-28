
import os
import struct
from dataclasses import dataclass
from uuid import uuid4

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL_INFO = b"PQSM-demo-v1"
MESSAGE_DOMAIN = b"PQSM-message-v1"


@dataclass
class Message:
    sender_id: str
    recipient_id: str
    prekey_id: str
    message_id: str
    kem_ciphertext: bytes
    nonce: bytes
    ciphertext: bytes
    signature: bytes


def _pack(data: bytes) -> bytes:
    """Length-prefix data to prevent ambiguous serialization."""
    return struct.pack(">I", len(data)) + data


def _signed_data(
    sender_id: str,
    recipient_id: str,
    prekey_id: str,
    message_id: str,
    kem_ciphertext: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    fields = [
        sender_id.encode("utf-8"),
        recipient_id.encode("utf-8"),
        prekey_id.encode("utf-8"),
        message_id.encode("utf-8"),
        kem_ciphertext,
        nonce,
        ciphertext,
    ]

    return MESSAGE_DOMAIN + b"".join(_pack(field) for field in fields)


def derive_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=PROTOCOL_INFO,
    ).derive(shared_secret)


def generate_bob_keys():
    """Generate Bob's ML-KEM-768 public and private keys."""
    return ml_kem_768.keygen()


def generate_alice_signing_keys():
    """Generate Alice's ML-DSA-65 signing key pair."""
    return ml_dsa_65.keygen()


def send_message(
    bob_public_key: bytes,
    alice_signing_secret_key: bytes,
    plaintext: str,
    *,
    sender_id: str = "alice",
    recipient_id: str = "bob",
    prekey_id: str = "demo-prekey",
    message_id: str | None = None,
) -> Message:
    if not sender_id or not recipient_id or not prekey_id:
        raise ValueError("Sender, recipient and prekey IDs are required")

    if sender_id == recipient_id:
        raise ValueError("Sender and recipient must be different")

    if message_id is None:
        message_id = str(uuid4())

    if not message_id:
        raise ValueError("Message ID is required")

    # Establish a shared secret using Bob's public KEM key.
    kem_ciphertext, shared_secret = ml_kem_768.encaps(bob_public_key)

    # Derive an AES-256 key and encrypt the plaintext.
    aes_key = derive_key(shared_secret)
    nonce = os.urandom(12)

    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        PROTOCOL_INFO,
    )

    # Sign both the encrypted payload and its message context.
    data = _signed_data(
        sender_id,
        recipient_id,
        prekey_id,
        message_id,
        kem_ciphertext,
        nonce,
        ciphertext,
    )

    signature = ml_dsa_65.sign(alice_signing_secret_key, data)

    return Message(
        sender_id=sender_id,
        recipient_id=recipient_id,
        prekey_id=prekey_id,
        message_id=message_id,
        kem_ciphertext=kem_ciphertext,
        nonce=nonce,
        ciphertext=ciphertext,
        signature=signature,
    )


def receive_message(
    bob_secret_key: bytes,
    alice_signing_public_key: bytes,
    message: Message,
) -> str:
    if not message.sender_id or not message.recipient_id:
        raise ValueError("Missing sender or recipient ID")

    if not message.prekey_id or not message.message_id:
        raise ValueError("Missing prekey or message ID")

    data = _signed_data(
        message.sender_id,
        message.recipient_id,
        message.prekey_id,
        message.message_id,
        message.kem_ciphertext,
        message.nonce,
        message.ciphertext,
    )

    # Verify the sender before attempting decryption.
    try:
        result = ml_dsa_65.verify(
            alice_signing_public_key,
            data,
            message.signature,
        )
        if result is False:
            raise ValueError("Invalid signature")
    except Exception as exc:
        raise ValueError("Invalid signature: message rejected") from exc

    # Recover the shared secret and decrypt the message.
    shared_secret = ml_kem_768.decaps(
        bob_secret_key,
        message.kem_ciphertext,
    )
    aes_key = derive_key(shared_secret)

    try:
        plaintext = AESGCM(aes_key).decrypt(
            message.nonce,
            message.ciphertext,
            PROTOCOL_INFO,
        )
    except Exception as exc:
        raise ValueError("Message decryption failed") from exc

    return plaintext.decode("utf-8")


def main():
    bob_public_key, bob_secret_key = generate_bob_keys()
    alice_public_key, alice_secret_key = generate_alice_signing_keys()

    message = send_message(
        bob_public_key,
        alice_secret_key,
        "Hello Bob!",
        sender_id="alice",
        recipient_id="bob",
        prekey_id="demo-prekey",
    )

    plaintext = receive_message(
        bob_secret_key,
        alice_public_key,
        message,
    )

    print("Encrypted message created successfully.")
    print(f"Message ID: {message.message_id}")
    print(f"Decrypted plaintext: {plaintext}")


if __name__ == "__main__":
    main()
