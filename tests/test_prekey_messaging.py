
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from src.prekeys import (
    create_identity_keys,
    create_signed_prekey_bundle,
    verify_signed_prekey_bundle,
)
from src.main import derive_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def test_message_uses_verified_prekey():
    # Bob creates an identity and publishes a signed prekey.
    bob_identity_public, bob_identity_secret = create_identity_keys()

    bundle, bob_prekey_secret = create_signed_prekey_bundle(
        user_id="bob",
        prekey_id="prekey-001",
        identity_secret_key=bob_identity_secret,
    )

    # Alice verifies Bob's bundle using a trusted identity key.
    assert verify_signed_prekey_bundle(
        bundle,
        bob_identity_public,
    )

    # Alice encapsulates to the verified KEM public key.
    kem_ciphertext, alice_shared_secret = ml_kem_768.encaps(
        bundle.kem_public_key
    )

    # Bob decapsulates with the matching private key.
    bob_shared_secret = ml_kem_768.decaps(
        bob_prekey_secret,
        kem_ciphertext,
    )

    assert alice_shared_secret == bob_shared_secret

    # Alice encrypts a message using the shared secret.
    key = derive_key(alice_shared_secret)
    nonce = os.urandom(12)
    aad = b"PQSM-demo-v1"
    plaintext = b"Hello Bob, verified prekey!"

    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    # Bob derives the same key and decrypts.
    bob_key = derive_key(bob_shared_secret)
    recovered = AESGCM(bob_key).decrypt(nonce, ciphertext, aad)

    assert recovered == plaintext
