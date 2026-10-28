
from dataclasses import dataclass
import struct

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65


PROTOCOL_INFO = b"PQSM-demo-v1"
PREKEY_DOMAIN = b"PQSM-signed-prekey-v1"


@dataclass(frozen=True)
class SignedPreKeyBundle:
    user_id: str
    prekey_id: str
    kem_public_key: bytes
    signature: bytes


def _length_prefixed(value: bytes) -> bytes:
    """Encode bytes with a 4-byte length prefix."""
    return struct.pack(">I", len(value)) + value


def _prekey_signed_data(
    user_id: str,
    prekey_id: str,
    kem_public_key: bytes,
) -> bytes:
    """Create an unambiguous, domain-separated signed payload."""
    return (
        _length_prefixed(PREKEY_DOMAIN)
        + _length_prefixed(PROTOCOL_INFO)
        + _length_prefixed(user_id.encode("utf-8"))
        + _length_prefixed(prekey_id.encode("utf-8"))
        + _length_prefixed(kem_public_key)
    )


def create_identity_keys():
    """Create the user's long-term ML-DSA identity signing keys."""
    return ml_dsa_65.keygen()


def create_signed_prekey_bundle(
    user_id: str,
    prekey_id: str,
    identity_secret_key: bytes,
) -> tuple[SignedPreKeyBundle, bytes]:
    """
    Generate a fresh ML-KEM key pair and sign its public key
    using the user's identity signing key.

    Returns:
        (signed_bundle, kem_secret_key)

    Keep the secret key private. Do not publish it with the bundle.
    """
    if not user_id or not prekey_id:
        raise ValueError("user_id and prekey_id must not be empty")

    kem_public_key, kem_secret_key = ml_kem_768.keygen()

    signed_data = _prekey_signed_data(
        user_id,
        prekey_id,
        kem_public_key,
    )
    signature = ml_dsa_65.sign(identity_secret_key, signed_data)

    bundle = SignedPreKeyBundle(
        user_id=user_id,
        prekey_id=prekey_id,
        kem_public_key=kem_public_key,
        signature=signature,
    )

    return bundle, kem_secret_key


def verify_signed_prekey_bundle(
    bundle: SignedPreKeyBundle,
    trusted_identity_public_key: bytes,
) -> bool:
    """
    Verify the bundle using an identity public key already
    trusted by the recipient.

    The identity public key must be authenticated separately,
    such as by comparing a fingerprint with Bob through a
    trusted channel.
    """
    signed_data = _prekey_signed_data(
        bundle.user_id,
        bundle.prekey_id,
        bundle.kem_public_key,
    )

    try:
        result = ml_dsa_65.verify(
            trusted_identity_public_key,
            signed_data,
            bundle.signature,
        )
    except Exception as exc:
        raise ValueError("Invalid signed prekey bundle") from exc

    # Some library versions return None on success and raise
    # on failure; others may return a boolean.
    if result is False:
        raise ValueError("Invalid signed prekey bundle")

    return True
