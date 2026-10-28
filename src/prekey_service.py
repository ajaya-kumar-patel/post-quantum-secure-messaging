
from datetime import timedelta

from src.prekeys import (
    SignedPreKeyBundle,
    create_signed_prekey_bundle,
    verify_signed_prekey_bundle,
)
from src.prekey_store import PreKeyStore


class PreKeyService:
    """Coordinates signed prekey publication and one-time consumption."""

    def __init__(self):
        self.store = PreKeyStore()
        self._bundles: dict[tuple[str, str], SignedPreKeyBundle] = {}
        self._kem_secret_keys: dict[tuple[str, str], bytes] = {}

    def register_prekey(
        self,
        user_id: str,
        prekey_id: str,
        identity_secret_key: bytes,
        lifetime: timedelta = timedelta(hours=24),
    ) -> SignedPreKeyBundle:
        key = (user_id, prekey_id)

        # Create the bundle and private key before publishing.
        bundle, kem_secret_key = create_signed_prekey_bundle(
            user_id,
            prekey_id,
            identity_secret_key,
        )

        # Store metadata and private key separately from the public bundle.
        self.store.add(user_id, prekey_id, lifetime)

        self._bundles[key] = bundle
        self._kem_secret_keys[key] = kem_secret_key
        return bundle

    def get_bundle(
        self,
        user_id: str,
        prekey_id: str,
    ) -> SignedPreKeyBundle:
        key = (user_id, prekey_id)

        if self.store.status(user_id, prekey_id) != "available":
            raise ValueError("Prekey is unavailable")

        bundle = self._bundles.get(key)
        if bundle is None:
            raise ValueError("Prekey bundle not found")

        return bundle

    def verify_bundle(
        self,
        bundle: SignedPreKeyBundle,
        trusted_identity_public_key: bytes,
    ) -> bool:
        return verify_signed_prekey_bundle(
            bundle,
            trusted_identity_public_key,
        )

    def consume_prekey(
        self,
        user_id: str,
        prekey_id: str,
    ) -> bytes:
        key = (user_id, prekey_id)

        # Lock-protected consumption prevents two callers from
        # successfully consuming the same prekey.
        if not self.store.consume(user_id, prekey_id):
            raise ValueError("Prekey is expired, missing, or already consumed")

        secret_key = self._kem_secret_keys.pop(key, None)
        self._bundles.pop(key, None)

        if secret_key is None:
            raise ValueError("Prekey secret key not found")

        return secret_key
