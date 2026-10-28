
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from threading import Lock


@dataclass
class StoredPreKey:
    user_id: str
    prekey_id: str
    expires_at: datetime
    consumed: bool = False


class PreKeyStore:
    """In-memory prototype store for one-time prekey metadata."""

    def __init__(self):
        self._prekeys: dict[tuple[str, str], StoredPreKey] = {}
        self._lock = Lock()

    def add(
        self,
        user_id: str,
        prekey_id: str,
        lifetime: timedelta = timedelta(hours=24),
    ) -> None:
        if not user_id or not prekey_id:
            raise ValueError("user_id and prekey_id must not be empty")

        key = (user_id, prekey_id)
        record = StoredPreKey(
            user_id=user_id,
            prekey_id=prekey_id,
            expires_at=datetime.now(timezone.utc) + lifetime,
        )

        with self._lock:
            if key in self._prekeys:
                raise ValueError("Prekey ID already exists")
            self._prekeys[key] = record

    def consume(self, user_id: str, prekey_id: str) -> bool:
        """Atomically consume an unexpired, unused prekey."""
        key = (user_id, prekey_id)

        with self._lock:
            record = self._prekeys.get(key)

            if record is None or record.consumed:
                return False

            if datetime.now(timezone.utc) >= record.expires_at:
                return False

            record.consumed = True
            return True

    def status(self, user_id: str, prekey_id: str) -> str:
        with self._lock:
            record = self._prekeys.get((user_id, prekey_id))

            if record is None:
                return "unknown"
            if record.consumed:
                return "consumed"
            if datetime.now(timezone.utc) >= record.expires_at:
                return "expired"
            return "available"
