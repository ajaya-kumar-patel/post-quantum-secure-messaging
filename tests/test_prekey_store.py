
from datetime import timedelta

import pytest

from src.prekey_store import PreKeyStore


def test_prekey_can_only_be_consumed_once():
    store = PreKeyStore()
    store.add("bob", "prekey-001")

    assert store.status("bob", "prekey-001") == "available"
    assert store.consume("bob", "prekey-001") is True
    assert store.status("bob", "prekey-001") == "consumed"
    assert store.consume("bob", "prekey-001") is False


def test_expired_prekey_cannot_be_consumed():
    store = PreKeyStore()
    store.add("bob", "prekey-expired", lifetime=timedelta(microseconds=-1))

    assert store.status("bob", "prekey-expired") == "expired"
    assert store.consume("bob", "prekey-expired") is False


def test_duplicate_prekey_id_is_rejected():
    store = PreKeyStore()
    store.add("bob", "prekey-001")

    with pytest.raises(ValueError, match="already exists"):
        store.add("bob", "prekey-001")


def test_unknown_prekey_cannot_be_consumed():
    store = PreKeyStore()

    assert store.status("bob", "missing") == "unknown"
    assert store.consume("bob", "missing") is False
