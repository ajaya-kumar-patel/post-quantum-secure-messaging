
from collections import defaultdict
from threading import Lock

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(
    title="PQSM Relay",
    description="Prototype relay for encrypted message envelopes",
    version="0.2.0",
)

_inboxes: dict[str, list[dict]] = defaultdict(list)
_seen_message_ids: set[str] = set()
_lock = Lock()


class EncryptedEnvelope(BaseModel):
    sender_id: str = Field(min_length=1, max_length=128)
    recipient_id: str = Field(min_length=1, max_length=128)
    prekey_id: str = Field(min_length=1, max_length=128)
    message_id: str = Field(min_length=1, max_length=128)
    kem_ciphertext: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    ciphertext: str = Field(min_length=1)
    signature: str = Field(min_length=1)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/messages", status_code=202)
def submit_message(envelope: EncryptedEnvelope):
    if envelope.sender_id == envelope.recipient_id:
        raise HTTPException(
            status_code=400,
            detail="Sender and recipient must be different",
        )

    message = envelope.model_dump()

    with _lock:
        if envelope.message_id in _seen_message_ids:
            raise HTTPException(
                status_code=409,
                detail="Duplicate message ID",
            )

        _seen_message_ids.add(envelope.message_id)
        _inboxes[envelope.recipient_id].append(message)

    return {
        "status": "accepted",
        "message_id": envelope.message_id,
    }


@app.get("/messages/{recipient_id}")
def get_messages(recipient_id: str):
    with _lock:
        messages = _inboxes.pop(recipient_id, [])

    return {"messages": messages}
