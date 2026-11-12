"""Маршрути захищених службових приміток (включно з варіантом 0 — PATCH)."""

from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status

from app.repositories.secure_note_repository import (
    EncryptedNote,
    repository as note_repository,
)
from app.repositories.student_repository import (
    StudentNotFoundError,
    student_repository,
)
from app.schemas.secure_note import (
    NoteCreate,
    NoteMetadata,
    NoteRead,
    NoteUpdate,
)
from app.security.adapters import CiphertextError, open_bytes, seal_bytes
from app.security.context import note_aad
from app.security.keys import get_process_key
from app.security.profiles import BACKENDS, KEY_BYTES, NONCE_BYTES, TAG_BYTES

router = APIRouter(prefix="/api/v1/students", tags=["secure-notes"])

DEFAULT_ALGORITHM = "AES-256-GCM"
DEFAULT_BACKEND = "cryptography"
UNAVAILABLE_DETAIL = "Protected note unavailable"


def _ensure_student_exists(student_id: UUID) -> None:
    try:
        student_repository.get(student_id)
    except StudentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Student not found",
        ) from exc


def _decrypt_note(student_id: UUID, note_id: UUID, envelope: EncryptedNote) -> str:
    process_key = get_process_key()
    if (
        envelope.version != 1
        or envelope.student_id != student_id
        or envelope.note_id != note_id
        or envelope.algorithm not in KEY_BYTES
        or envelope.backend not in BACKENDS
        or envelope.key_id != process_key.key_id
        or not isinstance(envelope.nonce, bytes)
        or len(envelope.nonce) != NONCE_BYTES
        or not isinstance(envelope.ciphertext, bytes)
        or not isinstance(envelope.tag, bytes)
        or len(envelope.tag) != TAG_BYTES
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=UNAVAILABLE_DETAIL,
        )

    aad = note_aad(
        student_id=student_id,
        note_id=note_id,
        algorithm=envelope.algorithm,
        key_id=process_key.key_id,
    )
    try:
        plaintext_bytes = open_bytes(
            backend=envelope.backend,
            algorithm=envelope.algorithm,
            key=process_key.key,
            nonce=envelope.nonce,
            ct=envelope.ciphertext,
            tag=envelope.tag,
            aad=aad,
        )
        return plaintext_bytes.decode("utf-8")
    except (CiphertextError, ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=UNAVAILABLE_DETAIL,
        ) from exc


@router.post(
    "/{student_id}/secure-notes",
    response_model=NoteMetadata,
    status_code=status.HTTP_201_CREATED,
)
def create_secure_note(student_id: UUID, payload: NoteCreate) -> NoteMetadata:
    _ensure_student_exists(student_id)
    process_key = get_process_key()
    try:
        nonce = process_key.nonces.next()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=UNAVAILABLE_DETAIL,
        ) from exc

    note_id = uuid4()
    aad = note_aad(
        student_id=student_id,
        note_id=note_id,
        algorithm=DEFAULT_ALGORITHM,
        key_id=process_key.key_id,
    )
    ct, tag = seal_bytes(
        backend=DEFAULT_BACKEND,
        algorithm=DEFAULT_ALGORITHM,
        key=process_key.key,
        nonce=nonce,
        data=payload.text.encode("utf-8"),
        aad=aad,
    )
    envelope = EncryptedNote(
        version=1,
        student_id=student_id,
        note_id=note_id,
        algorithm=DEFAULT_ALGORITHM,
        backend=DEFAULT_BACKEND,
        key_id=process_key.key_id,
        nonce=nonce,
        ciphertext=ct,
        tag=tag,
    )
    note_repository.add(envelope)
    return NoteMetadata(
        id=note_id,
        student_id=student_id,
        algorithm=DEFAULT_ALGORITHM,
    )


@router.get(
    "/{student_id}/secure-notes/{note_id}",
    response_model=NoteRead,
    status_code=status.HTTP_200_OK,
)
def get_secure_note(student_id: UUID, note_id: UUID) -> NoteRead:
    _ensure_student_exists(student_id)
    try:
        envelope = note_repository.get(student_id, note_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found",
        ) from exc

    text = _decrypt_note(student_id, note_id, envelope)
    return NoteRead(
        id=note_id,
        student_id=student_id,
        algorithm=envelope.algorithm,  # type: ignore[arg-type]
        text=text,
    )


@router.patch(
    "/{student_id}/secure-notes/{note_id}",
    response_model=NoteRead,
    status_code=status.HTTP_200_OK,
)
def update_secure_note(
    student_id: UUID, note_id: UUID, payload: NoteUpdate
) -> NoteRead:
    """Індивідуальний варіант 0: оновлення тексту із резервуванням нового nonce."""
    _ensure_student_exists(student_id)
    try:
        existing = note_repository.get(student_id, note_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found",
        ) from exc

    _decrypt_note(student_id, note_id, existing)

    process_key = get_process_key()
    try:
        new_nonce = process_key.nonces.next()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=UNAVAILABLE_DETAIL,
        ) from exc

    aad = note_aad(
        student_id=student_id,
        note_id=note_id,
        algorithm=existing.algorithm,
        key_id=process_key.key_id,
    )
    ct, tag = seal_bytes(
        backend=existing.backend,
        algorithm=existing.algorithm,
        key=process_key.key,
        nonce=new_nonce,
        data=payload.text.encode("utf-8"),
        aad=aad,
    )
    updated_envelope = EncryptedNote(
        version=1,
        student_id=student_id,
        note_id=note_id,
        algorithm=existing.algorithm,
        backend=existing.backend,
        key_id=process_key.key_id,
        nonce=new_nonce,
        ciphertext=ct,
        tag=tag,
    )
    note_repository.replace(updated_envelope)
    return NoteRead(
        id=note_id,
        student_id=student_id,
        algorithm=existing.algorithm,  # type: ignore[arg-type]
        text=payload.text,
    )