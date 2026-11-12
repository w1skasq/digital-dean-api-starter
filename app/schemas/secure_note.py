"""Моделі API відокремлені від внутрішнього криптографічного конверта."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

Algorithm = Literal["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"]


def _validate_note_text(value: str) -> str:
    if not value.strip():
        raise ValueError("Empty note")
    if len(value.encode("utf-8")) > 4096:
        raise ValueError("Note exceeds 4096 bytes")
    return value


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=4096)

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        """1–4096 байтів UTF-8, не лише пробіли; не обрізати текст."""
        return _validate_note_text(value)


class NoteUpdate(BaseModel):
    """Індивідуальний варіант 0: оновлення тексту примітки через PATCH."""

    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=4096)

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _validate_note_text(value)


class NoteMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    student_id: UUID
    algorithm: Algorithm


class NoteRead(NoteMetadata):
    text: str