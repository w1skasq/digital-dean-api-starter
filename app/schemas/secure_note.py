"""Моделі API відокремлені від внутрішнього криптографічного конверта."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

Algorithm = Literal["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"]


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=4096)

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        """TODO: 1–4096 байтів UTF-8, не лише пробіли; не обрізати текст."""
        raise NotImplementedError("Implement nonblank UTF-8 byte length validation")


class NoteMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    student_id: UUID
    algorithm: Algorithm


class NoteRead(NoteMetadata):
    text: str


# TODO: виконайте індивідуальний варіант, зберігаючи базові правила.
