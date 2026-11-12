"""Сховище зберігає конверт, не відкритий текст і не ключ."""

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class EncryptedNote:
    version: int
    student_id: UUID
    note_id: UUID
    algorithm: str
    backend: str
    key_id: UUID
    nonce: bytes
    ciphertext: bytes
    tag: bytes


class SecureNoteRepository:
    def __init__(self):
        self._items: dict[UUID, EncryptedNote] = {}

    def add(self, note: EncryptedNote) -> None:
        """TODO: зберегти коректний конверт без дублювання note_id."""
        raise NotImplementedError("Implement encrypted note storage")

    def get(self, student_id: UUID, note_id: UUID) -> EncryptedNote:
        """TODO: перевірити належність ресурсу; невідомий запис дає KeyError."""
        raise NotImplementedError("Implement resource-scoped lookup")

    def clear(self) -> None:
        """Очищення записів не змінює ключ і не скидає його лічильник."""
        self._items.clear()


repository = SecureNoteRepository()

# TODO: додайте операції свого індивідуального варіанта.
# Підміна _items допустима лише в тестах, не через окремий HTTP-маршрут.
