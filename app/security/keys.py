"""Матеріал ключа створюють один раз під час запуску процесу API."""

from dataclasses import dataclass, field
from secrets import token_bytes
from uuid import UUID, uuid4

from app.security.nonce import NonceSequence


@dataclass(frozen=True)
class ProcessKey:
    key_id: UUID
    key: bytes = field(repr=False)
    nonces: NonceSequence = field(repr=False)


def create_process_key(limit: int = 1_000_000) -> ProcessKey:
    """Викликайте при запуску, а не при кожному запиті чи читанні примітки."""
    return ProcessKey(uuid4(), token_bytes(32), NonceSequence(limit))


_process_key: ProcessKey = create_process_key()


def get_process_key() -> ProcessKey:
    """Повертає активний ключ процесу."""
    return _process_key


def reset_process_key(limit: int = 1_000_000) -> ProcessKey:
    """Скидає ключ процесу (використовується лише у тестових фікстурах)."""
    global _process_key
    _process_key = create_process_key(limit=limit)
    return _process_key