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


# TODO: збережіть один ProcessKey у стані застосунку/його залежностях.
# TODO: маршрути запису й читання використовують цей самий матеріал ключа.
# Не зберігайте ключ у репозиторії приміток, файлі, JSON чи Git.
