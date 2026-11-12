"""Один лічильник на ключ; захист потоків не координує різні процеси."""

from threading import Lock


class NonceSequence:
    def __init__(self, limit: int = 1_000_000):
        if type(limit) is not int or not 1 <= limit <= 1_000_000:
            raise ValueError("Invalid teaching key usage limit")
        self._value = 0
        self._limit = limit
        self._lock = Lock()

    def next(self) -> bytes:
        """Під Lock зарезервувати нові 12 байтів або підняти RuntimeError."""
        with self._lock:
            if self._value >= self._limit:
                raise RuntimeError("Key usage limit reached")
            result = self._value.to_bytes(12, "big")
            self._value += 1
            return result