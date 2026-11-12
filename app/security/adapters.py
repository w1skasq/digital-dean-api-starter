"""Спільний контракт для cryptography та PyCryptodome без відкритого fallback."""


class CiphertextError(Exception):
    """Повідомлення не пройшло перевірку автентичності."""


def seal_bytes(backend, algorithm, key, nonce, data, aad):
    """TODO: повернути (ciphertext, tag); перевірити профіль і бібліотеку."""
    raise NotImplementedError("Implement both authenticated encryption adapters")


def open_bytes(backend, algorithm, key, nonce, ct, tag, aad):
    """TODO: видати байти тільки після успішної перевірки повного тега."""
    raise NotImplementedError("Implement verified decryption; never return ct")
