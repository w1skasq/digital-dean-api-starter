"""Самодостатня демонстрація RSA-OAEP; не розв'язок експерименту."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def demonstrate() -> tuple[bool, int, int]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    oaep = padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(), label=b"digital-dean:practice-03",
    )
    message = b"synthetic-dean-record"
    ciphertext = private.public_key().encrypt(message, oaep)
    recovered = private.decrypt(ciphertext, oaep)
    max_bytes = private.key_size // 8 - 2 * hashes.SHA256().digest_size - 2
    return recovered == message, len(ciphertext), max_bytes


if __name__ == "__main__":
    ok, length, limit = demonstrate()
    print({"roundtrip_ok": ok, "ciphertext_bytes": length, "max_bytes": limit})
