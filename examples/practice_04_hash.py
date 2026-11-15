"""Працездатний початковий приклад. Дані публічні й синтетичні."""
import hashlib

payload = "Синтетична відомість Цифрового деканату".encode("utf-8")
whole = hashlib.sha256(payload).digest()
stream = hashlib.sha256()
for offset in range(0, len(payload), 16):
    stream.update(payload[offset:offset + 16])
assert whole == stream.digest()
assert len(whole) == 32
print({"algorithm": "sha256", "digest_bytes": len(whole),
       "whole_equals_chunked": True, "hex": whole.hex()})
