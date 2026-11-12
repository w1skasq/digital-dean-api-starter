# Результати власного експерименту

Після реалізації `python -m benchmarks.asymmetric_benchmark` створює тут `raw.csv` і `report.json`. Готових числових результатів у стартовій гілці немає.

CSV: `group,profile,operation,payload_bytes,series_index,operations,elapsed_ns,ns_per_operation,ciphertext_bytes`.

Для `key_generation`: `profile` дорівнює `rsa-2048`, `rsa-3072`, `x25519` або `p256`; `operation=keygen`, `payload_bytes=0`, `operations=1`, `ciphertext_bytes=0`. П'ять незалежних рядків на профіль, `series_index=1..5`. Для шифрування/розшифрування — п'ять рядків на кожну комбінацію, `operations=20`. Усього 130 рядків даних, без заголовка.

JSON базового звіту: `schema_version`, `experiment`, `environment`, `key_generation` (4), `results` (22), `checks` (22). Точні поля визначає `app/schemas/asymmetric_report.py`. Типи чисел мають бути скінченними; час додатний; IQR невід'ємний. Генерація ключа вимірюється окремо, а його відкритий DER/SPKI розмір — поза таймером.

`ciphertext_bytes` — розмір сирого двійкового результату, не JSON/Base64. RSA: 256/384 байти; RSA/AES: S+412; HPKE X25519: S+48; HPKE P-256: S+81. Пропускна здатність MiB/s тільки для гібридних результатів: S * 1e9 / (2**20 * median_ns); для прямих RSA — null.

`checks`: чотири перевірки для кожного з п'яти профілів (`roundtrip`, `wrong_key`, `tamper`, `wrong_context`) і `oaep_boundary` для двох прямих RSA. `passed=false` потрібно зберегти як факт невдалої перевірки, а не замінити на true.

Зберігайте версії Python, cryptography 48.0.1, OpenSSL саме цієї бібліотеки, ОС, модель процесора, UTC час та Git SHA коду на момент запуску. Не зберігайте ім'я хоста, користувача, локальні шляхи, ключі, вхідні повідомлення чи шифротексти. Числові результати не є доказом криптографічної стійкості.
