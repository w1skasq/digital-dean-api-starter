# Практична робота 3 — асиметричне та гібридне шифрування

Це доповнення до **власного завершеного API практичної 2**, а не готовий розв'язок. Файли практичних 1 і 2 не замінено. Інструкція та критерії оцінювання наведені у DOCX практичної 3.

## Імпорт без втрати попередніх змін

Працюйте у тому самому локальному клоні власного форку. `origin` має вказувати на ваш форк, `upstream` — на `https://github.com/serhii-ch-eu/digital-dean-api-starter.git`. Перед імпортом завершена робота 2 повинна мати тег `practice-02`, чистий робочий каталог і працездатні тести.

```bash
git status --short
git remote -v
git fetch upstream
git switch -c practice-03 practice-02
git merge --no-ff upstream/practice-03-starter -m "Import practice 3 scaffold"
git tag -a practice-03-base -m "Practice 3 imported baseline"
python -m pip install -e ".[dev]"
python -m pip install -r requirements-practice-02.txt
python -m pip install -r requirements-practice-03.txt
python examples/practice_03_rsa.py
```

Якщо `upstream` відсутній, додайте його один раз. Не використовуйте `reset`, `--allow-unrelated-histories` або копіювання всього застосунку. За конфлікту збережіть власну реалізацію практичної 2, інтегруйте тільки нові файли і повторіть попередні тести.

## Що реалізувати

- П'ять профілів у `app/security/asymmetric/profiles.py`: прямі RSA-OAEP 2048/3072; навчальна RSA-3072-OAEP + AES-256-GCM; HPKE Base X25519 та P-256 із HKDF-SHA256 і AES-256-GCM.
- Функції `generate_keypair`, `encrypt`, `decrypt` у `adapters.py`. Використовуйте тільки бібліотечні криптографічні операції. RSA застосовує SHA-256 в OAEP і MGF1; гібридна схема створює нові 32-байтовий ключ і 12-байтовий nonce для кожного повідомлення. HPKE використовує `cryptography.hazmat.primitives.hpke.Suite`.
- Семантичну перевірку звіту `validate_complete_report`: точне покриття профілів, розмірів і операцій, відсутність дублікатів, узгоджені розміри, пропускна здатність та 22 перевірки коректності.
- Окремий вимірювальний запуск `python -m benchmarks.asymmetric_benchmark`. П'ять серій по 20 операцій після 10 прогрівальних операцій; п'ять незалежних вимірювань генерації кожного типу ключа. Медіана та IQR за `quantiles(..., method="inclusive")`.
- Зареєструйте **новий** `GET /api/v1/lab/crypto/asymmetric-benchmark-results` з моделлю відповіді та підключіть маршрутизатор до наявного `app/main.py`. Він читає збережений JSON, не запускає експеримент.
- Для фільтру `payload_bytes` приймайте `int` і явно перевіряйте перелік 64/1024/65536/1048576; за іншого значення повертайте 422. Для `profile` і `operation` підходить рядковий `Literal`. Повний файл спочатку перевіряє `BenchmarkReport`, а фільтровану відповідь — `BenchmarkResponse`.
- Виконайте індивідуальний варіант і додайте свої тести. Початкові тести з TODO мають не проходити; їх потрібно задовольнити реалізацією, а не видаленням, `skip` або `xfail`.

## Запуск і дані

```bash
python -m benchmarks.asymmetric_benchmark
python -m pytest
python -m uvicorn app.main:app --reload
```

`results/practice-03/report.json` і `raw.csv` створює ваша реалізація. Готового звіту з числами у гілці немає. HTTP: 200 валідний звіт; 404 відсутній; 500 некоректний із безпечним повідомленням; 422 некоректний параметр вашого варіанта. Шлях файлу задається тільки сервером. У звіт не потрапляють приватні ключі, відкриті тексти, шифротексти, токени, імена користувачів або локальні шляхи. Використовуйте лише синтетичні дані та локальний сервер.

## Версіонування

Після `practice-03-base` створіть щонайменше чотири **власні змістові комміти**: криптографічні адаптери; експеримент і схема; API та варіант; тести й документація. Імпорт і викладацькі комміти не зараховуються. Оновіть версію цього самого застосунку до `0.3.0`, не створюйте другий API.

```bash
git log --oneline practice-03-base..HEAD
git merge-base --is-ancestor practice-02 HEAD
git push -u origin practice-03
git tag -a practice-03 -m "Practice 3 verified result"
git push origin tag practice-03-base
git push origin tag practice-03
```

Подайте власний форк/гілку/тег, результати тестів і Postman, сирий CSV, JSON, не менше двох графіків та звіт за шаблоном `docs/practice-03-report-template.md`. Не публікуйте ключі або персональні дані.
