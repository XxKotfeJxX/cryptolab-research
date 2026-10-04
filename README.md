# Криптографічне дослідження — власні реалізації на C++

Початок етапу 5. Наразі реалізовано навчальні прототипи Цезаря, моноалфавітної заміни, Віженера та Гілла 3×3, спільний SHA-256 і власний графік частот SVG. Решта методів реєстру — заплановані, **не реалізовані**. Це навчальний код, а не засіб захисту секретів.

## Навігація дослідження

- **Дослідницьке питання:** як за визначеного сценарію використання змістовно порівняти криптографічні методи різних класів, поєднавши вимірювані витрати, вимоги та відомі гарантії? [Протокол дослідження](docs/research/research_protocol.md) визначає метод і межі висновків; [план](docs/research/plan_kryptohrafichnoho_doslidzhennia.md) описує етапи 0–12, [паспорт етапу 0](docs/research/etap_0_pasport.md) — організаційні правила, а [загальні вимоги](docs/research/zahalni_vymohy_do_naukovoi_roboty.md) — підготовку наукової роботи.
- [Реєстр методів](docs/research/etap_2_reiestr_shyfriv.md): 30 незмінних позицій і 27 карток, бо три пари позицій об'єднані в картки (№1+2, №7+15, №9+12). [Бібліографічна матриця](docs/research/etap_3_literatura_matrytsia.md) містить джерела й вектори для карток.
- [ТЗ етапу 5](docs/SPEC_STAGE5.md) і [зафіксовані рішення](DECISIONS.md).
- [Протокол корпусу](docs/research/etap_4_korpus_protokol.md), [картка перевірки](docs/corpus_stage4.md) та [незмінний ZIP-архів](etap_4_korpus.zip).
- [Стан 30 позицій](STATUS.md), профілі [Цезаря](docs/profiles/caesar.md), [заміни](docs/profiles/substitution.md), [Віженера](docs/profiles/vigenere.md), [Гілла](docs/profiles/hill.md) і [збірка та тести](#збірка).

## Збірка

Потрібен C++20. Без CMake і сторонніх бібліотек.

Linux/macOS (з кореня проєкту):

```sh
sh scripts/build_gcc.sh
./build/tests
python3 tests/test_cli.py ./build/cryptolab
python3 tests/test_corpus.py ./etap_4_korpus.zip ./build/cryptolab
python3 tests/test_docs_links.py
```

Windows, Developer Command Prompt for Visual Studio:

```bat
scripts\build_msvc.bat
build\tests.exe
python tests\test_cli.py build\cryptolab.exe
python tests\test_corpus.py etap_4_korpus.zip build\cryptolab.exe
python tests\test_docs_links.py
```

Windows, PowerShell із MinGW `g++` у `PATH`:

```powershell
.\scripts\build_mingw.ps1
.\build\tests.exe
python tests\test_cli.py build\cryptolab.exe
python tests\test_corpus.py etap_4_korpus.zip build\cryptolab.exe
python tests\test_docs_links.py
```

Інтеграційні тести потребують Python 3.11+; робочий C++ код його не використовує. Ті самі перевірки запускає [CI для Linux і Windows MSVC](.github/workflows/ci.yml).

Виклики CLI:

```sh
./build/cryptolab caesar encrypt --alphabet en --shift 3 --in input.txt --out result.txt --policy strict --steps 8 --chart chart.svg
./build/cryptolab caesar decrypt --alphabet uk --shift 5 --in cipher.txt --out plain.txt --policy strict
./build/cryptolab caesar encrypt --alphabet en --shift 13 --in input.txt --out result.txt --steps 8 --trace trace.txt
./build/cryptolab substitution encrypt --alphabet en --key-file key.txt --in input.txt --out result.txt --policy passthrough
./build/cryptolab vigenere encrypt --alphabet en --key-file key.txt --in input.txt --out result.txt
./build/cryptolab hill3 encrypt --alphabet en --key-file matrix.txt --in input.txt --out result.txt
./build/cryptolab sha256 hash --in input.bin --out digest.bin
```

`sha256 hash` записує рівно 32 сирі байти; алгоритм і константи реалізовані в `src/core/sha256.cpp` за [профілем](docs/profiles/sha256.md). Hex є окремим текстовим представленням, тому CLI не підмінює ним двійковий digest.

Для `substitution` ключовий файл містить рівно 26 або 33 унікальні літери обраної абетки без переведення рядка. Порядок літер задає повну перестановку. Повні правила та походження опублікованого англійського прикладу — у [профілі](docs/profiles/substitution.md).

Для `vigenere` ключовий файл містить непорожню послідовність літер обраної абетки без переведення рядка. Ключ циклічно повторюється за літерами вхідного тексту; сторонні символи в `passthrough` не зсувають його позицію. Опублікований вектор і межі описані у [профілі](docs/profiles/vigenere.md).

Для `hill3` ключовий файл містить 9 літер у порядку рядків матриці 3×3, наприклад `GYBNQKURP`. Матриця повинна бути оборотною modulo довжина абетки, а кількість літер входу — кратною трьом. Доповнення не виконується; [профіль](docs/profiles/hill.md) описує точний формат.

## Корпус етапу 4

Корпус зберігається у корені проєкту як `etap_4_korpus.zip`. Його `raw/*.txt` — збережені UTF-8-знімки тексту сторінок, а не оригінальні байти вебвідповідей. [Картка корпусу](docs/corpus_stage4.md) фіксує хеші, межі та спосіб перевірки. Архівний код не виконується, файли корпусу не розпаковуються у вихідні каталоги репозиторію.

```powershell
python scripts\corpus_stage4.py verify --archive .\etap_4_korpus.zip
python scripts\corpus_stage4.py run --archive .\etap_4_korpus.zip --artifact derived/en_austen_1342/letters_16_head.txt --cryptolab .\build\cryptolab.exe --out .\build\caesar_corpus.txt --journal .\build\corpus_runs.jsonl --public-test-key-id caesar-shift-3-demo -- caesar encrypt --alphabet en --shift 3
python tests\test_corpus.py .\etap_4_korpus.zip .\build\cryptolab.exe
```

`run` перевіряє маніфест перед запуском, використовує тимчасовий файл для одного артефакту та дописує до JSONL-журналу профіль, доступну Git-версію коду, SHA-256 входу й успішного виходу та несекретні параметри. У прикладі `caesar-shift-3-demo` позначає відкритий тестовий зсув 3; журнал зберігає лише цей ID, а не значення ключа чи його відбиток. `verify` і `run` потребують Python 3.11+; робоче шифрування залишається у C++.

`--steps N` показує перші N **зашифрованих літер** у консолі; `--steps all` — усі (на великому тексті буде величезний вивід). `--trace FILE` разом із `--steps` записує ті самі кроки у файл. Без `--steps` трасування вимкнено. `--chart` зберігає SVG із двома рядами частот вхідних і вихідних літер, одиницями та джерелом даних; графік пише власний код. `--policy strict` відхиляє сторонні символи, `--policy passthrough` зберігає їх без зміни. Вхід і вихід — UTF-8; файли з етапу 4 `derived/<id>/letters.txt` підходять до `strict`. Вихід записується через тимчасовий файл у тому самому каталозі та перейменування після перевірки входу; псевдоніми вхідного шляху відхиляються.

Цезар не розрізняє регістр у цьому першому профілі: малі літери переводяться у великі, а вихід завжди великими. Жодної прихованої нормалізації Unicode немає; для NFC користуйтеся корпусом етапу 4. Після додавання кожного шифру його точний профіль, вектори та статус заносимо у `STATUS.md`.

## Як додавати наступний метод

1. Зафіксувати `docs/profiles/<id>.md`: редакцію специфікації, параметри, формати, обмеження та джерела точних векторів.
2. Написати власні спільні компоненти й модуль методу; каталог створювати разом із кодом.
3. Додати незалежний точний вектор, негативні та граничні тести.
4. Підключити CLI, осмислений корпусний запуск, трасування та потрібні власні SVG-графіки.
5. Записати фактично виконані перевірки й відкриті обмеження у [STATUS.md](STATUS.md).

Критерії закриття всіх 30 позицій наведено у [ТЗ етапу 5](docs/SPEC_STAGE5.md). Наявність чотирьох класичних прототипів не закриває етап.

## Межі першої версії

Для великих корпусів `--steps all` вимагає пам'яті для всього трасування. Утворення графіка включає підрахунок символів і генерацію SVG; воно не входитиме до таймінгу шифру. Для поточних класичних модулів графік показує частоти **літер**, а не байтів UTF-8. Якщо запис кількох артефактів запитаний одночасно, кожен файл замінюється атомарно окремо; спільної транзакції для графіка, траси й виходу поки немає. Джерела і правила вибору решти 30 позицій містяться в окремому реєстрі дослідження.
