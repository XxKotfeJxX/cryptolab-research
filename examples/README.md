# Зразок SVG-графіка

`nechui_caesar_shift7.svg` створено **власним C++ кодом**, `--alphabet uk --shift 7 --chart`, на `uk_nechui_1879/letters.txt` етапу 4 (240294 літери), без покрокового виводу під час побудови. Графік показує частки літер до й після перетворення; це демонстраційний артефакт, а не вимірювання безпеки чи швидкодії.

Шлях до даних: [SVG](nechui_caesar_shift7.svg) → [генератор](../src/viz/svg.cpp) і режим `caesar encrypt` → [архів](../etap_4_korpus.zip), файл `etap_4_korpus/output/derived/uk_nechui_1879/letters.txt` → запис про `uk_nechui_1879` у [протоколі](../docs/research/etap_4_korpus_protokol.md) та `raw/acquisition.json` усередині ZIP. SHA-256 вхідного `letters.txt` за маніфестом: `0004c53af6aeaf72820384d02bf8bec50551f8d7fc054ad4dba32924f2439417`; SHA-256 збереженого SVG: `88cc22420362fd96cd3e3e38da1a5808ca97e70455a8a47331a67b55060f3ec3`. SVG внесено комітом `fe360f4`; параметри запуску наведено вище.
