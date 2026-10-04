"""CLI regressions: failed validation must not touch output files."""

from pathlib import Path
import subprocess
import sys
import tempfile
from reference.python_oracles import rot13_ascii, sha256_digest


executable = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="cryptolab-cli-") as folder:
    root = Path(folder)
    source = root / "source.txt"
    output = root / "output.txt"
    trace = root / "trace.txt"
    source.write_text("АБВ", encoding="utf-8")

    def run(*extra):
        return subprocess.run(
            [str(executable), "caesar", "encrypt", "--alphabet", "uk",
             "--shift", "1", "--in", str(source), "--out", str(output), *extra],
            capture_output=True,
            check=False,
        )

    result = run("--steps", "2", "--trace", str(trace))
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8") == "БВГ"
    assert trace.read_text(encoding="utf-8").count("позиція=") == 2

    output.write_text("KEEP", encoding="utf-8")
    source.write_text("А!", encoding="utf-8")
    result = run("--steps", "all", "--trace", str(trace))
    assert result.returncode != 0
    assert output.read_text(encoding="utf-8") == "KEEP"
    assert trace.read_text(encoding="utf-8").count("позиція=") == 2
    assert not result.stdout

    result = subprocess.run(
        [str(executable), "caesar", "encrypt", "--alphabet", "uk", "--shift", "1",
         "--in", str(source), "--out", str(root / "." / "source.txt")],
        capture_output=True, check=False,
    )
    assert result.returncode != 0
    assert source.read_text(encoding="utf-8") == "А!"

    source.write_text("АБВ", encoding="utf-8")
    result = run()
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8") == "БВГ"
    assert not list(root.glob("*.tmp.*"))

    chart = root / "chart.svg"
    result = subprocess.run(
        [str(executable), "caesar", "encrypt", "--alphabet", "uk", "--shift", "1",
         "--in", str(source), "--out", str(root), "--chart", str(chart)],
        capture_output=True, check=False,
    )
    assert result.returncode != 0
    assert not chart.exists()

    source.write_text("HELLOWORLD", encoding="ascii")
    result = subprocess.run(
        [str(executable), "caesar", "encrypt", "--alphabet", "en", "--shift", "13",
         "--in", str(source), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="ascii") == rot13_ascii("HELLOWORLD")

    key = root / "key.txt"
    key.write_text("mnbvcxzasdfghjklpoiuytrewq", encoding="ascii")
    source.write_text("bob. i love you. alice", encoding="ascii")
    result = subprocess.run(
        [str(executable), "substitution", "encrypt", "--alphabet", "en",
         "--key-file", str(key), "--in", str(source), "--out", str(output),
         "--policy", "passthrough"], capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="ascii") == "NKN. S GKTC WKY. MGSBC"
    key.write_text("AAAAAAAAAAAAAAAAAAAAAAAAAA", encoding="ascii")
    result = subprocess.run(
        [str(executable), "substitution", "encrypt", "--alphabet", "en",
         "--key-file", str(key), "--in", str(source), "--out", str(output),
         "--policy", "passthrough"], capture_output=True, check=False,
    )
    assert result.returncode != 0
    assert output.read_text(encoding="ascii") == "NKN. S GKTC WKY. MGSBC"

    key.write_text("DECAF", encoding="ascii")
    source.write_text("ATTACKATDAWN", encoding="ascii")
    result = subprocess.run(
        [str(executable), "vigenere", "encrypt", "--alphabet", "en",
         "--key-file", str(key), "--in", str(source), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="ascii") == "DXVAHNEVDFZR"

    key.write_text("GYBNQKURP", encoding="ascii")
    source.write_text("ACT", encoding="ascii")
    result = subprocess.run(
        [str(executable), "hill3", "encrypt", "--alphabet", "en",
         "--key-file", str(key), "--in", str(source), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="ascii") == "POH"
    source.write_text("AC", encoding="ascii")
    result = subprocess.run(
        [str(executable), "hill3", "encrypt", "--alphabet", "en",
         "--key-file", str(key), "--in", str(source), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode != 0
    assert output.read_text(encoding="ascii") == "POH"

    for length in (0, 1, 55, 56, 63, 64, 65, 1000):
        data = bytes(range(256)) * (length // 256) + bytes(range(length % 256))
        source.write_bytes(data)
        result = subprocess.run(
            [str(executable), "sha256", "hash", "--in", str(source), "--out", str(output)],
            capture_output=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        assert output.read_bytes() == sha256_digest(data), length

    source.write_bytes(bytes([0, 255, 65]))
    key.write_bytes(bytes([255, 85, 65]))
    result = subprocess.run(
        [str(executable), "otp", "xor", "--in", str(source),
         "--key-file", str(key), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == bytes(a ^ b for a, b in zip(source.read_bytes(), key.read_bytes()))
    key.write_bytes(b"short")
    prior = output.read_bytes()
    result = subprocess.run(
        [str(executable), "otp", "xor", "--in", str(source),
         "--key-file", str(key), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode != 0 and output.read_bytes() == prior

    source.write_bytes(bytes.fromhex("1234"))
    key.write_bytes(bytes.fromhex("01020304"))
    result = subprocess.run(
        [str(executable), "feistel-demo", "encrypt", "--in", str(source),
         "--key-file", str(key), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == bytes.fromhex("f937")
    source.write_bytes(output.read_bytes())
    result = subprocess.run(
        [str(executable), "feistel-demo", "decrypt", "--in", str(source),
         "--key-file", str(key), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode == 0 and output.read_bytes() == bytes.fromhex("1234")

    key.write_text("PLAYFAIREXAMPLE", encoding="ascii")
    source.write_text("HIDETHEGOLDINTHETREESTUMP", encoding="ascii")
    result = subprocess.run(
        [str(executable), "playfair", "encrypt", "--alphabet", "en",
         "--key-file", str(key), "--in", str(source), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="ascii") == "BMODZBXDNABEKUDMUIXMMOUVIF"
    source.write_text("ABC", encoding="ascii")
    result = subprocess.run(
        [str(executable), "playfair", "decrypt", "--alphabet", "en",
         "--key-file", str(key), "--in", str(source), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode != 0 and output.read_text(encoding="ascii") == "BMODZBXDNABEKUDMUIXMMOUVIF"

    key.write_text("0125", encoding="ascii")
    source.write_text("ABCDEFGHIJKLMNOP", encoding="ascii")
    result = subprocess.run(
        [str(executable), "grille", "encrypt", "--alphabet", "en",
         "--key-file", str(key), "--in", str(source), "--out", str(output)],
        capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="ascii") == "ABCEMDFGNOIHPJKL"

print("OK: CLI validation, atomic replacement, path aliases, classic vectors, Python ROT13/SHA-256/OTP, Feistel, Playfair, grille")
