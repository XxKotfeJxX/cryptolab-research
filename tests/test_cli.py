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

print("OK: CLI validation, atomic replacement, path aliases, published classic vectors, Python ROT13/SHA-256")
