"""Integration test against the supplied immutable stage-4 ZIP."""

import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


archive = Path(sys.argv[1]).resolve()
executable = Path(sys.argv[2]).resolve()
tool = Path(__file__).resolve().parents[1] / "scripts" / "corpus_stage4.py"
artifact = "derived/en_austen_1342/letters_16_head.txt"
member = "etap_4_korpus/output/" + artifact


def invoke(*args):
    return subprocess.run([sys.executable, str(tool), *map(str, args)], capture_output=True, check=False)


result = invoke("verify", "--archive", archive)
assert result.returncode == 0, result.stderr

with tempfile.TemporaryDirectory(prefix="cryptolab-corpus-test-") as folder:
    root = Path(folder)
    output = root / "cipher.txt"
    journal = root / "runs.jsonl"
    result = invoke("run", "--archive", archive, "--artifact", artifact,
                    "--cryptolab", executable, "--out", output, "--journal", journal,
                    "--public-test-key-id", "caesar-shift-3-demo",
                    "--", "caesar", "encrypt", "--alphabet", "en", "--shift", "3")
    assert result.returncode == 0, result.stderr
    with zipfile.ZipFile(archive) as package:
        original = package.read(member).decode("ascii")
    expected = "".join(chr((ord(letter) - 65 + 3) % 26 + 65) for letter in original)
    assert output.read_text(encoding="ascii") == expected
    record = json.loads(journal.read_text(encoding="utf-8").strip())
    assert record["artifact"] == artifact and record["input_bytes"] == 16
    assert record["output_bytes"] == 16 and record["status"] == "success"
    assert record["output_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert record["profile_id"] == "position-16-card-19-caesar-en-v1"
    assert record["public_test_key_id"] == "caesar-shift-3-demo"
    assert record["parameters"] == {"alphabet": "en"}
    assert '"shift":' not in journal.read_text(encoding="utf-8")
    version = subprocess.run(["git", "rev-parse", "HEAD"], cwd=tool.parents[1],
                             capture_output=True, text=True, check=False)
    if version.returncode == 0:
        assert record["code_version"]["git_commit"] == version.stdout.strip()
        assert record["code_version"]["tracked_changes"] in (True, False)

    byte_artifact = "derived/uk_nechui_1879/utf8_at_most_4096.bin"
    digest_out = root / "digest.bin"
    result = invoke("run", "--archive", archive, "--artifact", byte_artifact,
                    "--cryptolab", executable, "--out", digest_out, "--journal", journal,
                    "--", "sha256", "hash")
    assert result.returncode == 0, result.stderr
    with zipfile.ZipFile(archive) as package:
        byte_data = package.read("etap_4_korpus/output/" + byte_artifact)
        manifest = json.loads(package.read("etap_4_korpus/output/manifest.json"))
    declared = next(item["sha256"] for item in manifest["artifacts"] if item["path"] == byte_artifact)
    assert digest_out.read_bytes().hex() == declared == hashlib.sha256(byte_data).hexdigest()
    hash_record = json.loads(journal.read_text(encoding="utf-8").splitlines()[1])
    assert hash_record["profile_id"] == "sha256-fips180-4-2015"
    assert hash_record["output_sha256"] == hashlib.sha256(digest_out.read_bytes()).hexdigest()
    assert "public_test_key_id" not in hash_record

    grille_key = root / "grille_key.txt"
    grille_key.write_text("0125", encoding="ascii")
    grille_out = root / "grille.txt"
    result = invoke("run", "--archive", archive, "--artifact", artifact,
                    "--cryptolab", executable, "--out", grille_out, "--journal", journal,
                    "--public-test-key-id", "grille-mask-0125",
                    "--", "grille", "encrypt", "--alphabet", "en", "--key-file", grille_key)
    assert result.returncode == 0, result.stderr
    assert grille_out.read_text(encoding="ascii") == "ILLSGUTREOTARION"
    grille_record = json.loads(journal.read_text(encoding="utf-8").splitlines()[2])
    assert grille_record["profile_id"] == "position-28-card-26-grille-en-v1"
    assert grille_record["public_test_key_id"] == "grille-mask-0125"

    otp_key = root / "otp_public_key.bin"
    otp_key.write_bytes(bytes([0xA5]) * len(byte_data))
    otp_out = root / "otp.bin"
    result = invoke("run", "--archive", archive, "--artifact", byte_artifact,
                    "--cryptolab", executable, "--out", otp_out, "--journal", journal,
                    "--public-test-key-id", "otp-fixed-a5-demo",
                    "--", "otp", "xor", "--key-file", otp_key)
    assert result.returncode == 0, result.stderr
    assert otp_out.read_bytes() == bytes(value ^ 0xA5 for value in byte_data)
    otp_record = json.loads(journal.read_text(encoding="utf-8").splitlines()[3])
    assert otp_record["profile_id"] == "position-23-card-18-otp-byte-xor-v1"
    assert otp_record["output_sha256"] == hashlib.sha256(otp_out.read_bytes()).hexdigest()
    assert "key-file" not in otp_record["parameters"]

    result = invoke("run", "--archive", archive, "--artifact", artifact,
                    "--cryptolab", executable, "--out", output, "--journal", output,
                    "--", "caesar", "encrypt", "--alphabet", "en", "--shift", "3")
    assert result.returncode != 0
    assert output.read_text(encoding="ascii") == expected

    damaged = root / "damaged.zip"
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(damaged, "w") as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == member:
                data = b"?" + data[1:]
            target.writestr(info, data)
    result = invoke("verify", "--archive", damaged)
    assert result.returncode != 0
    assert b"mismatch" in result.stderr.lower()

    replaced_manifest = root / "replaced_manifest.zip"
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(replaced_manifest, "w") as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "etap_4_korpus/output/manifest.json":
                data += b"\n"
            target.writestr(info, data)
    result = invoke("verify", "--archive", replaced_manifest)
    assert result.returncode != 0
    assert b"frozen stage-4 corpus" in result.stderr

print("OK: pinned stage-4 manifest, classic/byte/SHA-256 runs, journal, alias and tamper rejection")
