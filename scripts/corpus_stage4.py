"""Verify the fixed stage-4 ZIP and run cryptolab on a verified artifact.

This is an I/O and provenance tool. hashlib is an independent instrumental
checker; cryptographic algorithms in src/ remain C++ implementations.
Nothing from the ZIP is executed or extracted into the repository.
"""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import zipfile


ROOT = "etap_4_korpus/"
MANIFEST = ROOT + "output/manifest.json"
# Recorded from the user-supplied, frozen stage-4 corpus on 2026-10-01.
EXPECTED_MANIFEST_SHA256 = "f8057037011e521080cf999c5083e37b6f657671521d9f673827813272af51e7"
ACQUISITION = ROOT + "raw/acquisition.json"
METADATA = {
    ROOT + "README.md",
    ROOT + "build_corpus.py",
    MANIFEST,
    ACQUISITION,
    ROOT + "raw/en_dickens_parts.json",
    ROOT + "raw/uk_nechui_chapters.json",
    ROOT + "sources.json",
}
MAX_ENTRY = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
CLASSIC = {"caesar", "substitution", "vigenere", "hill3", "playfair", "grille", "homophonic", "solitaire"}
CLASSIC_PROFILE = {
    "caesar": (16, 19),
    "substitution": (17, 20),
    "vigenere": (18, 21),
    "hill3": (19, 22),
    "playfair": (25, 24),
    "solitaire": (27, 25),
    "grille": (28, 26),
    "homophonic": (29, 27),
}
BYTE_METHODS = {"otp", "feistel-demo"}
PUBLIC_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}\Z")


class CorpusError(Exception):
    pass


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CorpusError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes, name: str):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CorpusError(f"Invalid JSON in {name}: {error}") from error


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return (name.startswith(ROOT) and not name.endswith("/") and "\\" not in name
            and not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts))


def check_digest(data: bytes, expected_bytes: int, expected_sha: str, name: str):
    if type(expected_bytes) is not int or expected_bytes < 0 or not isinstance(expected_sha, str) or not HEX256.fullmatch(expected_sha):
        raise CorpusError(f"Invalid size or SHA-256 metadata: {name}")
    actual = hashlib.sha256(data).hexdigest()
    if len(data) != expected_bytes or actual != expected_sha:
        raise CorpusError(f"Size or SHA-256 mismatch: {name}")


def load_verified(archive: Path):
    with zipfile.ZipFile(archive) as package:
        infos = package.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise CorpusError("Duplicate ZIP member name")
        if any(not safe_member(name) for name in names):
            raise CorpusError("Unexpected or unsafe ZIP member path")
        if any(item.file_size > MAX_ENTRY for item in infos) or sum(item.file_size for item in infos) > MAX_TOTAL:
            raise CorpusError("ZIP exceeds the configured uncompressed size limit")
        if not METADATA.issubset(names):
            raise CorpusError("Missing stage-4 metadata")

        manifest_bytes = package.read(MANIFEST)
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        if manifest_sha != EXPECTED_MANIFEST_SHA256:
            raise CorpusError("Manifest SHA-256 differs from the frozen stage-4 corpus")
        manifest = parse_json(manifest_bytes, MANIFEST)
        acquisition = parse_json(package.read(ACQUISITION), ACQUISITION)
        if manifest.get("schema") != 1 or len(manifest.get("originals", [])) != 4 or len(manifest.get("artifacts", [])) != 124:
            raise CorpusError("Unexpected stage-4 manifest schema or counts")
        originals = manifest["originals"]
        artifacts = manifest["artifacts"]
        if len(acquisition.get("sources", [])) != 4:
            raise CorpusError("Unexpected acquisition record count")
        acquisition_by_id = {item["id"]: item for item in acquisition["sources"]}
        if len(acquisition_by_id) != 4:
            raise CorpusError("Duplicate acquisition ID")

        implementation = manifest["implementation"]
        check_digest(package.read(ROOT + "build_corpus.py"),
                     package.getinfo(ROOT + "build_corpus.py").file_size,
                     implementation["script_sha256"], "build_corpus.py")
        check_digest(package.read(ROOT + "sources.json"),
                     package.getinfo(ROOT + "sources.json").file_size,
                     implementation["source_spec_sha256"], "sources.json")

        expected = set(METADATA)
        original_ids = set()
        for item in originals:
            origin_id = item["id"]
            if origin_id in original_ids or origin_id not in acquisition_by_id:
                raise CorpusError("Duplicate or missing original ID")
            original_ids.add(origin_id)
            member = ROOT + item["raw_file"]
            expected.add(member)
            data = package.read(member)
            check_digest(data, item["raw_bytes"], item["raw_sha256"], member)
            acquired = acquisition_by_id[origin_id]
            if (acquired["raw_file"], acquired["bytes"], acquired["sha256"]) != (
                    item["raw_file"], item["raw_bytes"], item["raw_sha256"]):
                raise CorpusError(f"Acquisition/manifest mismatch: {origin_id}")
            decoded = data.decode("utf-8")
            if not decoded.startswith(acquired["first_100"]) or not decoded.endswith(acquired["last_100"]):
                raise CorpusError(f"Acquisition boundary mismatch: {origin_id}")

        by_path = {}
        data_by_path = {}
        for item in artifacts:
            path = item["path"]
            if path in by_path or not (path.startswith("derived/") or path.startswith("controls/")):
                raise CorpusError(f"Duplicate or unexpected artifact path: {path}")
            if item["origin"] != "constructed_control" and item["origin"] not in original_ids:
                raise CorpusError(f"Unknown artifact origin: {path}")
            member = ROOT + "output/" + path
            expected.add(member)
            data = package.read(member)
            check_digest(data, item["bytes"], item["sha256"], member)
            if item.get("utf8_valid"):
                decoded = data.decode("utf-8")
                if "codepoints" in item and len(decoded) != item["codepoints"]:
                    raise CorpusError(f"Code point count mismatch: {path}")
            by_path[path] = item
            data_by_path[path] = data
        if set(names) != expected:
            raise CorpusError("ZIP contents differ from the manifest and fixed metadata set")

        for path, item in by_path.items():
            if item["view"] == "classic_window":
                base = f"derived/{item['origin']}/letters.txt"
                decoded = data_by_path[base].decode("utf-8")
                start = item["start_codepoint"]
                length = item["target_letters"]
                if type(start) is not int or type(length) is not int or start < 0 or length < 0:
                    raise CorpusError(f"Invalid window boundaries: {path}")
                if data_by_path[path].decode("utf-8") != decoded[start:start + length]:
                    raise CorpusError(f"Window boundaries differ from letters.txt: {path}")
            elif item["view"] == "utf8_budget":
                base = f"derived/{item['origin']}/text_utf8.txt"
                if not data_by_path[base].startswith(data_by_path[path]):
                    raise CorpusError(f"UTF-8 budget is not a prefix: {path}")
        return manifest, by_path, data_by_path, manifest_sha


def same_existing_path(left: Path, right: Path) -> bool:
    try:
        return left.samefile(right)
    except FileNotFoundError:
        return left.resolve() == right.resolve()


def file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def code_version():
    project = Path(__file__).resolve().parents[1]
    try:
        commit = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=project,
                                capture_output=True, text=True, check=False)
        value = commit.stdout.strip()
        if commit.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40,64}", value):
            return None
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=project,
                               capture_output=True, text=True, check=False)
        if dirty.returncode != 0:
            return None
        return {"git_commit": value, "tracked_changes": bool(dirty.stdout)}
    except OSError:
        return None


def run_verified(args, artifacts, data_by_path, manifest_sha):
    item = artifacts.get(args.artifact)
    if item is None:
        raise CorpusError("Artifact is absent from the manifest")
    forwarded = args.cryptolab_args
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]
    if len(forwarded) < 2 or forwarded[0] not in CLASSIC | BYTE_METHODS | {"sha256"}:
        raise CorpusError("Expected a supported cryptolab algorithm and operation")
    algorithm, operation = forwarded[:2]
    expected = {"sha256": {"hash"}, "otp": {"xor"}, "feistel-demo": {"encrypt", "decrypt"}}
    if operation not in expected.get(algorithm, {"encrypt", "decrypt"}):
        raise CorpusError("Unsupported cryptolab operation")
    if any(flag in forwarded for flag in ("--in", "--out")):
        raise CorpusError("The wrapper sets --in and --out itself")
    if algorithm in CLASSIC and item["view"] not in {"classic_letters", "classic_window"}:
        raise CorpusError("Classic algorithms require a letters artifact")
    if algorithm in BYTE_METHODS and item["view"] not in {"utf8_budget", "control"}:
        raise CorpusError("Byte methods require a byte-budget or control artifact")
    if item["view"] == "hex_display_only":
        raise CorpusError("A hex display is not a binary input artifact")
    if args.public_test_key_id and not PUBLIC_KEY_ID.fullmatch(args.public_test_key_id):
        raise CorpusError("Public test key ID must be 1–80 ASCII identifier characters")
    if algorithm == "sha256" and args.public_test_key_id:
        raise CorpusError("SHA-256 has no test key")

    if algorithm in CLASSIC:
        alphabet = next((forwarded[index + 1] for index, flag in enumerate(forwarded[:-1])
                         if flag == "--alphabet"), None)
        if alphabet not in {"en", "uk"}:
            raise CorpusError("Classic corpus runs require --alphabet en or uk")
        if algorithm in {"playfair", "solitaire"} and alphabet != "en":
            raise CorpusError("This method has only an English profile")
        position, card = CLASSIC_PROFILE[algorithm]
        profile_id = f"position-{position}-card-{card}-{algorithm}-{alphabet}-v1"
    elif algorithm == "otp":
        profile_id = "position-23-card-18-otp-byte-xor-v1"
    elif algorithm == "feistel-demo":
        profile_id = "position-20-card-23-feistel-demo-16bit-v1"
    else:
        profile_id = "sha256-fips180-4-2015"

    archive = args.archive.resolve()
    output = args.out.resolve()
    journal = args.journal.resolve()
    if same_existing_path(output, journal):
        raise CorpusError("The output path aliases the journal")
    if not journal.parent.is_dir() or journal.is_dir():
        raise CorpusError("The journal needs an existing parent directory and a file path")
    destinations = [output, journal]
    for index, flag in enumerate(forwarded):
        if flag in ("--chart", "--trace") and index + 1 < len(forwarded):
            destinations.append(Path(forwarded[index + 1]).resolve())
    if any(same_existing_path(path, archive) for path in destinations):
        raise CorpusError("An output path aliases the corpus archive")
    if any(same_existing_path(path, journal) for path in destinations[2:]):
        raise CorpusError("An output path aliases the journal")

    executable = args.cryptolab.resolve()
    executable_sha = file_sha256(executable)
    archive_sha = file_sha256(archive)
    with tempfile.TemporaryDirectory(prefix="cryptolab-corpus-") as folder:
        verified_input = Path(folder) / "verified-input.bin"
        verified_input.write_bytes(data_by_path[args.artifact])
        command = [str(executable), algorithm, operation, "--in", str(verified_input),
                   "--out", str(output), *forwarded[2:]]
        result = subprocess.run(command, check=False)

    public_params = {}
    for index, flag in enumerate(forwarded):
        if flag in ("--alphabet", "--policy") and index + 1 < len(forwarded):
            public_params[flag[2:]] = forwarded[index + 1]
    record = {
        "schema": 1,
        "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "algorithm": algorithm,
        "operation": operation,
        "profile_id": profile_id,
        "implementation_sha256": executable_sha,
        "archive_sha256": archive_sha,
        "manifest_sha256": manifest_sha,
        "corpus_id": item["origin"],
        "artifact": args.artifact,
        "view": item["view"],
        "input_sha256": item["sha256"],
        "input_bytes": item["bytes"],
        "parameters": public_params,
        "status": "success" if result.returncode == 0 else "failed",
        "exit_code": result.returncode,
    }
    if "start_codepoint" in item:
        record["start_codepoint"] = item["start_codepoint"]
    if args.public_test_key_id:
        record["public_test_key_id"] = args.public_test_key_id
    version = code_version()
    if version is not None:
        record["code_version"] = version
    if result.returncode == 0:
        record["output_bytes"] = output.stat().st_size
        record["output_sha256"] = file_sha256(output)
    with journal.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"Corpus {item['origin']} / {args.artifact}: {item['bytes']} bytes, SHA-256 {item['sha256']}")
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    verify = sub.add_parser("verify", help="check every raw and derived byte against the stage-4 manifest")
    verify.add_argument("--archive", required=True, type=Path)
    run = sub.add_parser("run", help="verify, then run cryptolab on one temporary artifact")
    run.add_argument("--archive", required=True, type=Path)
    run.add_argument("--artifact", required=True)
    run.add_argument("--cryptolab", required=True, type=Path)
    run.add_argument("--out", required=True, type=Path)
    run.add_argument("--journal", required=True, type=Path)
    run.add_argument("--public-test-key-id", help="identifier of a documented, non-secret test key")
    run.add_argument("cryptolab_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        manifest, artifacts, data_by_path, manifest_sha = load_verified(args.archive)
        if args.action == "verify":
            print(f"OK: {len(manifest['originals'])} UTF-8 raw snapshots, "
                  f"{len(artifacts)} artifacts, manifest SHA-256 {manifest_sha}")
            return 0
        return run_verified(args, artifacts, data_by_path, manifest_sha)
    except (CorpusError, OSError, KeyError, ValueError, TypeError, IndexError, UnicodeError,
            zipfile.BadZipFile) as error:
        print(f"Corpus error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
