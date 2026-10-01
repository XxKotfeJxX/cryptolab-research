"""Python 3.14 standard-library oracles for published and boundary tests."""

import codecs
import hashlib


def rot13_ascii(text: str) -> str:
    return codecs.encode(text, "rot_13")


def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
