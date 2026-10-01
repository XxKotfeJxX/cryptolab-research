"""Check local Markdown links used as repository navigation."""

from html import unescape
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit


root = Path(__file__).resolve().parents[1]
documents = list(root.glob("*.md")) + list((root / "docs").rglob("*.md"))
link = re.compile(r"\[[^\]\n]+\]\(([^)\n]+)\)")
missing = []

for document in documents:
    for match in link.finditer(document.read_text(encoding="utf-8")):
        target = unescape(match.group(1)).strip()
        parsed = urlsplit(target)
        if parsed.scheme or target.startswith("#"):
            continue
        path = (document.parent / unquote(parsed.path)).resolve()
        if not path.is_file():
            missing.append(f"{document.relative_to(root)}: {target}")

if missing:
    raise SystemExit("Missing local Markdown targets:\n" + "\n".join(missing))
print(f"OK: local links in {len(documents)} Markdown documents")
