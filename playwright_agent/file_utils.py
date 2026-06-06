from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os
import re
import tempfile


def ensure_dir(path: str | Path) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def atomic_write_text(path: str | Path, text: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent), encoding="utf-8") as tmp:
        tmp.write(text)
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def slugify_filename(value: str, limit: int = 120) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_.")
    return value[:limit] or "item"


def sha256_text(text: str) -> str:
    return sha256(text.encode("utf-8", errors="ignore")).hexdigest()

