#!/usr/bin/env python3
"""Target/domain normalization shared by API routes and recon pipeline."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class TargetNormalization:
    raw: str
    value: str = ""
    ok: bool = False
    error: str = ""
    wildcard: bool = False


def _strip_url_parts(value: str) -> str:
    value = value.strip()
    if "://" in value:
        parsed = urlsplit(value)
        value = parsed.hostname or ""
    else:
        value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if ":" in value and not value.startswith("["):
            value = value.rsplit(":", 1)[0]
    return value.strip().strip(".").lower()


def normalize_domain(
    value: str,
    *,
    allow_wildcard: bool = True,
    preserve_wildcard: bool = False,
) -> TargetNormalization:
    raw = "" if value is None else str(value)
    if not raw.strip():
        return TargetNormalization(raw=raw or "", error="empty domain")

    domain = _strip_url_parts(raw)
    if not domain:
        return TargetNormalization(raw=raw, error="empty domain")

    wildcard = "*" in domain
    normalized = domain.lower().strip(".")
    return TargetNormalization(raw=raw, value=normalized, ok=True, wildcard=wildcard)


def normalize_domain_list(
    values,
    *,
    allow_wildcard: bool = True,
    preserve_wildcard: bool = False,
) -> tuple[list[str], list[dict]]:
    if isinstance(values, str):
        values = [part for part in re.split(r"[\s,]+", values) if part.strip()]
    elif not isinstance(values, list):
        values = [values]

    normalized: list[str] = []
    seen: set[str] = set()
    errors: list[dict] = []
    for item in values:
        if item is None:
            continue
        item_text = str(item).strip()
        if not item_text:
            continue
        res = normalize_domain(
            item_text,
            allow_wildcard=allow_wildcard,
            preserve_wildcard=preserve_wildcard,
        )
        if res.value not in seen:
            seen.add(res.value)
            normalized.append(res.value)
    return normalized, errors
