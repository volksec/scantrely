from __future__ import annotations

import re


_EMAIL_RE = re.compile(r"(?P<user>[A-Za-z0-9._%+-]{2})[A-Za-z0-9._%+-]*@(?P<host>[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_JWT_RE = re.compile(r"([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})")
_TOKEN_RE = re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization)\b[:= ]+([^\s,'\"<>]{6,})")
_CPF_RE = re.compile(r"\b(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})\b")


def mask_text(text: str) -> str:
    if not text:
        return text
    text = _JWT_RE.sub(r"\1.REDACTED.\3", text)
    text = _TOKEN_RE.sub(lambda m: f"{m.group(1)}=REDACTED", text)
    text = _EMAIL_RE.sub(lambda m: f"{m.group('user')}***@{m.group('host')}", text)
    text = _CPF_RE.sub(lambda m: f"{m.group(1)}.***.***-**", text)
    return text


def _mask_value(val: str) -> str:
    val = str(val)
    return f"{val[:4]}…REDACTED" if len(val) > 4 else "REDACTED"


def mask_cookie(cookie: dict) -> dict:
    out = dict(cookie)
    if "value" in out and out["value"]:
        out["value"] = _mask_value(out["value"])
    return out


def mask_storage_value(val) -> str:
    """Mask a storage value: redact secret-looking strings, keep short readable ones."""
    s = str(val)
    if len(s) > 20 and (s.startswith("eyJ") or _looks_high_entropy(s)):
        return _mask_value(s)
    return mask_text(s)[:200]


def _looks_high_entropy(s: str) -> bool:
    import re as _re
    return bool(_re.fullmatch(r"[A-Za-z0-9_\-+/=.]{20,}", s)) and any(c.isdigit() for c in s) and any(c.isalpha() for c in s)


def mask_cookie_string(raw: str) -> str:
    """Mask a raw `document.cookie` string (name=value; name=value; ...)."""
    if not raw:
        return raw
    parts = []
    for pair in raw.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, val = pair.split("=", 1)
            parts.append(f"{name.strip()}={_mask_value(val.strip())}")
        elif pair:
            parts.append(pair)
    return "; ".join(parts)


def mask_headers(headers: dict[str, str]) -> dict[str, str]:
    masked: dict[str, str] = {}
    for key, value in headers.items():
        low = key.lower()
        if low in {"authorization", "cookie", "set-cookie", "x-api-key"}:
            masked[key] = mask_text(str(value))
        else:
            masked[key] = str(value)
    return masked

