"""Token / JWT analysis from client storage and cookies.

Flags tokens stored where XSS can read them (localStorage/sessionStorage) and decodes
JWT claims (masked) to expose the client-trusted authz model (role/scope/alg/exp).
"""
from __future__ import annotations

import base64
import json
import re

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
_CLAIM_KEYS = ("sub", "role", "roles", "scope", "scopes", "admin", "isAdmin",
               "iss", "aud", "exp", "email", "user_id", "uid", "tenant", "org", "groups")


def _b64url(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def decode_jwt(tok: str) -> dict | None:
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return {
        "alg": (header or {}).get("alg"),
        "typ": (header or {}).get("typ"),
        "claims": {k: payload.get(k) for k in _CLAIM_KEYS if k in payload},
        "claim_keys": sorted(payload.keys())[:40],
    }


def analyze_tokens(storage: dict, cookies: list[dict]) -> list[dict]:
    """storage = raw snapshot_storage() output (unmasked); returns masked findings."""
    out: list[dict] = []
    sources: list[tuple[str, str, str]] = []
    for store in ("localStorage", "sessionStorage"):
        for k, v in (storage.get(store) or {}).items():
            sources.append((store, k, str(v)))
    for c in cookies or []:
        sources.append(("cookie", c.get("name", ""), str(c.get("value", ""))))

    seen = set()
    for loc, key, val in sources:
        for tok in _JWT_RE.findall(val):
            dec = decode_jwt(tok)
            if not dec:
                continue
            sig = (loc, key, dec["alg"], tuple(sorted(dec["claims"].items(), key=lambda x: x[0])))
            if sig in seen:
                continue
            seen.add(sig)
            notes, severity = [], "low"
            if loc in ("localStorage", "sessionStorage"):
                severity = "medium"
                notes.append(f"JWT stored in {loc} — readable by any XSS; prefer an httpOnly cookie")
            if str(dec["alg"]).lower() == "none":
                severity = "high"
                notes.append("alg:none — signature is not verified")
            if any(k in dec["claims"] for k in ("role", "roles", "admin", "isAdmin", "scope", "scopes")):
                notes.append("authorization claims present in client token — verify server re-checks them")
            out.append({
                "location": f"{loc}:{key}", "alg": dec["alg"],
                "claims": dec["claims"], "claim_keys": dec["claim_keys"],
                "severity": severity, "notes": notes,
            })
    return out
