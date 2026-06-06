"""postMessage listener audit — missing origin checks = cross-origin abuse vector."""
from __future__ import annotations


def analyze_postmessage(listeners: list[dict]) -> dict:
    # dedupe by sample
    seen, uniq = set(), []
    for l in listeners or []:
        s = l.get("sample", "")
        if s in seen:
            continue
        seen.add(s)
        uniq.append(l)
    no_origin = [l for l in uniq if not l.get("hasOriginCheck")]
    return {
        "total_listeners": len(uniq),
        "without_origin_check": len(no_origin),
        "severity": "medium" if no_origin else "info",
        "samples": [l.get("sample", "")[:140] for l in no_origin[:5]],
        "note": ("message listener(s) without an origin check — verify they validate "
                 "event.origin (postMessage XSS / data exfiltration)") if no_origin else "",
    }
