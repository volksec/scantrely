"""DOM-based XSS testing via URL-fragment taint (active, execution-confirmed).

Injects a unique marker into location.hash and observes whether it reaches a DOM sink
(captured by the init-script sink hooks) and/or actually executes (a dialog fires).
Reflection/taint alone is a manual lead; only real execution is confirmed.
"""
from __future__ import annotations

from pathlib import Path
import secrets

from .browser import BrowserRuntime
from .file_utils import ensure_dir


def run_dom_xss(
    urls: list[str],
    *,
    headless: bool = True,
    timeout: int = 15,
    user_agent: str = "",
    auth_state: str | None = None,
    evidence_dir: str | Path = "evidence",
    max_urls: int = 12,
) -> list[dict]:
    ev = ensure_dir(Path(evidence_dir) / "dom_xss")
    seen, targets = set(), []
    for u in urls or []:
        base = (u or "").split("#")[0]
        if not base.startswith("http") or base in seen:
            continue
        seen.add(base)
        targets.append(base)
        if len(targets) >= max_urls:
            break

    results: list[dict] = []
    if not targets:
        return results

    with BrowserRuntime(headless=headless, timeout=timeout, user_agent=user_agent,
                        storage_state=auth_state) as rt:
        for base in targets:
            marker = "PDOM" + secrets.token_hex(4)
            payload = f"\"><img src=x onerror=alert('{marker}')>"
            target = f"{base}#{payload}"
            d0, s0 = len(rt.dialogs), len(rt.sink_hits)
            try:
                rt.goto(target)
                rt.page.wait_for_timeout(700)
                rt.harvest_agent_events()
            except Exception:
                continue
            fired = [d for d in rt.dialogs[d0:] if marker in str(d.get("message", ""))]
            sinks = [s for s in rt.sink_hits[s0:]
                     if marker in str(s.get("sample", "")) or marker in str(s.get("source", ""))]
            if fired:
                shot = str(ev / f"{marker}.png")
                try:
                    rt.page.screenshot(path=shot)
                except Exception:
                    shot = ""
                results.append({
                    "url": base, "status": "confirmed_dom_xss", "marker": marker,
                    "sink": (sinks[0]["sink"] if sinks else "unknown"),
                    "severity": "high", "evidence": [shot], "cwe": "CWE-79",
                    "note": "URL fragment executed in a DOM sink",
                })
            elif sinks:
                results.append({
                    "url": base, "status": "tainted_sink", "marker": marker,
                    "sink": sinks[0]["sink"], "severity": "medium",
                    "note": "URL hash flows into a DOM sink without executing — verify manually",
                })
            else:
                results.append({"url": base, "status": "no_sink", "severity": "info"})
    return results
