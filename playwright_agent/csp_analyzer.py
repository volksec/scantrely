"""Content-Security-Policy weakness analysis (static, no browser)."""
from __future__ import annotations


def _directive(csp: str, name: str) -> str:
    for part in csp.split(";"):
        part = part.strip()
        if part.lower().startswith(name + " ") or part.lower() == name:
            return part
    return ""


def analyze_csp(headers: dict) -> dict:
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    csp = lower.get("content-security-policy", "") or ""
    if not csp:
        return {"present": False, "severity": "low",
                "issues": ["No Content-Security-Policy header — no XSS defense-in-depth."]}
    c = csp.lower()
    script = _directive(c, "script-src") or _directive(c, "default-src")
    issues = []
    if "unsafe-inline" in script:
        issues.append("script-src allows 'unsafe-inline' — inline-script XSS not mitigated")
    if "unsafe-eval" in script:
        issues.append("script-src allows 'unsafe-eval' — eval()/Function() allowed")
    if "*" in script:
        issues.append("wildcard host in script-src — scripts from anywhere")
    if "object-src" not in c:
        issues.append("missing object-src 'none' — plugin/Flash XSS vector")
    if "base-uri" not in c:
        issues.append("missing base-uri — <base> tag injection possible")
    if "default-src" not in c and "script-src" not in c:
        issues.append("no default-src/script-src — policy does not constrain scripts")
    if "report-uri" in c or "report-to" in c:
        pass
    sev = "medium" if issues else "info"
    return {"present": True, "policy": csp[:400], "issues": issues, "severity": sev}
