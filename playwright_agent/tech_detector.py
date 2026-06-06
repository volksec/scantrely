from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

import yaml

from .models import ConsoleEvent, TechFinding


CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Signature:
    name: str
    category: str
    source: str
    match: str
    pattern: str
    confidence: str = "medium"
    security_relevance: str = ""
    manual_follow_up: str = ""


@dataclass
class DetectorContext:
    url: str
    html: str = ""
    headers: dict[str, str] = None
    cookies: list[dict[str, Any]] = None
    js_texts: list[str] = None
    paths: list[str] = None
    console: list[ConsoleEvent] = None

    def __post_init__(self):
        self.headers = self.headers or {}
        self.cookies = self.cookies or []
        self.js_texts = self.js_texts or []
        self.paths = self.paths or []
        self.console = self.console or []


class TechnologyDetector:
    def __init__(self, signatures: list[Signature]):
        self.signatures = signatures

    @classmethod
    def load_default(cls, signatures_dir: str | Path | None = None) -> "TechnologyDetector":
        signatures_dir = Path(signatures_dir or Path(__file__).parent / "signatures")
        signatures: list[Signature] = []
        for path in sorted(signatures_dir.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            for item in raw:
                signatures.append(Signature(**item))
        return cls(signatures)

    def detect(self, ctx: DetectorContext) -> list[TechFinding]:
        findings: list[TechFinding] = []
        texts = {
            "html": ctx.html or "",
            "headers": "\n".join(f"{k}: {v}" for k, v in (ctx.headers or {}).items()),
            "cookies": "\n".join(f"{c.get('name','')}={c.get('value','')}" for c in (ctx.cookies or [])),
            "js": "\n".join(ctx.js_texts or []),
            "paths": "\n".join(ctx.paths or []),
            "console": "\n".join(e.message for e in (ctx.console or [])),
        }
        for sig in self.signatures:
            haystack = texts.get(sig.source, "")
            if not haystack:
                continue
            matched = self._match(sig, haystack)
            if not matched:
                continue
            findings.append(
                TechFinding(
                    name=sig.name,
                    category=sig.category,
                    confidence=sig.confidence,
                    evidence=self._shorten(matched),
                    source=sig.source,
                    security_relevance=sig.security_relevance,
                    manual_follow_up=sig.manual_follow_up,
                )
            )
        return self._dedupe(findings)

    def _match(self, sig: Signature, haystack: str) -> str | None:
        if sig.match == "contains":
            return sig.pattern if sig.pattern.lower() in haystack.lower() else None
        if sig.match == "regex":
            m = re.search(sig.pattern, haystack, flags=re.I | re.M)
            return m.group(0) if m else None
        if sig.match == "header_present":
            return sig.pattern if any(k.lower() == sig.pattern.lower() for k in haystack.splitlines()) else None
        if sig.match == "cookie_name":
            return sig.pattern if re.search(rf"(?i)\b{re.escape(sig.pattern)}\b", haystack) else None
        return None

    def _dedupe(self, items: list[TechFinding]) -> list[TechFinding]:
        by_key: dict[tuple[str, str], TechFinding] = {}
        for item in items:
            key = (item.name, item.category)
            existing = by_key.get(key)
            if not existing or CONFIDENCE_RANK.get(item.confidence, 0) > CONFIDENCE_RANK.get(existing.confidence, 0):
                by_key[key] = item
        return sorted(by_key.values(), key=lambda x: (x.category, x.name))

    @staticmethod
    def _shorten(text: str, limit: int = 220) -> str:
        text = text.strip().replace("\n", " ")
        return text[:limit] + ("…" if len(text) > limit else "")


def build_stack_profile(findings: list[TechFinding], html: str = "", headers: dict[str, str] | None = None, cookies: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    names = {f.name.lower() for f in findings}
    categories = {f.category for f in findings}
    modern_frontend = any(
        name in names
        for name in {"react", "next.js", "nuxt", "vue", "angular", "vite", "webpack"}
    )
    legacy_aspnet = any(name in names for name in {"asp.net / iis", "asp.net webforms"}) or "__viewstate" in html.lower()
    legacy_webforms = "__viewstate" in html.lower() or "__eventvalidation" in html.lower()
    java_legacy = any(name in names for name in {"jsf", "struts"})
    api_heavy = any(cat == "api_style" for cat in categories) or any(name in names for name in {"graphql", "soap", "odata", "websocket"})
    auth_provider = next((f.name for f in findings if f.category == "auth_provider"), "")
    cms = next((f.name for f in findings if f.category == "cms"), "")

    skip_viewstate = modern_frontend and not legacy_aspnet and not legacy_webforms
    return {
        "modern_frontend": modern_frontend,
        "legacy_aspnet": legacy_aspnet,
        "legacy_webforms": legacy_webforms,
        "java_legacy": java_legacy,
        "api_heavy": api_heavy,
        "auth_provider": auth_provider,
        "cms": cms,
        "skip_viewstate": skip_viewstate,
        "run_viewstate_audit": legacy_aspnet or legacy_webforms,
        "run_legacy_form_audit": java_legacy or legacy_aspnet,
        "run_spa_focus": modern_frontend,
        "run_api_focus": api_heavy or modern_frontend,
        "notes": _profile_notes(modern_frontend, legacy_aspnet, legacy_webforms, java_legacy),
    }


def _profile_notes(modern_frontend: bool, legacy_aspnet: bool, legacy_webforms: bool, java_legacy: bool) -> list[str]:
    notes = []
    if modern_frontend:
        notes.append("Modern SPA detected; prioritize JS chunks, runtime APIs, routes, source maps, and storage.")
    if legacy_aspnet or legacy_webforms:
        notes.append("ASP.NET/WebForms signals detected; ViewState/EventValidation review is relevant.")
    if java_legacy:
        notes.append("Java/JSF/Struts signals detected; inspect hidden view state, action endpoints, and session handling.")
    if modern_frontend and not (legacy_aspnet or legacy_webforms or java_legacy):
        notes.append("Skip legacy ViewState checks; they are not useful on this stack.")
    return notes

