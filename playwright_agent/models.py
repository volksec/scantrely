from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _relativize_paths(obj: Any, base: Path) -> None:
    """Recursively rewrite absolute filesystem paths under ``base`` to paths
    relative to it, in place. Strings that are not absolute paths under ``base``
    (URLs, unrelated absolute paths, plain text) are left untouched."""
    def _rel(value: str) -> str:
        try:
            p = Path(value)
            if p.is_absolute():
                return str(p.relative_to(base))
        except (ValueError, OSError):
            pass
        return value

    if isinstance(obj, dict):
        for key, val in obj.items():
            if isinstance(val, str):
                obj[key] = _rel(val)
            else:
                _relativize_paths(val, base)
    elif isinstance(obj, list):
        for idx, val in enumerate(obj):
            if isinstance(val, str):
                obj[idx] = _rel(val)
            else:
                _relativize_paths(val, base)


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    status: int | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    content_type: str | None = None
    auth_required: bool | None = None
    source_page: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class ConsoleEvent:
    page_url: str
    type: str
    message: str
    source_file: str | None = None
    line: int | None = None
    column: int | None = None
    stack: str | None = None
    related_request: str | None = None
    classification: str | None = None
    ts: str = field(default_factory=_utc_now)


@dataclass
class JsArtifact:
    file_url: str
    size: int = 0
    sha256: str = ""
    lazy_chunk: bool = False
    endpoints: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    secrets_hint: list[str] = field(default_factory=list)
    source_map_url: str | None = None
    source_map_accessible: bool = False
    source_map_sources: list[str] = field(default_factory=list)


@dataclass
class TechFinding:
    name: str
    category: str
    confidence: str
    evidence: str
    source: str
    security_relevance: str = ""
    manual_follow_up: str = ""


@dataclass
class InputPoint:
    kind: str
    name: str = ""
    action: str = ""
    method: str = "GET"
    field_type: str = ""
    value_hint: str = ""
    risky_intent: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class AuthObservation:
    login_forms: list[dict[str, Any]] = field(default_factory=list)
    csrf_fields: list[str] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    session_mechanisms: list[str] = field(default_factory=list)
    cookie_flags: list[dict[str, Any]] = field(default_factory=list)
    logout_urls: list[str] = field(default_factory=list)
    access_control: list[dict[str, Any]] = field(default_factory=list)  # authed-vs-anon (Fase 15)
    logout: dict[str, Any] = field(default_factory=dict)                 # logout invalidation test
    session_fixation: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class RaceCandidate:
    url: str
    method: str = "GET"
    category: str = ""            # coupon|vote|cart|comment|upload|points|...
    reason: str = ""
    risky_intent: bool = False    # destructive intent → never auto-probed
    probe_status: str = "not_tested"  # not_tested|consistent|inconsistent|skipped_destructive
    probe_detail: str = ""
    suggested_test: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class Finding:
    title: str
    severity: str
    endpoint: str = ""
    parameter: str | None = None
    status: str = "needs_manual_validation"
    evidence: list[str] = field(default_factory=list)
    impact: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    recommendation: str = ""
    cwe: str | None = None


@dataclass
class IdorCandidate:
    url: str
    endpoint: str = ""
    parameter: str = ""
    reason: str = ""
    kind: str = "path"
    notes: list[str] = field(default_factory=list)


@dataclass
class IdorResult:
    url: str
    parameter: str = ""
    candidate_kind: str = "path"
    status: str = "not_tested"  # confirmed_idor|potential_idor|access_denied|not_tested|needs_manual_validation
    severity: str = "info"
    evidence: list[str] = field(default_factory=list)
    a_status: int | None = None
    b_status: int | None = None
    a_length: int | None = None
    b_length: int | None = None
    notes: list[str] = field(default_factory=list)
    cwe: str | None = None


@dataclass
class XssResult:
    url: str
    parameter: str = ""
    context: str = ""           # html|attribute|js_string|event_handler|unknown
    status: str = "no_reflection"  # confirmed_xss|reflected_only|blocked_or_encoded|no_reflection|needs_manual_validation
    severity: str = "info"
    marker: str = ""
    payload: str = ""
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    cwe: str | None = None


@dataclass
class PageSnapshot:
    url: str
    depth: int
    title: str = ""
    status: int | None = None
    html_path: str = ""
    screenshot_path: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    inputs: list[InputPoint] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    console: list[ConsoleEvent] = field(default_factory=list)
    js: list[JsArtifact] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class SessionState:
    scope: list[str]
    target: str
    started_at: str = field(default_factory=_utc_now)
    config: dict[str, Any] = field(default_factory=dict)
    pages: list[PageSnapshot] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    console: list[ConsoleEvent] = field(default_factory=list)
    js: list[JsArtifact] = field(default_factory=list)
    tech: list[TechFinding] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    idor: list[IdorResult] = field(default_factory=list)
    xss: list[XssResult] = field(default_factory=list)
    race: list[RaceCandidate] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    storage: dict[str, Any] = field(default_factory=dict)
    routes: list[dict[str, Any]] = field(default_factory=list)
    inputs: list[InputPoint] = field(default_factory=list)
    auth: AuthObservation = field(default_factory=AuthObservation)
    response_headers: dict[str, str] = field(default_factory=dict)
    stack_profile: dict[str, Any] = field(default_factory=dict)
    skipped_checks: list[str] = field(default_factory=list)
    discovered_hosts: list[str] = field(default_factory=list)
    validated_hosts: list[str] = field(default_factory=list)
    pending_hosts: list[str] = field(default_factory=list)
    host_inventory: list[dict[str, Any]] = field(default_factory=list)
    # ── Extended browser-only surface (dicts for simple round-trip) ──
    websockets: list[dict[str, Any]] = field(default_factory=list)
    sse: list[dict[str, Any]] = field(default_factory=list)
    tokens: list[dict[str, Any]] = field(default_factory=list)
    globals_secrets: list[dict[str, Any]] = field(default_factory=list)
    postmessage: list[dict[str, Any]] = field(default_factory=list)
    graphql: dict[str, Any] = field(default_factory=dict)
    csp: dict[str, Any] = field(default_factory=dict)
    dom_xss: list[dict[str, Any]] = field(default_factory=list)
    client_trust: list[dict[str, Any]] = field(default_factory=list)
    evidence_dir: str = "evidence"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def _rebuild_page(p: dict[str, Any]) -> "PageSnapshot":
        p = dict(p)
        p["inputs"] = [InputPoint(**i) if isinstance(i, dict) else i for i in p.get("inputs", [])]
        p["endpoints"] = [Endpoint(**e) if isinstance(e, dict) else e for e in p.get("endpoints", [])]
        p["js"] = [JsArtifact(**j) if isinstance(j, dict) else j for j in p.get("js", [])]
        p["console"] = [ConsoleEvent(**c) if isinstance(c, dict) else c for c in p.get("console", [])]
        return PageSnapshot(**p)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SessionState":
        pages = [cls._rebuild_page(p) for p in data.get("pages", [])]
        endpoints = [Endpoint(**e) for e in data.get("endpoints", [])]
        console = [ConsoleEvent(**c) for c in data.get("console", [])]
        js = [JsArtifact(**j) for j in data.get("js", [])]
        tech = [TechFinding(**t) for t in data.get("tech", [])]
        findings = [Finding(**f) for f in data.get("findings", [])]
        idor = [IdorResult(**i) for i in data.get("idor", [])]
        xss = [XssResult(**x) for x in data.get("xss", [])]
        race = [RaceCandidate(**r) for r in data.get("race", [])]
        inputs = [InputPoint(**i) for i in data.get("inputs", [])]
        auth = AuthObservation(**data.get("auth", {}))
        return cls(
            scope=list(data.get("scope", [])),
            target=data.get("target", ""),
            started_at=data.get("started_at", _utc_now()),
            config=dict(data.get("config", {})),
            pages=pages,
            endpoints=endpoints,
            console=console,
            js=js,
            tech=tech,
            findings=findings,
            idor=idor,
            xss=xss,
            race=race,
            cookies=list(data.get("cookies", [])),
            storage=dict(data.get("storage", {})),
            routes=list(data.get("routes", [])),
            inputs=inputs,
            auth=auth,
            response_headers=dict(data.get("response_headers", {})),
            stack_profile=dict(data.get("stack_profile", {})),
            websockets=list(data.get("websockets", [])),
            sse=list(data.get("sse", [])),
            tokens=list(data.get("tokens", [])),
            globals_secrets=list(data.get("globals_secrets", [])),
            postmessage=list(data.get("postmessage", [])),
            graphql=dict(data.get("graphql", {})),
            csp=dict(data.get("csp", {})),
            dom_xss=list(data.get("dom_xss", [])),
            client_trust=list(data.get("client_trust", [])),
            skipped_checks=list(data.get("skipped_checks", [])),
            discovered_hosts=list(data.get("discovered_hosts", [])),
            validated_hosts=list(data.get("validated_hosts", [])),
            pending_hosts=list(data.get("pending_hosts", [])),
            host_inventory=list(data.get("host_inventory", [])),
            evidence_dir=data.get("evidence_dir", "evidence"),
        )

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        # session.json lives at <job_root>/evidence/session*.json, so the job
        # root is two levels up. Rewrite any absolute path under it to a job-root
        # relative one so the artifact never leaks the server's install path.
        try:
            _relativize_paths(data, path.parent.parent.resolve())
        except Exception:
            pass
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "SessionState":
        path = Path(path)
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
