"""Markdown report generator (Fase 19).

Renders a low-noise, deduplicated, evidence-first report from a SessionState so a
pentester can read it in ~5 minutes and know where to start. Only execution-/access-
confirmed results land in "Confirmed Findings"; everything else is a manual lead.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from .console_recon import summarize as summarize_console
from .file_utils import atomic_write_text
from .masking import mask_text
from .models import SessionState


# Security headers we expect on an HTTPS app (absence is informational/low per spec).
_EXPECTED_HEADERS = {
    "content-security-policy": "XSS/clickjacking mitigation",
    "strict-transport-security": "TLS downgrade protection",
    "x-frame-options": "clickjacking protection",
    "x-content-type-options": "MIME-sniffing protection",
    "referrer-policy": "referrer leakage control",
    "permissions-policy": "browser feature restriction",
}


def _md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["_None._", ""]
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        cells = [str(c).replace("\n", " ").replace("|", "\\|") for c in row]
        out.append("| " + " | ".join(cells) + " |")
    out.append("")
    return out


def _score_endpoint(ep) -> tuple[int, list[str]]:
    url = (ep.url or "").lower()
    reasons: list[str] = []
    score = 0
    if "/api/" in url or "/graphql" in url or "/rest/" in url:
        score += 3; reasons.append("API endpoint")
    if (ep.parameters or {}).get("sensitive_keys"):
        score += 3; reasons.append("object-reference params")
    if "json" in (ep.content_type or "").lower():
        score += 2; reasons.append("JSON response")
    if (ep.method or "GET").upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 2; reasons.append("state-changing")
    if any(k in url for k in ("admin", "debug", "internal", "export", "import", "report")):
        score += 2; reasons.append("admin/debug/export")
    if ep.status == 200:
        score += 1
    return score, reasons


def _security_header_rows(headers: dict[str, str]) -> list[list[str]]:
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    rows = []
    for name, why in _EXPECTED_HEADERS.items():
        present = name in lower
        rows.append([name, "present" if present else "**missing**",
                     "info" if present else "low", why])
    aco = lower.get("access-control-allow-origin", "")
    acc = lower.get("access-control-allow-credentials", "")
    if aco == "*" and str(acc).lower() == "true":
        rows.append(["access-control-allow-origin", "`*` + credentials", "medium",
                     "wildcard CORS with credentials — review"])
    return rows


def render_markdown(session: SessionState) -> str:
    stack = session.stack_profile or {}
    L: list[str] = []
    add = L.append

    confirmed = [f for f in session.findings if f.status == "confirmed"]
    console_counts = summarize_console(session.console)
    sec_rel = [c for c in session.console if c.classification == "security_relevant"]
    failed = [e for e in session.endpoints if "request_failed" in (e.notes or [])]
    smaps = [j for j in session.js if j.source_map_accessible]

    # ── Executive Summary ──
    add("# Attack Surface Report — Playwright Pentest Agent")
    add("")
    add("## Executive Summary")
    add(f"- Target: `{session.target}` — scope: {', '.join(session.scope) or '(host only)'}")
    add(f"- Crawled **{len(session.pages)}** routes, **{len(session.endpoints)}** endpoints, "
        f"**{len(session.js)}** JS files ({len(smaps)} with readable source maps).")
    add(f"- Host inventory: **{len(session.discovered_hosts)}** discovered, "
        f"**{len(session.validated_hosts)}** validated, **{len(session.pending_hosts)}** pending.")
    add(f"- **{len(confirmed)}** confirmed finding(s); "
        f"{len(session.tech)} technologies; {console_counts.get('security_relevant', 0)} "
        f"security-relevant console events.")
    top = top_endpoints(session, limit=3)
    if top:
        add("- Start manual testing here: " + ", ".join(f"`{u}`" for u, _, _ in top))
    add("")

    # ── Scope ──
    add("## Scope")
    cfg = session.config or {}
    add(f"- Target: `{session.target}`")
    add(f"- Started: `{session.started_at}`")
    add(f"- Safe-mode: `{cfg.get('safe_mode', True)}` | XSS tested: `{cfg.get('test_xss', False)}` "
        f"| External allowed: `{cfg.get('allow_external', False)}`")
    add(f"- Limits: max_pages={cfg.get('max_pages')} max_depth={cfg.get('max_depth')}")
    add("")

    # ── Host Inventory ──
    add("## Host Inventory")
    if session.host_inventory:
        add("| Host | Status | Code | Source | Final URL |")
        add("| --- | --- | --- | --- | --- |")
        for item in session.host_inventory[:100]:
            host = str(item.get("host", ""))[:60]
            status = item.get("status", "pending")
            code = item.get("status_code", "")
            source = str(item.get("source", ""))[:24]
            final_url = str(item.get("final_url", ""))[:70]
            add(f"| `{host}` | `{status}` | `{code}` | `{source}` | `{final_url}` |")
    else:
        add("_No hosts recorded yet._")
    add("")

    # ── Stack Profile ──
    add("## Stack Profile")
    for key in ("modern_frontend", "legacy_aspnet", "legacy_webforms", "java_legacy",
                "api_heavy", "auth_provider", "cms", "skip_viewstate"):
        if key in stack:
            add(f"- {key}: `{stack.get(key)}`")
    for note in stack.get("notes", []) or []:
        add(f"- {note}")
    add("")

    # ── Technology Fingerprint ──
    add("## Technology Fingerprint")
    L += _md_table(
        ["Technology", "Category", "Confidence", "Evidence", "Manual Follow-up"],
        [[t.name, t.category, t.confidence, mask_text(t.evidence)[:80], t.manual_follow_up[:80]]
         for t in session.tech],
    )

    # ── Framework-Specific: ASP.NET ViewState (only when relevant) ──
    if stack.get("legacy_aspnet") or stack.get("legacy_webforms"):
        add("## ASP.NET / ViewState Analysis")
        add(f"- ViewState present: `{stack.get('legacy_webforms')}`")
        add("- Manual checks: ViewState MAC/encryption, exposed `.axd` handlers "
            "(Trace.axd, elmah.axd), Telerik dialog handlers, custom-errors config.")
        add("- Note: presence of ViewState is **not** a vulnerability by itself.")
        add("")

    # ── Application Map ──
    add("## Application Map")
    L += _md_table(
        ["Route", "Depth", "Status", "Links", "Forms", "Title"],
        [[r.get("url", ""), r.get("depth"), r.get("status"), r.get("links"),
          r.get("forms"), mask_text(r.get("title", ""))[:50]]
         for r in session.routes[:60]],
    )

    # ── Endpoint Inventory ──
    add("## Endpoint Inventory")
    L += _md_table(
        ["Method", "URL", "Status", "Content-Type", "Sensitive Params"],
        [[e.method, e.url[:90], e.status, (e.content_type or "")[:30],
          ",".join((e.parameters or {}).get("sensitive_keys", []))]
         for e in session.endpoints[:100]],
    )

    # ── JavaScript Bundles ──
    add("## JavaScript Bundles and Chunks")
    L += _md_table(
        ["JS File", "Size", "Source Map", "Endpoints", "Sinks"],
        [[j.file_url[:70], j.size, "yes" if j.source_map_accessible else
          ("ref" if j.source_map_url else "no"), len(j.endpoints), len(j.sinks)]
         for j in session.js[:60]],
    )

    # ── Source Maps ──
    add("## Source Maps")
    L += _md_table(
        ["JS File", "Accessible", "Original Sources (sample)"],
        [[j.file_url[:60], "yes", ", ".join(j.source_map_sources[:4])[:90]]
         for j in smaps[:40]],
    )

    # ── Console Recon ──
    add("## Console Recon")
    add(f"- Counts: security_relevant={console_counts.get('security_relevant', 0)}, "
        f"recon_useful={console_counts.get('recon_useful', 0)}, noise={console_counts.get('noise', 0)}")
    L += _md_table(
        ["Type", "Message", "Source"],
        [[c.type, mask_text(c.message)[:90], (c.source_file or "")[:50]] for c in sec_rel[:40]],
    )

    # ── Failed Requests ──
    add("## Failed Requests and Errors")
    L += _md_table(
        ["Method", "URL", "Failure"],
        [[e.method, e.url[:80], (e.parameters or {}).get("failure", "")] for e in failed[:40]],
    )

    # ── Input Entry Points ──
    add("## Input Entry Points")
    L += _md_table(
        ["Kind", "Name", "Type/Method", "Risky"],
        [[i.kind, i.name[:50], i.field_type or i.method, "yes" if i.risky_intent else ""]
         for i in session.inputs[:80]],
    )

    # ── Authentication & Session ──
    add("## Authentication and Session Analysis")
    if session.auth.login_forms:
        for f in session.auth.login_forms:
            add(f"- Login form: `{f.get('action', '')}` method={f.get('method')} "
                f"password={f.get('password_field')} csrf={f.get('csrf_field')}")
    else:
        add("- No login form detected.")
    if session.auth.session_mechanisms:
        add(f"- Session mechanisms: {', '.join(session.auth.session_mechanisms)}")
    if session.auth.logout_urls:
        add(f"- Logout URLs: {', '.join(session.auth.logout_urls[:5])}")
    lo = session.auth.logout or {}
    if lo.get("verdict"):
        add(f"- Logout invalidation: **{lo['verdict']}** "
            f"(re-check `{lo.get('rechecked_url','')}` → {lo.get('status_after_logout')})")
    for note in session.auth.notes[:10]:
        add(f"- {note}")
    add("")
    if session.auth.access_control:
        add("### Access Control (authed vs anonymous)")
        L_local = _md_table(
            ["URL", "Authed", "Anon", "Verdict"],
            [[a.get("url", "")[:70], a.get("authed_status"), a.get("anon_status"), a.get("verdict")]
             for a in session.auth.access_control[:40]],
        )
        L.extend(L_local)

    # ── Security Headers ──
    add("## Security Headers")
    L += _md_table(["Header", "Status", "Risk", "Purpose"],
                   _security_header_rows(session.response_headers))

    # ── Cookie Analysis ──
    add("## Cookie Analysis")
    L += _md_table(
        ["Cookie", "HttpOnly", "Secure", "SameSite", "Notes"],
        [[c.get("name"), c.get("httpOnly"), c.get("secure"), c.get("sameSite") or "—",
          "" if (c.get("httpOnly") and c.get("secure") and c.get("sameSite")) else "weak flags"]
         for c in session.auth.cookie_flags[:40]],
    )

    # ── XSS Results ──
    add("## XSS Testing Results")
    if session.xss:
        L += _md_table(
            ["URL", "Param", "Context", "Result", "Notes"],
            [[x.url[:60], x.parameter, x.context, x.status, "; ".join(x.notes)[:60]]
             for x in session.xss[:50]],
        )
    else:
        add("_Not run (safe-mode on or no parameterized URLs)._")
        add("")

    # ── IDOR Results ──
    add("## IDOR / Access Control Results")
    if session.idor:
        L += _md_table(
            ["URL", "Param", "Result", "A", "B", "Notes"],
            [[i.url[:55], i.parameter, i.status, i.a_status, i.b_status, "; ".join(i.notes)[:50]]
             for i in session.idor[:50]],
        )
    else:
        add("_No IDOR candidates produced._")
        add("")

    # ── WebSocket / SSE ──
    add("## WebSocket / SSE Traffic")
    if session.websockets or session.sse:
        wsurls = sorted({w.get("url", "") for w in session.websockets})
        for u in wsurls[:10]:
            frames = [w for w in session.websockets if w.get("url") == u and w.get("dir") in ("sent", "recv")]
            add(f"- `{u}` — {len(frames)} frame(s) captured")
        for s in session.sse[:10]:
            add(f"- SSE: `{s.get('url', '')}`")
        add("")
    else:
        add("_No WebSocket/SSE traffic observed._")
        add("")

    # ── Tokens & Client Secrets ──
    add("## Tokens & Client-Side Secrets")
    if session.tokens:
        L += _md_table(
            ["Location", "Alg", "Claims", "Severity", "Notes"],
            [[t.get("location"), t.get("alg"),
              ", ".join(f"{k}={v}" for k, v in (t.get("claims") or {}).items())[:60],
              t.get("severity"), "; ".join(t.get("notes", []))[:70]]
             for t in session.tokens[:30]],
        )
    else:
        add("_No JWTs found in storage/cookies._")
        add("")
    if session.globals_secrets:
        add("Runtime secrets in window globals:")
        for g in session.globals_secrets[:15]:
            add(f"- `window.{g.get('key')}` → {g.get('sample')}")
        add("")

    # ── postMessage & CSP ──
    add("## postMessage Listeners")
    pm = session.postmessage or {}
    add(f"- Listeners: {pm.get('total_listeners', 0)} | without origin check: "
        f"**{pm.get('without_origin_check', 0)}** ({pm.get('severity', 'info')})")
    if pm.get("note"):
        add(f"- {pm['note']}")
    add("")
    add("## Content-Security-Policy")
    csp = session.csp or {}
    add(f"- Present: `{csp.get('present', False)}` | severity: {csp.get('severity', 'info')}")
    for iss in (csp.get("issues") or [])[:8]:
        add(f"- {iss}")
    add("")

    # ── GraphQL ──
    add("## GraphQL")
    gq = session.graphql or {}
    if gq.get("introspection_enabled"):
        add(f"- **Introspection enabled** at `{gq.get('endpoint')}` — {gq.get('type_count')} types")
        add(f"- Queries: {', '.join(gq.get('query_fields', [])[:20])}")
        add(f"- Mutations: {', '.join(gq.get('mutation_fields', [])[:20])}")
    elif gq.get("endpoints"):
        add(f"- GraphQL endpoint(s) found but introspection disabled: {', '.join(gq.get('endpoints', []))}")
    else:
        add("_No GraphQL endpoint detected._")
    add("")

    # ── DOM XSS ──
    add("## DOM-based XSS")
    if session.dom_xss:
        L += _md_table(
            ["URL", "Result", "Sink", "Severity"],
            [[d.get("url", "")[:60], d.get("status"), d.get("sink", ""), d.get("severity")]
             for d in session.dom_xss if d.get("status") != "no_sink"][:30] or [["—", "no sinks reached", "", "info"]],
        )
    else:
        add("_Not run (safe-mode on or XSS testing disabled)._")
        add("")

    # ── Client Trust / Broken Access Control ──
    add("## Client-Side Trust / Broken Access Control")
    if session.client_trust:
        L += _md_table(
            ["Privileged Endpoint", "Anon", "Authed", "Verdict", "Severity"],
            [[c.get("url", "")[:55], c.get("anon_status"), c.get("authed_status"),
              c.get("verdict"), c.get("severity")]
             for c in session.client_trust[:40]],
        )
    else:
        add("_Not run (safe-mode on or access testing disabled)._")
        add("")

    # ── Race Condition Candidates ──
    add("## Race Condition Candidates")
    if session.race:
        L += _md_table(
            ["Endpoint", "Method", "Category", "Probe", "Suggested Manual Test"],
            [[c.url[:55], c.method, c.category, c.probe_status, c.suggested_test[:60]]
             for c in session.race[:40]],
        )
    else:
        add("_No race-prone operations detected._")
        add("")

    # ── Top N Promising Endpoints ──
    add("## Top Promising Endpoints for Manual Testing")
    L += _md_table(
        ["Rank", "Endpoint", "Method", "Why"],
        [[str(i), u[:80], m, ", ".join(reasons)]
         for i, (u, m, reasons) in enumerate(top_endpoints(session, limit=10), 1)],
    )

    # ── Confirmed Findings ──
    add("## Confirmed Findings")
    if confirmed:
        for f in confirmed:
            add(f"### {f.title}")
            add(f"- Severity: **{f.severity}** | CWE: {f.cwe or '—'}")
            add(f"- Endpoint: `{f.endpoint}` | Parameter: `{f.parameter or '—'}`")
            if f.impact:
                add(f"- Impact: {f.impact}")
            for step in f.reproduction_steps:
                add(f"  - {step}")
            if f.evidence:
                add(f"- Evidence: {', '.join(e for e in f.evidence if e)}")
            if f.recommendation:
                add(f"- Fix: {f.recommendation}")
            add("")
    else:
        add("_No confirmed findings. Items above are manual leads, not vulnerabilities._")
        add("")

    # ── Not Confirmed ──
    add("## Not Confirmed / False Positives")
    nc = [x for x in session.xss if x.status in {"reflected_only", "blocked_or_encoded"}]
    if nc:
        for x in nc[:30]:
            add(f"- XSS `{x.parameter}` on `{x.url[:60]}` → {x.status} (manual validation)")
    else:
        add("- None recorded.")
    add("")

    # ── Skipped Checks / Decisions ──
    if session.skipped_checks:
        add("## Decisions & Skipped Checks")
        for item in session.skipped_checks:
            add(f"- {item}")
        add("")

    # ── Appendix ──
    add("## Appendix")
    # Show only the evidence subdir name, not the absolute server install path.
    add(f"- Evidence dir: `{Path(session.evidence_dir).name or session.evidence_dir}`")
    add(f"- JS files analyzed: {len(session.js)} | Source maps read: {len(smaps)}")
    add(f"- Routes: {len(session.pages)} | Endpoints: {len(session.endpoints)}")
    add("")

    return "\n".join(str(x) for x in L).rstrip() + "\n"


def top_endpoints(session: SessionState, limit: int = 10) -> list[tuple[str, str, list[str]]]:
    scored = []
    seen = set()
    for ep in session.endpoints:
        key = (ep.method, urlparse(ep.url).path)
        if key in seen:
            continue
        seen.add(key)
        score, reasons = _score_endpoint(ep)
        if score > 0:
            scored.append((score, ep.url, ep.method, reasons))
    scored.sort(key=lambda x: -x[0])
    return [(u, m, r) for _, u, m, r in scored[:limit]]


def write_markdown(session: SessionState, output: str | Path) -> Path:
    output = Path(output)
    atomic_write_text(output, render_markdown(session))
    return output
