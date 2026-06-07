from pathlib import Path

from playwright_agent.models import TechFinding
from playwright_agent.auth_analyzer import analyze_auth_surface
from playwright_agent.idor_mapper import compare_access, extract_candidates
from playwright_agent.asm_bridge import build_playwright_job_options
from playwright_agent.pipeline import PipelineConfig, PlaywrightPentestPipeline
from playwright_agent.tech_detector import build_stack_profile
from playwright_agent.url_utils import extract_surface, in_scope, normalize_url, scope_from_url
from playwright_agent.input_surface import collect_input_surface


def test_normalize_url_dedupes_volatile_query():
    url = normalize_url("https://Example.com/path/?utm_source=x&b=2&a=1#frag")
    assert url == "https://example.com/path?a=1&b=2"


def test_scope_from_url_uses_hostname():
    assert scope_from_url("https://sub.example.com/path") == ["sub.example.com"]


def test_scope_check_accepts_subdomain():
    assert in_scope("https://api.example.com/a", ["example.com"]) is True


def test_extract_surface_finds_links_forms_and_scripts():
    html = """
    <html>
      <body>
        <a href="/dashboard">Dash</a>
        <script src="/assets/app.js"></script>
        <form action="/login" method="post">
          <input type="hidden" name="__VIEWSTATE" value="abc">
          <input type="password" name="password">
        </form>
      </body>
    </html>
    """
    surface = extract_surface(html, "https://example.com/")
    assert "https://example.com/dashboard" in surface["links"]
    assert "https://example.com/assets/app.js" in surface["scripts"]
    assert surface["forms"][0]["action"] == "https://example.com/login"


def test_collect_input_surface_marks_legacy_forms():
    html = """
    <form action="/login" method="post">
      <input type="hidden" name="__VIEWSTATE" value="abc">
      <input type="password" name="password">
    </form>
    """
    items = collect_input_surface(html, "https://example.com/login")
    forms = [i for i in items if i.kind == "form"]
    assert forms and forms[0].risky_intent is False
    assert "password_field" in forms[0].notes
    assert "csrf_field" not in forms[0].notes


def test_stack_profile_skips_viewstate_on_modern_spa():
    findings = [
        TechFinding(name="React", category="frontend_framework", confidence="high", evidence="react-dom", source="html"),
        TechFinding(name="Next.js", category="frontend_framework", confidence="high", evidence="__NEXT_DATA__", source="html"),
    ]
    profile = build_stack_profile(findings, html="<div id='root'></div>")
    assert profile["modern_frontend"] is True
    assert profile["skip_viewstate"] is True
    assert profile["run_viewstate_audit"] is False


def test_stack_profile_enables_viewstate_on_legacy_aspnet():
    findings = [
        TechFinding(name="ASP.NET WebForms", category="backend_framework", confidence="high", evidence="__VIEWSTATE", source="html"),
        TechFinding(name="ASP.NET / IIS", category="backend_framework", confidence="high", evidence="Microsoft-IIS", source="headers"),
    ]
    profile = build_stack_profile(findings, html="__VIEWSTATE __EVENTVALIDATION")
    assert profile["legacy_aspnet"] is True
    assert profile["skip_viewstate"] is False
    assert profile["run_viewstate_audit"] is True


def test_auth_surface_flags_session_cookie_issues():
    cookies = [
        {"name": "sessionid", "value": "abcdef123456", "httpOnly": False, "secure": False, "sameSite": None},
        {"name": "csrftoken", "value": "token", "httpOnly": True, "secure": True, "sameSite": "Lax"},
    ]
    obs = analyze_auth_surface([], cookies, html="Logout")
    assert "sessionid" in [s.lower() for s in obs.session_mechanisms]
    assert any("missing HttpOnly" in n for n in obs.notes)
    assert any("missing Secure" in n for n in obs.notes)
    assert any("Logout-like" in n for n in obs.notes)


def test_idor_candidate_extraction_finds_numeric_ids():
    candidates = extract_candidates([
        "https://example.com/orders/12345",
        "https://example.com/api/users?id=77",
        "https://example.com/profile/view?tab=info",
    ])
    assert any(c.parameter == "12345" for c in candidates)
    assert any(c.parameter == "id" for c in candidates)


def test_idor_compare_without_second_session_marks_not_tested():
    candidates = extract_candidates(["https://example.com/orders/12345"])
    results = compare_access(candidates, auth_state_a=None, auth_state_b=None, evidence_dir="/tmp/idor-test")
    assert results and results[0].status == "not_tested"


# ── New coverage: reporter prioritization, XSS helpers, source maps, round-trip ──

from playwright_agent.models import SessionState, Endpoint, PageSnapshot, InputPoint
from playwright_agent.reporter import top_endpoints, render_markdown
from playwright_agent.xss_tester import _testable_params, _set_param
from playwright_agent.source_map import extract_source_map_url, summarize_source_map
from playwright_agent.browser import goto_resilient, _looks_slow_host


def test_xss_param_helpers():
    assert _testable_params("https://t/search?q=a&id=1") == ["q", "id"]
    assert _testable_params("https://t/path") == []
    assert _set_param("https://t/s?q=a&id=1", "q", "X<>") == "https://t/s?q=X%3C%3E&id=1"


def test_top_endpoints_prioritizes_api_and_sensitive_params():
    s = SessionState(scope=["t"], target="https://t")
    s.endpoints = [
        Endpoint(url="https://t/static/app.css", method="GET", status=200),
        Endpoint(url="https://t/api/users?user_id=5", method="GET", status=200,
                 content_type="application/json",
                 parameters={"sensitive_keys": ["user_id"]}),
    ]
    top = top_endpoints(s, limit=5)
    assert top and "/api/users" in top[0][0]
    assert "API endpoint" in top[0][2]


def test_source_map_helpers():
    assert extract_source_map_url("x=1\n//# sourceMappingURL=app.js.map") == "app.js.map"
    assert extract_source_map_url("no map here") is None
    summ = summarize_source_map({"sources": ["src/a.ts", "src/b.ts"], "names": []})
    assert summ["accessible"] and summ["sources"] == ["src/a.ts", "src/b.ts"]


def test_goto_resilient_falls_back_through_wait_states():
    class _Timeout(Exception):
        pass

    class FakePage:
        def __init__(self):
            self.calls = []
            self.url = ""
        def goto(self, url, wait_until="domcontentloaded", timeout=None):
            self.calls.append((url, wait_until, timeout))
            if wait_until == "domcontentloaded":
                raise _Timeout("Timeout 15000ms exceeded")
            self.url = url
            return type("Resp", (), {"status": 200})()

    page = FakePage()
    resp, err, used_timeout, used_wait = goto_resilient(page, "https://example.com", base_timeout=15)
    assert resp is not None and err is None
    assert used_wait in ("load", "commit")
    assert used_timeout >= 15000
    assert len(page.calls) >= 2


def test_slow_host_hint_detection():
    assert _looks_slow_host("https://mail.example.com") is True
    assert _looks_slow_host("https://example.com") is False


def test_session_roundtrip_rebuilds_nested_pages(tmp_path):
    s = SessionState(scope=["t"], target="https://t")
    s.pages = [PageSnapshot(url="https://t/x", depth=1,
                            inputs=[InputPoint(kind="form", name="login")])]
    path = tmp_path / "session.json"
    s.save(path)
    loaded = SessionState.load(path)
    assert isinstance(loaded.pages[0].inputs[0], InputPoint)
    assert loaded.pages[0].inputs[0].name == "login"
    # report renders from a loaded session without raising
    assert "Attack Surface Report" in render_markdown(loaded)


def test_playwright_inventory_persists_and_validates_hosts(tmp_path, monkeypatch):
    cfg = PipelineConfig(
        url="https://example.com",
        output=str(tmp_path / "report.md"),
        evidence_dir=str(tmp_path / "evidence"),
        scope=["example.com"],
        headless=True,
        safe_mode=True,
    )
    pipe = PlaywrightPentestPipeline(cfg)

    probes = []

    def fake_probe(hosts):
        probes.extend(hosts)
        out = []
        for host in hosts:
            out.append({
                "host": host,
                "url": f"https://{host}",
                "scheme": "https",
                "status_code": 200,
                "content_type": "text/html",
                "title": "Example",
                "server": "nginx",
                "final_url": f"https://{host}",
                "error": "",
            })
        return out

    monkeypatch.setattr(pipe, "_probe_hosts_httpx", fake_probe)

    validated = pipe._sync_host_inventory(
        [
            "https://app.example.com/login",
            "https://api.example.com/v1/users",
            "https://app.example.com/dashboard",
        ],
        source="browser",
    )

    assert probes == ["app.example.com", "api.example.com"]
    assert len(validated) == 2
    assert pipe.session.discovered_hosts == ["api.example.com", "app.example.com"]
    assert pipe.session.validated_hosts == ["api.example.com", "app.example.com"]
    assert pipe.session.pending_hosts == []
    assert any(item["host"] == "app.example.com" and item["status"] == "validated" for item in pipe.session.host_inventory)
    assert (tmp_path / "evidence" / "session.partial.json").exists()


def test_build_playwright_job_options_uses_settings_defaults():
    company = {"domains": ["example.com"]}
    opts = build_playwright_job_options(company, settings={
        "playwright_safe_mode": "no",
        "playwright_headless": "0",
        "playwright_allow_external": "1",
        "playwright_trace": "yes",
        "playwright_max_pages": "77",
        "playwright_max_depth": "4",
        "playwright_timeout": "31",
        "playwright_slow_mo": "12",
        "playwright_user_agent": "UA/1.0",
        "playwright_auth_state": "/tmp/auth.json",
        "playwright_auth_state_b": "/tmp/auth-b.json",
    })
    assert opts["safe_mode"] is False
    assert opts["headless"] is False
    assert opts["allow_external"] is True
    assert opts["trace"] is True
    assert opts["max_pages"] == 77
    assert opts["max_depth"] == 4
    assert opts["timeout"] == 31
    assert opts["slow_mo"] == 12
    assert opts["user_agent"] == "UA/1.0"
    assert opts["auth_state"] == "/tmp/auth.json"
    assert opts["auth_state_b"] == "/tmp/auth-b.json"


# ── Race mapper (Fase 17) + logout discovery (Fase 15) ──

from playwright_agent.race_mapper import map_candidates
from playwright_agent.auth_analyzer import find_logout_urls
from playwright_agent.models import Endpoint as _Ep


def test_race_map_classifies_and_flags_destructive():
    eps = [
        _Ep(url="https://t/api/coupon/redeem?c=1", method="POST"),
        _Ep(url="https://t/cart/checkout/transfer", method="POST"),
        _Ep(url="https://t/static/app.js", method="GET"),
    ]
    cands = map_candidates(eps, [])
    cats = {c.category: c for c in cands}
    assert "coupon" in cats and cats["coupon"].method == "POST"
    # checkout/transfer is destructive intent → flagged, never auto-probed
    assert any(c.risky_intent for c in cands)
    # static asset is not a race candidate
    assert not any("app.js" in c.url for c in cands)


def test_find_logout_urls_in_scope_only():
    links = ["https://t/account/logout", "https://t/home", "https://evil/logout"]
    out = find_logout_urls(links, ["t"])
    assert out == ["https://t/account/logout"]


# ── Extended browser-only analyzers (token/CSP/postMessage) ──

import base64, json as _json
from playwright_agent.token_analyzer import decode_jwt, analyze_tokens
from playwright_agent.csp_analyzer import analyze_csp
from playwright_agent.postmessage_analyzer import analyze_postmessage


def _mkjwt(payload, alg="HS256"):
    b = lambda d: base64.urlsafe_b64encode(_json.dumps(d).encode()).rstrip(b"=").decode()
    return b({"alg": alg, "typ": "JWT"}) + "." + b(payload) + ".sigAbc123Def456"


def test_jwt_decode_and_storage_flag():
    tok = _mkjwt({"sub": "1", "role": "admin", "exp": 9999999999})
    dec = decode_jwt(tok)
    assert dec["alg"] == "HS256" and dec["claims"]["role"] == "admin"
    findings = analyze_tokens({"localStorage": {"auth": tok}}, [])
    assert findings and findings[0]["severity"] == "medium"
    assert any("localStorage" in n for n in findings[0]["notes"])


def test_jwt_alg_none_is_high():
    tok = _mkjwt({"sub": "1"}, alg="none")
    findings = analyze_tokens({}, [{"name": "jwt", "value": tok}])
    assert findings and findings[0]["severity"] == "high"


def test_csp_flags_unsafe_inline():
    r = analyze_csp({"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"})
    assert r["present"] and any("unsafe-inline" in i for i in r["issues"])
    assert analyze_csp({})["present"] is False


def test_postmessage_flags_missing_origin():
    r = analyze_postmessage([{"hasOriginCheck": False, "sample": "fn"}, {"hasOriginCheck": True, "sample": "fn2"}])
    assert r["without_origin_check"] == 1 and r["severity"] == "medium"
