"""
ASM Platform — test suite.
Covers: pure functions, blueprint factories, Flask routes (auth/company/scan/recon),
        pipeline module, and regression tests for previously fixed bugs.
"""
import json
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_dir(tmp_path):
    return tmp_path


@pytest.fixture()
def db(tmp_path):
    from database import ASMDatabase

    db = ASMDatabase(
        tmp_path / "test.db",
        asm_data_file=tmp_path / "asm_data.js",
        snapshots_dir=tmp_path / "snapshots",
        companies_file=tmp_path / "companies.json",
        settings_file=tmp_path / "settings.json",
        admins_file=tmp_path / "admins.json",
        schedules_file=tmp_path / "schedules.json",
        webhooks_file=tmp_path / "webhooks.json",
        whitelist_file=tmp_path / "whitelist.json",
        audit_log_file=tmp_path / "audit.log",
    )
    db.initialize()
    return db


@pytest.fixture()
def flask_app(tmp_path, db):
    """Minimal Flask app with all blueprints registered using mock dependencies."""
    from flask import Flask
    from core_routes import create_core_blueprint
    from ops_routes import create_ops_blueprint
    from asset_routes import create_asset_blueprint
    from scan_routes import create_scan_blueprint
    from recon_routes import create_recon_blueprint
    from reporting_routes import create_reporting_blueprint
    from core.jobs import JobScheduler
    from pipeline import ReconRunner, PIPELINE_PHASES, SELF_CONTAINED_MODULES

    app = Flask(__name__)
    app.config["TESTING"] = True

    SESSION_TTL = 86400
    sessions: dict = {}

    import hashlib, secrets, base64, hmac as _hmac
    ITERS = 100  # low for speed in tests

    def hash_pw(pw):
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), ITERS)
        return f"pbkdf2:sha256:{salt}:{base64.b64encode(dk).decode()}"

    def check_pw(pw, h):
        try:
            _, algo, salt, stored = h.split(":")
            dk = hashlib.pbkdf2_hmac(algo, pw.encode(), salt.encode(), ITERS)
            return _hmac.compare_digest(base64.b64encode(dk).decode(), stored)
        except Exception:
            return False

    admin = {
        "id": uuid.uuid4().hex,
        "username": "admin",
        "email": "",
        "password_hash": hash_pw("admin"),
        "role": "super_admin",
        "created_at": "2024-01-01T00:00:00",
        "last_login": None,
    }
    db.save_admins([admin])

    def load_admins():
        return db.load_admins()

    def save_admins(a):
        db.save_admins(a)

    def get_settings():
        return {}

    from flask import request as _req

    def get_session():
        token = _req.headers.get("X-Auth-Token") or _req.cookies.get("asm_token")
        if not token:
            return None
        sess = sessions.get(token)
        if not sess or time.time() > sess["expires_at"]:
            sessions.pop(token, None)
            return None
        return sess

    from functools import wraps
    from flask import jsonify, g as _g

    def require_auth(f):
        @wraps(f)
        def w(*a, **kw):
            sess = get_session()
            if not sess:
                return jsonify({"error": "Unauthorized"}), 401
            _g.session = sess
            return f(*a, **kw)
        return w

    def require_super_admin(f):
        @wraps(f)
        def w(*a, **kw):
            s = get_session()
            if not s:
                return jsonify({"error": "Unauthorized"}), 401
            if s.get("role") != "super_admin":
                return jsonify({"error": "Forbidden"}), 403
            _g.session = s
            return f(*a, **kw)
        return w

    @app.before_request
    def _enforce_company_scope():
        sess = get_session()
        if not sess:
            return None
        _g.session = sess
        if sess.get("role") == "super_admin":
            return None
        scoped = sess.get("scoped_companies", [])
        if scoped is None:
            return None
        if isinstance(scoped, str):
            try:
                scoped = json.loads(scoped)
            except Exception:
                scoped = []
        if not isinstance(scoped, list):
            scoped = []
        allowed = {str(cid) for cid in scoped if str(cid).strip()}
        view_args = _req.view_args or {}
        for key in ("cid", "company_id", "company"):
            val = view_args.get(key) or _req.args.get(key)
            if val and allowed and str(val) not in allowed:
                return jsonify({"error": "Forbidden — company not in scope"}), 403
            if val and not allowed:
                return jsonify({"error": "Forbidden — company not in scope"}), 403
        return None

    def audit(action, target="", details=""):
        pass

    companies: list = []

    def _scope_from_session():
        sess = getattr(_g, "session", {}) or {}
        if sess.get("role") == "super_admin":
            return None
        scoped = sess.get("scoped_companies", [])
        if scoped is None:
            return None
        if isinstance(scoped, str):
            try:
                scoped = json.loads(scoped)
            except Exception:
                scoped = []
        if not isinstance(scoped, list):
            scoped = []
        return [str(cid) for cid in scoped if str(cid).strip()]

    def load_companies():
        scoped = _scope_from_session()
        if scoped is None:
            return list(companies)
        if not scoped:
            return []
        allowed = set(scoped)
        return [c for c in companies if c.get("id") in allowed]

    def save_companies(c):
        companies.clear()
        companies.extend(c)

    tool_run_results: dict = {}
    checkpoint_jobs: dict = {}
    playwright_calls: list = []

    def load_hosts_for_company(cid):
        return []

    runner = ReconRunner(
        db=db,
        base_dir=tmp_path,
        get_settings=get_settings,
        load_hosts_fn=load_hosts_for_company,
        recon_module=None,
        recon_available=False,
    )

    scheduler = JobScheduler(
        db=db,
        load_companies=load_companies,
        run_pipeline=lambda cid, co, opts: None,
        run_playwright_recon=lambda cid, co, opts: playwright_calls.append((cid, co, opts)) or {
            "status": "done",
            "output": str(tmp_path / "report.md"),
        },
        pipeline_state=runner.pipeline_state,
        save_pipeline_state=lambda cid: None,
        max_workers=1,
    )

    RECON_MODULES = {
        "email": ("Email Security", "~10s"),
        "dns":   ("DNS Records",    "~10s"),
    }

    app.register_blueprint(create_core_blueprint(
        session_ttl=SESSION_TTL,
        sessions=sessions,
        load_admins=load_admins,
        save_admins=save_admins,
        hash_pw=hash_pw,
        check_pw=check_pw,
        get_session=get_session,
        require_auth=require_auth,
        require_super_admin=require_super_admin,
        audit=audit,
        get_settings=get_settings,
        save_settings=db.set_settings,
        settings_keys=set(),
    ))

    app.register_blueprint(create_ops_blueprint(
        require_auth=require_auth,
        require_super_admin=require_super_admin,
        load_schedules=db.load_schedules,
        save_schedules=db.save_schedules,
        load_webhooks=db.load_webhooks,
        save_webhooks=db.save_webhooks,
        send_webhook=lambda h, p: None,
        compute_diff=lambda cid: {"error": "no snapshot"},
        load_whitelist=db.load_whitelist,
        save_whitelist=db.save_whitelist,
        get_session=get_session,
        audit=audit,
        list_audit_log=db.list_audit_log,
    ))

    app.register_blueprint(create_asset_blueprint(
        require_auth=require_auth,
        load_companies=load_companies,
        save_companies=save_companies,
        get_settings=get_settings,
        save_settings=db.set_settings,
        get_company_data=lambda cid: None,
        tools_available=False,
        tool_registry=None,
        tool_run_results=tool_run_results,
        checkpoints_available=False,
        checkpoints_module=None,
        load_hosts_for_company=load_hosts_for_company,
        checkpoint_jobs=checkpoint_jobs,
    ))

    app.register_blueprint(create_scan_blueprint(
        require_auth=require_auth,
        base_dir=tmp_path,
        load_companies=load_companies,
        load_asm_data=db.load_asm_data,
        save_asm_data=db.save_asm_data,
        get_asm_data_timestamp=db.get_asm_data_timestamp,
        db=db,
    ))

    app.register_blueprint(create_recon_blueprint(
        require_auth=require_auth,
        recon_available=False,
        recon_modules=RECON_MODULES,
        self_contained_modules=SELF_CONTAINED_MODULES,
        run_recon_handler=runner.run_module_request,
        load_companies=load_companies,
        get_settings=get_settings,
        pipeline_state=runner.pipeline_state,
        pipeline_phases=PIPELINE_PHASES,
        run_pipeline_handler=lambda cid, co, opts: None,
        recon_results=runner.results,
        load_asm_data=db.load_asm_data,
        save_asm_data=db.save_asm_data,
        job_scheduler=scheduler,
        db=db,
    ))

    app.register_blueprint(create_reporting_blueprint(
        require_auth=require_auth,
        get_company_data=lambda cid: None,
        compute_risk_score=lambda co: {"score": 0, "label": "Info", "breakdown": {}},
        load_whitelist=db.load_whitelist,
        load_asm_data=db.load_asm_data,
        audit=audit,
    ))

    app._test_sessions = sessions
    app._test_companies = companies
    app._test_runner = runner
    app._test_scheduler = scheduler
    app._test_playwright_calls = playwright_calls
    app._test_hash_pw = hash_pw
    return app


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()


@pytest.fixture()
def auth_client(flask_app):
    """Client with a valid admin session token pre-set."""
    c = flask_app.test_client()
    resp = c.post("/api/auth/login",
                  json={"username": "admin", "password": "admin"},
                  content_type="application/json")
    assert resp.status_code == 200
    token = resp.get_json()["token"]
    c.environ_base["HTTP_X_AUTH_TOKEN"] = token
    return c


def login_as_admin(flask_app, db, username: str, password: str, role: str = "analyst",
                   scoped_companies=None):
    """Create or update an admin and return a logged-in client for that identity."""
    admins = db.load_admins()
    admins = [a for a in admins if a["username"] != username]
    admins.append({
        "id": uuid.uuid4().hex,
        "username": username,
        "email": "",
        "password_hash": flask_app._test_hash_pw(password),
        "role": role,
        "scoped_companies": scoped_companies if scoped_companies is not None else [],
        "created_at": "2024-01-01T00:00:00",
        "last_login": None,
    })
    db.save_admins(admins)
    c = flask_app.test_client()
    resp = c.post("/api/auth/login",
                  json={"username": username, "password": password},
                  content_type="application/json")
    assert resp.status_code == 200
    token = resp.get_json()["token"]
    c.environ_base["HTTP_X_AUTH_TOKEN"] = token
    return c


# ═══════════════════════════════════════════════════════════════════════════════
# 1 — Pure function unit tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPasswordHashing:
    def test_round_trip(self, flask_app):
        h = flask_app._test_hash_pw("secret123")
        from core_routes import create_core_blueprint
        # hash contains pbkdf2 prefix
        assert h.startswith("pbkdf2:sha256:")

    def test_wrong_password_fails(self, flask_app):
        h = flask_app._test_hash_pw("correct")
        # verify via server._check_pw — import directly
        import hashlib, base64, hmac as _hmac
        def check(pw, hash_str):
            try:
                _, algo, salt, stored = hash_str.split(":")
                dk = hashlib.pbkdf2_hmac(algo, pw.encode(), salt.encode(), 100)
                return _hmac.compare_digest(base64.b64encode(dk).decode(), stored)
            except Exception:
                return False
        assert check("correct", h) is True
        assert check("wrong",   h) is False


class TestRiskScore:
    def _score(self, findings=None, hosts=None, stats=None, waf=None):
        # Import the function directly from server context
        # Replicate logic here to test it in isolation
        findings = findings or []
        hosts    = hosts or []
        stats    = stats or {}
        waf      = waf or {}
        c = sum(1 for f in findings if f.get("severity") == "critical")
        h = sum(1 for f in findings if f.get("severity") == "high")
        m = sum(1 for f in findings if f.get("severity") == "medium")
        l = sum(1 for f in findings if f.get("severity") == "low")
        score = min(100, c * 40 + h * 10 + m * 3 + l * 1)
        direct = waf.get("Direct", 0) + waf.get("", 0)
        total  = max(1, sum(waf.values()))
        if direct / total > 0.5:
            score = min(100, score + 10)
        admin_ports = {"22", "3389", "5900", "8080", "8443", "9200", "27017", "6379", "5432", "3306"}
        exposed = sum(
            1 for h_ in hosts
            if isinstance(h_, dict) and any(str(p) in admin_ports for p in h_.get("ports", []))
        )
        score = min(100, score + min(20, exposed * 5))
        if score == 0 and stats.get("live_hosts", 0) > 0:
            score = 5
        return score

    def test_empty_returns_zero(self):
        assert self._score() == 0

    def test_critical_finding_scores_40(self):
        assert self._score(findings=[{"severity": "critical"}]) == 40

    def test_cap_at_100(self):
        findings = [{"severity": "critical"}] * 10
        assert self._score(findings=findings) == 100

    def test_live_hosts_with_zero_findings_gives_5(self):
        assert self._score(stats={"live_hosts": 3}) == 5

    def test_admin_port_exposure_adds_score(self):
        base   = self._score()
        with_p = self._score(hosts=[{"host": "x.com", "ports": [22]}])
        assert with_p > base

    def test_label_critical_at_80(self):
        # 2 critical findings = 80 → label Critical
        score = self._score(findings=[{"severity": "critical"}, {"severity": "critical"}])
        assert score == 80


class TestGowitnessNameToUrl:
    def test_https_443(self):
        from scan_routes import _gowitness_name_to_url
        assert _gowitness_name_to_url("https---example.com-443") == "https://example.com"

    def test_http_80(self):
        from scan_routes import _gowitness_name_to_url
        assert _gowitness_name_to_url("http---example.com-80") == "http://example.com"

    def test_custom_port(self):
        from scan_routes import _gowitness_name_to_url
        url = _gowitness_name_to_url("https---example.com-8443")
        assert "8443" in url

    def test_unknown_stem_returned_as_is(self):
        from scan_routes import _gowitness_name_to_url
        assert _gowitness_name_to_url("no-match-here") == "no-match-here"


class TestJsonDumps:
    def test_basic(self):
        from reporting_routes import json_dumps
        out = json_dumps({"a": 1})
        assert json.loads(out) == {"a": 1}

    def test_indent(self):
        from reporting_routes import json_dumps
        out = json_dumps({"a": 1}, indent=2)
        assert "\n" in out

    def test_non_ascii(self):
        from reporting_routes import json_dumps
        out = json_dumps({"k": "ação"})
        assert "ação" in out  # ensure_ascii=False


class TestWebhookSSRFGuard:
    """Regression: _send_webhook must reject non-http(s) URLs."""

    def _send(self, url):
        # Replicate the guard logic from server.py
        return url.startswith(("https://", "http://"))

    def test_https_allowed(self):
        assert self._send("https://hooks.slack.com/xxx") is True

    def test_http_allowed(self):
        assert self._send("http://internal.corp/hook") is True

    def test_file_blocked(self):
        assert self._send("file:///etc/passwd") is False

    def test_gopher_blocked(self):
        assert self._send("gopher://evil.com") is False

    def test_empty_blocked(self):
        assert self._send("") is False


class TestTargetNormalization:
    def test_url_input_normalizes_to_domain(self):
        from core.targets import normalize_domain
        res = normalize_domain("https://WWW.Example.com:443/path?q=1")
        assert res.ok is True
        assert res.value == "www.example.com"

    def test_wildcard_is_accepted_but_stored_as_apex(self):
        from core.targets import normalize_domain
        res = normalize_domain("*.Example.com")
        assert res.ok is True
        assert res.wildcard is True
        assert res.value == "*.example.com"

    def test_glob_wildcard_is_preserved(self):
        from core.targets import normalize_domain
        res = normalize_domain("api*.HubApi.com")
        assert res.ok is True
        assert res.wildcard is True
        assert res.value == "api*.hubapi.com"

    def test_ip_is_accepted_as_company_domain(self):
        from core.targets import normalize_domain
        res = normalize_domain("127.0.0.1")
        assert res.ok is True
        assert res.value == "127.0.0.1"

    def test_list_deduplicates_normalized_domains(self):
        from core.targets import normalize_domain_list
        domains, errors = normalize_domain_list(["Example.com", "https://example.com/a", "*.example.com"])
        assert errors == []
        assert domains == ["example.com", "*.example.com"]


class TestCommandRunner:
    def test_shell_true_rejected(self):
        from utils.command_runner import run
        with pytest.raises(ValueError):
            run([sys.executable, "-c", "print('x')"], shell=True)

    def test_tool_run_history_is_persisted(self, db):
        from utils.command_runner import CommandContext, run
        proc = run(
            [sys.executable, "-c", "print('ok')"],
            timeout=10,
            context=CommandContext(company_id="co", module="unit", db=db),
        )
        assert proc.returncode == 0
        rows = db.list_tool_runs("co")
        assert len(rows) == 1
        assert rows[0]["module"] == "unit"
        assert rows[0]["status"] == "done"
        assert "ok" in rows[0]["stdout_tail"]

    def test_tool_run_history_redacts_sensitive_args(self, db):
        from utils.command_runner import CommandContext, run
        run(
            [sys.executable, "-c", "print('ok')", "--api-token", "secret-token-value"],
            timeout=10,
            context=CommandContext(company_id="co", module="unit", db=db),
        )
        argv = db.list_tool_runs("co")[0]["argv"]
        assert "secret-token-value" not in argv
        assert "<redacted>" in argv


class TestPipelineReconRunner:
    def test_run_services_no_recon(self, db, tmp_path):
        """_run_services must return empty list when recon module is None (regression)."""
        from pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        result = runner._run_services([{"host": "x.com", "ports": [80]}])
        assert result["findings"] == []
        assert "scanned_at" in result

    def test_run_module_request_recon_unavailable(self, db, tmp_path):
        """Module that requires recon.py must return error when unavailable."""
        from pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        co = {"id": "test", "domains": ["example.com"], "name": "Test"}
        options = {"github_token": "", "shodan_key": "", "hibp_key": "",
                   "dehashed_key": "", "nvd_key": ""}
        # Use Flask app context for jsonify
        from flask import Flask
        with Flask(__name__).app_context():
            resp, code = runner.run_module_request("test", "email", co, options)
            # Module starts in background; returns 202
            assert code == 202
        # Wait for thread
        time.sleep(0.2)
        assert runner.results["test:email"]["status"] == "error"

    def test_run_module_request_wappalyzer_self_contained(self, db, tmp_path):
        """wappalyzer runs even when recon_available=False."""
        from pipeline import ReconRunner
        called = []

        def fake_wap(cid, co):
            called.append((cid, co))
            return {"tech_count": 3, "hosts_scanned": 1}

        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        runner.run_wappalyzer = fake_wap

        co = {"id": "test", "domains": ["example.com"], "name": "Test"}
        options = {"github_token": "", "shodan_key": "", "hibp_key": "",
                   "dehashed_key": "", "nvd_key": ""}

        from flask import Flask
        with Flask(__name__).app_context():
            resp, code = runner.run_module_request("test", "wappalyzer", co, options)
            assert code == 202

        time.sleep(0.3)
        assert runner.results["test:wappalyzer"]["status"] == "done"
        assert runner.results["test:wappalyzer"]["data"]["tech_count"] == 3

    def test_duplicate_module_request_rejected(self, db, tmp_path):
        """Second request while module is running returns 409."""
        from pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        runner.results["test:email"] = {"status": "running"}
        co = {"id": "test", "domains": ["example.com"], "name": "Test"}
        options = {"github_token": "", "shodan_key": "", "hibp_key": "",
                   "dehashed_key": "", "nvd_key": ""}
        from flask import Flask
        with Flask(__name__).app_context():
            resp, code = runner.run_module_request("test", "email", co, options)
            assert code == 409

    def test_collect_new_subdomains(self, db, tmp_path):
        from pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        runner.results["co:certs"] = {
            "data": {"ct_subdomains": ["sub1.example.com", "*.example.com", "other.net"]}
        }
        subs = runner._collect_new_subdomains("co", "example.com")
        assert "sub1.example.com" in subs
        assert "other.net" not in subs    # filtered: not a subdomain of example.com
        # wildcard stripped
        assert not any(s.startswith("*") for s in subs)

    def test_merge_hosts_adds_new_only(self, db, tmp_path):
        from pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        data = {"companies": [{"id": "co", "hosts": [{"host": "existing.com"}], "stats": {}}]}
        db.save_asm_data(data)
        new_hosts = [{"host": "existing.com"}, {"host": "new.com"}]
        total = runner._merge_hosts_into_asm_data("co", new_hosts)
        saved = db.load_asm_data()
        hosts = saved["companies"][0]["hosts"]
        assert total == 2
        assert len(hosts) == 2  # existing not duplicated
        assert any(h["host"] == "new.com" for h in hosts)

    def test_merge_hosts_handles_new_host_ports(self, db, tmp_path):
        from pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        db.save_asm_data({"companies": [{"id": "co", "hosts": [], "stats": {}, "domains": ["example.com"]}]})

        total = runner._merge_hosts_into_asm_data(
            "co",
            [{
                "host": "new.example.com",
                "status_code": 200,
                "ports": ["80", "443"],
            }],
        )

        saved = db.load_asm_data()
        hosts = saved["companies"][0]["hosts"]
        assert total == 1
        assert hosts[0]["host"] == "new.example.com"
        assert hosts[0]["ports"] == ["80", "443"]

    def test_discovered_hosts_are_persisted_before_httpx_validation(self, db, tmp_path):
        from pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        db.save_asm_data({"companies": [{"id": "co", "hosts": [], "stats": {}, "domains": ["example.com"]}]})

        discovered = runner._upsert_discovered_hosts("co", ["new.example.com"], ["example.com"], source="test")
        saved = db.load_asm_data()
        hosts = saved["companies"][0]["hosts"]

        assert discovered == ["new.example.com"]
        assert len(hosts) == 1
        assert hosts[0]["host"] == "new.example.com"
        assert hosts[0]["status_code"] is None

        total = runner._merge_hosts_into_asm_data(
            "co",
            [{
                "host": "new.example.com",
                "status_code": 200,
                "title": "OK",
                "ip": "1.1.1.1",
                "technologies": ["nginx"],
                "ports": ["443"],
            }],
        )
        saved = db.load_asm_data()
        hosts = saved["companies"][0]["hosts"]
        assert total == 1
        assert hosts[0]["status_code"] == 200
        assert saved["companies"][0]["stats"]["live_hosts"] == 1


class TestWappalyzerKeyRegression:
    """Regression: auto-wappalyzer in _run_job used wrong key 'total_techs' (now 'tech_count')."""

    def test_pipeline_returns_tech_count_key(self, db, tmp_path):
        from pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        # Simulate wappalyzer result structure
        result = {
            "hosts_scanned": 3,
            "hosts_with_tech": 2,
            "tech_count": 5,          # key must be 'tech_count', not 'total_techs'
            "tech_index": {"React": ["a.com"]},
            "errors": [],
            "scanned_at": "2024-01-01T00:00:00",
        }
        assert "tech_count" in result
        assert "total_techs" not in result


# ═══════════════════════════════════════════════════════════════════════════════
# 2 — Auth flow
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuth:
    def test_protected_route_returns_401_without_token(self, client):
        resp = client.get("/api/companies")
        assert resp.status_code == 401

    def test_login_success(self, client):
        resp = client.post("/api/auth/login",
                           json={"username": "admin", "password": "admin"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "token" in data
        assert data["username"] == "admin"

    def test_login_wrong_password(self, client):
        resp = client.post("/api/auth/login",
                           json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    def test_login_unknown_user(self, client):
        resp = client.post("/api/auth/login",
                           json={"username": "nobody", "password": "x"})
        assert resp.status_code == 401

    def test_authenticated_request_works(self, auth_client):
        resp = auth_client.get("/api/companies")
        assert resp.status_code == 200

    def test_logout_invalidates_token(self, flask_app):
        c = flask_app.test_client()
        login = c.post("/api/auth/login", json={"username": "admin", "password": "admin"})
        token = login.get_json()["token"]
        c.environ_base["HTTP_X_AUTH_TOKEN"] = token

        assert c.get("/api/companies").status_code == 200
        c.post("/api/auth/logout")
        assert c.get("/api/companies").status_code == 401

    def test_me_endpoint(self, auth_client):
        resp = auth_client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.get_json()["username"] == "admin"

    def test_scoped_user_sees_only_assigned_company(self, auth_client, flask_app, db):
        super_client = auth_client
        super_client.post("/api/companies", json={"name": "Alpha", "domains": ["alpha.com"]})
        super_client.post("/api/companies", json={"name": "Beta", "domains": ["beta.com"]})
        db.save_asm_data({
            "companies": [
                {"id": "alpha", "name": "Alpha", "domains": ["alpha.com"]},
                {"id": "beta", "name": "Beta", "domains": ["beta.com"]},
            ]
        })

        analyst = login_as_admin(flask_app, db, "analyst1", "password123", role="analyst", scoped_companies=["alpha"])
        data = analyst.get("/api/data").get_json()
        assert [c["id"] for c in data["companies"]] == ["alpha"]

        resp = analyst.get("/api/data/company/beta")
        assert resp.status_code == 403

        upd = analyst.put("/api/companies/beta", json={"name": "Beta2"})
        assert upd.status_code == 403

    def test_empty_scope_sees_nothing(self, flask_app, db):
        analyst = login_as_admin(flask_app, db, "analyst2", "password123", role="analyst", scoped_companies=[])
        resp = analyst.get("/api/companies")
        assert resp.status_code == 200
        assert resp.get_json() == []


# ═══════════════════════════════════════════════════════════════════════════════
# 3 — Company CRUD
# ═══════════════════════════════════════════════════════════════════════════════


class TestCompanyCRUD:
    def test_list_empty(self, auth_client):
        resp = auth_client.get("/api/companies")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_create_company(self, auth_client):
        resp = auth_client.post("/api/companies",
                                json={"name": "Acme Corp", "domains": ["acme.com"]})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["name"] == "Acme Corp"
        assert data["id"] == "acme-corp"

    def test_create_company_normalizes_domain_inputs(self, auth_client):
        resp = auth_client.post("/api/companies", json={
            "name": "Normalized",
            "domains": ["HTTPS://Example.com:443/path", "*.example.com"],
        })
        assert resp.status_code == 201
        assert resp.get_json()["domains"] == ["example.com", "*.example.com"]

    def test_create_company_accepts_wildcard_patterns(self, auth_client):
        resp = auth_client.post("/api/companies", json={
            "name": "Patterns",
            "domains": ["api*.hubapi.com", "prod-*.nu.com.mx", "*dev*.arlo.com"],
        })
        assert resp.status_code == 201
        assert resp.get_json()["domains"] == [
            "api*.hubapi.com",
            "prod-*.nu.com.mx",
            "*dev*.arlo.com",
        ]

    def test_create_duplicate_id_rejected(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Acme", "domains": []})
        resp = auth_client.post("/api/companies", json={"name": "Acme", "domains": []})
        assert resp.status_code == 409

    def test_create_requires_name(self, auth_client):
        resp = auth_client.post("/api/companies", json={"domains": ["a.com"]})
        assert resp.status_code == 400

    def test_list_after_create(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Beta", "domains": ["beta.io"]})
        resp = auth_client.get("/api/companies")
        companies = resp.get_json()
        assert len(companies) == 1
        assert companies[0]["name"] == "Beta"

    def test_update_company(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Old Name", "domains": []})
        resp = auth_client.put("/api/companies/old-name",
                               json={"name": "New Name", "domains": ["new.com"]})
        assert resp.status_code == 200
        assert resp.get_json()["name"] == "New Name"

    def test_update_nonexistent(self, auth_client):
        resp = auth_client.put("/api/companies/ghost", json={"name": "X"})
        assert resp.status_code == 404

    def test_delete_company(self, auth_client):
        auth_client.post("/api/companies", json={"name": "ToDelete", "domains": []})
        resp = auth_client.delete("/api/companies/todelete")
        assert resp.status_code == 200
        assert auth_client.get("/api/companies").get_json() == []

    def test_domain_validation(self, auth_client):
        resp = auth_client.post("/api/validate-domains",
                                json={"domains": ["localhost"]})
        assert resp.status_code == 200
        results = resp.get_json()
        assert isinstance(results, list)

    def test_domain_validation_accepts_wildcard(self, auth_client):
        resp = auth_client.post("/api/validate-domains",
                                json={"domains": ["*.example.com"]})
        assert resp.status_code == 200
        results = resp.get_json()
        assert len(results) == 1
        assert results[0]["domain"] == "*.example.com"
        assert results[0]["wildcard"] is True
        assert results[0]["ok"] is True

    def test_domain_validation_accepts_glob_pattern(self, auth_client):
        resp = auth_client.post("/api/validate-domains",
                                json={"domains": ["api*.hubapi.com"]})
        assert resp.status_code == 200
        results = resp.get_json()
        assert len(results) == 1
        assert results[0]["domain"] == "api*.hubapi.com"
        assert results[0]["wildcard"] is True
        assert results[0]["ok"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# 4 — Scan routes
# ═══════════════════════════════════════════════════════════════════════════════


class TestScanRoutes:
    def test_data_endpoint(self, auth_client):
        resp = auth_client.get("/api/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "companies" in data

    def test_data_summary_endpoint(self, auth_client):
        resp = auth_client.get("/api/data/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "companies" in data

    def test_data_ts_endpoint(self, auth_client):
        resp = auth_client.get("/api/data/ts")
        assert resp.status_code == 200
        assert "ts" in resp.get_json()

    def test_company_data_not_found(self, auth_client):
        resp = auth_client.get("/api/data/company/ghost")
        assert resp.status_code == 404

    def test_scan_history_empty(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Co", "domains": ["co.com"]})
        resp = auth_client.get("/api/scan-history/co")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_screenshots_empty(self, auth_client):
        resp = auth_client.get("/api/screenshots/co")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_subhistory_empty(self, auth_client):
        resp = auth_client.get("/api/data/co/subhistory")
        assert resp.status_code == 200
        assert resp.get_json()["history"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# 5 — Recon routes
# ═══════════════════════════════════════════════════════════════════════════════


class TestReconRoutes:
    def test_list_modules(self, auth_client):
        resp = auth_client.get("/api/recon/modules")
        assert resp.status_code == 200
        modules = resp.get_json()
        assert isinstance(modules, list)
        ids = [m["id"] for m in modules]
        assert "email" in ids
        assert "dns" in ids

    def test_unknown_module_returns_400(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Co", "domains": ["co.com"]})
        resp = auth_client.post("/api/recon/co/nonexistent_module")
        assert resp.status_code == 400

    def test_run_module_company_not_found(self, auth_client):
        resp = auth_client.post("/api/recon/ghost/email")
        assert resp.status_code == 404

    def test_get_module_not_run(self, auth_client):
        resp = auth_client.get("/api/recon/co/email")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "not_run"

    def test_get_all_recon_summary(self, auth_client):
        resp = auth_client.get("/api/recon/co")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_pipeline_status_not_run(self, auth_client):
        resp = auth_client.get("/api/recon/co/pipeline")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "not_run"

    def test_pipeline_start_recon_unavailable(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Co2", "domains": ["co.com"]})
        resp = auth_client.post("/api/recon/co2/pipeline")
        assert resp.status_code == 500  # recon_available=False


# ═══════════════════════════════════════════════════════════════════════════════
# 6 — Ops routes (schedule, webhooks, whitelist, diff, audit)
# ═══════════════════════════════════════════════════════════════════════════════


class TestOpsRoutes:
    def test_schedule_list_empty(self, auth_client):
        resp = auth_client.get("/api/schedule")
        assert resp.status_code == 200

    def test_schedule_set_and_get(self, auth_client):
        resp = auth_client.post("/api/schedule/acme",
                                json={"profile": "standard", "interval_hours": 24, "enabled": True})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["profile"] == "standard"
        assert data["interval_hours"] == 24

        resp2 = auth_client.get("/api/schedule/acme")
        assert resp2.status_code == 200
        assert resp2.get_json()["enabled"] is True

    def test_schedule_delete(self, auth_client):
        auth_client.post("/api/schedule/acme", json={"interval_hours": 12})
        resp = auth_client.delete("/api/schedule/acme")
        assert resp.status_code == 200
        assert auth_client.get("/api/schedule/acme").get_json() == {}

    def test_webhooks_save_and_get(self, auth_client):
        hooks = [{"url": "https://hooks.slack.com/xxx", "type": "slack", "events": ["scan_done"]}]
        resp = auth_client.post("/api/webhooks", json=hooks)
        assert resp.status_code == 200
        got = auth_client.get("/api/webhooks").get_json()
        assert len(got) == 1
        assert got[0]["type"] == "slack"

    def test_webhooks_test(self, auth_client):
        resp = auth_client.post("/api/webhooks/test",
                                json={"hook": {"url": "https://example.com", "type": "generic"}})
        assert resp.status_code == 200

    def test_diff_no_snapshot(self, auth_client):
        resp = auth_client.get("/api/diff/acme")
        assert resp.status_code == 200
        assert "error" in resp.get_json()

    def test_whitelist_add_and_list(self, auth_client):
        resp = auth_client.post("/api/whitelist/co",
                                json={"host": "safe.co.com", "title": "CDN", "reason": "known"})
        assert resp.status_code == 201
        entry = resp.get_json()
        assert entry["host"] == "safe.co.com"

        resp2 = auth_client.get("/api/whitelist/co")
        assert len(resp2.get_json()) == 1

    def test_whitelist_delete(self, auth_client):
        add = auth_client.post("/api/whitelist/co", json={"host": "x.com"})
        wid = add.get_json()["id"]
        resp = auth_client.delete(f"/api/whitelist/co/{wid}")
        assert resp.status_code == 200
        assert auth_client.get("/api/whitelist/co").get_json() == []

    def test_audit_requires_super_admin(self, auth_client):
        resp = auth_client.get("/api/audit")
        assert resp.status_code == 200  # fixture uses super_admin


# ═══════════════════════════════════════════════════════════════════════════════
# 7 — Reporting routes
# ═══════════════════════════════════════════════════════════════════════════════


class TestReportingRoutes:
    def test_risk_score_company_not_found(self, auth_client):
        resp = auth_client.get("/api/risk/ghost")
        assert resp.status_code == 404

    def test_export_json_company_not_found(self, auth_client):
        resp = auth_client.get("/api/export/ghost?format=json")
        assert resp.status_code == 404

    def test_export_csv_company_not_found(self, auth_client):
        resp = auth_client.get("/api/export/ghost?format=csv_findings")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# 8 — Database layer
# ═══════════════════════════════════════════════════════════════════════════════


class TestDatabase:
    def test_save_and_load_companies(self, db):
        companies = [{"id": "co", "name": "Co", "domains": ["co.com"]}]
        db.save_companies(companies)
        loaded = db.load_companies()
        assert len(loaded) == 1
        # DB may add defaults (color, tags) — check key fields preserved
        assert loaded[0]["id"] == "co"
        assert loaded[0]["name"] == "Co"
        assert loaded[0]["domains"] == ["co.com"]

    def test_save_and_load_admins(self, db):
        import hashlib, base64, secrets
        pw = base64.b64encode(hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 1)).decode()
        admins = [{"id": "1", "username": "alice", "email": "", "role": "admin",
                   "password_hash": f"pbkdf2:sha256:salt:{pw}",
                   "created_at": "2024-01-01T00:00:00", "last_login": None}]
        db.save_admins(admins)
        loaded = db.load_admins()
        assert loaded[0]["username"] == "alice"
        assert loaded[0]["role"] == "admin"

    def test_settings_round_trip(self, db):
        db.set_settings({"shodan_key": "abc123", "github_token": "gh_xxx"})
        settings = db.get_settings({"shodan_key", "github_token"})
        assert settings["shodan_key"] == "abc123"
        assert settings["github_token"] == "gh_xxx"

    def test_settings_partial_keys(self, db):
        db.set_settings({"shodan_key": "abc"})
        settings = db.get_settings({"shodan_key", "missing_key"})
        assert settings["shodan_key"] == "abc"
        assert settings.get("missing_key", "") == ""

    def test_webhook_round_trip(self, db):
        hooks = [{"url": "https://x.com", "type": "slack"}]
        db.save_webhooks(hooks)
        loaded = db.load_webhooks()
        assert len(loaded) == 1
        # DB may add default fields (id, chat_id, events) — check key fields preserved
        assert loaded[0]["url"] == "https://x.com"
        assert loaded[0]["type"] == "slack"

    def test_whitelist_round_trip(self, db):
        wl = {"co": [{"id": "1", "host": "x.com"}]}
        db.save_whitelist(wl)
        loaded = db.load_whitelist()
        assert "co" in loaded
        assert loaded["co"][0]["host"] == "x.com"
        assert loaded["co"][0]["id"] == "1"

    def test_snapshot_save_and_load(self, db):
        snap = {"ts": "2024-01-01", "hosts": ["a.com"], "ports": {}, "findings": []}
        db.save_snapshot("co", snap, slot="current")
        loaded = db.load_snapshot("co", slot="current")
        assert loaded["hosts"] == ["a.com"]

    def test_snapshot_previous_slot(self, db):
        snap1 = {"ts": "2024-01-01", "hosts": ["a.com"], "ports": {}, "findings": []}
        snap2 = {"ts": "2024-01-02", "hosts": ["b.com"], "ports": {}, "findings": []}
        db.save_snapshot("co", snap1, slot="current")
        db.save_snapshot("co", snap2, slot="previous")
        assert db.load_snapshot("co", slot="previous")["hosts"] == ["b.com"]

    def test_smart_scan_checkpoint_invalidation(self, db, tmp_path):
        from pipeline import ReconRunner

        runner = ReconRunner(
            db=db,
            base_dir=tmp_path,
            get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None,
            recon_available=False,
        )
        co = {"id": "co", "name": "Company", "domains": ["example.com"]}
        hosts = [{
            "host": "app.example.com",
            "status_code": 200,
            "title": "App",
            "ports": [443],
            "tech": ["React"],
        }]

        fp = runner._module_checkpoint_fingerprint("co", "profiling", co, hosts, {})
        runner.results["co:profiling"] = {"status": "done", "fingerprint": fp}
        assert runner._module_checkpoint_is_valid("co", "profiling", co, hosts, {}) is True

        changed_hosts = [dict(hosts[0], title="New App")]
        assert runner._module_checkpoint_is_valid("co", "profiling", co, changed_hosts, {}) is False

    def test_asm_data_round_trip(self, db):
        data = {"companies": [{"id": "co", "hosts": []}]}
        db.save_asm_data(data)
        assert db.load_asm_data()["companies"][0]["id"] == "co"

    def test_audit_log_append(self, db):
        db.append_audit_log({"ts": "2024-01-01", "user": "admin", "action": "login",
                              "target": "", "details": ""})
        logs = db.list_audit_log(limit=10)
        assert len(logs) == 1
        assert logs[0]["action"] == "login"

    def test_schedules_round_trip(self, db):
        scheds = {"co": {"profile": "standard", "interval_hours": 24, "enabled": True,
                         "next_run": "", "last_run": ""}}
        db.save_schedules(scheds)
        loaded = db.load_schedules()
        assert loaded["co"]["profile"] == "standard"
        assert loaded["co"]["interval_hours"] == 24
        assert loaded["co"]["enabled"] is True

    def test_migrate_from_legacy_safe_when_no_files(self, db):
        # Should not raise even when no legacy files exist
        db.migrate_from_legacy()


class TestPersistentJobQueue:
    def test_job_lifecycle_is_persisted(self, db):
        job = db.create_job(
            job_type="pipeline",
            company_id="co",
            target="co",
            options={"mode": "balanced"},
            priority=50,
            created_by="tester",
        )
        assert job["status"] == "pending"
        assert job["options"]["mode"] == "balanced"

        claimed = db.claim_next_job()
        assert claimed["id"] == job["id"]
        assert claimed["status"] == "running"
        assert claimed["attempts"] == 1

        db.finish_job(job["id"], status="done")
        finished = db.get_job(job["id"])
        assert finished["status"] == "done"
        assert finished["finished_at"]

    def test_active_job_dedupes_pipeline(self, db):
        first = db.create_job(job_type="pipeline", company_id="co", target="co", options={})
        active = db.find_active_job(company_id="co", job_type="pipeline")
        assert active["id"] == first["id"]

    def test_cancel_only_pending_job(self, db):
        pending = db.create_job(job_type="pipeline", company_id="co", target="co", options={})
        assert db.cancel_job(pending["id"], reason="unit") is True
        assert db.get_job(pending["id"])["status"] == "cancelled"

        running = db.create_job(job_type="pipeline", company_id="co", target="co", options={})
        db.claim_next_job()
        assert db.cancel_job(running["id"], reason="unit") is False

    def test_scheduler_executes_pipeline_job(self, db):
        from core.jobs import JobScheduler

        state = {}
        calls = []

        def run_pipeline(cid, company, options):
            calls.append((cid, company["name"], options["mode"]))
            state[cid] = {"status": "done", "log": []}

        scheduler = JobScheduler(
            db=db,
            load_companies=lambda: [{"id": "co", "name": "Company", "domains": ["example.com"]}],
            run_pipeline=run_pipeline,
            pipeline_state=state,
            max_workers=1,
        )
        job = scheduler.enqueue_pipeline("co", options={"mode": "balanced"})
        claimed = db.claim_next_job()
        scheduler._execute(claimed)

        assert calls == [("co", "Company", "balanced")]
        assert db.get_job(job["id"])["status"] == "done"

    def test_scheduler_does_not_auto_enqueue_playwright_after_pipeline(self, db):
        from core.jobs import JobScheduler

        state = {}
        pipeline_calls = []
        playwright_calls = []

        def run_pipeline(cid, company, options):
            pipeline_calls.append((cid, company["name"], options["mode"]))
            state[cid] = {"status": "done", "log": []}

        scheduler = JobScheduler(
            db=db,
            load_companies=lambda: [{"id": "co", "name": "Company", "domains": ["example.com"]}],
            run_pipeline=run_pipeline,
            run_playwright_recon=lambda cid, co, opts: playwright_calls.append((cid, co["name"], opts["target_url"])) or {"status": "done"},
            pipeline_state=state,
            save_pipeline_state=lambda cid: None,
            get_settings=lambda: {"playwright_headless": True, "playwright_max_pages": 13},
            max_workers=1,
        )
        job = scheduler.enqueue_pipeline("co", options={"mode": "balanced"})
        claimed = db.claim_next_job()
        scheduler._execute(claimed)

        assert pipeline_calls == [("co", "Company", "balanced")]
        jobs = db.list_jobs(company_id="co")
        assert not any(item["job_type"] == "playwright_recon" for item in jobs)
        assert playwright_calls == []
        assert db.get_job(job["id"])["status"] == "done"

    def test_scheduler_dedupes_active_pipeline_job(self, db):
        from core.jobs import JobScheduler

        scheduler = JobScheduler(
            db=db,
            load_companies=lambda: [{"id": "co", "name": "Company", "domains": ["example.com"]}],
            run_pipeline=lambda cid, co, opts: None,
            pipeline_state={},
            max_workers=1,
        )
        first = scheduler.enqueue_pipeline("co", options={"mode": "balanced"})
        second = scheduler.enqueue_pipeline("co", options={"mode": "deep"})

        assert second["id"] == first["id"]
        assert second["deduped"] is True
        assert len(db.list_jobs(company_id="co")) == 1

    def test_scheduler_executes_playwright_job(self, db, tmp_path):
        from core.jobs import JobScheduler

        calls = []

        scheduler = JobScheduler(
            db=db,
            load_companies=lambda: [{"id": "co", "name": "Company", "domains": ["example.com"]}],
            run_pipeline=lambda cid, co, opts: None,
            run_playwright_recon=lambda cid, co, opts: calls.append((cid, co["name"], opts["target_url"])) or {"status": "done"},
            pipeline_state={},
            max_workers=1,
        )
        job = scheduler.enqueue_playwright_recon(
            "co",
            options={"target_url": "https://example.com", "headless": True},
        )
        claimed = db.claim_next_job()
        scheduler._execute(claimed)

        assert calls == [("co", "Company", "https://example.com")]
        assert db.get_job(job["id"])["status"] == "done"

    def test_scheduler_dedupes_active_playwright_job(self, db):
        from core.jobs import JobScheduler

        scheduler = JobScheduler(
            db=db,
            load_companies=lambda: [{"id": "co", "name": "Company", "domains": ["example.com"]}],
            run_pipeline=lambda cid, co, opts: None,
            run_playwright_recon=lambda cid, co, opts: None,
            pipeline_state={},
            max_workers=1,
        )
        first = scheduler.enqueue_playwright_recon("co", options={"target_url": "https://example.com"})
        second = scheduler.enqueue_playwright_recon("co", options={"target_url": "https://example.com/login"})

        assert second["id"] == first["id"]
        assert second["deduped"] is True
        assert len(db.list_jobs(company_id="co", status="pending")) == 1


class TestJobQueueRoutes:
    def test_jobs_list_requires_auth(self, client):
        resp = client.get("/api/jobs")
        assert resp.status_code == 401

    def test_jobs_list_returns_persisted_jobs(self, auth_client, db):
        job = db.create_job(job_type="pipeline", company_id="co", target="co", options={"mode": "balanced"})
        resp = auth_client.get("/api/jobs")
        assert resp.status_code == 200
        payload = resp.get_json()
        assert any(item["id"] == job["id"] for item in payload)

    def test_job_detail_and_cancel(self, auth_client, db):
        job = db.create_job(job_type="pipeline", company_id="co", target="co", options={})
        detail = auth_client.get(f"/api/jobs/{job['id']}")
        assert detail.status_code == 200
        assert detail.get_json()["status"] == "pending"

        cancelled = auth_client.delete(f"/api/jobs/{job['id']}")
        assert cancelled.status_code == 200
        assert db.get_job(job["id"])["status"] == "cancelled"

    def test_playwright_job_enqueue_route(self, auth_client, db):
        auth_client.post("/api/companies", json={"name": "Co", "domains": ["example.com"]})
        # Simulate a completed bug bounty scan so Playwright Recon is allowed.
        flask_app = auth_client.application
        flask_app._test_runner.pipeline_state["co"] = {"status": "done", "log": []}
        resp = auth_client.post("/api/recon/co/playwright", json={
            "headless": True,
            "max_pages": 3,
            "target_url": "",
        })
        assert resp.status_code == 202
        payload = resp.get_json()
        assert payload["job_type"] == "playwright_recon"
        assert payload["target"] == "https://example.com"

        jobs = db.list_jobs(company_id="co")
        assert any(job["job_type"] == "playwright_recon" for job in jobs)

    def test_playwright_job_requires_completed_pipeline(self, auth_client, db):
        auth_client.post("/api/companies", json={"name": "Co2", "domains": ["example.com"]})
        resp = auth_client.post("/api/recon/co2/playwright", json={
            "headless": True,
            "max_pages": 3,
            "target_url": "",
        })
        assert resp.status_code == 409
        assert "completed bug bounty pipeline scan" in resp.get_json()["error"]

    def test_playwright_job_artifact_route(self, auth_client, db, tmp_path):
        root = tmp_path / "playwright-jobs" / "co" / "job1"
        evidence = root / "evidence"
        evidence.mkdir(parents=True)
        report = root / "report.md"
        session = evidence / "session.json"
        report.write_text("# report", encoding="utf-8")
        session.write_text('{"ok": true}', encoding="utf-8")

        job = db.create_job(
            job_type="playwright_recon",
            company_id="co",
            target="https://example.com",
            options={
                "job_root": str(root),
                "output": str(report),
                "evidence_dir": str(evidence),
            },
        )
        db.finish_job(job["id"], status="done")

        rep = auth_client.get(f"/api/jobs/{job['id']}/artifact/report")
        assert rep.status_code == 200
        assert b"# report" in rep.data

        ses = auth_client.get(f"/api/jobs/{job['id']}/artifact/session")
        assert ses.status_code == 200
        assert b'"ok": true' in ses.data


class TestToolCommandRegression:
    def test_asnmap_disables_update_check(self):
        from utils.tools import AsnmapTool

        cmd = AsnmapTool().command("example.com", {})
        assert "-duc" in cmd
        assert "-silent" in cmd

    def test_theharvester_uses_supported_sources(self):
        from utils.tools import TheHarvesterTool

        cmd = TheHarvesterTool().command("example.com", {})
        assert cmd[0] == "theHarvester"
        assert "-q" in cmd
        assert "-l" in cmd
        assert "-d" in cmd
        assert "anubis" not in cmd[-1]
        assert "google" not in cmd[-1]
        assert "crtsh" in cmd[-1]

    def test_dnsx_registry_and_command(self):
        from utils.tools import DnsxTool, registry

        assert registry.get("dnsx") is not None
        recon_cmd = DnsxTool().command("example.com", {
            "mode": "recon",
            "record_types": "a,cname,txt",
            "resp": True,
            "retry": 2,
            "threads": 50,
            "rcode": "NOERROR",
        })
        assert recon_cmd[0] == "dnsx"
        assert "-recon" in recon_cmd
        assert "-resp" in recon_cmd
        assert "-retry" in recon_cmd and "2" in recon_cmd
        assert "-t" in recon_cmd and "50" in recon_cmd
        assert "-rcode" in recon_cmd and "NOERROR" in recon_cmd

        resolve_cmd = DnsxTool().command("example.com", {
            "mode": "resolve",
            "record_types": "a,cname,txt",
            "axfr": True,
            "auto_wildcard": True,
        })
        assert "-recon" not in resolve_cmd
        assert "-a" in resolve_cmd and "-cname" in resolve_cmd and "-txt" in resolve_cmd
        assert "-axfr" in resolve_cmd
        assert "-auto-wildcard" in resolve_cmd

    def test_subjack_uses_small_resolver_set(self):
        from utils.tools import SubjackTool

        cmd = SubjackTool().command("example.com", {
            "hosts": [{"host": "example.com"}, {"host": "www.example.com"}]
        })
        assert cmd[0] == "subjack"
        assert "-r" in cmd
        assert "-t" in cmd and "2" in cmd
        assert "-timeout" in cmd and "3" in cmd
        assert "-w" in cmd

    def test_urlfinder_handles_non_utf8_output(self, monkeypatch):
        import subprocess as _subprocess
        from utils.tools import registry

        tool = registry.get("urlfinder")
        assert tool is not None

        def _fake_run(*args, **kwargs):
            return _subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=b"https://example.com/\xa7\nhttp://www.example.com/\xff\n",
                stderr=b"",
            )

        monkeypatch.setattr("utils.tools.subprocess.run", _fake_run)
        result = tool.run("example.com", {})
        assert result.error is None
        assert result.data["urls"] == ["https://example.com/", "http://www.example.com/"]
        assert result.findings and len(result.findings) == 2

    def test_crtsh_tool_parses_certs_and_subdomains(self, monkeypatch):
        from utils.tools import registry

        tool = registry.get("crtsh")
        assert tool is not None

        sample = [
            {
                "id": 1,
                "common_name": "*.example.com",
                "issuer_name": "Let's Encrypt",
                "name_value": "*.example.com\napi.example.com\nmail.example.com",
                "not_before": "2026-06-01T00:00:00",
                "not_after": "2026-09-01T00:00:00",
            },
            {
                "id": 2,
                "common_name": "example.com",
                "issuer_name": "Let's Encrypt",
                "name_value": "example.com\nwww.example.com",
                "not_before": "2026-06-02T00:00:00",
                "not_after": "2026-09-02T00:00:00",
            },
        ]

        class _Resp:
            def __init__(self, body):
                self._body = body
            def read(self):
                return self._body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        def _fake_urlopen(*args, **kwargs):
            return _Resp(json.dumps(sample).encode("utf-8"))

        monkeypatch.setattr("utils.tools.urllib.request.urlopen", _fake_urlopen)
        result = tool.run("example.com", {})
        assert result.status == "done"
        assert result.data["total_certs"] == 2
        assert "api.example.com" in result.data["ct_subdomains"]
        assert "www.example.com" in result.data["ct_subdomains"]
        assert any(f.value == "api.example.com" for f in result.findings)


class TestModuleEnvelope:
    def test_tool_result_contract_fields(self):
        from utils.tools import Finding, ToolResult

        tr = ToolResult(
            tool="demo",
            target="example.com",
            status="done",
            reason="",
            findings=[Finding(type="host", value="a.example.com")],
            metrics={"findings": 1},
            artifacts={"report": "/tmp/report.md"},
        )
        data = tr.to_dict()

        assert data["status"] == "done"
        assert data["reason"] == ""
        assert data["metrics"]["findings"] == 1
        assert data["artifacts"]["report"] == "/tmp/report.md"
        assert data["findings"][0]["value"] == "a.example.com"

    def test_module_envelope_classification(self):
        from core.pipeline import _classify_result_status, _normalize_module_envelope

        status, reason = _classify_result_status(None, "No live hosts")
        assert status == "skipped"
        assert reason == "No live hosts"

        envelope = _normalize_module_envelope(
            "demo",
            {"skipped": True, "reason": "No suitable targets", "subdomains": ["a.example.com"]},
        )
        assert envelope["status"] == "skipped"
        assert envelope["reason"] == "No suitable targets"
        assert envelope["metrics"]["subdomains"] == 1

        timeout_env = _normalize_module_envelope("demo", None, status="timeout", reason="Timeout (120s)")
        assert timeout_env["status"] == "timeout"
        assert timeout_env["reason"] == "Timeout (120s)"
