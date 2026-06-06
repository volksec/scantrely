from __future__ import annotations

from pathlib import Path
import re

from .pipeline import PipelineConfig, PlaywrightPentestPipeline
from .url_utils import scope_from_url


def _slugify(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", value or "").strip("-").lower()
    return text or "company"


def _normalize_target_url(value: str) -> str:
    target = (value or "").strip()
    if not target:
        return ""
    if target.startswith(("http://", "https://")):
        return target
    return "https://" + target.lstrip("/")


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _boolish(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off", ""}:
        return False
    return default


def _intish(value, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def build_playwright_job_options(
    company: dict,
    *,
    overrides: dict | None = None,
    settings: dict | None = None,
) -> dict:
    """Build Playwright job options from company scope, persisted defaults and overrides."""
    overrides = dict(overrides or {})
    settings = dict(settings or {})
    domains = [str(d).strip().lower().strip("*.") for d in company.get("domains", []) if str(d).strip()]

    target_url = str(
        overrides.get("target_url")
        or overrides.get("url")
        or settings.get("playwright_target_url", "")
        or (f"https://{domains[0]}" if domains else "")
    ).strip()
    target_url = _normalize_target_url(target_url)

    scope = overrides.get("scope")
    if scope is None:
        raw_scope = settings.get("playwright_scope", [])
        scope = raw_scope if isinstance(raw_scope, list) else domains
    if isinstance(scope, str):
        scope = [scope]
    scope = _dedupe_preserve_order([str(item).strip().lower().strip("*.") for item in (scope or []) if str(item).strip()])
    if not scope:
        scope = domains or scope_from_url(target_url)

    if not target_url:
        raise ValueError("Company has no domains and no target_url override")

    def _pick_bool(key: str, default: bool) -> bool:
        if key in overrides:
            return _boolish(overrides.get(key), default)
        if key in settings:
            return _boolish(settings.get(key), default)
        return default

    def _pick_int(key: str, default: int) -> int:
        if key in overrides:
            return _intish(overrides.get(key), default)
        if key in settings:
            return _intish(settings.get(key), default)
        return default

    def _pick_str(key: str, default: str = "") -> str:
        if key in overrides and overrides.get(key) is not None:
            return str(overrides.get(key) or "")
        if key in settings and settings.get(key) is not None:
            return str(settings.get(key) or "")
        return default

    return {
        "target_url": target_url,
        "scope": scope,
        "max_pages": _pick_int("playwright_max_pages", 50),
        "max_depth": _pick_int("playwright_max_depth", 3),
        "timeout": _pick_int("playwright_timeout", 20),
        "slow_mo": _pick_int("playwright_slow_mo", 0),
        "user_agent": _pick_str("playwright_user_agent", ""),
        "allow_external": _pick_bool("playwright_allow_external", False),
        "safe_mode": _pick_bool("playwright_safe_mode", True),
        "test_xss": _pick_bool("playwright_test_xss", False),
        "test_race": _pick_bool("playwright_test_race", False),
        "test_access": _pick_bool("playwright_test_access", False),
        "trace": _pick_bool("playwright_trace", False),
        "headless": _pick_bool("playwright_headless", True),
        "auth_state": _pick_str("playwright_auth_state", ""),
        "auth_state_b": _pick_str("playwright_auth_state_b", ""),
        "auto_run": _pick_bool("playwright_auto_run", True),
    }


def build_company_config(
    company_id: str,
    company: dict,
    options: dict,
    *,
    base_dir: str | Path = "data/playwright-jobs",
) -> PipelineConfig:
    domains = [str(d).strip().lower().strip("*.") for d in company.get("domains", []) if str(d).strip()]
    target_url = _normalize_target_url(
        str(options.get("target_url") or options.get("url") or (f"https://{domains[0]}" if domains else "")).strip()
    )
    if not target_url:
        raise ValueError("Company has no domains and no target_url override")

    scope = options.get("scope") or domains or scope_from_url(target_url)
    if isinstance(scope, str):
        scope = [scope]
    scope = _dedupe_preserve_order([str(item).strip().lower().strip("*.") for item in scope if str(item).strip()])
    if not scope:
        scope = scope_from_url(target_url)

    job_id = str(options.get("job_id") or "manual")
    base_path = Path(options.get("base_dir") or base_dir)
    if not base_path.is_absolute():
        base_path = Path(__file__).resolve().parent.parent / base_path
    root = base_path / _slugify(company_id) / job_id
    root.mkdir(parents=True, exist_ok=True)

    def _safe_path(value: str | None, default: Path) -> Path:
        if not value:
            return default
        candidate = Path(str(value))
        if not candidate.is_absolute():
            return root / candidate
        try:
            candidate.resolve().relative_to(root.resolve())
            return candidate
        except Exception:
            return default

    evidence_dir = _safe_path(options.get("evidence_dir"), root / "evidence")
    output = _safe_path(options.get("output"), root / "report.md")

    def _int(name: str, default: int) -> int:
        try:
            return int(options.get(name, default))
        except Exception:
            return default

    return PipelineConfig(
        url=target_url,
        output=str(output),
        evidence_dir=str(evidence_dir),
        scope=scope,
        max_pages=_int("max_pages", 50),
        max_depth=_int("max_depth", 3),
        headless=bool(options.get("headless", True)),
        timeout=_int("timeout", 20),
        slow_mo=_int("slow_mo", 0),
        user_agent=str(options.get("user_agent") or ""),
        allow_external=bool(options.get("allow_external", False)),
        safe_mode=bool(options.get("safe_mode", True)),
        test_xss=bool(options.get("test_xss", False)),
        test_race=bool(options.get("test_race", False)),
        test_access=bool(options.get("test_access", False)),
        trace=bool(options.get("trace", False)),
        auth_state=options.get("auth_state"),
        auth_state_b=options.get("auth_state_b"),
        config_path=options.get("config_path"),
    )


def run_company_playwright_job(
    company_id: str,
    company: dict,
    options: dict,
    *,
    base_dir: str | Path = "data/playwright-jobs",
) -> dict:
    cfg = build_company_config(company_id, company, options, base_dir=base_dir)
    session = PlaywrightPentestPipeline(cfg).run()
    session_path = Path(cfg.evidence_dir) / "session.json"
    # evidence_dir is <job_root>/evidence, so the job root is its parent.
    job_root = Path(cfg.evidence_dir).parent
    return {
        "target_url": cfg.url,
        "output": cfg.output,
        "evidence_dir": cfg.evidence_dir,
        "job_root": str(job_root),
        "session_path": str(session_path),
        "report_path": cfg.output,
        "tech_count": len(session.tech),
        "status": "done",
    }
