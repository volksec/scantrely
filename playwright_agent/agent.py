from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from .pipeline import PipelineConfig, PlaywrightPentestPipeline, render_report_from_session
from .tech_detector import TechnologyDetector, DetectorContext, build_stack_profile
from .browser import BrowserRuntime
from .url_utils import scope_from_url


def load_yaml_config(path: str | None) -> dict:
    if not path:
        return {}
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return data or {}


def cmd_recon(args) -> int:
    cfg_data = load_yaml_config(args.config)
    scope = args.scope or cfg_data.get("scope") or scope_from_url(args.url)
    cfg = PipelineConfig(
        url=args.url,
        output=args.output or cfg_data.get("output", "reports/report.md"),
        evidence_dir=args.evidence_dir or cfg_data.get("evidence_dir", "evidence"),
        scope=scope,
        max_pages=args.max_pages or cfg_data.get("max_pages", 50),
        max_depth=args.max_depth or cfg_data.get("max_depth", 3),
        headless=bool(args.headless),
        timeout=args.timeout or cfg_data.get("timeout", 20),
        slow_mo=args.slow_mo or cfg_data.get("slow_mo", 0),
        user_agent=args.user_agent or cfg_data.get("user_agent", ""),
        allow_external=args.allow_external,
        safe_mode=not args.no_safe_mode,
        test_xss=getattr(args, "test_xss", False),
        test_race=getattr(args, "test_race", False),
        test_access=getattr(args, "test_access", False),
        trace=args.trace,
        auth_state=args.auth_state or cfg_data.get("auth_state"),
        auth_state_b=args.auth_state_b or cfg_data.get("auth_state_b"),
        config_path=args.config,
    )
    print("[+] Starting Playwright Pentest Agent")
    print(f"[+] Target: {cfg.url}   Scope: {', '.join(cfg.scope)}   Mode: {'safe' if cfg.safe_mode else 'active'}")
    print("[+] Browser instrumentation enabled")
    print("[+] Crawling visible routes")
    print("[+] Capturing console + network + failed requests")
    print("[+] Fingerprinting technologies")
    pipeline = PlaywrightPentestPipeline(cfg)
    session = pipeline.run()
    print(f"[+] Report saved: {cfg.output}")
    print(f"[+] Session saved: {Path(cfg.evidence_dir) / 'session.json'}")
    print(f"[+] Technologies detected: {len(session.tech)}")
    if session.stack_profile.get("skip_viewstate"):
        print("[+] ViewState audit skipped: modern SPA detected")
    return 0


def cmd_fingerprint(args) -> int:
    cfg_data = load_yaml_config(args.config)
    scope = args.scope or cfg_data.get("scope") or scope_from_url(args.url)
    with BrowserRuntime(headless=bool(args.headless), timeout=args.timeout or 20) as runtime:
        runtime.goto(args.url)
        runtime.page.wait_for_timeout(500)
        html = runtime.page.content()
        headers = {}
        cookies = runtime.context.cookies()
        detector = TechnologyDetector.load_default()
        ctx = DetectorContext(
            url=runtime.page.url,
            html=html,
            headers=headers,
            cookies=cookies,
            js_texts=list(runtime.js_bodies.values()),
            paths=[runtime.page.url],
            console=runtime.console_events,
        )
        tech = detector.detect(ctx)
        profile = build_stack_profile(tech, html=html, headers=headers, cookies=cookies)
        print(json.dumps(
            {
                "scope": scope,
                "target": args.url,
                "tech": [t.__dict__ for t in tech],
                "stack_profile": profile,
            },
            ensure_ascii=False,
            indent=2,
        ))
    return 0


def cmd_xss(args) -> int:
    from .xss_tester import run_xss_tests

    print(f"[+] Controlled XSS test: {args.url}")
    results = run_xss_tests(
        [args.url],
        headless=bool(args.headless),
        timeout=args.timeout,
        auth_state=args.auth_state,
        evidence_dir=args.evidence_dir,
    )
    if not results:
        print("[!] No testable query parameters found in the URL.")
        return 0
    for r in results:
        print(f"  - param `{r.parameter}` [{r.context}] -> {r.status}"
              + (f"  (marker {r.marker})" if r.status == "confirmed_xss" else ""))
    confirmed = [r for r in results if r.status == "confirmed_xss"]
    print(f"[+] Confirmed: {len(confirmed)} / {len(results)}")
    return 0


def cmd_report(args) -> int:
    out = render_report_from_session(args.input, args.output)
    print(f"[+] Report saved: {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="playwright-agent", description="Playwright Pentest Agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    recon = sub.add_parser("recon", help="Run full safe recon pipeline")
    recon.add_argument("--url", required=True)
    recon.add_argument("--scope", nargs="*", default=[])
    recon.add_argument("--output", default="reports/report.md")
    recon.add_argument("--evidence-dir", default="evidence")
    recon.add_argument("--max-pages", type=int, default=50)
    recon.add_argument("--max-depth", type=int, default=3)
    recon.add_argument("--timeout", type=int, default=20)
    recon.add_argument("--slow-mo", type=int, default=0)
    recon.add_argument("--user-agent", default="")
    recon.add_argument("--auth-state", default=None)
    recon.add_argument("--auth-state-b", default=None)
    recon.add_argument("--config", default=None)
    recon.add_argument("--headless", dest="headless", action="store_true", default=True)
    recon.add_argument("--no-headless", dest="headless", action="store_false")
    recon.add_argument("--safe-mode", dest="no_safe_mode", action="store_false", default=False)
    recon.add_argument("--no-safe-mode", dest="no_safe_mode", action="store_true")
    recon.add_argument("--allow-external", action="store_true")
    recon.add_argument("--test-xss", dest="test_xss", action="store_true",
                       help="Enable controlled XSS testing (requires --no-safe-mode)")
    recon.add_argument("--test-race", dest="test_race", action="store_true",
                       help="Enable bounded race probe on non-destructive candidates (requires --no-safe-mode)")
    recon.add_argument("--test-access", dest="test_access", action="store_true",
                       help="Enable client-trust / broken-access-control replay (requires --no-safe-mode)")
    recon.add_argument("--trace", action="store_true")
    recon.set_defaults(func=cmd_recon)

    xss = sub.add_parser("xss", help="Controlled XSS test on a single URL's parameters")
    xss.add_argument("--url", required=True)
    xss.add_argument("--timeout", type=int, default=15)
    xss.add_argument("--evidence-dir", default="evidence")
    xss.add_argument("--auth-state", default=None)
    xss.add_argument("--headless", dest="headless", action="store_true", default=True)
    xss.add_argument("--no-headless", dest="headless", action="store_false")
    xss.set_defaults(func=cmd_xss)

    fp = sub.add_parser("fingerprint", help="Fingerprint stack only")
    fp.add_argument("--url", required=True)
    fp.add_argument("--scope", nargs="*", default=[])
    fp.add_argument("--timeout", type=int, default=20)
    fp.add_argument("--config", default=None)
    fp.add_argument("--headless", dest="headless", action="store_true", default=True)
    fp.add_argument("--no-headless", dest="headless", action="store_false")
    fp.set_defaults(func=cmd_fingerprint)

    report = sub.add_parser("report", help="Render Markdown report from session.json")
    report.add_argument("--input", required=True)
    report.add_argument("--output", required=True)
    report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
