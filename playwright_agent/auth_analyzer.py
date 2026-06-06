from __future__ import annotations

from .models import AuthObservation, InputPoint
from .url_utils import dedupe_urls, in_scope

_SESSION_COOKIE_NAMES = {
    "sessionid", "phpsessid", "asp.net_sessionid", ".aspxauth", "jsessionid",
    "connect.sid", "laravel_session", "_session_id",
}
_LOGOUT_HINTS = ("logout", "signout", "sign-out", "sair", "log-out")


def analyze_auth_surface(inputs: list[InputPoint], cookies: list[dict], html: str = "") -> AuthObservation:
    obs = AuthObservation()
    obs.cookies = [dict(c) for c in cookies]
    for cookie in cookies:
        name = cookie.get("name", "")
        flags = {
            "name": name,
            "httpOnly": bool(cookie.get("httpOnly")),
            "secure": bool(cookie.get("secure")),
            "sameSite": cookie.get("sameSite"),
            "domain": cookie.get("domain", ""),
            "path": cookie.get("path", ""),
        }
        obs.cookie_flags.append(flags)
        if name.lower() in {"sessionid", "phpsessid", "asp.net_sessionid", ".aspxauth", "jsessionid", "connect.sid"}:
            obs.session_mechanisms.append(name)
        if not flags["httpOnly"]:
            obs.notes.append(f"Cookie {name} missing HttpOnly")
        if not flags["secure"]:
            obs.notes.append(f"Cookie {name} missing Secure")
        if not flags["sameSite"]:
            obs.notes.append(f"Cookie {name} missing SameSite")
    for item in inputs:
        if item.kind == "form" and item.method.upper() == "POST":
            has_password = "password_field" in item.notes
            has_csrf = "csrf_field" in item.notes
            if has_password or "login" in (item.action or "").lower() or "signin" in (item.action or "").lower():
                obs.login_forms.append(
                    {
                        "name": item.name,
                        "action": item.action,
                        "method": item.method,
                        "password_field": has_password,
                        "csrf_field": has_csrf,
                    }
                )
                if has_csrf:
                    obs.csrf_fields.append(item.name)
    if "logout" in html.lower():
        obs.notes.append("Logout-like link or text detected.")
    return obs


# ── Fase 15 — Active session analysis (authed vs anon, logout, fixation) ──────

def find_logout_urls(links: list[str], scope: list[str]) -> list[str]:
    out = []
    for url in dedupe_urls(links or []):
        if any(h in url.lower() for h in _LOGOUT_HINTS) and in_scope(url, scope):
            out.append(url)
    return out


def _looks_login(url: str) -> bool:
    return any(k in (url or "").lower() for k in ("login", "signin", "sign-in", "auth", "sso"))


def run_session_analysis(
    urls: list[str],
    logout_urls: list[str],
    *,
    auth_state: str | None,
    scope: list[str],
    headless: bool = True,
    timeout: int = 20,
    user_agent: str = "",
    max_urls: int = 10,
) -> dict:
    """Compare authenticated vs anonymous access, then test logout invalidation.

    Read-only (GET) and bounded. Uses ONE browser with two contexts (authed via
    storage_state + anon) — never nests Playwright instances. Needs auth_state to
    be meaningful; without it, returns a note instead of guessing.
    """
    result: dict = {"access_control": [], "logout": {}, "notes": []}
    targets = [u for u in dedupe_urls(urls or []) if in_scope(u, scope)][:max_urls]
    if not targets:
        result["notes"].append("No in-scope URLs to evaluate.")
        return result
    if not auth_state:
        result["notes"].append("No auth_state provided — skipped authed-vs-anon access comparison.")
        return result

    from .browser import _lazy_playwright

    sync_playwright, _ = _lazy_playwright()
    args = ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"]
    ua = user_agent or None

    def _status(page, url):
        from .browser import goto_resilient

        try:
            resp, err, _, _ = goto_resilient(page, url, base_timeout=timeout)
            if err and resp is None:
                return None, url
            return (resp.status if resp else None), page.url
        except Exception:
            return None, url

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless, args=args)
        anon_ctx = browser.new_context(ignore_https_errors=True, user_agent=ua)
        auth_ctx = browser.new_context(ignore_https_errors=True, storage_state=auth_state, user_agent=ua)
        anon_pg, auth_pg = anon_ctx.new_page(), auth_ctx.new_page()

        first_protected = ""
        for url in targets:
            a_status, a_final = _status(anon_pg, url)
            u_status, _ = _status(auth_pg, url)
            if u_status == 200 and (a_status in (401, 403) or (a_status in (301, 302) and _looks_login(a_final)) or _looks_login(a_final)):
                verdict = "protected"
                first_protected = first_protected or url
            elif u_status == 200 and a_status == 200:
                verdict = "accessible_without_auth"
            elif u_status in (401, 403) and a_status in (401, 403):
                verdict = "inaccessible"
            else:
                verdict = "needs_manual_validation"
            result["access_control"].append({
                "url": url, "authed_status": u_status, "anon_status": a_status, "verdict": verdict,
            })

        # Session-fixation heuristic: anon context holds a session cookie pre-auth?
        try:
            anon_cookies = anon_ctx.cookies()
            pre_auth = [c["name"] for c in anon_cookies if c.get("name", "").lower() in _SESSION_COOKIE_NAMES]
            if pre_auth:
                result["notes"].append(
                    f"Session cookie(s) {pre_auth} issued before authentication — "
                    "verify they are regenerated on login (fixation risk)."
                )
        except Exception:
            pass

        # Logout invalidation: hit logout in authed ctx, then re-check a protected URL.
        logout = next((u for u in (logout_urls or []) if in_scope(u, scope)), "")
        if logout and first_protected:
            try:
                from .browser import goto_resilient
                goto_resilient(auth_pg, logout, base_timeout=timeout)
                auth_pg.wait_for_timeout(500)
                after_status, after_final = _status(auth_pg, first_protected)
                invalidated = after_status in (401, 403) or _looks_login(after_final)
                result["logout"] = {
                    "logout_url": logout,
                    "rechecked_url": first_protected,
                    "status_after_logout": after_status,
                    "verdict": "invalidates_session" if invalidated else "may_not_invalidate_session",
                }
                if not invalidated:
                    result["notes"].append(
                        f"After logout, `{first_protected}` still returned {after_status} — "
                        "server-side session may not be invalidated (manual lead)."
                    )
            except Exception as exc:
                result["logout"] = {"logout_url": logout, "error": str(exc)}
        elif not logout:
            result["notes"].append("No logout URL discovered — logout invalidation not tested.")

        browser.close()
    return result
