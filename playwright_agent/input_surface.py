from __future__ import annotations

from .models import InputPoint
from .url_utils import extract_surface, looks_risky_action


def collect_input_surface(html: str, url: str) -> list[InputPoint]:
    surface = extract_surface(html, url)
    points: list[InputPoint] = []
    for form in surface["forms"]:
        risky = looks_risky_action(form.get("action", "")) or any(looks_risky_action(b.get("text", "")) for b in surface["buttons"])
        has_password = any((f.get("type") or "").lower() == "password" for f in form.get("fields", []))
        has_csrf = any("csrf" in (f.get("name", "").lower()) for f in form.get("fields", []))
        points.append(
            InputPoint(
                kind="form",
                name=form.get("name", "") or form.get("id", "") or form.get("action", ""),
                action=form.get("action", ""),
                method=form.get("method", "GET"),
                risky_intent=risky,
                notes=[
                    "password_field" if has_password else "",
                    "csrf_field" if has_csrf else "",
                ],
            )
        )
    for field in surface["inputs"]:
        points.append(
            InputPoint(
                kind="input",
                name=field.get("name", ""),
                field_type=field.get("type", "text"),
                value_hint=field.get("placeholder", "") or field.get("value", ""),
            )
        )
    return points

