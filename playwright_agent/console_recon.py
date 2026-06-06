from __future__ import annotations

import re

from .models import ConsoleEvent


SECURITY_PATTERNS = [
    r"/api/",
    r"/admin/",
    r"/internal/",
    r"/graphql",
    r"/ws",
    r"csrf",
    r"token",
    r"jwt",
    r"secret",
    r"apikey",
    r"unauthorized",
    r"forbidden",
    r"csp",
    r"source map",
    r"stack trace",
]


def classify(event: ConsoleEvent) -> ConsoleEvent:
    text = (event.message or "").lower()
    if any(re.search(p, text) for p in SECURITY_PATTERNS):
        event.classification = "security_relevant"
    elif "error" in text or event.type in {"error", "exception"}:
        event.classification = "recon_useful"
    else:
        event.classification = "noise"
    return event


def summarize(events: list[ConsoleEvent]) -> dict[str, int]:
    counts = {"security_relevant": 0, "recon_useful": 0, "noise": 0, "false_positive": 0}
    for event in events:
        counts[event.classification or "noise"] = counts.get(event.classification or "noise", 0) + 1
    return counts

