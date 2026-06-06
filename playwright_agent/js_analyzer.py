from __future__ import annotations

import re

from .file_utils import sha256_text
from .models import JsArtifact
from .source_map import extract_source_map_url


ENDPOINT_RE = re.compile(
    r"""(?:
        https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+|
        /(?:api|graphql|rest|v1|v2|auth|internal|admin|socket\.io|ws)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*
    )""",
    re.I | re.X,
)
ROUTE_RE = re.compile(r"""['"`](/(?:[A-Za-z0-9._-]+/){0,4}[A-Za-z0-9._-]+)['"`]""")
PARAM_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\b\s*(?==|\)|,)")
SINK_RE = re.compile(
    r"innerHTML|outerHTML|document\.write|eval\(|new Function|dangerouslySetInnerHTML|v-html|"
    r"bypassSecurityTrust|insertAdjacentHTML|postMessage|location\.href",
    re.I,
)
SECRET_HINT_RE = re.compile(r"api[_-]?key|token|secret|dsn|client[_-]?secret|private[_-]?key", re.I)


def analyze_js(file_url: str, text: str) -> JsArtifact:
    text = text or ""
    return JsArtifact(
        file_url=file_url,
        size=len(text.encode("utf-8", errors="ignore")),
        sha256=sha256_text(text),
        lazy_chunk=any(marker in file_url for marker in (".chunk.", "lazy", "vendors", "runtime")),
        endpoints=dedupe([m.group(0) for m in ENDPOINT_RE.finditer(text)]),
        routes=dedupe([m.group(1) for m in ROUTE_RE.finditer(text)]),
        params=dedupe([m.group(1) for m in PARAM_RE.finditer(text) if m.group(1) not in {"function", "return", "const", "let", "var"}]),
        sinks=dedupe([m.group(0) for m in SINK_RE.finditer(text)]),
        secrets_hint=dedupe([m.group(0) for m in SECRET_HINT_RE.finditer(text)]),
        source_map_url=extract_source_map_url(text),
        source_map_accessible=False,
    )


def dedupe(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        item = item.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out

