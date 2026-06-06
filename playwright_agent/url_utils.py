from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
import re


_VOLATILE_QUERY_KEYS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "_", "cache", "cb", "nocache", "ts", "timestamp", "nonce",
}


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query_pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k.lower() not in _VOLATILE_QUERY_KEYS]
    query = urlencode(sorted(query_pairs), doseq=True)
    return urlunparse((scheme, netloc, path, "", query, ""))


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc.lower()) == (pb.scheme, pb.netloc.lower())


def in_scope(url: str, scope: list[str], allow_external: bool = False) -> bool:
    if allow_external:
        return True
    host = urlparse(url).netloc.lower()
    if not host:
        return False
    host = host.split("@")[-1]
    host = host.split(":")[0]
    if not scope:
        return False
    return any(host == s or host.endswith("." + s) for s in scope)


def scope_from_url(url: str) -> list[str]:
    host = urlparse(url).hostname or ""
    return [host.lower()] if host else []


class LinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self.inputs: list[dict] = []
        self.buttons: list[dict] = []
        self._form_stack: list[dict] = []
        self._current_button: dict | None = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(urljoin(self.base_url, attrs["href"]))
        elif tag == "script":
            src = attrs.get("src")
            if src:
                self.scripts.append(urljoin(self.base_url, src))
        elif tag == "form":
            form = {
                "action": urljoin(self.base_url, attrs.get("action") or self.base_url),
                "method": (attrs.get("method") or "GET").upper(),
                "id": attrs.get("id", ""),
                "name": attrs.get("name", ""),
                "fields": [],
            }
            self._form_stack.append(form)
        elif tag == "input":
            field = {
                "name": attrs.get("name", ""),
                "type": (attrs.get("type") or "text").lower(),
                "value": attrs.get("value", ""),
                "placeholder": attrs.get("placeholder", ""),
                "id": attrs.get("id", ""),
            }
            self.inputs.append(field)
            if self._form_stack:
                self._form_stack[-1]["fields"].append(field)
        elif tag in {"button", "textarea", "select"}:
            self._current_button = {
                "tag": tag,
                "text": "",
                "type": attrs.get("type", ""),
                "name": attrs.get("name", ""),
                "id": attrs.get("id", ""),
                "class": attrs.get("class", ""),
            }
        elif tag == "option" and self._form_stack:
            self._form_stack[-1]["fields"].append({"type": "option"})

    def handle_endtag(self, tag):
        if tag == "form" and self._form_stack:
            self.forms.append(self._form_stack.pop())
        elif tag in {"button", "textarea", "select"} and self._current_button:
            self.buttons.append(self._current_button)
            self._current_button = None

    def handle_data(self, data):
        if self._current_button is not None:
            self._current_button["text"] = (self._current_button.get("text", "") + data).strip()


def extract_surface(html: str, base_url: str) -> dict:
    parser = LinkExtractor(base_url)
    parser.feed(html or "")
    return {
        "links": dedupe_urls(parser.links),
        "scripts": dedupe_urls(parser.scripts),
        "forms": parser.forms,
        "inputs": parser.inputs,
        "buttons": parser.buttons,
    }


def dedupe_urls(urls: list[str]) -> list[str]:
    seen = set()
    out = []
    for url in urls:
        norm = normalize_url(url)
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def looks_risky_action(text: str) -> bool:
    t = (text or "").lower()
    patterns = [
        r"\bdelete\b", r"\bremove\b", r"\bexcluir\b", r"\bapagar\b",
        r"\bbuy\b", r"\bpagar\b", r"\bpay\b", r"\bcheckout\b", r"\btransfer\b",
        r"\blogout\b", r"\bdesativar\b", r"\bcancel\b", r"\benviar\b", r"\bsubmit\b",
    ]
    return any(re.search(p, t) for p in patterns)

