"""Reusable, transport-independent gateway matching helpers."""
from __future__ import annotations
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

def normalize_host(value: str | None) -> str:
    if not value:
        return ""
    value = value.strip().lower().rstrip(".")
    return urlsplit(value).netloc if "://" in value else value

def canonical_path(path: str) -> str:
    path = "/" + (path or "").split("?", 1)[0].strip("/")
    return path if path == "/" else path.rstrip("/")

def match_path_template(template: str, actual: str) -> bool:
    template, actual = canonical_path(template), canonical_path(actual)
    escaped = re.escape(template)
    pattern = re.sub(r"\\\{[^/{}]+\\\}", r"[^/]+", escaped)
    return re.fullmatch(pattern, actual) is not None

def _host_matches(expected: str | None, actual: str) -> bool:
    expected, actual = normalize_host(expected), normalize_host(actual)
    if not expected:
        return True
    if ":" in expected and not expected.startswith("["):
        return expected == actual
    actual_name = actual.rsplit(":", 1)[0] if ":" in actual else actual
    return expected == actual_name

def find_matching_rule(request: Any, allowlist: Mapping[str, Any] | list[dict[str, Any]]) -> dict[str, Any] | None:
    if isinstance(allowlist, Mapping):
        entries = allowlist.get("entries", [])
        target = allowlist.get("target", {})
        default_host = target.get("host")
        if default_host and target.get("port"):
            default_host = f"{default_host}:{target['port']}"
    else:
        entries, default_host = allowlist, None
    method = str(getattr(request, "method", "")).upper()
    host, path = str(getattr(request, "host", "")), str(getattr(request, "path", ""))
    for entry in entries:
        if not entry.get("allow", True):
            continue
        if str(entry.get("method", "")).upper() != method:
            continue
        if not _host_matches(entry.get("host", default_host), host):
            continue
        if entry.get("path") and match_path_template(str(entry["path"]), path):
            return entry
    return None

def host_is_in_scope(host: str, allowlist: Mapping[str, Any]) -> bool:
    target = allowlist.get("target", {})
    expected = target.get("host")
    if expected and target.get("port"):
        expected = f"{expected}:{target['port']}"
    return _host_matches(expected, host)
