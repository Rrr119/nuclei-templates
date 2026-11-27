"""Semantic fingerprints: normalize templates into comparable feature sets."""

from __future__ import annotations

import re
from typing import Optional

from .loader import PROTOCOL_KEYS, Template

# Canonical vulnerability types, mapped from nuclei tags / name keywords.
VULN_TYPE_ALIASES = {
    "rce": "rce",
    "sqli": "sqli",
    "sql-injection": "sqli",
    "xss": "xss",
    "lfi": "lfi",
    "rfi": "rfi",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "ssti": "ssti",
    "csrf": "csrf",
    "redirect": "open-redirect",
    "open-redirect": "open-redirect",
    "traversal": "path-traversal",
    "fileupload": "file-upload",
    "upload": "file-upload",
    "auth-bypass": "auth-bypass",
    "default-login": "default-login",
    "exposure": "exposure",
    "disclosure": "exposure",
    "info-leak": "exposure",
    "misconfig": "misconfig",
    "misconfiguration": "misconfig",
    "deserialization": "deserialization",
    "injection": "injection",
    "takeover": "takeover",
    "panel": "panel",
    "detect": "detect",
    "tech": "detect",
    "cve": "cve",
}

_VAR_RE = re.compile(r"\{\{[^}]*\}\}")
_HEX_RE = re.compile(r"^[0-9a-f]{8,}$")
_NUM_RE = re.compile(r"^\d+$")
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_RAW_REQ_RE = re.compile(r"^([A-Z]{3,8})\s+(\S+)\s+HTTP", re.MULTILINE)


def vuln_types(template: Template) -> tuple:
    """Canonical vuln types derived from tags, falling back to the name."""
    found = []
    for tag in template.tags:
        alias = VULN_TYPE_ALIASES.get(tag)
        if alias and alias not in ("cve", "detect", "panel"):
            found.append(alias)
    if not found:
        for token in _TOKEN_RE.findall(template.name.lower()):
            alias = VULN_TYPE_ALIASES.get(token)
            if alias and alias not in ("cve", "detect", "panel"):
                found.append(alias)
    return tuple(sorted(set(found)))


def primary_vuln_type(template: Template) -> Optional[str]:
    types = vuln_types(template)
    return types[0] if types else None


def normalize_path(path: str) -> str:
    """Normalize a request path so variants collapse to one shape."""
    path = _VAR_RE.sub("", str(path)).lower()
    path = path.split("?")[0].split("#")[0]
    segments = []
    for seg in path.split("/"):
        if not seg:
            continue
        if _HEX_RE.match(seg) or _NUM_RE.match(seg):
            segments.append("*")
        else:
            segments.append(seg)
    return "/" + "/".join(segments)


def request_ops(template: Template) -> tuple:
    """(protocol, method, normalized path) tuples for every request."""
    ops = []
    for proto in PROTOCOL_KEYS:
        blocks = template.data.get(proto)
        if not isinstance(blocks, list):
            continue
        for block in blocks:
            if not isinstance(block, dict):
                continue
            method = str(block.get("method") or "GET").upper()
            for raw in block.get("raw") or []:
                for match in _RAW_REQ_RE.finditer(str(raw)):
                    ops.append((proto, match.group(1), normalize_path(match.group(2))))
            for entry in block.get("path") or []:
                ops.append((proto, method, normalize_path(str(entry))))
            if proto != "http" and not block.get("raw") and not block.get("path"):
                for key in ("host", "name", "data", "source"):
                    if block.get(key):
                        ops.append((proto, key, normalize_path(str(block[key]))))
    return tuple(sorted(set(ops)))


def matcher_tokens(template: Template) -> frozenset:
    """Normalized tokens describing what the matchers actually check."""
    tokens = set()
    for proto in PROTOCOL_KEYS:
        blocks = template.data.get(proto)
        if not isinstance(blocks, list):
            continue
        for block in blocks:
            if not isinstance(block, dict):
                continue
            for matcher in block.get("matchers") or []:
                if not isinstance(matcher, dict):
                    continue
                mtype = str(matcher.get("type") or "word").lower()
                for key in ("words", "dsl", "regex"):
                    for value in matcher.get(key) or []:
                        norm = _VAR_RE.sub("", str(value)).lower()
                        for token in _TOKEN_RE.findall(norm):
                            if len(token) > 1:
                                tokens.add("m:%s:%s" % (mtype, token))
                for status in matcher.get("status") or []:
                    tokens.add("m:status:%s" % status)
    return frozenset(tokens)


def name_tokens(template: Template) -> frozenset:
    return frozenset(t for t in _TOKEN_RE.findall(template.name.lower()) if len(t) > 1)


def token_set(template: Template) -> frozenset:
    """Combined semantic token set used for similarity comparison."""
    tokens = set(name_tokens(template))
    for _proto, _method, path in request_ops(template):
        for seg in path.strip("/").split("/"):
            for token in _TOKEN_RE.findall(seg):
                if len(token) > 1:
                    tokens.add("p:" + token)
    tokens.update(matcher_tokens(template))
    return frozenset(tokens)


def hard_key(template: Template) -> Optional[str]:
    """Exact family key: CVE id first, then vendor+product+vuln-type."""
    if template.cve_id:
        return "cve:" + template.cve_id
    vendor = template.vendor
    product = template.product
    vtype = primary_vuln_type(template)
    if vendor and product and vtype:
        return "vp:%s:%s:%s" % (vendor, product, vtype)
    return None
