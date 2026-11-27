"""Tolerant loader for nuclei YAML templates.

Read-only: templates are never modified, keeping full compatibility with the
existing template format and the signing/checksum workflows.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

PROTOCOL_KEYS = (
    "http",
    "dns",
    "tcp",
    "udp",
    "file",
    "headless",
    "network",
    "ssl",
    "websocket",
    "javascript",
    "code",
    "offline",
    "dast",
)


@dataclass(frozen=True)
class Template:
    path: str
    template_id: str
    name: str
    severity: str
    tags: tuple
    cve_id: Optional[str]
    cwe_ids: tuple
    vendor: Optional[str]
    product: Optional[str]
    verified: bool
    max_request: Optional[int]
    data: dict = field(compare=False)


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [v for v in value if v is not None]
    return [value]


def _norm_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def parse_template(path: Path, rel_path: str) -> Optional[Template]:
    """Parse one template file; returns None when the file is not a template."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    template_id = data.get("id")
    info = data.get("info")
    if not template_id or not isinstance(info, dict):
        return None

    classification = info.get("classification") or {}
    if not isinstance(classification, dict):
        classification = {}
    metadata = info.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    tags: list = []
    for tag in _as_list(info.get("tags")):
        tags.extend(t.strip().lower() for t in str(tag).split(",") if t.strip())

    cve_id = _norm_str(classification.get("cve-id"))
    if cve_id is None:
        cve_id = _norm_str(template_id) if str(template_id).lower().startswith("cve-") else None
    if cve_id is not None:
        cve_id = cve_id.upper()

    cwe_ids = tuple(
        sorted(
            c.upper()
            for c in (_norm_str(v) for v in _as_list(classification.get("cwe-id")))
            if c
        )
    )

    max_request = metadata.get("max-request")
    try:
        max_request = int(max_request) if max_request is not None else None
    except (TypeError, ValueError):
        max_request = None

    return Template(
        path=rel_path,
        template_id=str(template_id),
        name=str(info.get("name") or ""),
        severity=_norm_str(info.get("severity")) or "unknown",
        tags=tuple(sorted(set(tags))),
        cve_id=cve_id,
        cwe_ids=cwe_ids,
        vendor=_norm_str(metadata.get("vendor")),
        product=_norm_str(metadata.get("product")),
        verified=bool(metadata.get("verified")),
        max_request=max_request,
        data=data,
    )


def iter_template_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*.yaml")):
        if ".git" in path.parts:
            continue
        yield path


def load_templates(
    root: Path,
    limit: Optional[int] = None,
    seed: int = 20261127,
) -> list:
    """Load templates sorted by path; optionally take a deterministic sample.

    The sample uses a fixed-seed RNG over the sorted file list, so the same
    (root, limit, seed) triple always yields the same set of templates.
    """
    root = Path(root)
    files = list(iter_template_files(root))
    if limit is not None and limit < len(files):
        files = sorted(random.Random(seed).sample(files, limit))
    templates = []
    for path in files:
        template = parse_template(path, str(path.relative_to(root)))
        if template is not None:
            templates.append(template)
    templates.sort(key=lambda t: (t.template_id.lower(), t.path))
    return templates
