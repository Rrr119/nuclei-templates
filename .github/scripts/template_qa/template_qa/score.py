"""Deterministic template quality scoring.

Score = request efficiency (30) + false-positive resilience (50)
      + metadata completeness (20), all in [0, 100].

The score is a pure function of template content: no randomness, no
timestamps, no environment dependence, so results are reproducible.
"""

from __future__ import annotations

from .loader import PROTOCOL_KEYS, Template

SCORING_VERSION = "1.0.0"

WEIGHTS = {
    "request": 30.0,
    "false_positive": 50.0,
    "metadata": 20.0,
}

# Request-count -> efficiency points (fewer requests = cheaper to run).
REQUEST_POINTS = [(1, 30.0), (2, 24.0), (3, 18.0), (4, 12.0), (6, 8.0), (10, 4.0)]

# Words that match on almost any site and therefore cause false positives.
GENERIC_WORDS = frozenset(
    {
        "admin",
        "login",
        "welcome",
        "error",
        "index of",
        "dashboard",
        "password",
        "user",
        "test",
        "home",
        "default",
        "success",
        "logout",
        "signin",
        "sign in",
    }
)


def request_count(template: Template) -> int:
    """Number of requests a template sends (max-request metadata wins)."""
    if template.max_request is not None and template.max_request > 0:
        return template.max_request
    count = 0
    for proto in PROTOCOL_KEYS:
        blocks = template.data.get(proto)
        if isinstance(blocks, list):
            count += len(blocks)
    return max(count, 1)


def request_points(count: int) -> float:
    for threshold, points in REQUEST_POINTS:
        if count <= threshold:
            return points
    return 0.0


def _all_matchers(template: Template) -> list:
    matchers = []
    for proto in PROTOCOL_KEYS:
        blocks = template.data.get(proto)
        if not isinstance(blocks, list):
            continue
        for block in blocks:
            if isinstance(block, dict):
                for matcher in block.get("matchers") or []:
                    if isinstance(matcher, dict):
                        matchers.append(matcher)
    return matchers


def _all_extractors(template: Template) -> list:
    extractors = []
    for proto in PROTOCOL_KEYS:
        blocks = template.data.get(proto)
        if not isinstance(blocks, list):
            continue
        for block in blocks:
            if isinstance(block, dict):
                extractors.extend(block.get("extractors") or [])
    return extractors


def false_positive_risk(template: Template) -> float:
    """Heuristic false-positive risk in [0, 1]; higher means riskier."""
    matchers = _all_matchers(template)
    if not matchers:
        return 0.9

    risk = 0.5
    types = {str(m.get("type") or "word").lower() for m in matchers}
    conditions = {str(m.get("condition") or "or").lower() for m in matchers}

    words = []
    for matcher in matchers:
        words.extend(str(w).lower() for w in matcher.get("words") or [])

    status_only = types <= {"status"}
    generic_only = bool(words) and all(w in GENERIC_WORDS for w in words)

    if len(matchers) >= 2 and "and" in conditions:
        risk -= 0.20
    if "dsl" in types:
        risk -= 0.15
    if "regex" in types:
        risk -= 0.05
    if any(m.get("negative") for m in matchers):
        risk -= 0.10
    if _all_extractors(template):
        risk -= 0.05
    if template.verified:
        risk -= 0.10
    if status_only:
        risk += 0.30
    if generic_only and "dsl" not in types and "regex" not in types:
        risk += 0.25
    if len(matchers) == 1 and "and" not in conditions:
        risk += 0.05

    return min(max(risk, 0.0), 1.0)


def metadata_points(template: Template) -> float:
    info = template.data.get("info") or {}
    points = 0.0
    if info.get("description"):
        points += 4.0
    if info.get("reference"):
        points += 4.0
    if info.get("classification"):
        points += 4.0
    if info.get("impact") or info.get("remediation"):
        points += 4.0
    if template.tags and (template.vendor or template.product):
        points += 4.0
    elif template.tags:
        points += 2.0
    return points


def quality_score(template: Template) -> dict:
    """Quality score breakdown; deterministic for identical template content."""
    count = request_count(template)
    req_points = request_points(count)
    fp_risk = round(false_positive_risk(template), 4)
    fp_points = round(WEIGHTS["false_positive"] * (1.0 - fp_risk), 2)
    meta_points = metadata_points(template)
    total = round(req_points + fp_points + meta_points, 2)
    return {
        "total": total,
        "request_count": count,
        "components": {
            "request": req_points,
            "false_positive": fp_points,
            "metadata": meta_points,
        },
        "fp_risk": fp_risk,
        "scoring_version": SCORING_VERSION,
    }
