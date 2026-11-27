"""Semantic dedup and family merging.

Two deterministic passes:
1. Exact pass  - union templates sharing the same CVE id (same CVE is by
   definition the same vulnerability).
2. Similarity pass - union near-duplicates whose normalized token sets
   (name + request paths + matchers) have Jaccard similarity
   >= SIMILARITY_THRESHOLD, subject to hard guards that prevent merging
   different vulnerabilities. Vendor+product+vuln-type agreement alone is
   NOT enough to merge: distinct bugs in one product must stay separate.

Guards (never merge when both sides define the field and they differ):
CVE id, CWE id set, vendor, product, primary vuln type, severity.
Additionally the similarity pass requires a shared protocol, a minimum
token-set size, and rejects pairs where EACH side carries unique tokens
(both-sides-unique means the templates describe different things, e.g.
"key creation" vs "key upload" policy checks). One-sided differences may
only add matcher tokens ("m:"): a side that adds identity tokens (name
or path) describes a more specific target - letting it merge would turn
generic templates into hubs that absorb every specific one (e.g. a
generic "woocommerce" detect absorbing every woocommerce plugin detect).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .fingerprint import hard_key, primary_vuln_type, request_ops, token_set
from .loader import Template
from .score import quality_score

SIMILARITY_THRESHOLD = 0.80
# Tokens shared by more templates than this carry no blocking signal.
MAX_TOKEN_POSTINGS = 50
# Token sets smaller than this make Jaccard unreliable; skip the pair.
MIN_TOKEN_SET_SIZE = 4


class UnionFind:
    def __init__(self, items):
        self.parent = {item: item for item in items}

    def find(self, item):
        parent = self.parent
        root = item
        while parent[root] != root:
            root = parent[root]
        while parent[item] != root:
            parent[item], item = root, parent[item]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Deterministic: smaller id becomes the root.
            if rb < ra:
                ra, rb = rb, ra
            self.parent[rb] = ra


@dataclass(frozen=True)
class Family:
    family_id: str
    key: Optional[str]
    canonical: str
    members: tuple
    size: int


def compatible(a: Template, b: Template) -> bool:
    """Hard guards against merging different vulnerabilities."""
    if a.cve_id and b.cve_id and a.cve_id != b.cve_id:
        return False
    if a.cwe_ids and b.cwe_ids and not set(a.cwe_ids) & set(b.cwe_ids):
        return False
    if a.vendor and b.vendor and a.vendor != b.vendor:
        return False
    if a.product and b.product and a.product != b.product:
        return False
    if a.severity != "unknown" and b.severity != "unknown" and a.severity != b.severity:
        return False
    ta, tb = primary_vuln_type(a), primary_vuln_type(b)
    if ta and tb and ta != tb:
        return False
    return True


def _protocols(template: Template) -> frozenset:
    return frozenset(proto for proto, _method, _path in request_ops(template))


def similar(tokens_a: frozenset, tokens_b: frozenset) -> bool:
    """Precision-first similarity decision for the merge pass."""
    if min(len(tokens_a), len(tokens_b)) < MIN_TOKEN_SET_SIZE:
        return False
    only_a = tokens_a - tokens_b
    only_b = tokens_b - tokens_a
    if only_a and only_b:
        # Each side describes something the other does not mention.
        return False
    unique = only_a or only_b
    if any(not token.startswith("m:") for token in unique):
        # One-sided identity (name/path) difference: different targets.
        return False
    return _jaccard(tokens_a, tokens_b) >= SIMILARITY_THRESHOLD


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _candidate_pairs(templates, tokens_by_id):
    """Yield id pairs sharing at least one informative token, sorted."""
    postings = {}
    for template in templates:
        for token in tokens_by_id[template.template_id]:
            postings.setdefault(token, []).append(template.template_id)
    pairs = set()
    for token in sorted(postings):
        ids = postings[token]
        if len(ids) > MAX_TOKEN_POSTINGS:
            continue
        ids = sorted(ids)
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                pairs.add((ids[i], ids[j]))
    return sorted(pairs)


def build_families(templates) -> list:
    """Cluster templates into duplicate families; fully deterministic."""
    templates = sorted(templates, key=lambda t: (t.template_id.lower(), t.path))
    by_id = {t.template_id: t for t in templates}
    uf = UnionFind(by_id)

    # Pass 1: same CVE id => same vulnerability, merge unconditionally.
    groups = {}
    for template in templates:
        if template.cve_id:
            groups.setdefault(template.cve_id, []).append(template.template_id)
    for key in sorted(groups):
        ids = sorted(groups[key])
        for other in ids[1:]:
            uf.union(ids[0], other)

    # Pass 2: similarity with guards.
    tokens_by_id = {t.template_id: token_set(t) for t in templates}
    protos_by_id = {t.template_id: _protocols(t) for t in templates}
    for id_a, id_b in _candidate_pairs(templates, tokens_by_id):
        if uf.find(id_a) == uf.find(id_b):
            continue
        a, b = by_id[id_a], by_id[id_b]
        if not compatible(a, b):
            continue
        if protos_by_id[id_a] and protos_by_id[id_b] and not (
            protos_by_id[id_a] & protos_by_id[id_b]
        ):
            continue
        if similar(tokens_by_id[id_a], tokens_by_id[id_b]):
            uf.union(id_a, id_b)

    clusters = {}
    for template in templates:
        clusters.setdefault(uf.find(template.template_id), []).append(template)

    families = []
    for root in sorted(clusters):
        members = sorted(clusters[root], key=lambda t: t.template_id.lower())
        scored = sorted(
            members,
            key=lambda t: (-quality_score(t)["total"], t.template_id.lower()),
        )
        canonical = scored[0]
        keys = {hard_key(m) for m in members if hard_key(m)}
        families.append(
            Family(
                family_id="fam-" + canonical.template_id.lower(),
                key=sorted(keys)[0] if keys else None,
                canonical=canonical.template_id,
                members=tuple(m.template_id for m in members),
                size=len(members),
            )
        )
    families.sort(key=lambda f: f.family_id)
    return families


def family_report(templates) -> dict:
    """JSON-serializable dedup report."""
    families = build_families(templates)
    multi = [f for f in families if f.size > 1]
    return {
        "template_count": len(templates),
        "family_count": len(families),
        "merged_family_count": len(multi),
        "merged_template_count": sum(f.size for f in multi),
        "families": [
            {
                "family_id": f.family_id,
                "key": f.key,
                "canonical": f.canonical,
                "size": f.size,
                "members": list(f.members),
            }
            for f in families
        ],
    }
