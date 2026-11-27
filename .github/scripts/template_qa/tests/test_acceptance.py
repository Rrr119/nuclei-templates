"""Acceptance tests: 1000-template dedup merge quality + scoring reproducibility.

Run from the template_qa directory:
    python3 -m unittest discover -s tests -v
"""

import copy
import json
import unittest
from collections import defaultdict
from pathlib import Path

from template_qa.dedup import build_families
from template_qa.fingerprint import primary_vuln_type
from template_qa.loader import Template, load_templates
from template_qa.score import quality_score

REPO_ROOT = Path(__file__).resolve().parents[4]
SAMPLE_SIZE = 1000
SAMPLE_SEED = 20261127


def make_template(template_id, **overrides):
    """Build a synthetic Template with sensible defaults."""
    data = {
        "id": template_id,
        "info": {
            "name": "Acme Console - SQL Injection",
            "author": "tester",
            "severity": "high",
            "description": "SQL injection in the Acme console login form.",
            "reference": ["https://example.com/advisory"],
            "classification": {"cwe-id": "CWE-89"},
            "metadata": {"vendor": "acme", "product": "console"},
            "tags": "sqli,acme",
        },
        "http": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/acme/login?user='"],
                "matchers": [
                    {
                        "type": "word",
                        "part": "body",
                        "words": ["SQL syntax error", "acme_db"],
                        "condition": "and",
                    },
                    {"type": "status", "status": [500]},
                ],
            }
        ],
    }
    info = data["info"]
    for key, value in overrides.items():
        if key in info:
            info[key] = value
        elif key == "http":
            data["http"] = value
        else:
            data[key] = value
    classification = info.get("classification") or {}
    metadata = info.get("metadata") or {}
    cwe = classification.get("cwe-id")
    cwe_ids = (cwe.upper(),) if isinstance(cwe, str) else tuple(cwe or ())
    return Template(
        path="synthetic/%s.yaml" % template_id,
        template_id=template_id,
        name=str(info.get("name") or ""),
        severity=str(info.get("severity") or "unknown"),
        tags=tuple(t.strip() for t in str(info.get("tags") or "").split(",") if t.strip()),
        cve_id=(classification.get("cve-id") or None),
        cwe_ids=cwe_ids,
        vendor=metadata.get("vendor"),
        product=metadata.get("product"),
        verified=bool(metadata.get("verified")),
        max_request=metadata.get("max-request"),
        data=data,
    )


class RealCorpusTest(unittest.TestCase):
    """Acceptance on a deterministic 1000-template sample of the real repo."""

    @classmethod
    def setUpClass(cls):
        cls.templates = load_templates(REPO_ROOT, limit=SAMPLE_SIZE, seed=SAMPLE_SEED)
        cls.families = build_families(cls.templates)
        cls.family_of = {}
        for family in cls.families:
            for member in family.members:
                cls.family_of[member] = family.family_id

    def test_sample_size(self):
        self.assertEqual(len(self.templates), SAMPLE_SIZE)

    def test_duplicate_groups_fully_merged(self):
        """Every CVE group in the sample collapses into exactly one family."""
        by_cve = defaultdict(list)
        for template in self.templates:
            if template.cve_id:
                by_cve[template.cve_id].append(template.template_id)
        multi = {cve: ids for cve, ids in by_cve.items() if len(ids) > 1}
        self.assertGreater(len(multi), 0, "sample should contain duplicate CVE groups")
        for cve, ids in multi.items():
            families = {cls_family for tid in ids for cls_family in [self.family_of[tid]]}
            self.assertEqual(
                len(families), 1, "CVE group %s split across families %s" % (cve, families)
            )

    def test_no_distinct_vulnerabilities_merged(self):
        """No family mixes different CVEs; non-CVE families stay homogeneous."""
        by_id = {t.template_id: t for t in self.templates}
        for family in self.families:
            members = [by_id[m] for m in family.members]
            cves = {m.cve_id for m in members if m.cve_id}
            self.assertLessEqual(
                len(cves), 1, "family %s merges CVEs %s" % (family.family_id, cves)
            )
            if cves:
                # A shared CVE justifies the family by itself: one CVE can
                # legitimately span vendors/products (e.g. log4shell).
                continue
            vendors = {m.vendor for m in members if m.vendor}
            self.assertLessEqual(len(vendors), 1, "family %s mixes vendors" % family.family_id)
            products = {m.product for m in members if m.product}
            self.assertLessEqual(len(products), 1, "family %s mixes products" % family.family_id)
            vtypes = {primary_vuln_type(m) for m in members if primary_vuln_type(m)}
            self.assertLessEqual(
                len(vtypes), 1, "family %s mixes vuln types %s" % (family.family_id, vtypes)
            )
            # Without a shared CVE, members must share at least one CWE
            # whenever CWEs are annotated (disjoint CWEs => different bugs).
            cwe_sets = [set(m.cwe_ids) for m in members if m.cwe_ids]
            for i in range(len(cwe_sets)):
                for j in range(i + 1, len(cwe_sets)):
                    self.assertTrue(
                        cwe_sets[i] & cwe_sets[j],
                        "family %s merges disjoint CWEs" % family.family_id,
                    )

    def test_scoring_reproducible(self):
        """Identical scores across runs and input orderings."""
        first = {t.template_id: quality_score(t) for t in self.templates}
        second = {t.template_id: quality_score(t) for t in reversed(self.templates)}
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )

    def test_scores_within_bounds(self):
        for template in self.templates:
            score = quality_score(template)
            self.assertGreaterEqual(score["total"], 0.0)
            self.assertLessEqual(score["total"], 100.0)
            self.assertGreaterEqual(score["request_count"], 1)


class SyntheticVariantTest(unittest.TestCase):
    """Controlled ground truth: variants must merge, distinct bugs must not."""

    def test_variants_of_same_bug_merge(self):
        base = make_template("acme-console-sqli")
        renamed = make_template("acme-sqli-variant", author="someone-else")
        http = [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/acme/login?user=%27"],
                "matchers": [
                    {"type": "status", "status": [500]},
                    {
                        "type": "word",
                        "part": "body",
                        "words": ["SQL syntax error", "acme_db"],
                        "condition": "and",
                    },
                ],
            }
        ]
        reordered = make_template("acme-login-sqli", http=http)
        families = build_families([base, renamed, reordered])
        self.assertEqual(len(families), 1)
        self.assertEqual(families[0].size, 3)

    def test_same_product_different_vuln_types_not_merged(self):
        sqli = make_template("acme-console-sqli")
        xss = make_template(
            "acme-console-xss",
            name="Acme Console - Reflected XSS",
            tags="xss,acme",
            classification={"cwe-id": "CWE-79"},
        )
        families = build_families([sqli, xss])
        self.assertEqual(len(families), 2)

    def test_same_product_different_cves_not_merged(self):
        cve_a = make_template(
            "CVE-2024-10001", classification={"cve-id": "CVE-2024-10001", "cwe-id": "CWE-89"}
        )
        cve_b = make_template(
            "CVE-2024-10002", classification={"cve-id": "CVE-2024-10002", "cwe-id": "CWE-89"}
        )
        families = build_families([cve_a, cve_b])
        self.assertEqual(len(families), 2)

    def test_same_cve_always_merges(self):
        cve_a = make_template(
            "CVE-2024-10001", classification={"cve-id": "CVE-2024-10001", "cwe-id": "CWE-89"}
        )
        cve_b = make_template(
            "CVE-2024-10001-variant",
            name="Totally different wording for the same CVE",
            classification={"cve-id": "CVE-2024-10001", "cwe-id": "CWE-89"},
        )
        families = build_families([cve_a, cve_b])
        self.assertEqual(len(families), 1)

    def test_disjoint_cwe_not_merged(self):
        tpl_a = make_template("acme-console-bug-a", classification={"cwe-id": "CWE-89"})
        tpl_b = make_template("acme-console-bug-b", classification={"cwe-id": "CWE-787"})
        families = build_families([tpl_a, tpl_b])
        self.assertEqual(len(families), 2)


if __name__ == "__main__":
    unittest.main()
