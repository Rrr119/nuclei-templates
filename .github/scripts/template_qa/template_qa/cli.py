"""CLI: semantic dedup / family merge reports and quality scoring.

Usage:
    python3 -m template_qa dedup --root REPO [--limit N] [--seed S] [--out FILE]
    python3 -m template_qa score --root REPO [--limit N] [--seed S] [--out FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .dedup import family_report
from .loader import load_templates
from .score import SCORING_VERSION, quality_score


def _emit(report: dict, out: str) -> None:
    text = json.dumps(report, indent=2, sort_keys=True)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8")
        print("wrote %s" % out)
    else:
        print(text)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="template_qa")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("dedup", "score"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--root", default=".", help="repository root")
        cmd.add_argument("--limit", type=int, default=None, help="sample size")
        cmd.add_argument("--seed", type=int, default=20261127, help="sample seed")
        cmd.add_argument("--out", default=None, help="write JSON report to file")

    args = parser.parse_args(argv)
    templates = load_templates(Path(args.root), limit=args.limit, seed=args.seed)
    if not templates:
        print("no templates found under %s" % args.root, file=sys.stderr)
        return 1

    if args.command == "dedup":
        report = family_report(templates)
        report["tool_version"] = __version__
        _emit(report, args.out)
        print(
            "templates=%d families=%d merged_families=%d merged_templates=%d"
            % (
                report["template_count"],
                report["family_count"],
                report["merged_family_count"],
                report["merged_template_count"],
            ),
            file=sys.stderr,
        )
    else:
        scores = {t.template_id: quality_score(t) for t in templates}
        _emit(
            {
                "scoring_version": SCORING_VERSION,
                "template_count": len(templates),
                "scores": scores,
            },
            args.out,
        )
        print("scored %d templates" % len(templates), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
