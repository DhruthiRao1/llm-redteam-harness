"""Command line interface: python -m redteam --target mock-guarded"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .report import to_json, to_markdown
from .runner import run
from .targets import build_target


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="redteam", description="Red-team an LLM application.")
    p.add_argument("--target", default="mock-guarded",
                   choices=["mock-vulnerable", "mock-guarded", "openai"])
    p.add_argument("--model", default="gpt-4o-mini", help="model name for the openai target")
    p.add_argument("--out", type=Path, help="write report files with this path prefix")
    p.add_argument("--fail-under", type=float, default=None,
                   help="exit 1 if the security score is below this value (for CI)")
    args = p.parse_args(argv)

    report = run(build_target(args.target, args.model), target_name=args.target)
    md = to_markdown(report)
    print(md)
    if args.out:
        args.out.with_suffix(".md").write_text(md)
        args.out.with_suffix(".json").write_text(to_json(report))
    if args.fail_under is not None and report.score < args.fail_under:
        print(f"FAIL: score {report.score} < {args.fail_under}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
