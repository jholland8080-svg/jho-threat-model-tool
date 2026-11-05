"""Command-line interface: python -m tmtool <command>."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from typing import List, Optional

from . import __version__, vocab
from .engine import RATING_ORDER, analyze
from .model import DEFAULT_LIBRARY, IntakeError, load_intake, load_library
from .report import render_markdown, write_csv

TEMPLATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", "intake-template.yaml")


def _libraries(extra: Optional[List[str]]) -> List[str]:
    return [DEFAULT_LIBRARY] + (extra or [])


def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        model, warnings = load_intake(args.intake)
    except IntakeError as exc:
        print(exc, file=sys.stderr)
        return 1
    rules = load_library(_libraries(args.library))
    result = analyze(model, rules)

    if args.min_rating:
        floor = RATING_ORDER.index(args.min_rating)
        result["findings"] = [f for f in result["findings"] if RATING_ORDER.index(f["rating"]) >= floor]

    report = render_markdown(model, result, warnings)
    output = args.output or os.path.join(
        "reports", os.path.splitext(os.path.basename(args.intake))[0] + "-threat-model.md")
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with open(output, "w") as fh:
        fh.write(report)

    findings = result["findings"]
    active = [f for f in findings if f["status"] != "Mitigated"]
    print(f"Threat model written to {output}")
    print(f"  {len(findings)} threats ({len(active)} open or partially mitigated), "
          f"{len(result['gaps'])} open questions, {len(warnings)} warnings")
    for r in reversed(RATING_ORDER):
        n = sum(1 for f in active if f["rating"] == r)
        if n:
            print(f"  {r}: {n}")
    for w in warnings:
        print(f"  warning: {w}", file=sys.stderr)

    if args.csv:
        n = write_csv(args.csv, result)
        print(f"Backlog CSV written to {args.csv} ({n} items)")

    if args.fail_on:
        threshold = RATING_ORDER.index(args.fail_on)
        blocking = [f for f in active if RATING_ORDER.index(f["rating"]) >= threshold]
        if blocking:
            print(f"FAIL: {len(blocking)} open threat(s) rated {args.fail_on} or higher", file=sys.stderr)
            return 2
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        _, warnings = load_intake(args.intake)
    except IntakeError as exc:
        print(exc, file=sys.stderr)
        return 1
    load_library(_libraries(args.library))
    for w in warnings:
        print(f"warning: {w}")
    print("Intake is valid." + (f" ({len(warnings)} warnings)" if warnings else ""))
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    if os.path.exists(args.path) and not args.force:
        print(f"{args.path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(args.path) or ".", exist_ok=True)
    shutil.copyfile(TEMPLATE, args.path)
    print(f"Created {args.path}. Fill it in, then run: python -m tmtool analyze {args.path}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    for r in load_library(_libraries(args.library)):
        target = r["applies_to"] + (f" ({', '.join(r['types'])})" if r.get("types") else "")
        print(f"{r['id']:7} {''.join(r['stride']):4} {r['title']}  [{target}]")
    return 0


def _print_table(items) -> int:
    width = max(len(k) for k in items)
    for k, v in items.items():
        print(f"{k:<{width}}  {v}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tmtool", description="Rule-based threat modeling for cloud and AI architectures")
    p.add_argument("--version", action="version", version=f"tmtool {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Generate a threat model report from an intake file")
    a.add_argument("intake", help="Path to the intake YAML")
    a.add_argument("-o", "--output", help="Report path (default: reports/<intake>-threat-model.md)")
    a.add_argument("--csv", help="Also write open findings as a backlog CSV")
    a.add_argument("--min-rating", choices=RATING_ORDER, help="Only include findings at or above this rating")
    a.add_argument("--fail-on", choices=RATING_ORDER, help="Exit with code 2 if any open finding is at or above this rating")
    a.add_argument("--library", action="append", help="Extra threat library YAML (can repeat)")
    a.set_defaults(func=cmd_analyze)

    v = sub.add_parser("validate", help="Check an intake file without generating a report")
    v.add_argument("intake")
    v.add_argument("--library", action="append")
    v.set_defaults(func=cmd_validate)

    i = sub.add_parser("init", help="Create a new intake file from the template")
    i.add_argument("path", nargs="?", default="intake.yaml")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    r = sub.add_parser("rules", help="List the threat rules")
    r.add_argument("--library", action="append")
    r.set_defaults(func=cmd_rules)

    sub.add_parser("types", help="List component types").set_defaults(func=lambda _: _print_table(vocab.COMPONENT_TYPES))
    sub.add_parser("data", help="List data classes").set_defaults(func=lambda _: _print_table(vocab.DATA_CLASSES))
    sub.add_parser("controls", help="List known controls").set_defaults(func=lambda _: _print_table(vocab.CONTROLS))
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
