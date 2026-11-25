"""Command-line interface: python -m tmtool <command>."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from datetime import datetime
from typing import List, Optional

from . import __version__, vocab
from .engine import RATING_ORDER, analyze
from .model import DEFAULT_LIBRARY, IntakeError, check_platform_refs, load_intake, load_library, load_platforms
from .report import render_markdown, write_csv

TEMPLATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", "intake-template.yaml")


def _libraries(extra: Optional[List[str]]) -> List[str]:
    return [DEFAULT_LIBRARY] + (extra or [])


def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        model, warnings = load_intake(args.intake)
        platforms = load_platforms(args.platforms or [])
    except IntakeError as exc:
        print(exc, file=sys.stderr)
        return 1
    warnings += check_platform_refs(model, platforms)
    rules = load_library(_libraries(args.library))
    result = analyze(model, rules, platforms)

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
    inherited = sum(1 for f in findings if f["status"] == "Mitigated" and f["controls_inherited"]
                    and f["without_inheritance"]["status"] != "Mitigated")
    if platforms:
        print(f"  {inherited} threats fully mitigated by inherited platform controls")
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
        model, warnings = load_intake(args.intake)
        platforms = load_platforms(args.platforms or [])
    except IntakeError as exc:
        print(exc, file=sys.stderr)
        return 1
    warnings += check_platform_refs(model, platforms)
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


DEFAULT_TERMS = os.path.join("local", "redact-terms.txt")


def _read_terms(path: Optional[str]) -> List[str]:
    path = path or (DEFAULT_TERMS if os.path.exists(DEFAULT_TERMS) else None)
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def cmd_draft(args: argparse.Namespace) -> int:
    # Imported here so the core tool never needs the assist dependencies.
    from .assist.client import AssistError, make_client, model_name
    from .assist.draft import draft_intake, preview_redacted, to_yaml
    from .assist.sources import SourceError

    try:
        terms = _read_terms(args.redact_terms)
        if args.show_redacted:
            print(preview_redacted(args.sources, terms))
            return 0
        output = args.output or os.path.join(
            "local", "intakes", f"draft-{datetime.now().strftime('%Y%m%d-%H%M')}.yaml")
        if os.path.exists(output) and not args.force:
            print(f"{output} already exists (use --force to overwrite)", file=sys.stderr)
            return 1
        client = make_client(args.provider)
        model = model_name(args.model)
        print(f"Drafting an intake with {model}. Only redacted text is sent; the model can't write files.")
        intake, summary, redactions = draft_intake(args.sources, client, model, terms, args.verbose, args.max_steps)
    except (AssistError, SourceError) as exc:
        print(exc, file=sys.stderr)
        return 1

    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # owner-only: it describes your system
    with os.fdopen(fd, "w") as fh:
        fh.write(to_yaml(intake))

    n_prop = sum(len(h.get("proposed_controls", [])) + len(h.get("proposed_values", []))
                 for h in [intake["app"]] + intake["components"] + intake["flows"])
    print(f"\nDraft written to {output}")
    print(f"  {len(intake['components'])} components, {len(intake['flows'])} flows, "
          f"{n_prop} proposals (not credited), {len(intake['open_questions'])} open questions")
    if redactions:
        print("  redacted before sending: " + ", ".join(f"{v} {k.lower()}" for k, v in sorted(redactions.items())))
    notes = intake["draft"]["review_notes"]
    if notes:
        print(f"  {len(notes)} review note(s) — read these first:")
        for n in notes:
            print(f"    - {n}")
    print(f"\nAssistant summary (model-written, for context only):\n  {summary}")
    if not os.path.abspath(output).startswith(os.path.abspath("local") + os.sep):
        print("\nwarning: the draft is outside local/, which is git-ignored. Don't commit real architectures.",
              file=sys.stderr)
    print(f"\nNext: review it, then  python -m tmtool validate {output}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    for r in load_library(_libraries(args.library)):
        target = r["applies_to"] + (f" ({', '.join(r['types'])})" if r.get("types") else "")
        print(f"{r['id']:7} {''.join(r['stride']):4} {r['title']}  [{target}]")
    return 0


def cmd_platforms(args: argparse.Namespace) -> int:
    try:
        platforms = load_platforms(args.baseline)
    except IntakeError as exc:
        print(exc, file=sys.stderr)
        return 1
    for p in platforms.values():
        extra = f" (builds on {', '.join(p['inherits'])})" if p["inherits"] else ""
        print(f"{p['id']}: {p['name']}{extra}")
        for e in p["controls"]:
            covers = ", ".join(e["types"]) or ", ".join(e["applies_to"])
            print(f"    {e['control']:30} {e['enforcement']:10} {covers}")
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
    a.add_argument("--platforms", action="append", help="Platform baseline YAML: controls apps inherit (can repeat)")
    a.set_defaults(func=cmd_analyze)

    v = sub.add_parser("validate", help="Check an intake file without generating a report")
    v.add_argument("intake")
    v.add_argument("--library", action="append")
    v.add_argument("--platforms", action="append")
    v.set_defaults(func=cmd_validate)

    i = sub.add_parser("init", help="Create a new intake file from the template")
    i.add_argument("path", nargs="?", default="intake.yaml")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    d = sub.add_parser("draft", help="Agent-assisted: draft an intake from architecture documents (needs Claude)")
    d.add_argument("sources", nargs="+", help="Text documents or folders (.md, .txt, .html, .yaml, .mmd, ...)")
    d.add_argument("-o", "--output", help="Draft path (default: local/intakes/draft-<time>.yaml)")
    d.add_argument("--force", action="store_true", help="Overwrite the output file")
    d.add_argument("--show-redacted", action="store_true",
                   help="Print exactly what would be sent, after cleaning and redaction, and exit (no API call)")
    d.add_argument("--redact-terms", help="File of extra terms to redact, one per line "
                   "(default: local/redact-terms.txt if it exists)")
    d.add_argument("--provider", choices=("anthropic", "bedrock"), help="Default: $TMTOOL_PROVIDER or anthropic")
    d.add_argument("--model", help="Default: $TMTOOL_MODEL or the built-in default")
    d.add_argument("--max-steps", type=int, default=60, help="Cap on model round trips (cost control)")
    d.add_argument("-v", "--verbose", action="store_true", help="Show every tool result")
    d.set_defaults(func=cmd_draft)

    r = sub.add_parser("rules", help="List the threat rules")
    r.add_argument("--library", action="append")
    r.set_defaults(func=cmd_rules)

    pl = sub.add_parser("platforms", help="List platforms and the controls they provide")
    pl.add_argument("baseline", nargs="+", help="Platform baseline YAML file(s)")
    pl.set_defaults(func=cmd_platforms)

    sub.add_parser("types", help="List component types").set_defaults(func=lambda _: _print_table(vocab.COMPONENT_TYPES))
    sub.add_parser("data", help="List data classes").set_defaults(func=lambda _: _print_table(vocab.DATA_CLASSES))
    sub.add_parser("controls", help="List known controls").set_defaults(func=lambda _: _print_table(vocab.CONTROLS))
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
