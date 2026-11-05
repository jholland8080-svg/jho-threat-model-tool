"""Render the analysis as a Markdown threat model report and an optional CSV backlog."""

from __future__ import annotations

import csv
import datetime as dt
import re
from collections import Counter, OrderedDict
from typing import Any, Dict, List

from . import vocab
from .engine import RATING_ORDER, worst_open_rating

STRIDE_NAMES = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege",
}
RATING_BADGE = {"Critical": "🔴 Critical", "High": "🟠 High", "Medium": "🟡 Medium", "Low": "🟢 Low"}


def _cell(text: Any) -> str:
    """Make text safe inside a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _node_id(cid: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", cid)


def _label(text: str) -> str:
    return text.replace('"', "'")


def _missing(f: Dict[str, Any], code: bool = False) -> str:
    """Controls still needed; 'one of' when any single control would do."""
    items = [f"`{c}`" if code else c for c in f["controls_missing"]]
    if not items:
        return "—"
    return ("one of: " if f.get("any_of") else "") + ", ".join(items)


def _mermaid(model: Dict[str, Any]) -> str:
    shapes = {
        "user": ('(["', '"])'),
        "database": ('[("', '")]'), "object_storage": ('[("', '")]'), "vector_store": ('[("', '")]'),
        "secrets_store": ('[("', '")]'), "logging": ('[("', '")]'),
        "queue": ('[/"', '"/]'),
        "llm": ('{{"', '"}}'), "ai_agent": ('{{"', '"}}'),
        "external_system": ('>"', '"]'), "saas": ('>"', '"]'),
    }
    lines = ["flowchart LR"]

    def node(c):
        open_, close = shapes.get(c["type"], ('["', '"]'))
        return f"{_node_id(c['id'])}{open_}{_label(c['name'])}{close}"

    by_zone: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict((z, []) for z in model["zones"])
    no_zone = []
    for c in model["components"].values():
        (by_zone[c["zone"]] if c["zone"] else no_zone).append(c)

    for c in no_zone:
        lines.append(f"    {node(c)}")
    for zid, comps in by_zone.items():
        if not comps:
            continue
        zname = model["zones"][zid]["name"]
        lines.append(f'    subgraph {_node_id("zone_" + zid)}["{_label(zname)}"]')
        for c in comps:
            lines.append(f"        {node(c)}")
        lines.append("    end")

    for f in model["flows"]:
        parts = [p for p in (f["protocol"], ", ".join(f["data"])) if p]
        label = f"{f['id']}: " + " · ".join(parts) if parts else f["id"]
        arrow = "-.->" if f["encrypted"] is False else "-->"
        lines.append(f'    {_node_id(f["from"])} {arrow}|"{_label(label)}"| {_node_id(f["to"])}')
    return "\n".join(lines)


def render_markdown(model: Dict[str, Any], result: Dict[str, Any], warnings: List[str]) -> str:
    app = model["app"]
    findings = result["findings"]
    active = [f for f in findings if f["status"] != "Mitigated"]
    mitigated = [f for f in findings if f["status"] == "Mitigated"]
    out: List[str] = []
    w = out.append

    # ------------------------------------------------------------ header
    w(f"# Threat Model: {app['name']}\n")
    meta = [("Generated", dt.date.today().isoformat())]
    for key, label in (("owner", "Owner"), ("stage", "Stage"), ("criticality", "Criticality")):
        if app.get(key):
            meta.append((label, str(app[key]).capitalize() if key == "criticality" else app[key]))
    if app["users"]:
        meta.append(("Users", ", ".join(app["users"])))
    if app["regulatory"]:
        meta.append(("Regulatory scope", ", ".join(r.upper() for r in app["regulatory"])))
    w("| | |\n|---|---|")
    for k, v in meta:
        w(f"| **{k}** | {_cell(v)} |")
    w("")
    if app["description"]:
        w(f"{app['description'].strip()}\n")

    # ------------------------------------------------------------ summary
    w("## Executive summary\n")
    worst = worst_open_rating(findings)
    if worst:
        w(f"**Overall residual risk: {RATING_BADGE[worst]}** (highest-rated threat that is not fully mitigated)\n")
    else:
        w("**Overall residual risk: all identified threats have their listed controls in place.**\n")
    counts = Counter(f["rating"] for f in active)
    w("| Rating | Open / partially mitigated | Mitigated |\n|---|---|---|")
    mit_counts = Counter(f["rating"] for f in mitigated)
    for r in reversed(RATING_ORDER):
        w(f"| {RATING_BADGE[r]} | {counts.get(r, 0)} | {mit_counts.get(r, 0)} |")
    w("")
    top = active[:5]
    if top:
        w("**Top risks to address:**\n")
        for f in top:
            w(f"1. **{f['title']}** on *{f['target_name']}* ({RATING_BADGE[f['rating']]}, {f['status'].lower()}). "
              f"Add: {_missing(f, code=True)}")
        w("")
    if result["gaps"]:
        w(f"⚠️ The intake left **{len(result['gaps'])} open question{'s' if len(result['gaps']) != 1 else ''}** (see *Questions for the app team*). "
          "Answering them may add or change findings.\n")

    # ------------------------------------------------------------ scope
    w("## Scope\n")
    w("| Component | Type | Zone | Internet-facing | Data | Controls |\n|---|---|---|---|---|---|")
    for c in model["components"].values():
        w(f"| **{_cell(c['name'])}** (`{c['id']}`) | {c['type']} | {c['zone'] or '—'} | "
          f"{'Yes' if c['internet_facing'] else 'No'} | {', '.join(c['data']) or '—'} | "
          f"{', '.join(c['controls']) or '—'} |")
    w("")
    if app["controls"]:
        w(f"**Application-wide controls** (apply to every component): {', '.join('`' + c + '`' for c in app['controls'])}\n")

    # ------------------------------------------------------------ DFD
    w("## Data flow diagram\n")
    w("Boxes are trust zones. Dotted arrows are unencrypted flows.\n")
    w("```mermaid")
    w(_mermaid(model))
    w("```\n")

    crossings = result["boundary_crossings"]
    if crossings:
        w("### Trust boundary crossings\n")
        w("Threats concentrate where data crosses between zones.\n")
        w("| Flow | From → To | Zones | Protocol | Data | Encrypted | Authenticated |\n|---|---|---|---|---|---|---|")
        comps = model["components"]
        for f in crossings:
            def yn(v):
                return "Yes" if v is True else ("**No**" if v is False else "Unknown")
            w(f"| {f['id']} | {_cell(comps[f['from']]['name'])} → {_cell(comps[f['to']]['name'])} | "
              f"{comps[f['from']]['zone']} → {comps[f['to']]['zone']} | {f['protocol'] or '—'} | "
              f"{', '.join(f['data']) or '—'} | {yn(f['encrypted'])} | {yn(f['authenticated'])} |")
        w("")

    # ------------------------------------------------------------ register
    w("## Threat register\n")
    w("Sorted by risk score (likelihood × impact, 1–25).\n")
    w("| ID | Risk | Threat | Target | STRIDE | L | I | Score | Status | Missing controls |\n"
      "|---|---|---|---|---|---|---|---|---|---|")
    for f in findings:
        w(f"| {f['id']} | {RATING_BADGE[f['rating']]} | {_cell(f['title'])} | {_cell(f['target_name'])} | "
          f"{''.join(f['stride'])} | {f['likelihood']} | {f['impact']} | **{f['score']}** | {f['status']} | "
          f"{_missing(f)} |")
    w("")

    # ------------------------------------------------------------ go-live
    blockers = [f for f in active if f["rating"] in ("Critical", "High")]
    w("## Required before go-live\n")
    if blockers:
        w("Critical and High threats that are not fully mitigated. Fix these, or document a risk acceptance "
          "with a named owner and an expiry date.\n")
        w("| ID | Threat | Target | Controls to add |\n|---|---|---|---|")
        for f in blockers:
            w(f"| {f['id']} | {_cell(f['title'])} | {_cell(f['target_name'])} | "
              f"{_missing(f)} |")
    else:
        w("No open Critical or High threats.")
    w("")

    # ------------------------------------------------------------ details
    w("## Threat details\n")
    for f in active:
        w(f"### {f['id']} · {f['title']}\n")
        w(f"**{RATING_BADGE[f['rating']]}** · score {f['score']} (L{f['likelihood']} × I{f['impact']}) · "
          f"{f['status']} · rule `{f['rule_id']}`\n")
        w(f"- **Target:** {f['target_name']} ({f['target_type']})")
        w(f"- **STRIDE:** {', '.join(STRIDE_NAMES[s] for s in f['stride'])}")
        w(f"- **Threat:** {f['description']}")
        if f["controls_present"]:
            w(f"- **Controls in place:** {', '.join(f['controls_present'])}")
        if f["controls_missing"]:
            w("- **Recommended mitigations" + (" (any one is enough)" if f.get("any_of") else "") + ":**")
            for c in f["controls_missing"]:
                w(f"  - `{c}`: {vocab.CONTROLS.get(c, '')}")
        if f["adjustments"]:
            w(f"- **Score adjustments:** {'; '.join(f['adjustments'])}")
        if f["references"]:
            w(f"- **References:** {'; '.join(f['references'])}")
        w("")
    if mitigated:
        w("### Mitigated threats\n")
        w("These threats apply to the design, and all listed controls are reported as in place. "
          "Verify the controls actually exist (e.g. CSPM findings, config review).\n")
        for f in mitigated:
            w(f"- {f['id']} · **{f['title']}** on *{f['target_name']}* (residual {f['rating']}, "
              f"controls: {', '.join(f['controls_present'])})")
        w("")

    # ------------------------------------------------------------ questions
    w("## Questions for the app team\n")
    if result["gaps"]:
        w("**Missing from the intake:**\n")
        for g in result["gaps"]:
            w(f"- [ ] {g}")
        w("")
    by_target: "OrderedDict[str, List[str]]" = OrderedDict()
    for f in active:
        for q in f["questions"]:
            qs = by_target.setdefault(f["target_name"], [])
            if q not in qs:
                qs.append(q)
    if by_target:
        w("**To confirm during the review:**\n")
        for target, qs in by_target.items():
            w(f"*{target}*")
            for q in qs:
                w(f"- [ ] {q}")
            w("")

    # ------------------------------------------------------------ appendix
    if warnings:
        w("## Intake warnings\n")
        for x in warnings:
            w(f"- {x}")
        w("")
    w("## Method\n")
    w("- Threats come from a rule-based library (STRIDE, OWASP Top 10 for LLM Applications 2025, "
      "cloud and container threats). Each rule fires when the architecture matches its conditions.")
    w("- **Likelihood and impact** start from the rule's base score (1–5), then: +1 likelihood if internet-facing; "
      "+1 impact for highly sensitive data (restricted, customer PII, PCI, credentials); ±1 impact for "
      "high/low application criticality; −1 likelihood if some listed controls are in place, −2 if all are.")
    w("- **Ratings:** Critical 20–25 · High 12–19 · Medium 6–11 · Low 1–5.")
    w("- This is a starting point for a threat modeling session, not a replacement for one. "
      "Controls are as reported by the app team and should be verified.")
    return "\n".join(out) + "\n"


def write_csv(path: str, result: Dict[str, Any]) -> int:
    """Write open and partially mitigated findings as a backlog CSV (Jira-friendly columns)."""
    rows = [f for f in result["findings"] if f["status"] != "Mitigated"]
    priority = {"Critical": "Highest", "High": "High", "Medium": "Medium", "Low": "Low"}
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ID", "Summary", "Priority", "Risk rating", "Score", "Status", "Target",
                         "STRIDE", "Controls to add", "Description", "Labels"])
        for f in rows:
            writer.writerow([
                f["id"], f"{f['title']} ({f['target_name']})", priority[f["rating"]], f["rating"], f["score"],
                f["status"], f["target_name"], "".join(f["stride"]), _missing(f),
                f["description"], f"threat-model {f['rule_id']}",
            ])
    return len(rows)
