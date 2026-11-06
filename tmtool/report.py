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
    fmt = (lambda c: f"`{c}`") if code else (lambda c: c)
    items = [fmt(c) for c in f["controls_missing"]]
    if not items:
        if f.get("controls_detective_only"):
            return "make preventive: " + ", ".join(fmt(c) for c in f["controls_detective_only"])
        return "—"
    return ("one of: " if f.get("any_of") else "") + ", ".join(items)


def _status(f: Dict[str, Any]) -> str:
    """Status, marked when platform inheritance changed it."""
    before = f["without_inheritance"]["status"]
    if f["controls_inherited"] and before != f["status"]:
        return f"{f['status']} ⬇ platform"
    return f["status"]


def _without_sentence(findings: List[Dict[str, Any]], worst: Any, before: Any) -> str:
    """How the platforms change the top line: overall rating, and the number of open High/Critical threats."""
    def high_open(rows):
        return sum(1 for r in rows if r["status"] != "Mitigated" and r["rating"] in ("High", "Critical"))
    removed = high_open([f["without_inheritance"] for f in findings]) - high_open(findings)
    if not before:
        return ""
    if before != worst:
        return f"Without them, overall residual risk would be **{RATING_BADGE[before]}**."
    if removed > 0:
        return (f"Overall residual risk would still be {RATING_BADGE[before]} without them, but they take "
                f"**{removed} High/Critical threat{'s' if removed != 1 else ''}** off the go-live list.")
    return ""


def _present(f: Dict[str, Any], label: bool = True) -> List[str]:
    """Controls in place, labelled with where they come from."""
    if not label:
        return list(f["controls_present"])
    out = []
    for c in f["controls_present"]:
        src = f["controls_inherited"].get(c)
        if src:
            out.append(f"{c} (inherited: {src['platform_name']}, {src['enforcement']})")
        else:
            out.append(f"{c} (app team)")
    return out


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
    inheritance = result.get("inheritance") or {}
    if inheritance.get("platforms"):
        before = worst_open_rating(findings, without_inheritance=True)
        retired = [f for f in findings if f["status"] == "Mitigated"
                   and f["without_inheritance"]["status"] != "Mitigated" and f["controls_inherited"]]
        reduced = [f for f in findings if f["controls_inherited"] and f not in retired
                   and f["score"] < f["without_inheritance"]["score"]]
        names = ", ".join(p["name"] for p in inheritance["platforms"])
        w(f"**Inherited platform controls ({names}):** {len(retired)} threat{'s' if len(retired) != 1 else ''} "
          f"fully mitigated by the platform and {len(reduced)} more reduced. "
          + _without_sentence(findings, worst, before)
          + " See *Inherited platform controls*.\n")
    open_before = Counter(f["without_inheritance"]["rating"] for f in findings
                          if f["without_inheritance"]["status"] != "Mitigated")
    counts = Counter(f["rating"] for f in active)
    mit_counts = Counter(f["rating"] for f in mitigated)
    if inheritance.get("platforms"):
        w("| Rating | Open without platform controls | Open / partially mitigated | Mitigated |\n|---|---|---|---|")
    else:
        w("| Rating | Open / partially mitigated | Mitigated |\n|---|---|---|")
    for r in reversed(RATING_ORDER):
        before_cell = f"{open_before.get(r, 0)} | " if inheritance.get("platforms") else ""
        w(f"| {RATING_BADGE[r]} | {before_cell}{counts.get(r, 0)} | {mit_counts.get(r, 0)} |")
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
    inherited_by_comp = inheritance.get("components", {})
    if inheritance.get("platforms"):
        w("| Component | Type | Zone | Platform | Internet-facing | Data | App team controls | Inherited controls |\n"
          "|---|---|---|---|---|---|---|---|")
    else:
        w("| Component | Type | Zone | Internet-facing | Data | Controls |\n|---|---|---|---|---|---|")
    for c in model["components"].values():
        row = (f"| **{_cell(c['name'])}** (`{c['id']}`) | {c['type']} | {c['zone'] or '—'} | ")
        if inheritance.get("platforms"):
            inh = inherited_by_comp.get(c["id"], {})
            row += f"{c['platform'] or '—'} | "
            row += (f"{'Yes' if c['internet_facing'] else 'No'} | {', '.join(c['data']) or '—'} | "
                    f"{', '.join(c['controls']) or '—'} | {', '.join(sorted(inh)) or '—'} |")
        else:
            row += (f"{'Yes' if c['internet_facing'] else 'No'} | {', '.join(c['data']) or '—'} | "
                    f"{', '.join(c['controls']) or '—'} |")
        w(row)
    w("")
    if app["controls"]:
        w(f"**Application-wide controls** (apply to every component): {', '.join('`' + c + '`' for c in app['controls'])}\n")

    # ------------------------------------------------------------ inherited controls
    if inheritance.get("platforms"):
        w("## Inherited platform controls\n")
        w("Controls the app team gets from the cloud platforms it builds on. **Preventive** controls are "
          "guardrails that block non-compliant deployments; **detective** controls catch drift after the fact, "
          "so they reduce a threat but never fully mitigate it on their own. "
          "The platform team owns these controls and their evidence.\n")
        app_plats = set(model["app"]["platforms"])
        for plat in inheritance["platforms"]:
            users = sorted(c["name"] for c in model["components"].values() if plat["id"] in c["platforms"])
            via = [p["name"] for p in inheritance["platforms"] if plat["id"] in p["inherits"]]
            if plat["id"] in app_plats:
                scope = "whole application"
            elif users:
                scope = ", ".join(users)
            else:
                scope = "through " + ", ".join(via) if via else "inherited by another platform"
            w(f"### {plat['name']} (`{plat['id']}`)\n")
            meta = [f"Applies to: {scope}"]
            if plat["owner"]:
                meta.append(f"Owner: {plat['owner']}")
            if plat["inherits"]:
                meta.append("Builds on: " + ", ".join(f"`{p}`" for p in plat["inherits"]))
            w(" · ".join(meta) + "\n")
            if plat["description"]:
                w(plat["description"] + "\n")
            show_evidence = any(e["evidence"] for e in plat["controls"])
            w("| Control | Covers | Enforcement | Mechanism |" + (" Evidence |" if show_evidence else "")
              + "\n|---|---|---|---|" + ("---|" if show_evidence else ""))
            for e in plat["controls"]:
                covers = ", ".join(e["types"]) if e["types"] else ", ".join(e["applies_to"])
                if e["applies_to"] == ["component"] and not e["types"]:
                    covers = "all components"
                w(f"| `{e['control']}` | {covers} | {e['enforcement'].capitalize()} | {_cell(e['mechanism']) or '—'} |"
                  + (f" {_cell(e['evidence']) or '—'} |" if show_evidence else ""))
            w("")
        if inheritance.get("exceptions"):
            w("**Approved exceptions** (the platform control does *not* apply to these components):\n")
            for cid, exc in inheritance["exceptions"].items():
                w(f"- {model['components'][cid]['name']}: {', '.join('`' + x + '`' for x in exc)}")
            w("")

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
    w("Sorted by risk score (likelihood × impact, 1–25)."
      + (" ⬇ platform = inherited platform controls changed the status." if inheritance.get("platforms") else "") + "\n")
    w("| ID | Risk | Threat | Target | STRIDE | L | I | Score | Status | Missing controls |\n"
      "|---|---|---|---|---|---|---|---|---|---|")
    for f in findings:
        w(f"| {f['id']} | {RATING_BADGE[f['rating']]} | {_cell(f['title'])} | {_cell(f['target_name'])} | "
          f"{''.join(f['stride'])} | {f['likelihood']} | {f['impact']} | **{f['score']}** | {_status(f)} | "
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
            w(f"- **Controls in place:** {', '.join(_present(f, bool(inheritance.get('platforms'))))}")
        if f["controls_detective_only"]:
            w(f"- **Detective only:** {', '.join('`' + c + '`' for c in f['controls_detective_only'])} "
              "is caught after the fact, not prevented. A preventive guardrail would fully mitigate this.")
        if f["controls_inherited"] and f["without_inheritance"]["score"] != f["score"]:
            wi = f["without_inheritance"]
            w(f"- **Without platform controls:** {RATING_BADGE[wi['rating']]} (score {wi['score']}, {wi['status'].lower()})")
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
        w("These threats apply to the design, and all listed controls are in place. App team controls are "
          "self-reported, so verify them (e.g. CSPM findings, config review). Inherited controls are verified "
          "through the platform's evidence.\n")
        for f in mitigated:
            w(f"- {f['id']} · **{f['title']}** on *{f['target_name']}* (residual {f['rating']}, "
              f"controls: {', '.join(_present(f, bool(inheritance.get('platforms'))))})")
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
    w("- **Inherited controls** from the platform baseline count the same as app team controls, except that "
      "detective-only coverage can't fully mitigate a threat. Each finding is also scored without them, "
      "to show what the platforms contribute.")
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
                         "STRIDE", "Controls to add", "Inherited controls", "Description", "Labels"])
        for f in rows:
            writer.writerow([
                f["id"], f"{f['title']} ({f['target_name']})", priority[f["rating"]], f["rating"], f["score"],
                f["status"], f["target_name"], "".join(f["stride"]), _missing(f),
                ", ".join(f"{c} ({src['platform_name']})" for c, src in f["controls_inherited"].items()),
                f["description"], f"threat-model {f['rule_id']}",
            ])
    return len(rows)
