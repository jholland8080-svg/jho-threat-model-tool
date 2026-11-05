"""Load and validate the intake file (the app team's architecture) and the threat library."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

import yaml

from . import vocab

DEFAULT_LIBRARY = os.path.join(os.path.dirname(__file__), "library", "threats.yaml")

COMPONENT_CONDITIONS = {
    "attrs", "data_any", "sensitive_data", "receives_from_types", "sends_to_types",
    "app_regulatory_any", "app_criticality_any", "app_users_any",
}
FLOW_CONDITIONS = {
    "attrs", "data_any", "sensitive_data", "crosses_boundary", "from_types", "to_types", "exclude_from_types",
    "app_regulatory_any", "app_criticality_any", "app_users_any",
}
APP_CONDITIONS = {"app_regulatory_any", "app_criticality_any", "app_users_any"}
STRIDE = {"S", "T", "R", "I", "D", "E"}


class IntakeError(Exception):
    """Raised when the intake file can't be used."""


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def load_intake(path: str) -> Tuple[Dict[str, Any], List[str]]:
    """Read an intake YAML file. Returns (normalized model, warnings). Raises IntakeError on errors."""
    try:
        with open(path) as fh:
            raw = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        raise IntakeError(f"Intake file not found: {path}")
    except yaml.YAMLError as exc:
        raise IntakeError(f"Intake file is not valid YAML: {exc}")
    return normalize_intake(raw)


def normalize_intake(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    app_raw = raw.get("app") or {}
    app = {
        "name": app_raw.get("name") or "",
        "description": app_raw.get("description", ""),
        "owner": app_raw.get("owner", ""),
        "stage": app_raw.get("stage", ""),
        "criticality": str(app_raw.get("criticality", "medium")).lower(),
        "users": [str(u).lower() for u in _as_list(app_raw.get("users"))],
        "regulatory": [str(r).lower() for r in _as_list(app_raw.get("regulatory"))],
        "controls": [str(c) for c in _as_list(app_raw.get("controls"))],
    }
    if not app["name"]:
        errors.append("app.name is required")
    if app["criticality"] not in vocab.CRITICALITY:
        errors.append(f"app.criticality must be one of {', '.join(vocab.CRITICALITY)}")
    for u in app["users"]:
        if u not in vocab.USER_GROUPS:
            warnings.append(f"app.users: unknown group '{u}' (known: {', '.join(vocab.USER_GROUPS)})")
    for r in app["regulatory"]:
        if r not in vocab.REGULATORY:
            warnings.append(f"app.regulatory: unknown value '{r}' (known: {', '.join(vocab.REGULATORY)})")

    zones = {}
    for z in _as_list(raw.get("zones")):
        if isinstance(z, str):
            z = {"id": z}
        if not z.get("id"):
            errors.append("every zone needs an id")
            continue
        zones[z["id"]] = {"id": z["id"], "name": z.get("name", z["id"]), "description": z.get("description", "")}

    components: Dict[str, Dict[str, Any]] = {}
    for c in _as_list(raw.get("components")):
        cid = c.get("id")
        if not cid:
            errors.append("every component needs an id")
            continue
        if cid in components:
            errors.append(f"duplicate component id '{cid}'")
            continue
        ctype = c.get("type")
        if ctype not in vocab.COMPONENT_TYPES:
            errors.append(f"component '{cid}': unknown type '{ctype}' (run `python -m tmtool types`)")
        zone = c.get("zone")
        if zone and zone not in zones:
            zones[zone] = {"id": zone, "name": zone, "description": ""}
        comp = {
            "id": cid,
            "name": c.get("name", cid),
            "type": ctype,
            "zone": zone,
            "platform": str(c.get("platform", "")).lower() or None,
            "internet_facing": bool(c.get("internet_facing", False)),
            "data": [str(d).lower() for d in _as_list(c.get("data"))],
            "controls": [str(x) for x in _as_list(c.get("controls"))],
            "ai": c.get("ai") or {},
            "notes": c.get("notes", ""),
        }
        components[cid] = comp

    flows: List[Dict[str, Any]] = []
    for i, f in enumerate(_as_list(raw.get("flows")), start=1):
        fid = f.get("id") or f"F{i}"
        src, dst = f.get("from"), f.get("to")
        for end_name, end in (("from", src), ("to", dst)):
            if end not in components:
                errors.append(f"flow '{fid}': '{end_name}' references unknown component '{end}'")
        flows.append({
            "id": fid,
            "from": src,
            "to": dst,
            "protocol": f.get("protocol", ""),
            "description": f.get("description", ""),
            "data": [str(d).lower() for d in _as_list(f.get("data"))],
            "encrypted": f.get("encrypted"),
            "authenticated": f.get("authenticated"),
            "controls": [str(x) for x in _as_list(f.get("controls"))],
        })

    # Vocabulary checks (warnings, so a typo doesn't block the run but is visible)
    def check_data(where: str, values: List[str]) -> None:
        for d in values:
            if d not in vocab.DATA_CLASSES:
                warnings.append(f"{where}: unknown data class '{d}' (run `python -m tmtool data`)")

    def check_controls(where: str, values: List[str]) -> None:
        for x in values:
            if x not in vocab.CONTROLS:
                warnings.append(f"{where}: unknown control '{x}' (typo? run `python -m tmtool controls`)")

    check_controls("app.controls", app["controls"])
    for comp in components.values():
        check_data(f"component '{comp['id']}'", comp["data"])
        check_controls(f"component '{comp['id']}'", comp["controls"])
    for flow in flows:
        check_data(f"flow '{flow['id']}'", flow["data"])
        check_controls(f"flow '{flow['id']}'", flow["controls"])

    if errors:
        raise IntakeError("Intake file has errors:\n  - " + "\n  - ".join(errors))

    model = {"app": app, "zones": zones, "components": components, "flows": flows}
    return model, warnings


def load_library(paths: List[str]) -> List[Dict[str, Any]]:
    """Load and validate one or more threat library files. Later files can add rules or override by id."""
    rules: Dict[str, Dict[str, Any]] = {}
    for path in paths:
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        for rule in data.get("rules", []):
            _validate_rule(rule, path)
            rules[rule["id"]] = rule
    return list(rules.values())


def _validate_rule(rule: Dict[str, Any], path: str) -> None:
    rid = rule.get("id", "<no id>")
    where = f"{path}: rule {rid}"
    for key in ("id", "title", "stride", "applies_to", "likelihood", "impact"):
        if key not in rule:
            raise ValueError(f"{where}: missing '{key}'")
    target = rule["applies_to"]
    allowed = {"component": COMPONENT_CONDITIONS, "flow": FLOW_CONDITIONS, "app": APP_CONDITIONS}.get(target)
    if allowed is None:
        raise ValueError(f"{where}: applies_to must be component, flow, or app")
    unknown = set((rule.get("when") or {}).keys()) - allowed
    if unknown:
        raise ValueError(f"{where}: unsupported condition(s) for {target}: {', '.join(sorted(unknown))}")
    for t in rule.get("types", []):
        if t not in vocab.COMPONENT_TYPES:
            raise ValueError(f"{where}: unknown component type '{t}'")
    for s in rule["stride"]:
        if s not in STRIDE:
            raise ValueError(f"{where}: unknown STRIDE letter '{s}'")
    for c in rule.get("mitigated_by", []):
        if c not in vocab.CONTROLS:
            raise ValueError(f"{where}: unknown control '{c}' (add it to vocab.CONTROLS)")
    if rule.get("mitigation_mode", "all") not in ("all", "any"):
        raise ValueError(f"{where}: mitigation_mode must be 'all' or 'any'")
    for k in ("likelihood", "impact"):
        if not 1 <= int(rule[k]) <= 5:
            raise ValueError(f"{where}: {k} must be 1-5")
