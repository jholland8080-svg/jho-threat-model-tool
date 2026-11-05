"""Match threat rules against the architecture, score each finding, and collect intake gaps."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from . import vocab

RATING_ORDER = ["Low", "Medium", "High", "Critical"]


def rating_for(score: int) -> str:
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def _get_path(obj: Dict[str, Any], dotted: str) -> Any:
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _clamp(value: int) -> int:
    return max(1, min(5, value))


class Analyzer:
    def __init__(self, model: Dict[str, Any], rules: List[Dict[str, Any]]):
        self.model = model
        self.rules = rules
        self.app = model["app"]
        self.components = model["components"]
        self.flows = model["flows"]

    # ------------------------------------------------------------------ helpers
    def component_data(self, cid: str) -> Set[str]:
        data = set(self.components[cid]["data"])
        for f in self.flows:
            if f["from"] == cid or f["to"] == cid:
                data |= set(f["data"])
        return data

    def crosses_boundary(self, flow: Dict[str, Any]) -> bool:
        a = self.components[flow["from"]]["zone"]
        b = self.components[flow["to"]]["zone"]
        return bool(a and b and a != b)

    def _app_conditions_ok(self, when: Dict[str, Any]) -> bool:
        if "app_regulatory_any" in when and not set(when["app_regulatory_any"]) & set(self.app["regulatory"]):
            return False
        if "app_criticality_any" in when and self.app["criticality"] not in when["app_criticality_any"]:
            return False
        if "app_users_any" in when and not set(when["app_users_any"]) & set(self.app["users"]):
            return False
        return True

    def _attrs_ok(self, obj: Dict[str, Any], attrs: Dict[str, Any]) -> bool:
        for key, expected in attrs.items():
            actual = _get_path(obj, key)
            if isinstance(expected, str) and isinstance(actual, str):
                if actual.lower() != expected.lower():
                    return False
            elif actual != expected:
                return False
        return True

    # ------------------------------------------------------------------ matching
    def _component_matches(self, rule: Dict[str, Any], comp: Dict[str, Any]) -> bool:
        types = rule.get("types")
        if types and comp["type"] not in types:
            return False
        if not types and comp["type"] == "user":
            return False
        when = rule.get("when") or {}
        if not self._app_conditions_ok(when):
            return False
        if "attrs" in when and not self._attrs_ok(comp, when["attrs"]):
            return False
        data = self.component_data(comp["id"])
        if "data_any" in when and not set(when["data_any"]) & data:
            return False
        if "sensitive_data" in when and bool(data & vocab.SENSITIVE_DATA) != when["sensitive_data"]:
            return False
        if "receives_from_types" in when:
            sources = {self.components[f["from"]]["type"] for f in self.flows if f["to"] == comp["id"]}
            if not sources & set(when["receives_from_types"]):
                return False
        if "sends_to_types" in when:
            targets = {self.components[f["to"]]["type"] for f in self.flows if f["from"] == comp["id"]}
            if not targets & set(when["sends_to_types"]):
                return False
        return True

    def _flow_matches(self, rule: Dict[str, Any], flow: Dict[str, Any]) -> bool:
        when = rule.get("when") or {}
        if not self._app_conditions_ok(when):
            return False
        if "attrs" in when and not self._attrs_ok(flow, when["attrs"]):
            return False
        data = set(flow["data"])
        if "data_any" in when and not set(when["data_any"]) & data:
            return False
        if "sensitive_data" in when and bool(data & vocab.SENSITIVE_DATA) != when["sensitive_data"]:
            return False
        if "crosses_boundary" in when and self.crosses_boundary(flow) != when["crosses_boundary"]:
            return False
        if "from_types" in when and self.components[flow["from"]]["type"] not in when["from_types"]:
            return False
        if "exclude_from_types" in when and self.components[flow["from"]]["type"] in when["exclude_from_types"]:
            return False
        if "to_types" in when and self.components[flow["to"]]["type"] not in when["to_types"]:
            return False
        return True

    # ------------------------------------------------------------------ scoring
    def _score(self, rule: Dict[str, Any], controls: Set[str], data: Set[str], exposed: bool) -> Dict[str, Any]:
        likelihood, impact = int(rule["likelihood"]), int(rule["impact"])
        adjustments = []
        if exposed:
            likelihood += 1
            adjustments.append("+1 likelihood: internet-facing")
        if data & vocab.HIGHLY_SENSITIVE_DATA:
            impact += 1
            adjustments.append("+1 impact: highly sensitive data (" + ", ".join(sorted(data & vocab.HIGHLY_SENSITIVE_DATA)) + ")")
        if self.app["criticality"] == "high":
            impact += 1
            adjustments.append("+1 impact: high-criticality application")
        elif self.app["criticality"] == "low":
            impact -= 1
            adjustments.append("-1 impact: low-criticality application")

        mitigations = list(rule.get("mitigated_by", []))
        present = [m for m in mitigations if m in controls]
        missing = [m for m in mitigations if m not in controls]
        any_mode = rule.get("mitigation_mode") == "any"
        if any_mode and present:
            missing = []
        if mitigations and not missing:
            status = "Mitigated"
            likelihood -= 2
            adjustments.append("-2 likelihood: all listed controls in place")
        elif present:
            status = "Partially mitigated"
            likelihood -= 1
            adjustments.append("-1 likelihood: some listed controls in place")
        else:
            status = "Open"

        likelihood, impact = _clamp(likelihood), _clamp(impact)
        score = likelihood * impact
        return {
            "likelihood": likelihood,
            "impact": impact,
            "score": score,
            "rating": rating_for(score),
            "status": status,
            "controls_present": present,
            "controls_missing": missing,
            "any_of": any_mode and len(missing) > 1,
            "adjustments": adjustments,
        }

    # ------------------------------------------------------------------ main
    def run(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        app_controls = set(self.app["controls"])

        for rule in self.rules:
            target = rule["applies_to"]
            if target == "component":
                for comp in self.components.values():
                    if not self._component_matches(rule, comp):
                        continue
                    controls = set(comp["controls"]) | app_controls
                    scored = self._score(rule, controls, self.component_data(comp["id"]), comp["internet_facing"])
                    findings.append(self._finding(rule, "component", comp["id"], comp["name"], scored))
            elif target == "flow":
                for flow in self.flows:
                    if not self._flow_matches(rule, flow):
                        continue
                    src, dst = self.components[flow["from"]], self.components[flow["to"]]
                    exposed = src["internet_facing"] or src["zone"] == "internet"
                    controls = set(flow["controls"]) | app_controls
                    scored = self._score(rule, controls, set(flow["data"]), exposed)
                    label = f"{flow['id']}: {src['name']} → {dst['name']}"
                    findings.append(self._finding(rule, "flow", flow["id"], label, scored))
            elif target == "app":
                if self._app_conditions_ok(rule.get("when") or {}):
                    all_data: Set[str] = set()
                    for cid in self.components:
                        all_data |= self.component_data(cid)
                    scored = self._score(rule, app_controls, all_data, False)
                    findings.append(self._finding(rule, "app", "app", self.app["name"], scored))

        findings.sort(key=lambda f: (-f["score"], f["status"] == "Mitigated", f["rule_id"], f["target_id"]))
        for i, f in enumerate(findings, start=1):
            f["id"] = f"T-{i:03d}"

        return {
            "findings": findings,
            "boundary_crossings": [f for f in self.flows if self.crosses_boundary(f)],
            "gaps": self.intake_gaps(),
        }

    @staticmethod
    def _finding(rule, target_type, target_id, target_name, scored) -> Dict[str, Any]:
        finding = {
            "rule_id": rule["id"],
            "title": rule["title"],
            "stride": rule["stride"],
            "description": " ".join(str(rule.get("description", "")).split()),
            "references": rule.get("references", []),
            "questions": rule.get("questions", []),
            "target_type": target_type,
            "target_id": target_id,
            "target_name": target_name,
        }
        finding.update(scored)
        return finding

    # ------------------------------------------------------------------ gaps
    def intake_gaps(self) -> List[str]:
        """Things the intake doesn't tell us. These become questions for the app team."""
        gaps: List[str] = []
        types = {c["type"] for c in self.components.values()}
        connected: Set[str] = set()
        for f in self.flows:
            connected.update([f["from"], f["to"]])

        if not self.app["users"]:
            gaps.append("Who uses this application (employees, customers, partners, admins)?")
        if not self.app["description"]:
            gaps.append("What does the application do? Add app.description.")
        if "ci_cd" not in types:
            gaps.append("How is this application built and deployed? Add a `ci_cd` component so pipeline threats are covered.")
        if "logging" not in types and "logging_siem" not in self.app["controls"]:
            gaps.append("Where do logs go? Add a `logging` component or list `logging_siem` in app.controls.")
        if not self.app["regulatory"]:
            gaps.append("Is this application in scope for any regulations (PCI, GLBA, SOX, NYDFS, SR 11-7)?")

        for c in self.components.values():
            if not c["zone"] and c["type"] != "user":
                gaps.append(f"Which trust zone is **{c['name']}** in? (needed to find boundary crossings)")
            if c["id"] not in connected:
                gaps.append(f"**{c['name']}** has no data flows. Is it connected to anything?")
            if c["type"] in ("database", "object_storage", "vector_store", "queue") and not c["data"]:
                gaps.append(f"What data classification is stored in **{c['name']}**?")
            if c["type"] in ("llm", "ai_agent"):
                for key, question in (
                    ("rag", "use retrieval (RAG) over company documents"),
                    ("agent_actions", "take actions (call tools/APIs, change data, send messages)"),
                    ("untrusted_content", "read untrusted content (emails, web pages, uploaded files)"),
                    ("decision_support", "inform decisions about customers or money"),
                ):
                    if key not in c["ai"]:
                        gaps.append(f"Does **{c['name']}** {question}? Set `ai.{key}`.")

        for f in self.flows:
            name = f"flow {f['id']} ({self.components[f['from']]['name']} → {self.components[f['to']]['name']})"
            if f["encrypted"] is None:
                gaps.append(f"Is {name} encrypted in transit? Set `encrypted`.")
            if f["authenticated"] is None and self.crosses_boundary(f):
                gaps.append(f"How is the caller authenticated on {name}? It crosses a trust boundary. Set `authenticated`.")
            if not f["data"]:
                gaps.append(f"What data moves on {name}? Set `data`.")
        return gaps


def analyze(model: Dict[str, Any], rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    return Analyzer(model, rules).run()


def worst_open_rating(findings: List[Dict[str, Any]]) -> Optional[str]:
    open_ratings = [f["rating"] for f in findings if f["status"] != "Mitigated"]
    if not open_ratings:
        return None
    return max(open_ratings, key=RATING_ORDER.index)
