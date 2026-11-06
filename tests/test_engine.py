import os
import tempfile
import unittest

from tmtool import vocab
from tmtool.cli import main
from tmtool.engine import analyze, rating_for
from tmtool.model import (DEFAULT_LIBRARY, IntakeError, check_platform_refs, load_intake, load_library,
                          load_platforms, normalize_intake)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = load_library([DEFAULT_LIBRARY])


def minimal(**overrides):
    raw = {
        "app": {"name": "Test", "criticality": "medium", "users": ["employees"]},
        "components": [
            {"id": "u", "type": "user", "zone": "corp"},
            {"id": "web", "type": "web_app", "zone": "app"},
        ],
        "flows": [{"from": "u", "to": "web", "data": ["internal"], "encrypted": True, "authenticated": True}],
    }
    raw.update(overrides)
    return normalize_intake(raw)[0]


def by_rule(result, rule_id):
    return [f for f in result["findings"] if f["rule_id"] == rule_id]


class LibraryTests(unittest.TestCase):
    def test_library_loads_and_ids_unique(self):
        ids = [r["id"] for r in RULES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreater(len(ids), 30)

    def test_all_library_controls_are_known(self):
        for r in RULES:
            for c in r.get("mitigated_by", []):
                self.assertIn(c, vocab.CONTROLS, f"{r['id']} uses unknown control {c}")


class IntakeTests(unittest.TestCase):
    def test_unknown_flow_endpoint_is_an_error(self):
        with self.assertRaises(IntakeError):
            normalize_intake({"app": {"name": "x"}, "components": [], "flows": [{"from": "a", "to": "b"}]})

    def test_unknown_control_is_a_warning(self):
        _, warnings = normalize_intake({
            "app": {"name": "x", "controls": ["sso", "s_s_o"]},
            "components": [{"id": "a", "type": "web_app"}],
        })
        self.assertTrue(any("s_s_o" in w for w in warnings))

    def test_examples_are_valid(self):
        for name in os.listdir(os.path.join(ROOT, "examples")):
            if name.endswith(".yaml"):
                load_intake(os.path.join(ROOT, "examples", name))
        load_intake(os.path.join(ROOT, "templates", "intake-template.yaml"))


class EngineTests(unittest.TestCase):
    def test_rating_bands(self):
        self.assertEqual(rating_for(25), "Critical")
        self.assertEqual(rating_for(12), "High")
        self.assertEqual(rating_for(6), "Medium")
        self.assertEqual(rating_for(5), "Low")

    def test_user_auth_rule_fires_on_entry_point(self):
        result = analyze(minimal(), RULES)
        self.assertEqual(len(by_rule(result, "ID-01")), 1)

    def test_controls_reduce_likelihood_and_set_status(self):
        open_ = by_rule(analyze(minimal(), RULES), "ID-01")[0]
        model = minimal()
        model["components"]["web"]["controls"] = ["sso", "mfa"]
        done = by_rule(analyze(model, RULES), "ID-01")[0]
        self.assertEqual(open_["status"], "Open")
        self.assertEqual(done["status"], "Mitigated")
        self.assertEqual(done["likelihood"], open_["likelihood"] - 2)

    def test_app_controls_apply_to_components(self):
        model = minimal()
        model["app"]["controls"] = ["sso"]
        f = by_rule(analyze(model, RULES), "ID-01")[0]
        self.assertEqual(f["status"], "Partially mitigated")

    def test_internet_facing_raises_likelihood_and_adds_exposure_threats(self):
        model = minimal()
        model["components"]["web"]["internet_facing"] = True
        result = analyze(model, RULES)
        self.assertEqual(len(by_rule(result, "NW-01")), 1)
        base = by_rule(analyze(minimal(), RULES), "ID-01")[0]["likelihood"]
        self.assertEqual(by_rule(result, "ID-01")[0]["likelihood"], base + 1)

    def test_unencrypted_flow(self):
        model = minimal()
        model["flows"][0]["encrypted"] = False
        self.assertEqual(len(by_rule(analyze(model, RULES), "FL-01")), 1)

    def test_unauthenticated_flow_only_flagged_across_boundary(self):
        model, _ = normalize_intake({
            "app": {"name": "x"},
            "components": [{"id": "web", "type": "web_app", "zone": "app"},
                           {"id": "api", "type": "api", "zone": "backend"}],
            "flows": [{"from": "web", "to": "api", "data": ["internal"], "encrypted": True, "authenticated": False}],
        })
        self.assertEqual(len(by_rule(analyze(model, RULES), "FL-02")), 1)
        model["components"]["api"]["zone"] = "app"
        self.assertEqual(len(by_rule(analyze(model, RULES), "FL-02")), 0)

    def test_user_flows_are_left_to_user_auth_rule(self):
        model = minimal()
        model["flows"][0]["authenticated"] = False
        self.assertEqual(len(by_rule(analyze(model, RULES), "FL-02")), 0)

    def test_rag_and_agent_rules(self):
        model, _ = normalize_intake({
            "app": {"name": "AI", "users": ["employees"]},
            "components": [
                {"id": "app", "type": "api", "zone": "a"},
                {"id": "m", "type": "llm", "zone": "b", "data": ["confidential"],
                 "ai": {"rag": True, "agent_actions": True, "untrusted_content": True}},
                {"id": "kb", "type": "vector_store", "zone": "b", "data": ["confidential"]},
            ],
            "flows": [{"from": "app", "to": "m", "data": ["confidential"]},
                      {"from": "m", "to": "kb", "data": ["confidential"]}],
        })
        result = analyze(model, RULES)
        for rule_id in ("AI-02", "AI-04", "AI-05", "AI-13"):
            self.assertTrue(by_rule(result, rule_id), f"{rule_id} should fire")

    def test_pci_rules_need_pci_scope(self):
        model = minimal()
        model["components"]["web"]["data"] = ["pci"]
        self.assertTrue(by_rule(analyze(model, RULES), "PC-01"))
        self.assertFalse(by_rule(analyze(minimal(), RULES), "PC-01"))

    def test_high_sensitivity_and_criticality_raise_impact(self):
        base = by_rule(analyze(minimal(), RULES), "ID-01")[0]["impact"]
        model = minimal()
        model["app"]["criticality"] = "high"
        model["components"]["web"]["data"] = ["customer_pii"]
        self.assertEqual(by_rule(analyze(model, RULES), "ID-01")[0]["impact"], min(5, base + 2))

    def test_gaps_ask_about_unknowns(self):
        model = minimal()
        model["flows"][0]["encrypted"] = None
        gaps = analyze(model, RULES)["gaps"]
        self.assertTrue(any("encrypted" in g for g in gaps))
        self.assertTrue(any("ci_cd" in g for g in gaps))


BASELINE = os.path.join(ROOT, "platforms", "example-baseline.yaml")


def platforms(*controls_by_platform):
    """Build a platform dict in memory: platforms(("p1", [entry, ...], ["parent"]), ...)."""
    out = {}
    for pid, entries, *rest in controls_by_platform:
        out[pid] = {"id": pid, "name": pid.upper(), "owner": "", "description": "",
                    "inherits": rest[0] if rest else [],
                    "controls": [dict({"types": [], "applies_to": ["component"], "enforcement": "preventive",
                                       "mechanism": "", "evidence": ""}, **e) for e in entries]}
    return out


class InheritanceTests(unittest.TestCase):
    def setUp(self):
        self.model = minimal()
        self.model["components"]["db"] = {
            "id": "db", "name": "DB", "type": "object_storage", "zone": "app", "platform": None, "platforms": [],
            "exceptions": [], "internet_facing": False, "data": ["confidential"], "controls": [], "ai": {}, "notes": ""}
        self.model["flows"].append({"id": "F2", "from": "web", "to": "db", "protocol": "", "description": "",
                                    "data": ["confidential"], "encrypted": True, "authenticated": True, "controls": []})
        self.model["app"]["platforms"] = ["lz"]

    def test_baseline_example_loads(self):
        p = load_platforms([BASELINE])
        self.assertIn("aws-org", p)
        self.assertEqual(p["aws-network"]["inherits"], ["aws-org"])

    def test_preventive_inherited_control_mitigates(self):
        plats = platforms(("lz", [{"control": "public_access_block", "types": ["object_storage"]}]))
        f = by_rule(analyze(self.model, RULES, plats), "NW-03")
        f = [x for x in f if x["target_id"] == "db"][0]
        self.assertEqual(f["status"], "Mitigated")
        self.assertIn("public_access_block", f["controls_inherited"])
        self.assertEqual(f["without_inheritance"]["status"], "Open")

    def test_type_scoping(self):
        plats = platforms(("lz", [{"control": "sso", "types": ["object_storage"]},
                                  {"control": "mfa", "types": ["object_storage"]}]))
        self.assertEqual(by_rule(analyze(self.model, RULES, plats), "ID-01")[0]["status"], "Open")

    def test_detective_only_never_fully_mitigates(self):
        plats = platforms(("lz", [{"control": "public_access_block", "enforcement": "detective"}]))
        f = [x for x in by_rule(analyze(self.model, RULES, plats), "NW-03") if x["target_id"] == "db"][0]
        self.assertEqual(f["status"], "Partially mitigated")
        self.assertEqual(f["controls_detective_only"], ["public_access_block"])

    def test_team_control_plus_detective_platform_is_mitigated_and_credited_to_team(self):
        self.model["components"]["db"]["controls"] = ["public_access_block"]
        plats = platforms(("lz", [{"control": "public_access_block", "enforcement": "detective"}]))
        f = [x for x in by_rule(analyze(self.model, RULES, plats), "NW-03") if x["target_id"] == "db"][0]
        self.assertEqual(f["status"], "Mitigated")
        self.assertEqual(f["controls_inherited"], {})

    def test_exceptions_remove_inherited_control(self):
        self.model["components"]["db"]["exceptions"] = ["public_access_block"]
        plats = platforms(("lz", [{"control": "public_access_block"}]))
        f = [x for x in by_rule(analyze(self.model, RULES, plats), "NW-03") if x["target_id"] == "db"][0]
        self.assertEqual(f["status"], "Open")

    def test_platform_chain_and_component_platform(self):
        self.model["app"]["platforms"] = []
        self.model["components"]["web"]["platforms"] = ["child"]
        plats = platforms(("parent", [{"control": "sso"}]), ("child", [{"control": "mfa"}], ["parent"]))
        self.assertEqual(by_rule(analyze(self.model, RULES, plats), "ID-01")[0]["status"], "Mitigated")

    def test_not_hosted_and_platform_none_do_not_inherit(self):
        plats = platforms(("lz", [{"control": "vendor_risk_assessment"}, {"control": "branch_protection"}]))
        self.model["components"]["web"]["type"] = "saas"
        self.model["components"]["db"]["platforms"] = ["none"]
        inh = analyze(self.model, RULES, plats)["inheritance"]["components"]
        self.assertEqual(inh["web"], {})
        self.assertEqual(inh["db"], {})

    def test_flow_controls_need_both_ends_on_platform(self):
        self.model["app"]["platforms"] = []
        self.model["flows"][1]["encrypted"] = False
        plats = platforms(("mesh", [{"control": "tls", "applies_to": ["flow"]}]))
        self.model["components"]["web"]["platforms"] = ["mesh"]
        status = lambda: [x for x in by_rule(analyze(self.model, RULES, plats), "FL-01") if x["target_id"] == "F2"][0]["status"]
        self.assertEqual(status(), "Open")
        self.model["components"]["db"]["platforms"] = ["mesh"]
        self.assertEqual(status(), "Mitigated")

    def test_app_scope_controls_only_reach_app_rules(self):
        self.model["app"]["users"] = ["employees", "admins"]
        plats = platforms(("lz", [{"control": "mfa", "applies_to": ["app"]},
                                  {"control": "privileged_access_management", "applies_to": ["app"]}]))
        result = analyze(self.model, RULES, plats)
        self.assertEqual(by_rule(result, "ID-02")[0]["status"], "Mitigated")
        self.assertEqual(by_rule(result, "ID-01")[0]["status"], "Open")

    def test_unknown_platform_reference_warns(self):
        self.model["app"]["platforms"] = ["nope"]
        self.assertTrue(check_platform_refs(self.model, load_platforms([BASELINE])))
        self.assertTrue(check_platform_refs(self.model, {}))

    def test_bad_baseline_is_an_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
            fh.write("platforms:\n  - id: x\n    controls:\n      - control: not_a_control\n")
        try:
            with self.assertRaises(IntakeError):
                load_platforms([fh.name])
        finally:
            os.unlink(fh.name)


class CliTests(unittest.TestCase):
    def test_analyze_writes_report_and_csv_and_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, csv_path = os.path.join(tmp, "r.md"), os.path.join(tmp, "b.csv")
            code = main(["analyze", os.path.join(ROOT, "examples", "ivr-bedrock-pci.yaml"),
                         "-o", out, "--csv", csv_path, "--fail-on", "Critical"])
            self.assertEqual(code, 2)  # the PCI example has open Critical threats
            with open(out) as fh:
                text = fh.read()
            self.assertIn("# Threat Model: Contact Center IVR Assistant", text)
            self.assertIn("```mermaid", text)
            self.assertTrue(os.path.exists(csv_path))

    def test_analyze_with_platforms(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.md")
            code = main(["analyze", os.path.join(ROOT, "examples", "genai-rag-chatbot.yaml"),
                         "-o", out, "--platforms", BASELINE])
            self.assertEqual(code, 0)
            with open(out) as fh:
                text = fh.read()
            self.assertIn("## Inherited platform controls", text)
            self.assertIn("Open without platform controls", text)


if __name__ == "__main__":
    unittest.main()
