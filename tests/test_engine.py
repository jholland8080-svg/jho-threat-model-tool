import os
import tempfile
import unittest

from tmtool import vocab
from tmtool.cli import main
from tmtool.engine import analyze, rating_for
from tmtool.model import DEFAULT_LIBRARY, IntakeError, load_intake, load_library, normalize_intake

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


if __name__ == "__main__":
    unittest.main()
