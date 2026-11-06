# Threat Model Tool (tmtool)

Rule-based threat modeling for cloud and AI architectures. Describe an app team's reference architecture in a YAML **intake file**, and the tool produces a **risk-ranked threat model**:

- Threats from a library of **47 rules**: STRIDE, cloud identity and network threats, containers (EKS/AKS/OpenShift), CI/CD, data protection, PCI, and the **OWASP Top 10 for LLM Applications (2025)**, including RAG and AI agents
- **Risk scoring** (likelihood × impact) adjusted for internet exposure, data sensitivity, app criticality, and the controls already in place
- **Inherited platform controls**: guardrails your cloud platforms already enforce (SCPs, admission policies, gateways) are credited automatically, so app teams aren't asked to re-solve risks the platform already handles, and the report shows the risk with and without them
- A **data flow diagram** (Mermaid, renders on GitHub) with trust boundaries
- **Go-live blockers**, recommended mitigations, and **questions for the app team** about what the intake didn't cover
- A **backlog CSV** to import findings as tickets
- A **CI gate** (`--fail-on High`) so threat models can run in a pipeline as "threat modeling as code"

No API keys and no external calls: the same input always gives the same output, and architecture details never leave your machine.

**Example reports:** [GenAI RAG chatbot on EKS + Bedrock, with inherited platform controls](examples/reports/genai-rag-chatbot-threat-model.md) · [Customer IVR on Bedrock (PCI)](examples/reports/ivr-bedrock-pci-threat-model.md)

---

## Quick start

Requires Python 3.9+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run an example
python -m tmtool analyze examples/genai-rag-chatbot.yaml
# → reports/genai-rag-chatbot-threat-model.md
```

Model a new architecture:

```bash
python -m tmtool init intake/my-app.yaml        # copy the template
# ...fill it in with the app team...
python -m tmtool validate intake/my-app.yaml    # check for errors and typos
python -m tmtool analyze intake/my-app.yaml --csv reports/my-app-backlog.csv \
    --platforms platforms/example-baseline.yaml   # controls inherited from your cloud platforms
```

## Commands

| Command | What it does |
|---|---|
| `analyze INTAKE` | Generate the threat model report. Options: `-o` output path, `--csv` backlog file, `--min-rating` filter, `--fail-on RATING` (exit code 2 if open threats at or above it), `--library` extra rules, `--platforms` platform baseline |
| `validate INTAKE` | Check the intake without generating a report (accepts `--platforms` to check platform references) |
| `platforms BASELINE` | List the platforms in a baseline and the controls each provides |
| `init [PATH]` | Create a new intake file from the template |
| `rules` | List all threat rules |
| `types` / `data` / `controls` | List valid component types, data classes, and controls |

## The intake file

Four sections. See [templates/intake-template.yaml](templates/intake-template.yaml) for a commented example.

| Section | What goes in it |
|---|---|
| `app` | Name, description, owner, stage, **criticality** (low/medium/high), **users** (employees, customers, partners, admins), **regulatory** scope (pci, glba, sox, nydfs, sr11-7…), app-wide **controls**, and the **platforms** the app builds on |
| `zones` | Trust zones (internet, corporate network, app VPC, PCI segment, cloud-managed services…). Flows between zones are **trust boundary crossings** |
| `components` | Each part of the system: `id`, `type`, `zone`, `internet_facing`, `data` classifications, `controls` the app team implements, `platform` it runs on (e.g. `aws-network`, or `none`), approved `exceptions` to platform controls, and for AI components an `ai` block (`rag`, `agent_actions`, `untrusted_content`, `decision_support`) |
| `flows` | Each data flow: `from`, `to`, `protocol`, `data`, `encrypted`, `authenticated`, flow-level `controls` |

**Leave unknowns out** rather than guessing. Missing details (e.g. whether a flow is encrypted) become questions in the report.

## Inherited platform controls

Many risks are already handled by the cloud platforms an app is built on: RCPs keep data inside the org, VPC endpoints are enforced, every account is auto-enrolled in GuardDuty and the CNAPP. App teams shouldn't have to claim those controls themselves, and the threat model shouldn't flag them as gaps.

The **platform baseline** ([platforms/example-baseline.yaml](platforms/example-baseline.yaml)) describes what each platform enforces. The platform or cloud security team owns it, separately from app intakes:

```yaml
platforms:
  - id: aws-network
    name: Private Hybrid Network
    owner: Network / Infrastructure team
    inherits: [aws-org]                # also gets every org-wide guardrail (SCPs, RCPs, encryption...)
    controls:
      - control: private_endpoint
        types: [database, object_storage, vector_store, queue, secrets_store, llm]   # omit = all
        enforcement: preventive        # preventive | detective
        mechanism: VPC endpoint use enforced through shared services, with endpoint policies on data services
        evidence: Shared services VPCE inventory
```

Controls can also use `applies_to: [flow]` (e.g. TLS enforced in transit) or `applies_to: [app]` (e.g. federated workforce MFA, CloudTrail).

How an app picks them up:

- `app.platforms: [aws-network]` applies a platform to every component the app hosts. Users, `saas`, and `external_system` components never inherit, and `platform: none` opts a component out (e.g. a GitHub-hosted pipeline).
- A component's `platform: <id>` adds that platform (and whatever it `inherits`) for that component.
- **Flow** controls (like mesh mTLS) apply only when both ends of the flow are on the platform. **App** controls (like JIT admin access) satisfy only app-wide rules, so workforce MFA never counts as customer MFA.
- `exceptions: [public_access_block]` on a component removes an inherited control the app has an approved exception for.

How it changes the results:

- **Preventive** inherited controls count like any other control. **Detective** ones (drift detected after the fact) reduce likelihood but can't fully mitigate a threat on their own; the report suggests making them preventive.
- Every finding is scored **with and without** inheritance. The executive summary shows how many threats the platforms took off the board, the register marks status changes with *⬇ platform*, and a dedicated section lists each platform's controls with mechanism and evidence, ready for an auditor.

The example baseline describes AWS org guardrails (SCPs, RCPs, federated identity, permissions boundaries, auto-enrolled security tooling, protected logging) and a private hybrid network (VPC endpoints through shared services, endpoint policies). Fill in the `evidence` fields with your actual policy IDs and dashboards.

## How scoring works

1. Each rule has a base **likelihood** and **impact** (1–5).
2. Adjustments: **+1 likelihood** if internet-facing · **+1 impact** for highly sensitive data (restricted, customer PII, PCI, credentials) · **±1 impact** for high/low app criticality.
3. Controls (the app team's plus inherited platform controls): if all of the rule's mitigating controls are present, the threat is **Mitigated** (−2 likelihood); if some are, **Partially mitigated** (−1). Some rules accept **any one** control (e.g. private endpoint *or* public access blocked). Coverage that relies on a detective-only platform control stays **Partially mitigated**.
4. **Score = likelihood × impact.** Critical 20–25 · High 12–19 · Medium 6–11 · Low 1–5.

Every finding shows which adjustments were applied, so the rating can be explained and challenged.

## Writing rules

Rules live in [tmtool/library/threats.yaml](tmtool/library/threats.yaml). Add your own in a separate file and pass it with `--library my-rules.yaml` (a rule with the same `id` overrides the built-in one).

```yaml
rules:
  - id: ORG-01
    title: Mainframe connection without mutual TLS
    stride: [S, T]
    applies_to: flow            # component | flow | app
    when:
      to_types: [external_system]
      attrs: {protocol: MQ}
    description: Messages to the mainframe could be spoofed or altered.
    mitigated_by: [mtls]
    likelihood: 3
    impact: 5
    references: ["Internal standard SEC-NET-04"]
    questions: ["Is MQ configured with TLS client certificates?"]
```

**Conditions:**

| Condition | Applies to | Matches when |
|---|---|---|
| `types` | component | Component type is in the list |
| `attrs` | component, flow | Fields equal the given values (dotted paths like `ai.rag` work) |
| `data_any` | component, flow | Any listed data class is present (components include data on their flows) |
| `sensitive_data` | component, flow | Sensitive data is (or isn't) present |
| `receives_from_types` / `sends_to_types` | component | Has a flow from / to a component of these types |
| `crosses_boundary` | flow | Source and destination are in different zones |
| `from_types` / `to_types` / `exclude_from_types` | flow | Source / destination type checks |
| `app_regulatory_any` / `app_criticality_any` / `app_users_any` | all | App-level scope checks |

## Tests

```bash
python -m unittest discover -s tests -v
```

## Limits

- It finds threats that match known patterns. It doesn't replace a threat modeling conversation; it makes that conversation faster and more consistent.
- App team controls are self-reported. Verify them (CSPM, config review, testing). Inherited controls are only as good as the baseline, so keep it in sync with the guardrails actually deployed.
- Ratings are a consistent starting point. Map them to your organization's risk rating scale.
