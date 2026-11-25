# Security & threat model

This covers the agent-assisted part of tmtool (`tmtool draft`). The core tool (`analyze`, `validate`) makes
no network calls and runs no model, so its main risks are in its inputs (YAML parsing, handled with
`yaml.safe_load`) and its dependencies.

**tmtool threat-models itself.** The intake is [examples/tmtool-draft-agent.yaml](../examples/tmtool-draft-agent.yaml),
and the generated report is [tmtool-threat-model.md](tmtool-threat-model.md). Regenerate it with:
```bash
python -m tmtool analyze examples/tmtool-draft-agent.yaml -o docs/tmtool-threat-model.md
```
Why the design looks the way it does: [decisions/0001-llm-assist-boundary.md](decisions/0001-llm-assist-boundary.md).

## 1. What the system does
A security reviewer runs `tmtool draft` on their laptop with a set of design documents. Code cleans and
redacts the documents and sends them to Claude. Claude proposes an intake through a small set of tools.
Code checks every call and writes the draft to `local/`. A person reviews the draft before `tmtool analyze`
scores it.

```
design docs (untrusted) ──► tmtool draft ──HTTPS──► Claude
                             │   ▲
                 ant token ──┘   └── reviewer
                             ▼
                       local/ drafts ──(reviewed)──► tmtool analyze ──► report
```

## 2. Assets
| Asset | Where it lives | Impact if compromised |
|---|---|---|
| **Integrity of the threat model** | Drafts, then reports | A wrong model hides real risk and approves an unsafe go-live. **The most important asset.** |
| Architecture details | Source documents, drafts, prompts | A map of an app's components and gaps, useful to an attacker |
| Claude credential | `ant auth` (short-lived token) | Spend on your account; access to anything else the account can do |
| The code and pipeline | GitHub | A malicious change ships with every future run |

## 3. Trust boundaries
- **App teams → laptop:** design documents are written by others. Everything in them is untrusted.
- **Laptop → model provider:** cleaned, redacted text leaves the machine. Today the Anthropic API; for
  corporate use, Bedrock in the company's own AWS account.
- **PyPI and GitHub → laptop and CI:** third-party code that runs as you.

## 4. Untrusted inputs
- **Design documents:** can contain instructions aimed at the AI, hidden text (HTML comments, hidden
  elements, invisible characters) and attacker links. See the [injection lab](../lab/prompt-injection/README.md).
- **The model's output:** every tool call and every string Claude writes is treated as untrusted, because
  a fooled model will pass the attack on.
- **Dependencies:** any package update.

## 5. Threats, triaged
The self-analysis found 23 open or partially mitigated threats. Triaged:

**Real and actionable**
| Finding | Threat | Plan |
|---|---|---|
| T-004, T-013, T-017 | No record of what was sent to the model or what it did. A bad draft can't be investigated. | Add a local run log: redacted request hashes, tool calls and decisions. Never raw document text. |
| T-006 | Pipeline compromise: `main` has no branch protection. | Enable branch protection: require PRs and passing checks. |
| T-018 | Any model name is accepted (`TMTOOL_MODEL`). | Add an allowlist of approved model IDs. |

**Real but accepted (personal project)**
| Finding | Threat | Why accepted |
|---|---|---|
| T-001 | Prompt injection against the model | Can't be prevented at the model. The design assumes a fooled model: see controls below. |
| T-023 | Cost abuse | `--max-steps` caps a run; spend is on my own account. |
| T-007, T-020 | Drafts not scanned for sensitive data; no backups | Drafts are local, owner-only and regenerable. |
| T-022 | Document authors as a "vendor" | Treated as untrusted content instead. |

**False positives (finding 5: the rules assume cloud workloads)**
T-008–T-012, T-014, T-015 flag a laptop CLI for workload identity, public network exposure and
unencrypted flows, which apply to cloud services, not to reading a local file or a token from `ant`.
The vocabulary has no way to describe a local tool. Until it does, these stay in the report and are
dismissed here, with the reason.

## 6. Controls
| Threat | Preventive control | Detective control | Enforced in |
|---|---|---|---|
| A document lowers risk | Risk-lowering claims become proposals; never credited until a person applies them | Proposals listed in the draft with their quotes | Code: `draft.py` |
| A document removes a component | Append-only tools; no delete or overwrite | Coverage check: "documents mention X, no X component" | Code |
| A document invents evidence | Quotes checked against the cleaned document | Rejected quotes listed in review notes | Code |
| Hidden instructions | Hidden HTML and invisible characters stripped before the model reads them | Removals and instruction-like text in review notes | Code: `sources.py`, `safety.py` |
| Data sent to attackers (links, images) | Links, images and HTML stripped from model text; redacted URLs never restored | Lab grep; worst-case tests | Code |
| Architecture details leak | Identifiers redacted before sending; `--show-redacted` previews exactly what's sent | — | Code |
| Credential theft | Short-lived token from `ant auth`; no API key on disk | — | Setup |
| Private files committed | `local/` git-ignored | Pre-commit blocker; CI check over all history | Pre-commit and CI |
| Secrets committed | — | gitleaks in pre-commit and CI | Pre-commit and CI |
| Vulnerable or malicious dependency | Full dependency tree pinned | pip-audit in CI; Dependabot weekly; SBOM | CI |
| Unsafe code (incl. Trojan Source) | — | bandit in pre-commit and CI | Pre-commit and CI |
| Hijacked CI | Actions pinned to SHAs; read-only token, not persisted; timeouts | — | `security.yml` |

## 7. Residual risks
- **The reviewer is the last control.** If a person accepts a bad proposal without checking its quote,
  the defenses don't help. Review effort is the price of the design.
- **Drafts vary between runs** (finding 3): the same documents can produce different component types and
  so different findings.
- **Pattern-based detection can be evaded.** The instruction scanner missed doc 04's wording; Claude caught
  it, code didn't.
- **No audit trail yet** (T-004): a bad draft can't be reconstructed after the fact.
- **Omissions are flagged, not prevented:** a fooled model can leave a component out.
- **A compromised `ant` binary** on your PATH would see the token. Anything that can do that already runs
  code as you.

## 8. How to verify the controls
```bash
python -m unittest discover -s tests                        # includes the fully fooled worst-case model
python -m tmtool draft lab/prompt-injection/docs --show-redacted   # exactly what would be sent; free
pre-commit run --all-files                                   # secrets, private files, bandit
bandit -r tmtool                                             # expect: no issues
pip-audit -r requirements.txt -r requirements-assist.txt     # known vulnerabilities in pinned packages
```
Then rerun the [injection lab](../lab/prompt-injection/README.md) against the real model and score it.
