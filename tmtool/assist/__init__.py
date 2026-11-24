"""
Agent assistance for tmtool (optional).

The core tool (`analyze`, `validate`, ...) is deterministic and never calls a model. This package adds
a model that helps *draft* inputs, under one rule:

    The model proposes. Code decides. A person accepts.

- The model never scores threats. Scoring stays in tmtool/engine.py.
- Anything that would LOWER risk (a control, "encrypted: true", lower criticality) needs a verbatim quote
  from a source document, checked by code. Controls are written as `proposed_controls`, which the engine
  ignores until a person moves them into `controls`.
- The model can only add to a draft, never remove. There is no tool to delete or overwrite.
- Sensitive identifiers (IPs, ARNs, account IDs, emails, hostnames) are redacted before anything is sent.

Install the extra dependency with:  pip install -r requirements-assist.txt
See docs/decisions/0001-llm-assist-boundary.md.
"""
