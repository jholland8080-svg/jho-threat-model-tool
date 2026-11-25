"""
Model provider. One small function so the rest of the code doesn't care where Claude runs.

Providers (TMTOOL_PROVIDER):
  anthropic (default)  Claude API. Credentials, most secure first:
                         1. `ant auth login`: short-lived token per run, no API key on disk
                         2. ANTHROPIC_API_KEY in the environment
  bedrock              Claude on Amazon Bedrock in your own AWS account (for corporate use: data stays in
                       the account, IAM and CloudTrail apply). Uses the normal AWS credential chain, e.g.
                       `aws sso login`. Needs `pip install boto3`. Model IDs are Bedrock IDs.

The anthropic package is imported lazily, so the core tool and the tests never need it.
"""

from __future__ import annotations

import os
# bandit B404 reviewed: subprocess is used only to call the `ant` CLI with fixed arguments.
import subprocess  # nosec B404
from typing import Any

DEFAULT_MODEL = "claude-sonnet-5-5"
PROVIDERS = ("anthropic", "bedrock")


class AssistError(Exception):
    """Raised when the assistant can't run (missing package, credentials, bad settings)."""


def _import_anthropic() -> Any:
    try:
        import anthropic  # noqa: WPS433 (lazy on purpose)
    except ImportError:
        raise AssistError("The assist features need the Anthropic SDK: pip install -r requirements-assist.txt")
    return anthropic


def make_client(provider: str = "") -> Any:
    provider = (provider or os.environ.get("TMTOOL_PROVIDER") or "anthropic").lower()
    if provider not in PROVIDERS:
        raise AssistError(f"TMTOOL_PROVIDER must be one of {', '.join(PROVIDERS)}")
    anthropic = _import_anthropic()

    if provider == "bedrock":
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not region:
            raise AssistError("Set AWS_REGION for the Bedrock provider.")
        return anthropic.AnthropicBedrock(aws_region=region)

    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return anthropic.Anthropic()
    try:
        # B603: fixed arguments, no shell, no external input.
        # B607: `ant` is found via PATH because install locations vary. Accepted risk: anything able to
        # plant a fake `ant` in your PATH already runs code as you.
        result = subprocess.run(  # nosec B603 B607
            ["ant", "auth", "print-credentials", "--access-token"],
            capture_output=True, text=True, check=True, timeout=60,
        )
        token = result.stdout.strip()
        if token:
            return anthropic.Anthropic(auth_token=token)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    raise AssistError("No Claude credentials found. Run `ant auth login` (recommended) or set ANTHROPIC_API_KEY.")


def model_name(override: str = "") -> str:
    return override or os.environ.get("TMTOOL_MODEL") or DEFAULT_MODEL
