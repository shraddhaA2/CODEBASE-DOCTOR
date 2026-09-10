import re
from typing import Any

SECRET_PATTERNS = [
    # Private keys
    (re.compile(r"-----BEGIN [A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END [A-Z\s]+PRIVATE KEY-----", re.IGNORECASE), "[REDACTED_PRIVATE_KEY]"),
    # AWS Access Key ID
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_AWS_KEY]"),
    # AWS Secret Key (often 40 chars base64)
    (re.compile(r"(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), r"\1=[REDACTED_AWS_SECRET]"),
    # GitHub Tokens
    (re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b"), "[REDACTED_GITHUB_TOKEN]"),
    # Generic API Keys / Tokens (OpenAI, Anthropic, Stripe, Slack, etc.)
    (re.compile(r"\b(sk-[a-zA-Z0-9_\-]{20,})\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\b(sk_live_[0-9a-zA-Z]{24})\b"), "[REDACTED_STRIPE_KEY]"),
    # Bearer tokens
    (re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b"), "Bearer [REDACTED_BEARER_TOKEN]"),
    # Generic password assignments
    (re.compile(r"(?i)(password|passwd|secret|api_key|apikey|access_token|auth_token)\s*[:=]\s*['\"]([^'\"]{4,})['\"]"), r"\1='[REDACTED_SECRET]'"),
    # Database connection strings with credentials
    (re.compile(r"://([^:]+):([^@]+)@"), r"://\1:[REDACTED_CREDENTIAL]@"),
]


def redact_text(text: str | None) -> str | None:
    """Redact sensitive patterns and credentials from a text string."""
    if text is None or not isinstance(text, str):
        return text

    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)

    return redacted


def redact_dict(data: dict[str, Any] | None) -> dict[str, Any] | None:
    """Recursively redact strings in dictionary structures."""
    if data is None:
        return None

    result = {}
    for key, val in data.items():
        if isinstance(val, str):
            result[key] = redact_text(val)
        elif isinstance(val, dict):
            result[key] = redact_dict(val)
        elif isinstance(val, list):
            result[key] = [
                redact_text(item) if isinstance(item, str)
                else redact_dict(item) if isinstance(item, dict)
                else item
                for item in val
            ]
        else:
            result[key] = val
    return result
