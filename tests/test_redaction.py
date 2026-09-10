from app.security.redact import redact_text, redact_dict


def test_redact_api_keys():
    text = "openai_api_key = 'sk-1234567890abcdef1234567890abcdef'"
    redacted = redact_text(text)
    assert "sk-1234567890abcdef" not in redacted
    assert "[REDACTED_API_KEY]" in redacted or "[REDACTED_SECRET]" in redacted


def test_redact_aws_keys():
    text = "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'"
    redacted = redact_text(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_AWS_KEY]" in redacted


def test_redact_private_keys():
    text = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1W9EXAMPLE
-----END RSA PRIVATE KEY-----"""
    redacted = redact_text(text)
    assert "MIIEowIBAAKCAQEA0Y1W9EXAMPLE" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted


def test_redact_passwords_and_bearer_tokens():
    text = 'db_password = "SuperSecretPassword123!"'
    redacted = redact_text(text)
    assert "SuperSecretPassword123!" not in redacted
    assert "[REDACTED_SECRET]" in redacted

    bearer = "Authorization: Bearer mySecretToken123456789012345"
    redacted_bearer = redact_text(bearer)
    assert "mySecretToken123456789012345" not in redacted_bearer
    assert "[REDACTED_BEARER_TOKEN]" in redacted_bearer


def test_redact_nested_dict():
    data = {
        "user": "alice",
        "creds": {
            "token": "ghp_123456789012345678901234567890123456",
            "info": ["plain text", "sk-proj12345678901234567890"]
        }
    }
    redacted = redact_dict(data)
    assert redacted["user"] == "alice"
    assert "ghp_1234567890" not in redacted["creds"]["token"]
    assert "[REDACTED_GITHUB_TOKEN]" in redacted["creds"]["token"]
    assert "[REDACTED_API_KEY]" in redacted["creds"]["info"][1] or "[REDACTED_SECRET]" in redacted["creds"]["info"][1]
