from routerops.observability.redaction import redact, safe_json


def test_structured_and_text_secrets_are_redacted():
    value = {
        "api_key": "sk-secret-value",
        "nested": "token=visible-secret",
        "authorization": "Bearer abc.def.ghi",
    }
    safe = redact(value)
    encoded = safe_json(safe)
    assert safe["api_key"] == "REDACTED"
    assert "visible-secret" not in encoded
    assert "abc.def.ghi" not in encoded
    assert encoded.count("REDACTED") == 3

