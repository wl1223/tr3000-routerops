from routerops.observability.redaction import redact, safe_json


def test_structured_and_text_secrets_are_redacted():
    value = {
        "api_key": "sk-secret-value",
        "nested": "token=visible-secret",
        "authorization": "Bearer abc.def.ghi",
        "wireless": {"key": "wifi-secret", "passwd": "root-secret"},
        "log": "download https://provider.example/subscribe/opaque-value",
    }
    safe = redact(value)
    encoded = safe_json(safe)
    assert safe["api_key"] == "REDACTED"
    assert "visible-secret" not in encoded
    assert "abc.def.ghi" not in encoded
    assert "wifi-secret" not in encoded
    assert "root-secret" not in encoded
    assert "opaque-value" not in encoded
    assert encoded.count("REDACTED") >= 6

