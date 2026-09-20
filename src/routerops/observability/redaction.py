import json
import re
from collections.abc import Mapping
from typing import Any

SENSITIVE_KEYS = {
    "api_key",
    "authorization",
    "credential",
    "credentials",
    "cookie",
    "password",
    "passwd",
    "passphrase",
    "private_key",
    "private-key",
    "psk",
    "key",
    "secret",
    "subscription",
    "telegram_token",
    "token",
    "uuid",
}

PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r"(?i)((?:token|password|passwd|passphrase|psk|key|credential|secret|"
        r"uuid|api[_-]?key)\s*[=:]\s*)\S+"
    ),
    re.compile(r"(?i)((?:--?(?:secret|password|token|api[_-]?key))\s+)\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"https?://[^\s/@:]+:[^\s/@]+@"),
    re.compile(r"(?i)https?://\S*(?:subscribe|subscription)\S*"),
    re.compile(r"(?i)(?:ss|ssr|trojan|vmess|vless|hysteria2?)://\S+"),
]


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): "REDACTED" if str(key).lower() in SENSITIVE_KEYS else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str):
        result = value
        for pattern in PATTERNS:
            result = pattern.sub(
                lambda match: f"{match.group(1)}REDACTED" if match.lastindex else "REDACTED",
                result,
            )
        return result
    return value


def safe_json(value: Any) -> str:
    return json.dumps(redact(value), ensure_ascii=False, sort_keys=True, default=str)

