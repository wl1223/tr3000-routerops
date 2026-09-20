from routerops.tools.normalizers import RawObservation, normalize_observation


def test_system_observation_is_typed_and_normalized(ssh_outputs):
    stdout, stderr, code = ssh_outputs["get_system_info"]
    result = normalize_observation(
        RawObservation("get_system_info", stdout, stderr, code)
    )
    assert result["model"] == "Cudy TR3000 v1"
    assert result["firmware"] == "QWRT R26.1.1"
    assert result["platform"] == "mediatek/mt798x"


def test_interfaces_match_diagnostic_contract(ssh_outputs):
    stdout, stderr, code = ssh_outputs["get_interfaces"]
    result = normalize_observation(
        RawObservation("get_interfaces", stdout, stderr, code)
    )
    usb = next(item for item in result["interfaces"] if item["name"] == "usb0")
    assert usb["up"]
    assert usb["ipv4"] == ["192.168.0.2/24"]


def test_openclash_config_contains_only_safe_discovered_fields(ssh_outputs):
    stdout, stderr, code = ssh_outputs["get_openclash_config"]
    result = normalize_observation(
        RawObservation("get_openclash_config", stdout, stderr, code)
    )
    assert result["tun"]
    assert result["fake_ip"]
    assert result["ipv6"]
    assert "secret" not in str(result).lower()


def test_normalizer_redacts_raw_secrets():
    result = normalize_observation(
        RawObservation(
            "get_usb_logs",
            "driver password=super-secret token=abc123 key=wpa-secret",
            "",
            0,
        )
    )
    encoded = str(result)
    assert "super-secret" not in encoded
    assert "abc123" not in encoded
    assert "wpa-secret" not in encoded
    assert "REDACTED" in encoded

