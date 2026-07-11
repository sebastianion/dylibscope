from __future__ import annotations

from dylibscope.storage.normalize import parse_ios_version_label


def test_parse_standard_device_label():
    parsed = parse_ios_version_label("iPhone5,1_6.0_10A405")

    assert parsed.version_label == "iPhone5,1_6.0_10A405"
    assert parsed.device_model == "iPhone5,1"
    assert parsed.ios_release == "6.0"
    assert parsed.build_number == "10A405"


def test_parse_device_label_with_underscores():
    parsed = parse_ios_version_label("iPhone_4.0_64bit_10.3.3_14G60")

    assert parsed.version_label == "iPhone_4.0_64bit_10.3.3_14G60"
    assert parsed.device_model == "iPhone_4.0_64bit"
    assert parsed.ios_release == "10.3.3"
    assert parsed.build_number == "14G60"


def test_unrecognized_label_is_kept_without_parsed_fields():
    parsed = parse_ios_version_label("unknown-format")

    assert parsed.version_label == "unknown-format"
    assert parsed.device_model is None
    assert parsed.ios_release is None
    assert parsed.build_number is None
