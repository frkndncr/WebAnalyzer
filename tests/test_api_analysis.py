"""Tests for modules.api_analysis — response-type detection and XSS
safe-context checks extracted from the API security scanner."""
from modules.api_analysis import (
    is_json_response,
    is_xml_response,
    is_payload_safe_context,
)


# ─────────────────────────── is_json_response ───────────────────────────

def test_json_object_and_array():
    assert is_json_response('{"a": 1}') is True
    assert is_json_response('[1, 2, 3]') is True


def test_json_with_surrounding_whitespace():
    assert is_json_response('  {"a": 1}  ') is True


def test_json_rejects_non_json():
    assert is_json_response("<html></html>") is False
    assert is_json_response("just text") is False


def test_json_rejects_malformed_braces():
    assert is_json_response("{not valid json}") is False


def test_json_rejects_empty_or_tiny():
    assert is_json_response("") is False
    assert is_json_response("{") is False


def test_json_whitespace_only_is_safe():
    # Regression: whitespace-only input must not raise IndexError.
    assert is_json_response("   ") is False


# ─────────────────────────── is_xml_response ───────────────────────────

def test_xml_declaration():
    assert is_xml_response('<?xml version="1.0"?><root></root>') is True


def test_xml_generic_tags():
    assert is_xml_response("<root><child>value</child></root>") is True


def test_xml_rejects_short_or_non_xml():
    assert is_xml_response("<a>") is False          # too short (< 10)
    assert is_xml_response("plain text here") is False


# ─────────────────────────── is_payload_safe_context ───────────────────────────

PAYLOAD = "<script>alert(1)</script>"


def test_safe_when_not_reflected():
    assert is_payload_safe_context("<html>nothing here</html>", PAYLOAD) is True


def test_safe_when_html_encoded():
    encoded = PAYLOAD.replace("<", "&lt;").replace(">", "&gt;")
    assert is_payload_safe_context(f"<div>{encoded}</div>", PAYLOAD) is True


def test_safe_when_url_encoded():
    encoded = PAYLOAD.replace("<", "%3C").replace(">", "%3E")
    assert is_payload_safe_context(f"<div>{encoded}</div>", PAYLOAD) is True


def test_safe_when_inside_html_comment():
    assert is_payload_safe_context(f"<!-- {PAYLOAD} -->", PAYLOAD) is True


def test_unsafe_when_reflected_raw():
    assert is_payload_safe_context(f"<div>{PAYLOAD}</div>", PAYLOAD) is False
