"""Tests for utils.utils — pure helper functions (no network / DB)."""
import json
import os

import pytest

from utils.utils import (
    validate_domain,
    format_execution_time,
    serialize_results,
    save_results_to_json,
    get_file_size,
)


# ─────────────────────────── validate_domain ───────────────────────────

@pytest.mark.parametrize("domain", [
    "example.com",
    "sub.example.com",
    "a.co",
    "my-site.co.uk",
    "xn--80ak6aa92e.com",
])
def test_validate_domain_accepts_valid(domain):
    assert validate_domain(domain) is True


@pytest.mark.parametrize("domain", [
    "",
    "-bad.com",
    "bad-.com",
    "no_underscores.com",
    "spaces here.com",
    "a" * 254 + ".com",
])
def test_validate_domain_rejects_invalid(domain):
    assert validate_domain(domain) is False


# ─────────────────────────── format_execution_time ───────────────────────────

def test_format_execution_time_milliseconds():
    assert format_execution_time(0.25) == "250ms"


def test_format_execution_time_seconds():
    assert format_execution_time(5.5) == "5.5s"


def test_format_execution_time_minutes():
    assert format_execution_time(125) == "2m 5s"


def test_format_execution_time_hours():
    assert format_execution_time(3720) == "1h 2m"


# ─────────────────────────── serialize_results ───────────────────────────

def test_serialize_results_passes_through_plain_dicts():
    data = {"Module A": {"key": "value", "nested": {"n": 1}}}
    out = serialize_results(data)
    assert out == {"Module A": {"key": "value", "nested": {"n": 1}}}


def test_serialize_results_stringifies_unknown_objects():
    class Weird:
        def __str__(self):
            return "weird-repr"

    out = serialize_results({"Mod": Weird()})
    assert out["Mod"] == "weird-repr"


def test_serialize_results_handles_lists():
    out = serialize_results({"Mod": [1, 2, {"a": 3}]})
    assert out["Mod"] == [1, 2, {"a": 3}]


# ─────────────────────────── save_results_to_json ───────────────────────────

def test_save_results_to_json_writes_expected_structure(tmp_path):
    results = {
        "Good Module": {"ok": True},
        "Bad Module": {"error": "boom"},
    }
    save_results_to_json("example.com", results, output_dir=str(tmp_path))

    out_file = tmp_path / "example.com" / "results.json"
    assert out_file.exists()

    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved["domain"] == "example.com"
    assert saved["scan_info"]["total_modules"] == 2
    assert saved["scan_info"]["successful_modules"] == 1
    assert saved["scan_info"]["failed_modules"] == 1
    assert saved["results"]["Good Module"] == {"ok": True}


# ─────────────────────────── get_file_size ───────────────────────────

def test_get_file_size_formats_bytes(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"x" * 2048)
    assert get_file_size(str(f)) == "2.0 KB"


def test_get_file_size_missing_file_is_unknown():
    assert get_file_size("does-not-exist-123.file") == "Unknown"
