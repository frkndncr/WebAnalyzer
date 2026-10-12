"""The dashboard ships a fallback copy of the module catalogue. It must match
the registry, otherwise the picker would show stale modules when the API is
unreachable."""
import json
import os

from scripts.export_catalogue import OUTPUT, build


def test_the_dashboard_fallback_catalogue_matches_the_registry():
    with open(OUTPUT, encoding="utf-8") as handle:
        shipped = json.load(handle)
    assert shipped == build(), "catalogue.default.json is out of date - run: python scripts/export_catalogue.py"
