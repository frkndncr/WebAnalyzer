"""Write the dashboard's fallback module catalogue from the registry.

The dashboard loads the live catalogue from GET /api/modules and only uses this
snapshot when the API is unreachable. tests/test_catalogue_snapshot.py fails if
the snapshot is out of date; refresh it with:

    python scripts/export_catalogue.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUTPUT = os.path.join(ROOT, "dashboard", "src", "lib", "catalogue.default.json")


def build():
    """The catalogue of the built-in and shipped modules, as the API serves it."""
    from modules import builtin, registry

    registry.discover_plugins([os.path.join(ROOT, "modules", "plugins")])
    available = set(registry.names())
    presets = {key: [n for n in names if n in available] for key, names in builtin.PRESETS.items()}
    presets["full"] = list(registry.names())
    return {"modules": registry.catalogue(), "presets": presets}


if __name__ == "__main__":
    with open(OUTPUT, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(build(), handle, indent=2)
        handle.write("\n")
    print(f"wrote {os.path.relpath(OUTPUT, ROOT)}")
