"""action.yml must stay publishable on the GitHub Marketplace and safe to run."""
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

TEXT = (Path(__file__).resolve().parent.parent / "action.yml").read_text(encoding="utf-8")
ACTION = yaml.safe_load(TEXT)
STEPS = ACTION["runs"]["steps"]


def test_marketplace_required_fields():
    assert ACTION["name"] and ACTION["author"]
    assert len(ACTION["description"].strip()) <= 125, "Marketplace truncates descriptions beyond 125 characters"
    assert ACTION["branding"]["icon"] and ACTION["branding"]["color"]


def test_every_input_and_output_is_documented():
    for name, spec in ACTION["inputs"].items():
        assert spec.get("description"), f"input {name} has no description"
    for name, spec in ACTION["outputs"].items():
        assert spec.get("description"), f"output {name} has no description"


def test_every_run_step_declares_its_shell():
    for step in STEPS:
        if "run" in step:
            assert step.get("shell"), f"step {step.get('name')!r} has no shell"


def test_inputs_are_never_interpolated_into_scripts():
    """`${{ inputs.x }}` inside run: is shell injection; pass inputs through env: instead."""
    for step in STEPS:
        assert "${{" not in step.get("run", ""), f"step {step.get('name')!r} interpolates into its script"


def test_every_referenced_input_exists():
    referenced = set(re.findall(r"inputs\.([\w-]+)", TEXT))
    assert referenced <= set(ACTION["inputs"]), referenced - set(ACTION["inputs"])


def test_third_party_actions_are_pinned_to_a_version():
    for step in STEPS:
        if "uses" in step:
            assert "@" in step["uses"], step["uses"]
