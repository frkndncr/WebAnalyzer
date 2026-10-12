"""The version number lives in one place (utils/version.py) and everything else reads it."""
import pathlib
import re

from utils.version import VERSION

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKIP_DIRS = {"node_modules", ".git", "venv", "build", "dist", "tests", "dashboard"}


def python_files():
    for path in ROOT.rglob("*.py"):
        if not (set(path.relative_to(ROOT).parts) & SKIP_DIRS):
            yield path


def test_the_version_looks_like_a_version():
    assert re.fullmatch(r"\d+\.\d+\.\d+", VERSION)


def test_no_python_file_hardcodes_a_release_number():
    """The scattered "3.6.2" / "3.6.4" strings are what made the API, the banner and
    the package disagree. Only utils/version.py may spell out a version."""
    offenders = []
    for path in python_files():
        if path.name == "version.py":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if re.search(r"""['"\s(v]3\.\d+\.\d+""", line) and "python" not in line.lower() and "version=" not in line.lower():
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:80]}")
    assert not offenders, "hardcoded version strings:\n" + "\n".join(offenders)


def test_pyproject_takes_its_version_from_this_module():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in text
    assert "utils.version.VERSION" in text
    assert not re.search(r'^version\s*=\s*"', text, re.M)


def test_the_console_script_points_at_the_new_cli():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'webanalyzer = "cli:entry"' in text and '"cli"' in text
