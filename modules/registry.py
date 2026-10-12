"""The module registry: the one place that knows which analysis modules exist.

Everything that lists or runs modules (the API, the CLI, the dashboard's
catalogue, the ownership rules for the public demo) reads from here, so adding a
module means writing one function and registering it - nothing else changes.

    from modules.registry import module

    @module("Security.txt", description="RFC 9116 contact file", group="security", weight="light")
    def security_txt(domain):
        ...                      # return any JSON-serialisable value
        return {"found": True}

Modules are plain functions ``fn(domain)`` (sync or ``async``). Set
``needs_results=True`` for a module that builds on the others and takes
``fn(domain, results)``, where ``results`` maps module names to what they have
produced so far. Mark a module ``active=True`` if it sends intrusive traffic
(port scans, injection tests, probing): on a public demo those only run for
domains whose owner has verified them.

Drop a file into ``modules/plugins/`` (or a directory listed in the
``WEBANALYZER_PLUGIN_DIRS`` environment variable) and it is loaded at startup.
This module imports only the standard library so it is cheap to load and test.
"""
import hashlib
import importlib
import importlib.util
import logging
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

GROUPS = ("recon", "security", "offensive")
WEIGHTS = ("light", "medium", "heavy")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 &/.+_-]{0,63}$")


@dataclass(frozen=True)
class ModuleSpec:
    name: str                       # unique display name; also the key used by the API and CLI
    run: Callable[..., Any]
    description: str = ""
    group: str = "recon"            # one of GROUPS
    weight: str = "medium"          # one of WEIGHTS: how hard it hits the target (drives pacing)
    active: bool = False            # intrusive: needs a verified domain on the public demo
    needs_results: bool = False     # run(domain, results_so_far)
    runs_in_loop: bool = False      # call on the event loop instead of a worker thread
    order: int = 100                # position in listings (lower first)


_REGISTRY: Dict[str, ModuleSpec] = {}


def register(spec: ModuleSpec, replace: bool = False) -> ModuleSpec:
    """Add a module. Raises ValueError on a bad or duplicate name/metadata."""
    if not isinstance(spec.name, str) or not _NAME_RE.match(spec.name):
        raise ValueError(f"invalid module name: {spec.name!r}")
    if spec.group not in GROUPS:
        raise ValueError(f"{spec.name}: group must be one of {GROUPS}, got {spec.group!r}")
    if spec.weight not in WEIGHTS:
        raise ValueError(f"{spec.name}: weight must be one of {WEIGHTS}, got {spec.weight!r}")
    if not callable(spec.run):
        raise ValueError(f"{spec.name}: run must be callable")
    if spec.name in _REGISTRY and not replace:
        raise ValueError(f"module already registered: {spec.name}")
    _REGISTRY[spec.name] = spec
    return spec


def module(name: str, **options):
    """Decorator form of :func:`register`; returns the function unchanged."""
    def decorator(fn):
        register(ModuleSpec(name=name, run=fn, **options))
        return fn
    return decorator


def unregister(name: str) -> None:
    _REGISTRY.pop(name, None)


def all_modules() -> List[ModuleSpec]:
    return sorted(_REGISTRY.values(), key=lambda m: (m.order, m.name))


def get(name: str) -> Optional[ModuleSpec]:
    return _REGISTRY.get(name)


def names() -> Tuple[str, ...]:
    return tuple(m.name for m in all_modules())


def active_names() -> frozenset:
    return frozenset(m.name for m in _REGISTRY.values() if m.active)


def catalogue() -> List[dict]:
    """What clients need to know about each module (no callables)."""
    return [
        {"name": m.name, "description": m.description, "group": m.group,
         "weight": m.weight, "active": m.active}
        for m in all_modules()
    ]


# ─────────────────────────── plugin discovery ───────────────────────────

def _plugin_dirs() -> List[str]:
    dirs = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")]
    extra = os.getenv("WEBANALYZER_PLUGIN_DIRS", "")
    dirs += [d for d in extra.split(os.pathsep) if d.strip()]
    return dirs


def discover_plugins(directories: Optional[List[str]] = None) -> List[Tuple[str, Optional[str]]]:
    """Import every ``*.py`` file (not starting with ``_``) in the plugin directories.

    A broken plugin must never take the platform down, so each load is isolated:
    returns ``[(path, error_or_None), ...]`` and logs failures. Each file is
    executed at most once per process (it registers itself on import), and the
    plugins shipped in ``modules/plugins`` are imported as that package so
    importing them directly afterwards reuses the same module.
    """
    shipped = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
    outcomes: List[Tuple[str, Optional[str]]] = []
    for directory in (directories if directories is not None else _plugin_dirs()):
        if not os.path.isdir(directory):
            continue
        is_shipped = os.path.abspath(directory) == shipped
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue
            path = os.path.join(directory, filename)
            stem = os.path.splitext(filename)[0]
            try:
                if is_shipped:
                    importlib.import_module(f"modules.plugins.{stem}")
                else:
                    unique = hashlib.md5(os.path.abspath(path).encode()).hexdigest()[:10]
                    module_name = f"webanalyzer_plugin_{unique}_{stem}"
                    if module_name not in sys.modules:
                        spec = importlib.util.spec_from_file_location(module_name, path)
                        loaded = importlib.util.module_from_spec(spec)
                        sys.modules[module_name] = loaded
                        try:
                            spec.loader.exec_module(loaded)
                        except BaseException:
                            sys.modules.pop(module_name, None)   # let a fixed file be retried
                            raise
                outcomes.append((path, None))
            except Exception as exc:  # noqa: BLE001 - isolate any plugin failure
                logger.error("Plugin %s failed to load: %s", path, exc)
                outcomes.append((path, f"{type(exc).__name__}: {exc}"))
    return outcomes
