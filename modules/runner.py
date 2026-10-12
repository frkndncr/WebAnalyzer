"""Runs registered modules. Shared by the API and the CLI so both behave alike."""
import asyncio
import inspect
from typing import Any, Callable, Dict, Iterable, Optional

from modules import registry


async def run_module(spec: registry.ModuleSpec, domain: str, results: Optional[Dict[str, Any]] = None) -> Any:
    """Run one module and return what it produced.

    Blocking modules run in a worker thread so the event loop stays responsive;
    modules marked ``runs_in_loop`` (or written as coroutines) run on the loop.
    A module that returns an awaitable has it awaited. Modules with
    ``needs_results`` also receive what the other modules have produced so far.
    """
    results = {} if results is None else results

    def call():
        return spec.run(domain, results) if spec.needs_results else spec.run(domain)

    if spec.runs_in_loop or inspect.iscoroutinefunction(spec.run):
        outcome = call()
    else:
        outcome = await asyncio.get_running_loop().run_in_executor(None, call)
    if inspect.isawaitable(outcome):
        outcome = await outcome
    return outcome


async def run_modules(
    domain: str,
    names: Iterable[str],
    on_start: Optional[Callable[[str], None]] = None,
    on_done: Optional[Callable[[str, Any], None]] = None,
) -> Dict[str, Any]:
    """Run the named modules in order and return ``{name: result}``.

    A module that raises does not stop the others: its entry becomes
    ``{"error": "..."}``. Unknown names are skipped.
    """
    results: Dict[str, Any] = {}
    for name in names:
        spec = registry.get(name)
        if spec is None:
            continue
        if on_start:
            on_start(name)
        try:
            outcome = await run_module(spec, domain, results)
        except Exception as exc:  # noqa: BLE001 - one failing module must not end the scan
            outcome = {"error": str(exc)}
        results[name] = outcome
        if on_done:
            on_done(name, outcome)
    return results
