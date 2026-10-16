"""WebAnalyzer command line.

    webanalyzer scan example.com                          # standard preset, text summary
    webanalyzer scan example.com --passive -f sarif -o out.sarif --fail-on high
    webanalyzer scan -l domains.txt -f jsonl | jq .
    webanalyzer modules                                   # what can be run
    webanalyzer verify example.com                        # DNS record for ownership checks

Exit codes: 0 success, 1 findings at or above --fail-on, 2 usage error,
3 nothing could be scanned (no module produced a result).

Running ``webanalyzer`` with no arguments, or with the older -u/-l/-m flags,
still starts the interactive/legacy mode.
"""
import argparse
import asyncio
import difflib
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from utils import formats
from utils.safety import normalize_target
from utils.version import VERSION

COMMANDS = {"scan", "modules", "verify", "version", "diff"}
FORMATS = ("text", "json", "jsonl", "sarif", "markdown", "html")
THRESHOLDS = ("none", "info", "low", "medium", "high", "critical")
NOTICE = "Only scan systems you own or are authorized to test."

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_NOTHING = 0, 1, 2, 3

# Set when a module hit --timeout: its worker thread cannot be interrupted, so the
# process must not wait for it at exit.
_abandoned_threads = False


def _load_modules():
    """Make sure the built-in modules and any plugins are registered."""
    from modules import builtin, registry  # noqa: F401 - importing builtin registers the modules

    registry.discover_plugins()
    return registry


def _read_lines(path_or_stream) -> List[str]:
    lines = path_or_stream.read().splitlines() if hasattr(path_or_stream, "read") else open(path_or_stream, encoding="utf-8").read().splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def resolve_modules(selection: str, available: List[str]) -> Tuple[List[str], List[str]]:
    """Match a comma-separated list to module names (case-insensitive). Returns (names, unknown)."""
    by_lower = {name.lower(): name for name in available}
    names, unknown = [], []
    for raw in selection.split(","):
        key = raw.strip().lower()
        if not key:
            continue
        match = by_lower.get(key)
        if match:
            if match not in names:
                names.append(match)
        else:
            unknown.append(raw.strip())
    return names, unknown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webanalyzer",
        description="Domain reconnaissance and security analysis. " + NOTICE,
        epilog="Run `webanalyzer` with no arguments for the interactive mode.",
    )
    parser.add_argument("--version", action="version", version=f"WebAnalyzer {VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="{scan,diff,modules,verify,version}")

    scan = sub.add_parser("scan", help="scan one or more domains", description="Scan domains and report findings. " + NOTICE)
    scan.add_argument("targets", nargs="*", help="domains or URLs; '-' reads them from stdin")
    scan.add_argument("-l", "--list", metavar="FILE", help="file with one domain per line ('#' comments allowed)")
    scan.add_argument("-m", "--modules", metavar="NAMES", help="comma-separated module names (see `webanalyzer modules`)")
    scan.add_argument("--preset", choices=("quick", "standard", "full"), default="standard",
                      help="module set when --modules is not given (default: standard)")
    scan.add_argument("--passive", action="store_true", help="never run the intrusive modules (port scans, active tests, probing)")
    scan.add_argument("-f", "--format", choices=FORMATS, default="text", help="output format (default: text)")
    scan.add_argument("-o", "--output", metavar="FILE", help="write the output to FILE instead of stdout")
    scan.add_argument("--client", metavar="NAME", default="", help="client name on the html report cover")
    scan.add_argument("--author", metavar="NAME", default="", help="who prepared the html report")
    scan.add_argument("--title", metavar="TEXT", default="", help="html report title (default: Security Assessment Report)")
    scan.add_argument("--summary", metavar="FILE", help="also write a Markdown summary to FILE (e.g. $GITHUB_STEP_SUMMARY)")
    scan.add_argument("--fail-on", choices=THRESHOLDS, default="none", metavar="LEVEL",
                      help="exit 1 if a finding is at least this severe: " + ", ".join(THRESHOLDS) + " (default: none)")
    scan.add_argument("--baseline", metavar="FILE",
                      help="a previous `-f json` result: --fail-on then only counts findings that are new since then")
    scan.add_argument("--timeout", type=float, default=120.0, metavar="SECONDS", help="per-module time limit (default: 120)")
    scan.add_argument("-c", "--concurrency", type=int, default=1, metavar="N", help="domains scanned in parallel (default: 1)")
    scan.add_argument("--no-results", action="store_true", help="leave the raw module output out of json/jsonl")
    scan.add_argument("-q", "--quiet", action="store_true", help="no progress or notices on stderr")

    diff = sub.add_parser("diff", help="show what changed between two `-f json` scan results",
                          description="Compare two results written by `webanalyzer scan -f json`.")
    diff.add_argument("old", help="the earlier result (JSON)")
    diff.add_argument("new", help="the later result (JSON)")
    diff.add_argument("-f", "--format", choices=("text", "markdown", "json"), default="text")
    diff.add_argument("--fail-on-new", choices=THRESHOLDS, default="none", metavar="LEVEL",
                      help="exit 1 if a NEW finding is at least this severe (default: none)")

    mods = sub.add_parser("modules", help="list the available modules")
    mods.add_argument("--json", action="store_true", help="machine-readable output")

    verify = sub.add_parser("verify", help="show (and check) the DNS record that proves you own a domain")
    verify.add_argument("domain")
    verify.add_argument("--no-check", action="store_true", help="only print the record, do not query DNS")
    verify.add_argument("--json", action="store_true", help="machine-readable output")

    sub.add_parser("version", help="print the version")
    return parser


# ─────────────────────────── commands ───────────────────────────

def cmd_modules(args, out, err) -> int:
    registry = _load_modules()
    if args.json:
        print(json.dumps(registry.catalogue(), indent=2), file=out)
        return EXIT_OK
    rows = registry.catalogue()
    width = max(len(m["name"]) for m in rows)
    print(f"{'MODULE'.ljust(width)}  GROUP      WEIGHT  ACTIVE  DESCRIPTION", file=out)
    for m in rows:
        print(f"{m['name'].ljust(width)}  {m['group'].ljust(9)}  {m['weight'].ljust(6)}  {'yes' if m['active'] else '-':6}  {m['description']}", file=out)
    print(f"\n{len(rows)} modules. 'Active' modules send intrusive traffic; use --passive to exclude them.", file=out)
    return EXIT_OK


def cmd_verify(args, out, err) -> int:
    _load_modules()
    from utils import ownership

    host = normalize_target(args.domain)
    if not host:
        print("error: enter a valid domain", file=err)
        return EXIT_USAGE
    info = ownership.instructions(host)
    verified = None if args.no_check else ownership.is_verified(host)
    if args.json:
        print(json.dumps({**info, "verified": verified}, indent=2), file=out)
    else:
        rec = info["record"]
        print(f"Publish this DNS record for {host}:\n\n  Type : {rec['type']}\n  Name : {rec['name']}\n  Value: {rec['value']}\n", file=out)
        if verified is None:
            print("(DNS was not checked)", file=out)
        else:
            print("Status: VERIFIED" if verified else "Status: not verified yet (DNS can take a while to propagate)", file=out)
    return EXIT_OK if verified in (True, None) else EXIT_FINDINGS


def _collect_targets(args, stdin) -> List[str]:
    raw: List[str] = []
    for item in args.targets:
        raw.extend(_read_lines(stdin) if item == "-" else [item])
    if args.list:
        raw.extend(_read_lines(args.list))
    targets, seen = [], set()
    for item in raw:
        host = normalize_target(item)
        if host and host not in seen:
            seen.add(host)
            targets.append(host)
    return targets


def _select_modules(args, registry, err) -> Optional[List[str]]:
    available = list(registry.names())
    if args.modules:
        names, unknown = resolve_modules(args.modules, available)
        if unknown:
            for name in unknown:
                hint = difflib.get_close_matches(name, available, n=1, cutoff=0.5)
                print(f"error: unknown module '{name}'" + (f" - did you mean '{hint[0]}'?" if hint else ""), file=err)
            return None
    else:
        from modules import builtin
        names = available if args.preset == "full" else [n for n in builtin.PRESETS[args.preset] if n in available]
    if args.passive:
        active = registry.active_names()
        skipped = [n for n in names if n in active]
        names = [n for n in names if n not in active]
        if skipped and not args.quiet:
            print(f"note: --passive skips the intrusive modules: {', '.join(skipped)}", file=err)
    if not names:
        print("error: no modules to run", file=err)
        return None
    return names


async def _scan_all(targets, names, args, err):
    from modules.runner import run_modules

    semaphore = asyncio.Semaphore(max(1, args.concurrency))
    multi = len(targets) > 1

    async def one(domain):
        async with semaphore:
            prefix = f"[{domain}] " if multi else ""
            started = time.time()
            clock = {}

            def on_start(name):
                clock[name] = time.time()

            def on_done(name, outcome):
                if args.quiet:
                    return
                failed = isinstance(outcome, dict) and outcome.get("error")
                took = time.time() - clock.get(name, started)
                print(f"{prefix}{'[failed]' if failed else '[ok]    '} {name} ({took:.1f}s)" + (f" - {outcome['error']}" if failed else ""), file=err)

            results = await run_modules(domain, names, on_start=on_start, on_done=on_done, timeout=args.timeout)
            return {
                "domain": domain,
                "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "duration_seconds": round(time.time() - started, 1),
                "results": results,
            }

    return await asyncio.gather(*(one(d) for d in targets))


def cmd_scan(args, out, err, stdin) -> int:
    global _abandoned_threads
    registry = _load_modules()
    targets = _collect_targets(args, stdin)
    if not targets:
        print("error: no targets - pass domains, '-' for stdin, or --list FILE", file=err)
        return EXIT_USAGE
    names = _select_modules(args, registry, err)
    if names is None:
        return EXIT_USAGE
    if not args.quiet:
        print(f"{NOTICE}\nScanning {len(targets)} target(s) with {len(names)} module(s)...", file=err)

    baseline = _load_document(args.baseline, err) if args.baseline else None
    if args.baseline and baseline is None:
        return EXIT_USAGE                              # fail before spending time on the scan

    scans = asyncio.run(_scan_all(targets, names, args, err))
    doc = formats.build_document(scans, include_results=not args.no_results)

    _abandoned_threads = any(
        isinstance(data, dict) and str(data.get("error", "")).startswith("timed out after")
        for scan in scans for data in scan["results"].values()
    )

    if args.format == "json":
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    elif args.format == "jsonl":
        text = "".join(json.dumps(line, ensure_ascii=False) + "\n" for line in formats.to_jsonl_lines(doc))
    elif args.format == "sarif":
        text = json.dumps(formats.to_sarif(doc), indent=2, ensure_ascii=False) + "\n"
    elif args.format == "markdown":
        text = formats.to_markdown(doc)
    elif args.format == "html":
        from utils.report import to_html_report
        text = to_html_report(doc, client=args.client, author=args.author, title=args.title)
    else:
        text = formats.to_text(doc)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        if not args.quiet:
            print(f"wrote {args.output}", file=err)
            if args.format != "text":
                print(formats.to_text(doc, limit=10), file=err)
    else:
        out.write(text)

    if args.summary:
        with open(args.summary, "a", encoding="utf-8", newline="\n") as handle:      # append: GITHUB_STEP_SUMMARY is shared
            handle.write(formats.to_markdown(doc))

    produced = sum(1 for t in doc["targets"] for status in t["modules"].values() if status != "error")
    if produced == 0:
        print("error: every module failed - nothing was scanned (is the network reachable?)", file=err)
        return EXIT_NOTHING
    if baseline is not None:
        from utils import diff as changes
        new = changes.new_findings(baseline, doc)
        if not args.quiet:
            print(f"{len(new)} new finding(s) since the baseline", file=err)
        return EXIT_FINDINGS if changes.exceeds_new(baseline, doc, args.fail_on) else EXIT_OK
    return EXIT_FINDINGS if formats.exceeds(doc, args.fail_on) else EXIT_OK


def _load_document(path: str, err) -> Optional[dict]:
    """A scan document written by `-f json`, or None (with a message) when it cannot be used."""
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read {path}: {exc}", file=err)
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("targets"), list):
        print(f"error: {path} is not a `webanalyzer scan -f json` result", file=err)
        return None
    return doc


def cmd_diff(args, out, err) -> int:
    from utils import diff as changes
    old, new = _load_document(args.old, err), _load_document(args.new, err)
    if old is None or new is None:
        return EXIT_USAGE
    result = changes.diff_documents(old, new)
    if args.format == "json":
        out.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    elif args.format == "markdown":
        out.write(changes.to_markdown(result))
    else:
        out.write(changes.to_text(result))
    return EXIT_FINDINGS if changes.exceeds_new(old, new, args.fail_on_new) else EXIT_OK


def main(argv=None, stdout=None, stderr=None, stdin=None) -> int:
    out, err, stdin = stdout or sys.stdout, stderr or sys.stderr, stdin or sys.stdin
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:                         # argparse exits on --help/--version and on errors
        return EXIT_OK if exc.code in (0, None) else EXIT_USAGE
    if args.command == "scan":
        return cmd_scan(args, out, err, stdin)
    if args.command == "diff":
        return cmd_diff(args, out, err)
    if args.command == "modules":
        return cmd_modules(args, out, err)
    if args.command == "verify":
        return cmd_verify(args, out, err)
    if args.command == "version":
        print(f"WebAnalyzer {VERSION}", file=out)
        return EXIT_OK
    parser.print_help(out)
    return EXIT_OK


def entry():
    """Console-script entry point: new subcommands here, everything else to the legacy CLI."""
    argv = sys.argv[1:]
    if argv and (argv[0] in COMMANDS or argv[0] in ("--version", "-h", "--help")):
        code = main(argv)
        sys.stdout.flush()
        sys.stderr.flush()
        if _abandoned_threads:
            os._exit(code)          # a timed-out module's thread cannot be interrupted; do not wait for it
        sys.exit(code)
    from main import run_cli          # interactive mode and the older -u/-l/-m flags
    run_cli()


if __name__ == "__main__":
    entry()
