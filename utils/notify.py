"""Optional Telegram notifications for the operator of a WebAnalyzer instance.

Disabled unless both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set. Messages are
plain text and contain only the scanned domain and counts - never client IPs.
Failures never affect a scan.
"""
import json
import logging
import os
import urllib.request

logger = logging.getLogger("webanalyzer.notify")
audit_log = logging.getLogger("uvicorn.error")      # uvicorn shows INFO for this logger, so the line reaches the host log

TIMEOUT = 5


def enabled() -> bool:
    return bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"))


def send(text: str) -> bool:
    """Send a plain-text message. Returns True on success; never raises."""
    token, chat = os.getenv("TELEGRAM_BOT_TOKEN"), os.getenv("TELEGRAM_CHAT_ID")
    if not (token and chat):
        return False
    body = json.dumps({"chat_id": chat, "text": text[:3500], "disable_web_page_preview": True}).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=body, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # nosec - fixed https host
            return 200 <= response.status < 300
    except Exception as exc:                                 # the token is in the URL: log only the type
        logger.warning("Telegram notification failed (%s)", type(exc).__name__)
        return False


def scan_report(domain: str, client: dict, outcomes: dict, stats: dict, seconds: float) -> str:
    """One short message per scan: who asked, what was scanned, which modules worked."""
    failed = sorted(name for name, out in outcomes.items() if isinstance(out, dict) and out.get("error"))
    ran = len(outcomes)
    modules = f"{ran - len(failed)}/{ran} ok" + (f" (failed: {', '.join(failed)})" if failed else "")
    counts = ", ".join(f"{stats.get(k, 0)} {k}" for k in ("critical", "high", "medium", "low") if stats.get(k, 0))
    return (f"WebAnalyzer scan\nSite: {domain}\nIP: {client.get('ip') or '?'}\n"
            f"Browser: {client.get('agent') or '?'}\nModules: {modules}\n"
            f"Findings: {stats.get('total', 0)}" + (f" ({counts})" if counts else "") + f" - {seconds:.0f}s")


def audit(domain: str, client: dict, modules: list) -> None:
    """A durable line in the server log for every accepted scan (who, what, when)."""
    audit_log.info("scan accepted: %s", json.dumps({"domain": domain, "modules": len(modules), **client}))
