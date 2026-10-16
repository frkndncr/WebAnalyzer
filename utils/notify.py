"""Optional scan notifications for the operator of a WebAnalyzer instance.

Channels (each off unless configured):
  TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID   a Telegram bot message
  SLACK_WEBHOOK_URL                       a Slack incoming webhook
  WEBHOOK_URL                             any https endpoint, JSON {"event", "text"}

One short plain-text message per scan: the site, who asked (IP and browser), how many
modules worked and the finding counts. Failures never affect a scan, and the secret
in a URL is never logged.
"""
import json
import logging
import os
import urllib.request

logger = logging.getLogger("webanalyzer.notify")
audit_log = logging.getLogger("uvicorn.error")      # uvicorn shows INFO for this logger, so the line reaches the host log

TIMEOUT = 5


def _webhooks() -> dict:
    """Configured webhook URLs by kind. Only https is accepted."""
    urls = {"slack": os.getenv("SLACK_WEBHOOK_URL", ""), "generic": os.getenv("WEBHOOK_URL", "")}
    return {kind: url for kind, url in urls.items() if url.startswith("https://")}


def enabled() -> bool:
    return bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID")) or bool(_webhooks())


def _post(url: str, payload: dict, label: str) -> bool:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # nosec - operator-configured https URL
            return 200 <= response.status < 300
    except Exception as exc:                                 # the secret is in the URL: log only the type
        logger.warning("%s notification failed (%s)", label, type(exc).__name__)
        return False


def send(text: str) -> bool:
    """Send a plain-text Telegram message. Returns True on success; never raises."""
    token, chat = os.getenv("TELEGRAM_BOT_TOKEN"), os.getenv("TELEGRAM_CHAT_ID")
    if not (token and chat):
        return False
    return _post(f"https://api.telegram.org/bot{token}/sendMessage",
                 {"chat_id": chat, "text": text[:3500], "disable_web_page_preview": True}, "Telegram")


def deliver(text: str) -> int:
    """Send ``text`` on every configured channel. Returns how many succeeded; never raises."""
    sent = int(send(text))
    for kind, url in _webhooks().items():
        payload = {"text": text[:3500]} if kind == "slack" else {"event": "scan_finished", "text": text[:3500]}
        sent += int(_post(url, payload, kind.title() + " webhook"))
    return sent

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
