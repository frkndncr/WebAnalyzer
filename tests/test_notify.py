import urllib.error

from utils import notify


def test_disabled_without_configuration(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    assert notify.enabled() is False
    assert notify.send("x") is False


def test_needs_both_token_and_chat(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    assert notify.enabled() is False


def test_send_posts_to_telegram(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "42")
    seen = {}

    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(request, timeout):
        seen["url"], seen["body"], seen["timeout"] = request.full_url, request.data, timeout
        return Resp()

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    assert notify.send("hello") is True
    assert seen["url"] == "https://api.telegram.org/bot123:abc/sendMessage"
    assert b'"chat_id": "42"' in seen["body"] and seen["timeout"] == notify.TIMEOUT


def test_failures_never_raise_and_never_log_the_token(monkeypatch, caplog):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:secret-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "42")

    def boom(*a, **k):
        raise urllib.error.URLError("https://api.telegram.org/bot123:secret-token/sendMessage unreachable")

    monkeypatch.setattr(notify.urllib.request, "urlopen", boom)
    assert notify.send("hello") is False
    assert "secret-token" not in caplog.text


CLIENT = {"ip": "203.0.113.9", "agent": "Mozilla/5.0 Test"}


def test_report_is_one_short_message_with_who_what_and_module_health():
    outcomes = {"DNS Records": {"A": ["1.2.3.4"]}, "Nmap": {"error": "timed out after 120s"}, "WHOIS": {}}
    text = notify.scan_report("example.org", CLIENT, outcomes, {"total": 5, "high": 2, "low": 3}, 41.6)
    assert "Site: example.org" in text and "IP: 203.0.113.9" in text and "Browser: Mozilla/5.0 Test" in text
    assert "Modules: 2/3 ok (failed: Nmap)" in text
    assert "Findings: 5 (2 high, 3 low) - 42s" in text


def test_report_when_everything_worked_and_client_is_unknown():
    text = notify.scan_report("example.org", {}, {"DNS Records": {"A": []}}, {"total": 0}, 3)
    assert "Modules: 1/1 ok" in text and "failed" not in text and "IP: ?" in text and "Findings: 0 -" in text


def test_audit_line_is_json_with_the_client(caplog):
    import logging
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        notify.audit("example.org", {**CLIENT, "forwarded": "203.0.113.9, 10.0.0.1"}, ["a", "b"])
    assert '"domain": "example.org"' in caplog.text and '"modules": 2' in caplog.text and "203.0.113.9" in caplog.text


def test_webhooks_are_https_only_and_deliver_reaches_every_channel(monkeypatch):
    for name in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "http://insecure.example/hook")      # refused: not https
    assert notify.enabled() is False
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/T/secret")
    monkeypatch.setenv("WEBHOOK_URL", "https://example.test/hook")
    assert notify.enabled() is True
    posted = []

    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(notify.urllib.request, "urlopen", lambda req, timeout: posted.append((req.full_url, req.data)) or Resp())
    assert notify.deliver("hello") == 2
    assert (posted[0][0], posted[0][1]) == ("https://hooks.slack.test/T/secret", b'{"text": "hello"}')
    assert b'"event": "scan_finished"' in posted[1][1]


def test_a_failing_webhook_does_not_raise_or_leak_its_url(monkeypatch, caplog):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/T/very-secret")

    def boom(*a, **k):
        raise urllib.error.URLError("https://hooks.slack.test/T/very-secret down")

    monkeypatch.setattr(notify.urllib.request, "urlopen", boom)
    assert notify.deliver("x") == 0
    assert "very-secret" not in caplog.text