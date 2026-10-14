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


def test_messages_contain_domain_and_counts_only():
    assert "example.org" in notify.scan_started("example.org", 7)
    text = notify.scan_finished("example.org", {"total": 5, "high": 2, "low": 3}, 41.6)
    assert "5 findings (2 high, 3 low) in 42s" in text
    assert "0 findings" in notify.scan_finished("example.org", {"total": 0}, 3)
