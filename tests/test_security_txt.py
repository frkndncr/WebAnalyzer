"""The example plugin: RFC 9116 parsing, and that it never follows a redirect to
another host (the target must not be able to aim the scanner at an internal one)."""
from datetime import datetime, timezone

from modules.plugins import security_txt as st

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
GOOD = """# our policy
Contact: mailto:security@example.org
Contact: https://example.org/report
Expires: 2027-01-01T00:00:00Z
Policy: https://example.org/policy
Preferred-Languages: en, tr
"""


def test_parses_a_valid_file():
    out = st.parse_security_txt(GOOD, now=NOW)
    assert out["contact"] == ["mailto:security@example.org", "https://example.org/report"]
    assert out["expired"] is False and out["issues"] == []
    assert out["fields"]["policy"] == ["https://example.org/policy"]


def test_flags_missing_contact_and_missing_expires():
    out = st.parse_security_txt("Policy: https://example.org/p\n", now=NOW)
    assert "Missing the required Contact field" in out["issues"]
    assert "Missing the required Expires field" in out["issues"]


def test_flags_an_expired_file():
    out = st.parse_security_txt("Contact: mailto:a@b.c\nExpires: 2020-01-01T00:00:00Z\n", now=NOW)
    assert out["expired"] is True and "The Expires date has passed" in out["issues"]


def test_flags_an_unparseable_date():
    out = st.parse_security_txt("Contact: mailto:a@b.c\nExpires: next tuesday\n", now=NOW)
    assert "Expires is not a valid ISO 8601 date" in out["issues"]


def test_ignores_comments_and_blank_lines():
    out = st.parse_security_txt("# c\n\nContact: mailto:a@b.c\nExpires: 2027-01-01T00:00:00Z\n", now=NOW)
    assert out["issues"] == []


class Resp:
    def __init__(self, status=200, body="", location=None):
        self.status_code = status
        self.content = body.encode()
        self.headers = {"Location": location} if location else {}
        self.raw = None


def fake_get(table):
    def get(url):
        return table[url]
    return get


def test_finds_the_file_at_the_well_known_path():
    table = {"https://example.org/.well-known/security.txt": Resp(body=GOOD)}
    out = st.security_txt("example.org", get=fake_get(table))
    assert out["found"] is True and out["url"].endswith("/.well-known/security.txt")
    assert out["contact"][0] == "mailto:security@example.org"


def test_reports_not_found_when_nothing_is_published():
    table = {f"https://example.org{p}": Resp(status=404) for p in st.PATHS}
    out = st.security_txt("example.org", get=fake_get(table))
    assert out["found"] is False and out["issues"]


def test_an_html_page_served_with_200_is_not_a_security_txt():
    table = {f"https://example.org{p}": Resp(body="<html>Welcome</html>") for p in st.PATHS}
    assert st.security_txt("example.org", get=fake_get(table))["found"] is False


def test_follows_a_redirect_within_the_same_site():
    table = {
        "https://example.org/.well-known/security.txt": Resp(status=301, location="https://www.example.org/security.txt"),
        "https://www.example.org/security.txt": Resp(body=GOOD),
    }
    assert st.security_txt("example.org", get=fake_get(table))["found"] is True


def test_never_follows_a_redirect_to_another_host():
    asked = []

    def get(url):
        asked.append(url)
        if url == "https://example.org/.well-known/security.txt":
            return Resp(status=302, location="https://169.254.169.254/latest/meta-data/")
        return Resp(status=404)

    out = st.security_txt("example.org", get=get)
    assert out["found"] is False
    assert not any("169.254.169.254" in u for u in asked)


def test_never_downgrades_a_redirect_to_http():
    asked = []

    def get(url):
        asked.append(url)
        if url == "https://example.org/.well-known/security.txt":
            return Resp(status=302, location="http://example.org/security.txt")
        return Resp(status=404)

    st.security_txt("example.org", get=get)
    assert not any(u.startswith("http://") for u in asked)


def test_a_network_error_is_not_fatal():
    def get(url):
        raise OSError("unreachable")

    assert st.security_txt("example.org", get=get)["found"] is False
