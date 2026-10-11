"""Tests for utils.db_errors: reduce DB exceptions to safe, explainable categories."""
import pytest

from utils.db_errors import classify_db_error, db_error_code


class FakeDbError(Exception):
    def __init__(self, msg, errno=None):
        super().__init__(msg)
        self.errno = errno


@pytest.mark.parametrize("errno,kind", [
    (1040, "too_many_connections"), (1203, "too_many_connections"), (1226, "too_many_connections"),
    (1045, "access_denied"), (1044, "access_denied"), (1049, "unknown_database"),
    (2003, "cannot_connect"), (2002, "cannot_connect"), (2005, "unknown_host"),
    (2006, "connection_lost"), (2013, "connection_lost"), (1129, "host_blocked"),
])
def test_known_errnos(errno, kind):
    assert classify_db_error(FakeDbError("whatever", errno=errno)) == kind


def test_errno_is_read_from_the_message_when_missing():
    exc = Exception("2003 (HY000): Can't connect to MySQL server on 'db.internal:3306' (111)")
    assert db_error_code(exc) == 2003
    assert classify_db_error(exc) == "cannot_connect"


@pytest.mark.parametrize("text,kind", [
    ("Failed getting connection; pool exhausted", "pool_exhausted"),
    ("Too many connections", "too_many_connections"),
    ("Access denied for user 'x'@'y'", "access_denied"),
    ("connection timed out", "timeout"),
    ("[Errno -2] Name or service not known", "unknown_host"),
    ("MySQL server has gone away", "connection_lost"),
])
def test_text_fallbacks(text, kind):
    assert classify_db_error(Exception(text)) == kind


def test_unknown_errors_get_a_generic_category():
    assert classify_db_error(Exception("something odd")) == "unavailable"


def test_the_category_never_leaks_the_host_or_user():
    exc = FakeDbError("Can't connect to MySQL server on 'secret-host.example:3306'", errno=2003)
    kind = classify_db_error(exc)
    assert "secret-host" not in kind and "3306" not in kind
