"""Classify database connection errors into short, safe categories.

The raw MySQL message contains the database host and sometimes the user name,
so it must never be sent to a client. These helpers reduce an exception to a
category the dashboard can explain ("too_many_connections", "cannot_connect",
...). Standard library only, so it is unit tested without a database.
"""
import re
from typing import Optional

# MySQL / MariaDB / mysql-connector error numbers -> category.
_ERRNO_KINDS = {
    1040: "too_many_connections",   # Too many connections
    1203: "too_many_connections",   # max_user_connections exceeded
    1226: "too_many_connections",   # user resource limit reached
    1044: "access_denied",
    1045: "access_denied",
    1049: "unknown_database",
    1129: "host_blocked",
    1130: "host_blocked",
    2002: "cannot_connect",
    2003: "cannot_connect",
    2005: "unknown_host",
    2006: "connection_lost",
    2013: "connection_lost",
}

# Fallbacks for errors that carry no number (pool errors, socket timeouts, ...).
_TEXT_KINDS = (
    (re.compile(r"pool exhausted|failed getting connection", re.I), "pool_exhausted"),
    (re.compile(r"too many connections|max_user_connections", re.I), "too_many_connections"),
    (re.compile(r"access denied", re.I), "access_denied"),
    (re.compile(r"unknown database", re.I), "unknown_database"),
    (re.compile(r"name or service not known|getaddrinfo|unknown mysql server host", re.I), "unknown_host"),
    (re.compile(r"timed out|timeout", re.I), "timeout"),
    (re.compile(r"can't connect|connection refused|cannot connect", re.I), "cannot_connect"),
    (re.compile(r"lost connection|server has gone away|broken pipe", re.I), "connection_lost"),
)


def db_error_code(exc) -> Optional[int]:
    """The numeric MySQL error code of ``exc``, if it has one."""
    code = getattr(exc, "errno", None)
    if isinstance(code, int):
        return code
    match = re.match(r"\s*(\d{4})\b", str(exc))
    return int(match.group(1)) if match else None


def classify_db_error(exc) -> str:
    """A short category for ``exc`` (never contains host names or credentials)."""
    code = db_error_code(exc)
    if code in _ERRNO_KINDS:
        return _ERRNO_KINDS[code]
    text = str(exc)
    for pattern, kind in _TEXT_KINDS:
        if pattern.search(text):
            return kind
    return "unavailable"
