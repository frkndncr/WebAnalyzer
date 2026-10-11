"""The database manager must fail fast (not retry on every request) when the
database is down, report why without leaking the host, and recover on its own."""
import pytest

pytest.importorskip("mysql.connector")

import mysql.connector  # noqa: E402
from mysql.connector import errors as mysql_errors  # noqa: E402

from database import db_manager as dbm  # noqa: E402


class FakeConnection:
    def cursor(self):
        return self

    def execute(self, *_):
        pass

    def fetchall(self):
        return [(1,)]

    def close(self):
        pass


class FakePool:
    def __init__(self, **_):
        pass

    def get_connection(self):
        return FakeConnection()


@pytest.fixture
def manager(monkeypatch):
    attempts = []

    def failing_pool(**_):
        attempts.append(1)
        raise mysql_errors.DatabaseError(
            msg="Too many connections to 'secret-host.example'", errno=1040)

    monkeypatch.setattr(mysql.connector.pooling, "MySQLConnectionPool", failing_pool)
    m = dbm.DatabaseManager()
    m.retry_cooldown = 20
    m._initialize_schema = lambda: None
    m.attempts = attempts
    return m


def test_a_failed_connect_is_not_retried_during_the_cooldown(manager):
    with pytest.raises(RuntimeError):
        manager._init_pool()
    assert len(manager.attempts) == 1

    for _ in range(5):                     # a burst of requests while the DB is down
        with pytest.raises(RuntimeError) as err:
            manager._init_pool()
        assert "retrying in" in str(err.value)
    assert len(manager.attempts) == 1      # none of them tried to connect again


def test_it_retries_once_the_cooldown_has_passed(manager, monkeypatch):
    with pytest.raises(RuntimeError):
        manager._init_pool()
    manager._last_failure -= 21            # pretend 21 seconds went by
    with pytest.raises(RuntimeError):
        manager._init_pool()
    assert len(manager.attempts) == 2


def test_status_reports_the_category_without_leaking_the_host(manager):
    status = manager.status()
    assert status["connected"] is False
    assert status["error"] == "too_many_connections"
    assert status["retry_in"] > 0
    assert "secret-host" not in str(status)


def test_it_recovers_when_the_database_comes_back(manager, monkeypatch):
    assert manager.status()["connected"] is False
    monkeypatch.setattr(mysql.connector.pooling, "MySQLConnectionPool", FakePool)
    manager._last_failure -= 21
    assert manager.status() == {"connected": True, "error": None, "retry_in": 0}
    assert manager._last_error_kind is None


def test_defaults_keep_the_pool_small_and_the_timeout_short(monkeypatch):
    for var in ("DB_POOL_SIZE", "DB_CONNECT_TIMEOUT"):
        monkeypatch.delenv(var, raising=False)
    m = dbm.DatabaseManager()
    assert m.config["pool_size"] == 5
    assert m.config["connection_timeout"] == 10


def test_pool_size_can_still_be_overridden(monkeypatch):
    monkeypatch.setenv("DB_POOL_SIZE", "12")
    assert dbm.DatabaseManager().config["pool_size"] == 12
