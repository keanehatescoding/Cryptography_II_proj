"""
rate_limiter.py
-----------------
A small in-memory rate limiter to blunt brute-force / DoS attempts
against the handshake endpoint. Tracks failed handshake attempts per
remote address; once an address exceeds a threshold within a sliding
time window, further attempts from that address are refused for a
cooldown period.

Why this matters even with correct crypto: a valid protocol design
doesn't prevent an attacker from opening thousands of connections and
forcing the server to do ECDH + signature verification for each one -
that's still a CPU-exhaustion DoS vector. Rate limiting is a cheap,
separate layer of defense for exactly that failure mode; it does not
depend on or interact with the cryptography at all.

This is NOT a substitute for a real firewall/WAF/reverse-proxy in
production - it's in-memory and per-process (state resets on restart,
doesn't share across multiple server instances), and trivially bypassed
by an attacker who can spoof or rotate source addresses. It's included
here to demonstrate defense-in-depth thinking, not as a complete
DoS-mitigation solution.
"""

import sqlite3
import time
from collections import defaultdict, deque
from pathlib import Path

from audit_log import EventCode, security_logger


class RateLimiter:
    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: float = 60.0,
        cooldown_seconds: float = 30.0,
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self._failures: dict[str, deque] = defaultdict(deque)
        self._blocked_until: dict[str, float] = {}

    def is_blocked(self, key: str, now: float = None) -> bool:
        now = now if now is not None else time.monotonic()
        blocked_until = self._blocked_until.get(key)
        if blocked_until is None:
            return False
        if now >= blocked_until:
            del self._blocked_until[key]
            return False
        return True

    def seconds_until_unblocked(self, key: str, now: float = None) -> float:
        now = now if now is not None else time.monotonic()
        blocked_until = self._blocked_until.get(key)
        if blocked_until is None or now >= blocked_until:
            return 0.0
        return blocked_until - now

    def record_failure(self, key: str, now: float = None):
        now = now if now is not None else time.monotonic()
        attempts = self._failures[key]
        attempts.append(now)
        while attempts and now - attempts[0] > self.window_seconds:
            attempts.popleft()
        if len(attempts) >= self.max_attempts:
            self._blocked_until[key] = now + self.cooldown_seconds
            security_logger.security(
                EventCode.RATE_LIMIT_TRIGGERED,
                "rate limit triggered - too many failed attempts",
                key=key,
                attempts=len(attempts),
                window_seconds=self.window_seconds,
                cooldown_seconds=self.cooldown_seconds,
            )
            attempts.clear()

    def record_success(self, key: str):
        """A successful handshake clears prior failure history for that
        key - legitimate transient failures (e.g. a peer's earlier typo'd
        passphrase) shouldn't keep counting against them forever."""
        self._failures.pop(key, None)
        self._blocked_until.pop(key, None)


class SQLiteRateLimiter:
    """Same throttling behavior as RateLimiter, backed by a SQLite file
    instead of an in-memory dict, so state survives a process restart -
    without this, an attacker who trips the cooldown gets a free reset
    just by waiting for (or forcing) the app to restart.

    This gives up RateLimiter's use of time.monotonic(): a monotonic
    clock's reference point is arbitrary per-process and isn't meaningful
    to compare across a restart, so a timestamp recorded before one would
    be garbage to compare against the new process's monotonic clock.
    Persisted timestamps use time.time() (wall-clock) instead, which IS
    comparable across restarts, at the cost of being adjustable by the
    system clock - the same trade-off any persistent rate-limit store (a
    database, Redis, ...) makes in practice. RateLimiter keeps using
    monotonic time for the common in-memory case, where that trade-off
    isn't necessary.

    Like RateLimiter, this is still in NO way a substitute for a real
    firewall/WAF/reverse-proxy - it remains trivially bypassed by an
    attacker who can rotate source addresses; persistence only closes
    the specific "just restart the app" bypass, not spoofing/rotation.
    """

    def __init__(
        self,
        db_path: str,
        max_attempts: int = 5,
        window_seconds: float = 60.0,
        cooldown_seconds: float = 30.0,
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        # WAL + a busy timeout so a second process/thread hitting this
        # same file (e.g. two GUI windows sharing an identity) blocks
        # briefly and retries instead of raising "database is locked".
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS attempts (key TEXT NOT NULL, ts REAL NOT NULL)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_attempts_key ON attempts(key)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_attempts_ts ON attempts(ts)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS blocks ("
            "key TEXT PRIMARY KEY, blocked_until REAL NOT NULL)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blocks_until ON blocks(blocked_until)"
        )
        self._conn.commit()

    def is_blocked(self, key: str, now: float = None) -> bool:
        now = now if now is not None else time.time()
        row = self._conn.execute(
            "SELECT blocked_until FROM blocks WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return False
        if now >= row[0]:
            self._conn.execute("DELETE FROM blocks WHERE key = ?", (key,))
            self._conn.commit()
            return False
        return True

    def seconds_until_unblocked(self, key: str, now: float = None) -> float:
        now = now if now is not None else time.time()
        row = self._conn.execute(
            "SELECT blocked_until FROM blocks WHERE key = ?", (key,)
        ).fetchone()
        if row is None or now >= row[0]:
            return 0.0
        return row[0] - now

    def record_failure(self, key: str, now: float = None):
        now = now if now is not None else time.time()
        self._conn.execute("INSERT INTO attempts (key, ts) VALUES (?, ?)", (key, now))
        # Deleted GLOBALLY (every key), not just this one: an attacker
        # who rotates through many source addresses, each failing a few
        # times but never enough to trip a block and never coming back,
        # would otherwise leave permanent garbage rows behind for every
        # address that never revisits - since this is a persistent file,
        # not memory that resets, that garbage would accumulate forever
        # and could exhaust disk space. Piggybacking the global sweep on
        # every write keeps the file bounded without a background thread.
        # Same eviction rule as RateLimiter: an attempt exactly at the
        # window boundary (now - ts == window_seconds) still counts.
        self._conn.execute("DELETE FROM attempts WHERE ts < ?", (now - self.window_seconds,))
        self._conn.execute("DELETE FROM blocks WHERE blocked_until <= ?", (now,))
        count = self._conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE key = ?", (key,)
        ).fetchone()[0]
        if count >= self.max_attempts:
            self._conn.execute(
                "INSERT INTO blocks (key, blocked_until) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET blocked_until = excluded.blocked_until",
                (key, now + self.cooldown_seconds),
            )
            security_logger.security(
                EventCode.RATE_LIMIT_TRIGGERED,
                "rate limit triggered - too many failed attempts",
                key=key,
                attempts=count,
                window_seconds=self.window_seconds,
                cooldown_seconds=self.cooldown_seconds,
            )
            self._conn.execute("DELETE FROM attempts WHERE key = ?", (key,))
        self._conn.commit()

    def record_success(self, key: str):
        self._conn.execute("DELETE FROM attempts WHERE key = ?", (key,))
        self._conn.execute("DELETE FROM blocks WHERE key = ?", (key,))
        self._conn.commit()

    def close(self):
        self._conn.close()
