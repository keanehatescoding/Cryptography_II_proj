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

import time
from collections import defaultdict, deque

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
