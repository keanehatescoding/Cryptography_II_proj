"""
audit_log.py
------------
Structured security-event logging for the secure communication library.

Design:
  - A custom SECURITY level (35 - between WARNING=30 and ERROR=40) is used
    for events that are security-relevant but not necessarily application
    errors: a rejected replay, a failed signature check, a rekey. These are
    exactly the events a real deployment would want to alert on or feed into
    a SIEM, distinct from ordinary debug/info noise.
  - This module (a *library* module) NEVER calls logging.basicConfig() or
    attaches handlers itself. Library code should only call logger.log(...);
    configuring *where logs go* (file, stdout, syslog) is the application's
    decision, made once at process startup via configure_logging(). This
    avoids the classic bug of a library silently duplicating or hijacking a
    host application's logging config.
  - Log records are emitted as single-line JSON so they're greppable and
    machine-parseable without a special log-shipping parser.

Usage in library code (handshake.py, secure_channel.py, ...):

    from audit_log import security_logger, EventCode

    security_logger.security(
        EventCode.HANDSHAKE_SIG_FAIL,
        "signature verification failed",
        peer_name=msg2.name,
    )

Usage in an application entry point (main.py / gui.py), once at startup:

    from audit_log import configure_logging
    configure_logging(logfile="secure_comms_audit.log")
"""

from __future__ import annotations

import json
import logging
import sys
import time
from enum import Enum
from typing import Any

SECURITY_LEVEL = 35
logging.addLevelName(SECURITY_LEVEL, "SECURITY")


class EventCode(str, Enum):
    """Stable, greppable identifiers for security-relevant events.

    Keep these stable once used in a real deployment - they're the thing
    a downstream alert rule or dashboard would match against, and renaming
    one silently breaks that rule.
    """

    # Handshake
    HANDSHAKE_STARTED = "handshake_started"
    HANDSHAKE_COMPLETED = "handshake_completed"
    HANDSHAKE_UNKNOWN_IDENTITY = "handshake_unknown_identity"
    HANDSHAKE_SIG_FAIL = "handshake_signature_failed"
    HANDSHAKE_MALFORMED = "handshake_malformed_message"

    # Trust store / TOFU
    IDENTITY_PINNED = "identity_pinned"
    IDENTITY_MISMATCH = "identity_mismatch"

    # Channel
    REKEY_PERFORMED = "rekey_performed"
    REPLAY_REJECTED = "replay_rejected"
    TAMPER_DETECTED = "tamper_detected"
    CHAIN_DESYNC = "chain_desync"

    # Rate limiting
    RATE_LIMIT_TRIGGERED = "rate_limit_triggered"

    # Transport / framing
    FRAME_OVERSIZE_REJECTED = "frame_oversize_rejected"
    FRAME_MALFORMED = "frame_malformed"


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "event": getattr(record, "event_code", record.getMessage()),
            "msg": record.getMessage(),
        }
        extra = getattr(record, "event_context", None)
        if extra:
            payload["context"] = extra
        return json.dumps(payload, sort_keys=True)


class SecurityLogger(logging.LoggerAdapter):
    """Thin wrapper exposing a `.security(event_code, msg, **context)` call
    so call sites read as structured events rather than free-text strings."""

    def security(self, event: EventCode, msg: str, **context: Any) -> None:
        self.logger.log(
            SECURITY_LEVEL,
            msg,
            extra={"event_code": event.value, "event_context": context},
        )


# Library-wide logger instance. Library modules import and use this directly;
# it emits no output at all until an application calls configure_logging().
_logger = logging.getLogger("secure_comms.audit")
_logger.addHandler(logging.NullHandler())
security_logger = SecurityLogger(_logger, {})


def configure_logging(
    logfile: str | None = None,
    level: int = SECURITY_LEVEL,
    also_stderr: bool = True,
) -> None:
    """Call ONCE, from an application entry point (main.py / gui.py) - never
    from a library module. Attaches real handlers to the audit logger."""
    _logger.handlers.clear()
    _logger.setLevel(level)
    _logger.propagate = False

    formatter = _JsonFormatter()

    if logfile:
        file_handler = logging.FileHandler(logfile)
        file_handler.setFormatter(formatter)
        _logger.addHandler(file_handler)

    if also_stderr or not logfile:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        _logger.addHandler(stream_handler)
