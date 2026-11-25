"""Server-Sent Events parsing (WHATWG HTML §9.2.6) and reconnect policy."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Any

__all__ = ["ReconnectPolicy", "SSEEvent", "SSEParser", "SESSION_EVENTS"]

#: Events after which the SDK re-validates the login with a refresh.
SESSION_EVENTS = frozenset({"user.password_changed", "user.disabled", "user.deleted", "consent.revoked"})


@dataclass(frozen=True)
class SSEEvent:
    event: str
    data: str
    id: str | None = None
    retry: int | None = None

    def json(self) -> Any:
        """Decoded ``data`` (``{}`` when empty)."""
        return json.loads(self.data) if self.data else {}


class SSEParser:
    """Incremental parser: feed text chunks, get complete events back.

    Handles ``\\n``, ``\\r\\n`` and ``\\r`` line endings split across chunks,
    multi-line ``data:``, ``id:``, ``event:``, ``retry:`` and ignores comment
    lines such as ``: ping``. ``last_event_id`` and ``retry`` persist across
    events as the specification requires.
    """

    def __init__(self) -> None:
        self._buf = ""
        self._data: list[str] = []
        self._event = ""
        self._has_fields = False
        self.last_event_id: str | None = None
        self.retry: int | None = None
        self._pending_cr = False
        self._first = True

    def feed(self, chunk: str) -> list[SSEEvent]:
        if self._first and chunk:
            if chunk.startswith("﻿"):
                chunk = chunk[1:]
            self._first = False
        if self._pending_cr:
            if chunk.startswith("\n"):
                chunk = chunk[1:]
            self._pending_cr = False
        self._buf += chunk
        out: list[SSEEvent] = []
        while True:
            idx_n = self._buf.find("\n")
            idx_r = self._buf.find("\r")
            if idx_n < 0 and idx_r < 0:
                break
            if idx_r >= 0 and (idx_n < 0 or idx_r < idx_n):
                line = self._buf[:idx_r]
                rest = self._buf[idx_r + 1 :]
                if rest.startswith("\n"):
                    rest = rest[1:]
                elif rest == "":
                    self._pending_cr = True  # a following "\n" belongs to this CR
                self._buf = rest
            else:
                line = self._buf[:idx_n]
                self._buf = self._buf[idx_n + 1 :]
            ev = self._line(line)
            if ev is not None:
                out.append(ev)
        return out

    def _line(self, line: str) -> SSEEvent | None:
        if line == "":
            return self._dispatch()
        if line.startswith(":"):
            return None
        name, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if name == "data":
            self._data.append(value)
            self._has_fields = True
        elif name == "event":
            self._event = value
            self._has_fields = True
        elif name == "id":
            if "\x00" not in value:
                self.last_event_id = value
            self._has_fields = True
        elif name == "retry":
            if value.isdigit():
                self.retry = int(value)
        return None

    def _dispatch(self) -> SSEEvent | None:
        if not self._data and not self._has_fields:
            self._event = ""
            return None
        if not self._data:
            # id-only / event-only blocks update state but dispatch nothing.
            self._event = ""
            self._has_fields = False
            return None
        ev = SSEEvent(event=self._event or "message", data="\n".join(self._data), id=self.last_event_id, retry=self.retry)
        self._data = []
        self._event = ""
        self._has_fields = False
        return ev


class ReconnectPolicy:
    """Reconnect delays: server ``retry:`` (else 3–8 s) plus jitter, with exponential backoff on repeated failures."""

    def __init__(self, base_min: float = 3.0, base_max: float = 8.0, max_delay: float = 60.0, jitter: float = 1.0) -> None:
        self.base_min = base_min
        self.base_max = base_max
        self.max_delay = max_delay
        self.jitter = jitter
        self.failures = 0

    def delay(self, retry_ms: int | None) -> float:
        base = retry_ms / 1000.0 if retry_ms is not None else random.uniform(self.base_min, self.base_max)
        backoff = base * (2 ** min(self.failures, 6)) if self.failures else base
        return min(backoff, self.max_delay) + random.uniform(0, self.jitter)

    def success(self) -> None:
        self.failures = 0

    def failure(self) -> None:
        self.failures += 1
