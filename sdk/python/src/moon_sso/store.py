"""Token storage interfaces.

A store holds one login's :class:`~moon_sso.models.TokenSet`. Refresh tokens
rotate on every use, so ``save`` must persist atomically and immediately.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Callable, Protocol, runtime_checkable

from .models import TokenSet

__all__ = ["AsyncTokenStore", "CallbackTokenStore", "FileTokenStore", "MemoryTokenStore", "TokenStore"]


@runtime_checkable
class TokenStore(Protocol):
    def load(self) -> TokenSet | None: ...

    def save(self, tokens: TokenSet) -> None: ...

    def clear(self) -> None: ...


@runtime_checkable
class AsyncTokenStore(Protocol):
    async def load(self) -> TokenSet | None: ...

    async def save(self, tokens: TokenSet) -> None: ...

    async def clear(self) -> None: ...


class MemoryTokenStore:
    """Process-local store (the default)."""

    def __init__(self, tokens: TokenSet | None = None) -> None:
        self._tokens = tokens
        self._lock = threading.Lock()

    def load(self) -> TokenSet | None:
        with self._lock:
            return self._tokens

    def save(self, tokens: TokenSet) -> None:
        with self._lock:
            self._tokens = tokens

    def clear(self) -> None:
        with self._lock:
            self._tokens = None


class CallbackTokenStore:
    """Adapts three callables (e.g. reading/writing a web framework session)."""

    def __init__(
        self,
        load: Callable[[], TokenSet | None],
        save: Callable[[TokenSet], None],
        clear: Callable[[], None],
    ) -> None:
        self._load, self._save, self._clear = load, save, clear

    def load(self) -> TokenSet | None:
        return self._load()

    def save(self, tokens: TokenSet) -> None:
        self._save(tokens)

    def clear(self) -> None:
        self._clear()


class FileTokenStore:
    """JSON file store for scripts and CLIs.

    The file is replaced atomically and created with ``0600`` permissions on
    POSIX. It is **not** encrypted; desktop applications should prefer the
    operating system's secret store.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = os.fspath(path)
        self._lock = threading.Lock()

    def load(self) -> TokenSet | None:
        with self._lock:
            try:
                with open(self.path, encoding="utf-8") as fh:
                    return TokenSet.from_dict(json.load(fh))
            except FileNotFoundError:
                return None
            except (ValueError, KeyError, TypeError):
                return None

    def save(self, tokens: TokenSet) -> None:
        with self._lock:
            directory = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".moon-sso-", dir=directory)
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(tokens.to_dict(), fh)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

    def clear(self) -> None:
        with self._lock:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass

