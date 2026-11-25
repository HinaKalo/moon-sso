"""Framework adapters. Import the one you need; each imports its framework lazily:

* :mod:`moon_sso.contrib.fastapi` — ``pip install "moon_sso[fastapi]"``
* :mod:`moon_sso.contrib.flask` — ``pip install "moon_sso[flask]"``
* :mod:`moon_sso.contrib.django` — ``pip install "moon_sso[django]"``
"""

from ._web import MemorySessionStore, SessionStore, WebUser, is_htmx, safe_return_to

__all__ = ["MemorySessionStore", "SessionStore", "WebUser", "is_htmx", "safe_return_to"]
