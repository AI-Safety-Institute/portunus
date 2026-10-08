"""In-process (L1) auth-result cache in front of Redis.

Every ext_authz ``Check`` used to cost one Redis GET. The set of live
(payload, target_host) keys at any moment is small — one per active principal
per provider — so a short per-process TTL removes almost all of that traffic:
Redis load becomes roughly ``distinct keys × tasks ÷ TTL`` instead of the
request rate.

Each entry is served without touching Redis until the earlier of the L1 TTL
and the lifetime the Redis write is bounded by (``AuthService._cache_ttl``:
cache duration, credential expiry, minted-token expiry). Past that it is
dropped, never served: when the Redis refresh then fails, the request is
handled exactly as if L1 were not there.

``get_or_load`` coalesces concurrent misses for one key onto a single loader
("single-flight"), so a cold start or an L1 expiry costs one Redis read per
key per process rather than one per in-flight request.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Optional

from portunus.models import AuthResult


@dataclass(frozen=True, slots=True)
class _Entry:
    result: AuthResult
    fresh_until: float


class LocalAuthCache:
    """Bounded LRU of successful auth results with a TTL.

    Single event loop only (the gRPC.aio loop): no locks, and no ``await``
    separates a lookup from its use.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float,
        max_entries: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialise the cache.

        Args:
            ttl_seconds: How long an entry is served without consulting Redis.
                ``0`` disables the cache entirely.
            max_entries: LRU bound.
            clock: Monotonic clock, injectable for tests.
        """
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._clock = clock
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._inflight: dict[str, asyncio.Task[AuthResult]] = {}

    @property
    def enabled(self) -> bool:
        """Whether the cache stores anything at all."""
        return self.ttl_seconds > 0 and self.max_entries > 0

    def __len__(self) -> int:
        return len(self._entries)

    def get_fresh(self, key: str) -> Optional[AuthResult]:
        """Return the entry for ``key`` if it is inside its TTL."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        if self._clock() >= entry.fresh_until:
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return entry.result

    def put(
        self, key: str, result: AuthResult, credential_ttl: Optional[float]
    ) -> None:
        """Store a successful result.

        Args:
            key: The same key Redis uses (``CacheService.generate_cache_key``).
            result: A successful ``AuthResult``.
            credential_ttl: Seconds the result may be cached at all (the bound
                the Redis write uses), or ``None`` when there is none; the
                entry lives for the shorter of this and ``ttl_seconds``.
                ``<= 0`` is not stored.
        """
        if not self.enabled or not result.successful:
            return
        if credential_ttl is not None and credential_ttl <= 0:
            return
        lifetime = (
            self.ttl_seconds
            if credential_ttl is None
            else min(self.ttl_seconds, credential_ttl)
        )
        self._entries[key] = _Entry(result=result, fresh_until=self._clock() + lifetime)
        self._entries.move_to_end(key)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def clear(self) -> None:
        """Drop every entry (in-flight loads are left to finish)."""
        self._entries.clear()

    async def get_or_load(
        self, key: str, loader: Callable[[], Awaitable[AuthResult]]
    ) -> AuthResult:
        """Return a fresh entry, else run ``loader`` once per key concurrently.

        The loader runs in its own task and each caller awaits it through
        ``asyncio.shield``: a caller whose Check is cancelled (client gone,
        auth deadline) neither cancels the shared load nor poisons the other
        waiters with ``CancelledError``. The loader is responsible for
        calling :meth:`put`.
        """
        cached = self.get_fresh(key)
        if cached is not None:
            return cached

        task = self._inflight.get(key)
        if task is None:
            task = asyncio.ensure_future(loader())
            self._inflight[key] = task
            task.add_done_callback(lambda t: self._finish(key, t))
        return await asyncio.shield(task)

    def _finish(self, key: str, task: asyncio.Task[AuthResult]) -> None:
        if self._inflight.get(key) is task:
            del self._inflight[key]
        # Mark the exception retrieved: if every waiter was cancelled nobody
        # else will, and asyncio would log "exception was never retrieved".
        if not task.cancelled():
            task.exception()
