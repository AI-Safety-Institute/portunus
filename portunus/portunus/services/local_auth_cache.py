"""In-process (L1) auth-result cache in front of Redis.

Every ext_authz ``Check`` used to cost one Redis GET. The set of live
(payload, target_host) keys at any moment is small — one per active principal
per provider — so a short per-process TTL removes almost all of that traffic:
Redis load becomes roughly ``distinct keys × tasks ÷ TTL`` instead of the
request rate.

Entries carry two deadlines:

* ``fresh_until`` — served without touching Redis until then (the L1 TTL).
* ``hard_expiry`` — never served past this; it is the credential expiry the
  Redis write is already bounded by, so L1 can never outlive the credentials
  it was authorised with.

Between the two an entry is *stale*: it is only served when the refresh path
(Redis) fails, so a Redis outage is invisible to principals already cached
here.

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
    hard_expiry: float


class LocalAuthCache:
    """Bounded LRU of successful auth results with a TTL and a stale window.

    Single event loop only (the gRPC.aio loop): no locks, and no ``await``
    separates a lookup from its use.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float,
        stale_seconds: float,
        max_entries: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialise the cache.

        Args:
            ttl_seconds: How long an entry is served without consulting Redis.
                ``0`` disables the cache entirely.
            stale_seconds: How long past ``ttl_seconds`` an entry may still be
                served when the Redis refresh fails.
            max_entries: LRU bound.
            clock: Monotonic clock, injectable for tests.
        """
        self.ttl_seconds = ttl_seconds
        self.stale_seconds = stale_seconds
        self.max_entries = max_entries
        self._clock = clock
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._inflight: dict[str, asyncio.Task[AuthResult]] = {}
        self.hits_total = 0
        self.stale_served_total = 0
        self.misses_total = 0
        self.coalesced_total = 0

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
        now = self._clock()
        if now >= entry.hard_expiry:
            del self._entries[key]
            return None
        if now >= entry.fresh_until:
            return None
        self._entries.move_to_end(key)
        self.hits_total += 1
        return entry.result

    def get_stale(self, key: str) -> Optional[AuthResult]:
        """Return the entry for ``key`` if it is past TTL but still servable.

        Only for the degraded path: call this after the Redis refresh failed.
        """
        entry = self._entries.get(key)
        if entry is None:
            return None
        now = self._clock()
        if now >= entry.hard_expiry or now >= entry.fresh_until + self.stale_seconds:
            del self._entries[key]
            return None
        self.stale_served_total += 1
        return entry.result

    def put(
        self, key: str, result: AuthResult, credential_ttl: Optional[float]
    ) -> None:
        """Store a successful result.

        Args:
            key: The same key Redis uses (``CacheService.generate_cache_key``).
            result: A successful ``AuthResult``.
            credential_ttl: Seconds until the underlying credentials expire,
                or ``None`` when they carry no expiry. ``<= 0`` is not stored.
        """
        if not self.enabled or not result.successful:
            return
        if credential_ttl is not None and credential_ttl <= 0:
            return
        now = self._clock()
        hard_expiry = (
            now + credential_ttl
            if credential_ttl is not None
            else now + self.ttl_seconds + self.stale_seconds
        )
        self._entries[key] = _Entry(
            result=result,
            fresh_until=min(now + self.ttl_seconds, hard_expiry),
            hard_expiry=hard_expiry,
        )
        self._entries.move_to_end(key)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def has_servable_entries(self) -> bool:
        """Whether any entry could be served right now (fresh or stale)."""
        now = self._clock()
        return any(
            now < e.hard_expiry and now < e.fresh_until + self.stale_seconds
            for e in self._entries.values()
        )

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
            self.misses_total += 1
            task = asyncio.ensure_future(loader())
            self._inflight[key] = task
            task.add_done_callback(lambda t: self._finish(key, t))
        else:
            self.coalesced_total += 1
        return await asyncio.shield(task)

    def _finish(self, key: str, task: asyncio.Task[AuthResult]) -> None:
        if self._inflight.get(key) is task:
            del self._inflight[key]
        # Mark the exception retrieved: if every waiter was cancelled nobody
        # else will, and asyncio would log "exception was never retrieved".
        if not task.cancelled():
            task.exception()
