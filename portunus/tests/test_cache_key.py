"""Tests for the auth-cache key structure + host normalisation (security F4).

The previous key was ``sha256(f"{host or ''}:{payload}")`` — an unescaped
``:`` delimiter, so ``(host="a:b", payload="c")`` and
``(host="a", payload="b:c")`` hashed identically. The new scheme hashes the
components independently (structure-proof) and normalises the host
(lower-case, default ``:443`` stripped) so equivalent hosts share one entry.

The fail-closed miss-path recheck (``validate_and_extract_api_key``) applies
the SAME normalisation, so a cache hit can never admit a host variant the
validator would reject.
"""

import json

import pytest

from portunus.exceptions import AuthenticationError
from portunus.services.auth_service import validate_and_extract_api_key
from portunus.services.cache_service import CacheService, normalise_target_host


@pytest.fixture
def cache() -> CacheService:
    return CacheService()


class TestNormaliseTargetHost:
    def test_none_and_empty_pass_through(self):
        assert normalise_target_host(None) is None
        assert normalise_target_host("") == ""

    def test_lowercases_and_strips_default_https_port(self):
        assert normalise_target_host("API.Anthropic.COM") == "api.anthropic.com"
        assert normalise_target_host("api.anthropic.com:443") == "api.anthropic.com"
        assert normalise_target_host(" API.Host:443 ") == "api.host"

    def test_non_default_ports_are_preserved(self):
        assert normalise_target_host("api.host:8443") == "api.host:8443"
        assert normalise_target_host("api.host:80") == "api.host:80"


class TestGenerateCacheKey:
    def test_delimiter_shift_collision_is_gone(self, cache):
        """(host='a:b', payload='c') must not collide with (host='a', 'b:c')."""
        assert cache.generate_cache_key("c", "a:b") != cache.generate_cache_key(
            "b:c", "a"
        )

    def test_host_scoping_still_distinguishes(self, cache):
        payload = "payload-xyz"
        key_a = cache.generate_cache_key(payload, "api.openai.com")
        key_b = cache.generate_cache_key(payload, "api.anthropic.com")
        key_none = cache.generate_cache_key(payload, None)
        assert len({key_a, key_b, key_none}) == 3

    def test_equivalent_hosts_share_one_entry(self, cache):
        payload = "payload-xyz"
        canonical = cache.generate_cache_key(payload, "api.anthropic.com")
        assert cache.generate_cache_key(payload, "API.Anthropic.COM") == canonical
        assert cache.generate_cache_key(payload, "api.anthropic.com:443") == canonical

    def test_non_default_port_is_a_distinct_entry(self, cache):
        payload = "payload-xyz"
        assert cache.generate_cache_key(
            payload, "api.anthropic.com:8443"
        ) != cache.generate_cache_key(payload, "api.anthropic.com")

    def test_none_and_empty_host_share_the_unrestricted_entry(self, cache):
        payload = "payload-xyz"
        assert cache.generate_cache_key(payload, None) == cache.generate_cache_key(
            payload, ""
        )


class TestHostRestrictionRecheckStaysFailClosed:
    """The miss-path recheck and the cache key must accept the same hosts."""

    SECRET = json.dumps({"secret": "sk-real", "host": "api.anthropic.com"})

    def test_exact_host_passes(self):
        api_key, signing_key = validate_and_extract_api_key(
            self.SECRET, "api.anthropic.com"
        )
        assert api_key == "sk-real"
        assert signing_key is None

    @pytest.mark.parametrize(
        "variant",
        ["API.Anthropic.COM", "api.anthropic.com:443", "API.ANTHROPIC.COM:443"],
    )
    def test_equivalent_host_variants_pass(self, variant):
        """Variants that share the cache entry also pass the recheck."""
        api_key, _ = validate_and_extract_api_key(self.SECRET, variant)
        assert api_key == "sk-real"

    @pytest.mark.parametrize(
        "bad_host", ["evil.example.com", "api.anthropic.com.evil.com",
                     "api.anthropic.com:8443"]
    )
    def test_non_equivalent_host_fails_closed(self, bad_host):
        with pytest.raises(AuthenticationError):
            validate_and_extract_api_key(self.SECRET, bad_host)

    def test_missing_target_host_fails_closed(self):
        with pytest.raises(AuthenticationError):
            validate_and_extract_api_key(self.SECRET, None)

    def test_normalised_secret_host_also_matches(self):
        """Normalisation applies to the secret's host side too."""
        secret = json.dumps({"secret": "sk-real", "host": "API.Anthropic.COM:443"})
        api_key, _ = validate_and_extract_api_key(secret, "api.anthropic.com")
        assert api_key == "sk-real"

    def test_cache_key_and_recheck_agree(self):
        """Cache-entry sharing and validation accept the same host set.

        Any host sharing the secret-host cache entry passes validation; any
        host with a different cache entry is denied — the invariant that
        keeps normalised cache hits fail-closed.
        """
        cache_service = CacheService()
        payload = "bearer-payload"
        canonical_key = cache_service.generate_cache_key(payload, "api.anthropic.com")
        for host in [
            "api.anthropic.com",
            "API.Anthropic.COM",
            "api.anthropic.com:443",
            "api.anthropic.com:8443",
            "evil.example.com",
        ]:
            shares_entry = (
                cache_service.generate_cache_key(payload, host) == canonical_key
            )
            try:
                validate_and_extract_api_key(self.SECRET, host)
                validated = True
            except AuthenticationError:
                validated = False
            assert shares_entry == validated, host
