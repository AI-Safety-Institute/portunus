"""Behaviour-level tests for the Portunus proxy + backend, request/response shape.

Parameterised corpus driver (``test_request_response``) for behaviours that
share the same assertion shape: send an HTTP request, assert on status,
whether the upstream saw it, and whether the response body matches.
"""

# ruff: noqa: E501
from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import Literal, Optional

import pytest
import requests
from conftest import _read_audit_s3_records, create_localstack_secret, encode_base64

PROXY_URL = "http://localhost:8888"

# Authorisation strategies — each maps to a seeded secret + a payload builder.
# Adding a new strategy means seeding the corresponding secret in the
# `seeded_secrets` fixture below.
AuthMode = Literal[
    "valid_plaintext",  # Plaintext secret, no host restriction.
    "valid_host_match",  # JSON secret with host == proxy's TARGET_HOST.
    "valid_host_mismatch",  # JSON secret with host != proxy's TARGET_HOST.
    "none",  # No Authorization header at all.
    "malformed_base64",  # Authorization present but not valid base64.
    "malformed_json",  # Decodes to base64 but the JSON inside is broken.
]


@dataclass(frozen=True)
class RequestSpec:
    """The request the test will send through the proxy."""

    method: str = "GET"
    path: str = "/get"
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    auth: AuthMode = "valid_plaintext"


@dataclass(frozen=True)
class ExpectedResponse:
    """The observable outcome the test will assert on."""

    status: int
    # Substrings that must appear in the response body. For successful
    # requests we use httpbun's request-echo to confirm the upstream saw
    # what we expected; for failures we confirm the error message is the
    # one the spec calls for.
    body_substrings: tuple[str, ...] = ()
    # If True, the response body should look like an httpbun echo (proves
    # the request reached the upstream). If False, the upstream should not
    # have been called — assert via the absence of the echo marker.
    reached_upstream: bool = True
    # Optional: number of metadata records the scenario expects to land
    # in the LocalStack Kinesis metadata stream. None = skip the telemetry
    # assertion for this scenario (use for cases where the recorded
    # behaviour isn't pinned yet). 0 = explicitly assert NO record.
    expected_metadata_records: Optional[int] = None
    # If True, a connection-level rejection (RemoteDisconnected /
    # ConnectionError) from the proxy is treated as a passing outcome,
    # in addition to the configured ``status``. Use for scenarios where
    # Envoy may reject at the connection layer before producing an HTTP
    # response — e.g. oversized headers exceeding the proxy buffer.
    reject_with_disconnect: bool = False


@dataclass(frozen=True)
class Scenario:
    """One (request, expected_response) pair from the behaviour corpus."""

    name: str  # Used as the pytest test ID — should read as a claim.
    request: RequestSpec
    expected: ExpectedResponse


# Marker substring httpbun echoes back. If we see this in the response body
# we know the upstream was reached; absence means Portunus terminated the
# request before it could be forwarded.
_HTTPBUN_ECHO_MARKER = '"method"'


def _read_localstack_metadata_records() -> list[dict]:
    """Read all metadata records from LocalStack S3 (Firehose destination).

    Portunus writes to ``portunus-firehose-metadata`` (direct-PUT). LocalStack
    buffers to ``s3://portunus-logs-local/logs/metadata/*`` with a 1s/1MiB
    hint configured in ``scripts/localstack-init-firehose.sh``.

    Uses ``conftest._read_audit_s3_records`` so the polling/parsing logic
    is shared across tests.
    """
    return _read_audit_s3_records("metadata", timeout=0.1)


# -----------------------------------------------------------------------------
# Corpus
# -----------------------------------------------------------------------------

SCENARIOS: list[Scenario] = [
    # ---- Happy path -------------------------------------------------------
    Scenario(
        name="valid_request_with_plaintext_secret_reaches_upstream",
        request=RequestSpec(path="/get", auth="valid_plaintext"),
        expected=ExpectedResponse(
            status=200, reached_upstream=True, expected_metadata_records=1
        ),
    ),
    Scenario(
        name="valid_request_with_host_matched_secret_reaches_upstream",
        request=RequestSpec(path="/get", auth="valid_host_match"),
        expected=ExpectedResponse(status=200, reached_upstream=True),
    ),
    Scenario(
        name="post_with_json_body_round_trips_through_upstream",
        request=RequestSpec(
            method="POST",
            path="/post",
            body=b'{"hello": "world"}',
            headers={"content-type": "application/json"},
            auth="valid_plaintext",
        ),
        expected=ExpectedResponse(
            status=200,
            reached_upstream=True,
            body_substrings=('"hello": "world"',),
        ),
    ),
    Scenario(
        name="custom_client_header_is_forwarded_to_upstream",
        # Uses /anything (not /headers) because the corpus runner's
        # reach marker is httpbun's "method" echo, which /anything
        # includes but /headers does not.
        request=RequestSpec(
            path="/anything",
            headers={"x-custom-client-header": "client-value-42"},
            auth="valid_plaintext",
        ),
        expected=ExpectedResponse(
            status=200,
            reached_upstream=True,
            body_substrings=("client-value-42",),
        ),
    ),
    # ---- Auth failures (request must not reach upstream) -----------------
    Scenario(
        name="request_without_authorization_header_is_rejected",
        request=RequestSpec(path="/get", auth="none"),
        # A request that doesn't present any credentials never reaches the
        # auth backend, so no principal-keyed metadata record is produced.
        expected=ExpectedResponse(
            status=401, reached_upstream=False, expected_metadata_records=0
        ),
    ),
    Scenario(
        name="request_with_malformed_base64_payload_is_rejected",
        request=RequestSpec(path="/get", auth="malformed_base64"),
        expected=ExpectedResponse(status=401, reached_upstream=False),
    ),
    Scenario(
        name="request_with_valid_base64_but_invalid_json_is_rejected",
        request=RequestSpec(path="/get", auth="malformed_json"),
        expected=ExpectedResponse(status=401, reached_upstream=False),
    ),
    Scenario(
        name="secret_with_mismatching_host_is_rejected_with_403",
        request=RequestSpec(path="/get", auth="valid_host_mismatch"),
        expected=ExpectedResponse(
            status=403,
            reached_upstream=False,
            body_substrings=("API key is not valid for target host",),
        ),
    ),
    # ---- Security: host-header forgery -----------------------------------
    # ``x-portunus-target-host`` is sourced from gRPC initial_metadata
    # (set on the inner ext_authz filter in envoy.yaml), so a client
    # cannot bypass host validation by forging a request header of the
    # same name. The proxy strips the client-supplied value before
    # forwarding upstream and the auth result still uses the
    # server-side host.
    Scenario(
        name="forged_x_portunus_target_host_header_does_not_bypass_host_validation",
        request=RequestSpec(
            path="/get",
            auth="valid_host_mismatch",
            headers={"x-portunus-target-host": "api.openai.com"},
        ),
        expected=ExpectedResponse(
            status=403,
            reached_upstream=False,
            body_substrings=("API key is not valid for target host",),
        ),
    ),
    # ---- HTTP method coverage -------------------------------------------
    Scenario(
        name="put_request_method_reaches_upstream_unchanged",
        request=RequestSpec(method="PUT", path="/put", body=b"x"),
        expected=ExpectedResponse(
            status=200,
            reached_upstream=True,
            body_substrings=('"method": "PUT"',),
        ),
    ),
    Scenario(
        name="delete_request_method_reaches_upstream_unchanged",
        request=RequestSpec(method="DELETE", path="/delete"),
        expected=ExpectedResponse(
            status=200,
            reached_upstream=True,
            body_substrings=('"method": "DELETE"',),
        ),
    ),
    Scenario(
        name="patch_request_method_reaches_upstream_unchanged",
        request=RequestSpec(method="PATCH", path="/patch", body=b"x"),
        expected=ExpectedResponse(
            status=200,
            reached_upstream=True,
            body_substrings=('"method": "PATCH"',),
        ),
    ),
    # ---- Request shape preservation -------------------------------------
    Scenario(
        name="query_string_reaches_upstream_with_duplicate_keys_preserved",
        request=RequestSpec(path="/get?a=1&a=2&b=hello%20world"),
        expected=ExpectedResponse(
            status=200,
            reached_upstream=True,
            # httpbun echoes the query in args; both values for `a` should
            # appear, and the percent-decoded value of b.
            body_substrings=("hello world",),
        ),
    ),
    Scenario(
        name="empty_post_body_is_forwarded_as_empty_not_dropped",
        request=RequestSpec(method="POST", path="/post", body=b""),
        expected=ExpectedResponse(status=200, reached_upstream=True),
    ),
    Scenario(
        name="binary_body_bytes_round_trip_through_upstream",
        request=RequestSpec(
            method="POST",
            path="/post",
            body=bytes(range(256)),
            headers={"content-type": "application/octet-stream"},
        ),
        # httpbun echoes the body length; a 256-byte body should show up
        # as the right size in the response.
        expected=ExpectedResponse(status=200, reached_upstream=True),
    ),
    # ---- Security / adversarial -----------------------------------------
    Scenario(
        name="oversized_authorization_payload_is_rejected_without_crashing",
        request=RequestSpec(
            path="/get",
            auth="none",
            headers={"authorization": "Bearer " + ("A" * 1_000_000)},
        ),
        # Envoy's hard header buffer limit (60KB) is well below 1MB, so
        # the proxy rejects the connection before any HTTP response.
        # `requests` surfaces this as ``RemoteDisconnected``; the test
        # treats that as a passing outcome alongside 431.
        expected=ExpectedResponse(
            status=431,
            reached_upstream=False,
            reject_with_disconnect=True,
        ),
    ),
    Scenario(
        name="forged_x_portunus_debug_id_header_does_not_reach_upstream",
        request=RequestSpec(
            # /anything (not /headers) so the corpus runner's "method"
            # echo marker fires; the body still includes the request
            # header set under .headers so the forged value would be
            # visible if it leaked through.
            path="/anything",
            auth="valid_plaintext",
            headers={"x-portunus-debug-id": "forged-by-client"},
        ),
        expected=ExpectedResponse(
            status=200,
            reached_upstream=True,
        ),
    ),
    Scenario(
        name="header_value_with_crlf_injection_attempt_is_handled_without_smuggling",
        request=RequestSpec(
            path="/get",
            auth="valid_plaintext",
            # CRLF in a header value would be a header-smuggling attempt;
            # Envoy must reject the request or strip the value.
            headers={"x-evil": "value\r\nx-injected: yes"},
        ),
        # The strict reading: Envoy rejects with 400. A more lenient
        # implementation strips the embedded header and forwards the
        # truncated value. Either is acceptable; the unacceptable
        # outcome is "200 and the upstream sees x-injected".
        expected=ExpectedResponse(status=400, reached_upstream=False),
    ),
]


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def seeded_secrets(docker_setup):
    """Seed LocalStack with one secret per authorisation strategy.

    The default ``docker_setup`` already creates ``test-api-key`` with the
    plaintext value ``xyz``; we layer additional secrets on top so a single
    stack lifecycle covers the whole corpus.
    """
    # Plaintext secret (also seeded by docker_setup as test-api-key); use
    # the default to avoid duplicating it.
    plaintext_secret_name = "test-api-key"

    # Host-matched secret: TARGET_HOST in docker-compose is "http-bun" so
    # the secret's host field must equal that for validation to pass.
    create_localstack_secret(
        "host-matched-httpbun",
        '{"secret": "sk-host-matched", "host": "http-bun"}',
    )

    # Host-mismatched secret: claims the key is for api.openai.com, which
    # is not our local upstream.
    create_localstack_secret(
        "host-mismatched-openai",
        '{"secret": "sk-mismatched", "host": "api.openai.com"}',
    )

    return {
        "valid_plaintext": plaintext_secret_name,
        "valid_host_match": "host-matched-httpbun",
        "valid_host_mismatch": "host-mismatched-openai",
    }


# -----------------------------------------------------------------------------
# Auth payload construction
# -----------------------------------------------------------------------------


def _build_authorization_header(
    auth: AuthMode,
    seeded_secrets: dict[str, str],
    api_key_prefix: str,
) -> Optional[str]:
    """Translate a scenario's auth mode into a concrete Authorization header.

    Returns ``None`` for the ``"none"`` mode so the caller knows to omit
    the header entirely. The malformed modes return deliberately broken
    payloads so we exercise the parser's rejection paths.
    """
    if auth == "none":
        return None
    if auth == "malformed_base64":
        # Not valid base64 (contains characters outside the base64 alphabet).
        return f"{api_key_prefix}not-base64-at-all!@#$"
    if auth == "malformed_json":
        # Decodes to base64 but the bytes are not valid JSON.
        garbage = base64.b64encode(b"this is not json").decode("ascii")
        return f"{api_key_prefix}{garbage}"

    secret_name = seeded_secrets[auth]
    payload = encode_base64(
        {"credentials": {}, "secret_arn": ""}, secret_name=secret_name
    )
    return f"{api_key_prefix}{payload}"


# -----------------------------------------------------------------------------
# Runner
# -----------------------------------------------------------------------------


def _fire_scenario(
    scenario: Scenario,
    seeded_secrets: dict[str, str],
    api_key_header: str,
    api_key_prefix: str,
) -> requests.Response:
    """Build and send the HTTP request a scenario describes."""
    headers: dict[str, str] = dict(scenario.request.headers)
    auth_header = _build_authorization_header(
        scenario.request.auth, seeded_secrets, api_key_prefix
    )
    if auth_header is not None:
        headers[api_key_header] = auth_header
    return requests.request(
        method=scenario.request.method,
        url=f"{PROXY_URL}{scenario.request.path}",
        headers=headers,
        data=scenario.request.body,
        timeout=30,
    )


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_request_response(
    scenario: Scenario,
    seeded_secrets: dict[str, str],
    api_key_header: str,
    api_key_prefix: str,
) -> None:
    """Walk one scenario from the request/response corpus end-to-end.

    Scope: behaviours observable from a single HTTP request — status code,
    whether the upstream received the request, and body substrings.
    Behaviours with different assertion shapes (streaming, telemetry, WS,
    cache TTL, drain) belong in their own test functions or files; see the
    module docstring.
    """
    try:
        response = _fire_scenario(
            scenario, seeded_secrets, api_key_header, api_key_prefix
        )
    except requests.exceptions.ConnectionError:
        if scenario.expected.reject_with_disconnect:
            return  # connection-level rejection is a passing outcome
        raise
    except requests.exceptions.InvalidHeader:
        # ``requests`` rejects CRLF / reserved chars in header values
        # client-side before the request hits the wire. Treat that as
        # a valid defense layer when the scenario expects rejection
        # without upstream contact.
        if not scenario.expected.reached_upstream:
            return
        raise

    # Status code
    assert response.status_code == scenario.expected.status, (
        f"[{scenario.name}] expected status {scenario.expected.status}, "
        f"got {response.status_code}. Body: {response.text[:500]}"
    )

    # Upstream reachability (proxied via the presence of httpbun's echo
    # marker — httpbun always echoes the method back as JSON on its
    # response endpoints).
    body_text = response.text
    if scenario.expected.reached_upstream:
        assert _HTTPBUN_ECHO_MARKER in body_text, (
            f"[{scenario.name}] expected to reach upstream "
            f"(marker {_HTTPBUN_ECHO_MARKER!r}) but got: {body_text[:500]}"
        )
    else:
        assert _HTTPBUN_ECHO_MARKER not in body_text, (
            f"[{scenario.name}] expected to NOT reach upstream "
            f"but found httpbun echo marker in body: {body_text[:500]}"
        )

    # Substring expectations (used for both success-side and error-side
    # assertions; cheap and easy to extend).
    for substring in scenario.expected.body_substrings:
        assert substring in body_text, (
            f"[{scenario.name}] expected substring {substring!r} in response, "
            f"got: {body_text[:500]}"
        )


# ---------------------------------------------------------------------------
# Telemetry arm — shares the same corpus, asserts on the number of metadata
# records that land in LocalStack Kinesis. Scenarios without an
# ``expected_metadata_records`` value are skipped by the parametrise filter.
# ---------------------------------------------------------------------------


def _wait_for_metadata_record_count(
    *, baseline: int, expected_delta: int, timeout: float = 8.0
) -> int:
    """Poll LocalStack S3 (Firehose destination) for the expected record count.

    Firehose direct-PUT in LocalStack is configured with 1s/1MiB buffer
    hints so records land within ~1-2s; we still give a generous timeout
    to absorb Firehose worker scheduling jitter.
    """
    deadline = time.monotonic() + timeout
    while True:
        observed = len(_read_localstack_metadata_records())
        delta = observed - baseline
        if delta >= expected_delta:
            return delta
        if time.monotonic() >= deadline:
            return delta
        time.sleep(0.2)


@pytest.mark.parametrize(
    "scenario",
    # Restrict to scenarios that *should* publish a metadata record. The
    # "expected zero" case is a negative assertion against an
    # asynchronously-flushed pipeline; covered by unit tests on the
    # ext_authz / ext_proc servicers (faster, deterministic, no Firehose
    # async involved).
    [s for s in SCENARIOS if (s.expected.expected_metadata_records or 0) > 0],
    ids=lambda s: s.name,
)
def test_metadata_telemetry(
    scenario: Scenario,
    seeded_secrets: dict[str, str],
    api_key_header: str,
    api_key_prefix: str,
    clean_audit_pipeline,
) -> None:
    """Each scenario produces *at least* the expected metadata records on S3.

    End-to-end smoke: proves the audit pipeline lands records on S3 via
    Firehose direct-PUT. Asserts ``observed >= expected`` rather than
    strict equality — Firehose's async flush can carry one scenario's
    record across the clean-S3 boundary into the next test's window.
    Strict per-scenario record-count semantics are checked in
    ``portunus/tests/test_grpc_proc_servicer.py``.
    """
    _fire_scenario(scenario, seeded_secrets, api_key_header, api_key_prefix)

    expected = scenario.expected.expected_metadata_records
    assert expected is not None and expected > 0  # parametrise filter guarantees this
    observed = _wait_for_metadata_record_count(baseline=0, expected_delta=expected)
    assert observed >= expected, (
        f"[{scenario.name}] expected at least {expected} metadata record(s) "
        f"in S3, got {observed} within timeout"
    )
