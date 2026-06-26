"""
Main FastAPI application for the Portunus.

This module defines the FastAPI application and API endpoints for the Portunus.
It implements the authentication logic and log event publishing to Firehose.
"""

import asyncio
import logging
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from typing import Optional

# aws_xray_sdk.core is imported via XRayService
from aws_xray_sdk.core.utils import stacktrace
from fastapi import APIRouter, FastAPI, Request, Response, WebSocket
from pydantic import BaseModel, ValidationError

from portunus.config import config  # noqa: E402 — also used by XRayService
from portunus.exceptions import (
    AuthenticationError,
    CredentialsError,
    FetchSecretError,
    PayloadError,
)
from portunus.logging import LoggingMiddleware
from portunus.models import (
    AuthPayload,
    HeadersPayload,
    TrailersPayload,
)
from portunus.relay import WsCloseCode
from portunus.relay.handler import handle_ws_connection
from portunus.relay.logger import start_log_queue, stop_log_queue
from portunus.services.auth_service import AuthService
from portunus.services.cache_service import CacheService
from portunus.services.publish_service import PublishService
from portunus.services.signing_service import (
    SignableRequest,
    SignatureHeaders,
    sign_request,
)
from portunus.services.state_service import StateService
from portunus.services.xray_service import XRayService
from portunus.util import (
    chunk_body_data,
    generate_iso_timestamp,
)

logger = logging.getLogger("api.access")

# Initialize services
state_service = StateService()
cache_service = CacheService(state_service=state_service)
publish_service = PublishService(state_service=state_service)
auth_service = AuthService(cache_service=cache_service)
xray_service = XRayService()

common_router = APIRouter()
portunus_router = APIRouter()

# Count of audit records that failed to publish, keyed by "<record_type>:<reason>".
# Audit publishing is intentionally non-blocking, so a drop is surfaced here
# (rather than by failing the customer-facing request) and via an alarmable log.
audit_publish_failures: Counter = Counter()


def _record_audit_drop(record_type: str, reason: str, trace_id: str) -> None:
    """Record an audit-publish drop/failure so it is observable, not silent.

    Increments an in-process counter and logs at CRITICAL with a stable
    ``AUDIT_PUBLISH_DROPPED`` marker, so a CloudWatch Logs metric filter can
    alarm on it. Does not change the HTTP status returned to the caller — audit
    is non-blocking, so customer latency/status stays decoupled from the sink.

    Args:
        record_type: Audit record type that was dropped (e.g. ``"metadata"``).
        reason: Why it was dropped (``"stream_unconfigured"``, ``"publish_error"``
            or ``"publish_timeout"``).
        trace_id: Request/trace ID for correlation.
    """
    audit_publish_failures[f"{record_type}:{reason}"] += 1
    logger.critical(
        f"AUDIT_PUBLISH_DROPPED record_type={record_type} reason={reason} "
        f"request_id={trace_id}"
    )


class ErrorResponse(BaseModel):
    """Error response model for API endpoints.

    Attributes:
        message: Error message describing what went wrong
        debug_id: Debug/trace ID for correlation and troubleshooting
    """

    message: str
    debug_id: str


class AuthorizationResponse(BaseModel):
    """Successful authorization response model.

    Attributes:
        api_key: The API key to use for upstream requests
        request_id: Unique request ID for correlation
    """

    api_key: str
    request_id: str
    signature: Optional[str] = None
    signature_input: Optional[str] = None


@portunus_router.post("/authorise")
async def authorise(
    request: Request,
    response: Response,
) -> AuthorizationResponse | ErrorResponse:
    """
    Authorize a request by validating credentials and returning an API key.

    This endpoint receives a base64-encoded payload containing AWS credentials and a
    secret ARN. It validates the credentials, checks the identity of the caller, and
    retrieves the requested API key from AWS Secrets Manager. The retrieved API key is
    then returned to the proxy, which uses it to replace the original authorization
    header.

    The endpoint first checks Redis cache to see if this exact payload has been
    authorized before, to avoid unnecessary AWS API calls.

    Args:
        request: The FastAPI request object
        response: The FastAPI response object for setting status codes
        segment: The current X-Ray segment for tracing

    Returns:
        AuthorizationResponse: On success, contains the API key and request ID
        ErrorResponse: On failure, contains an error message and request ID

    HTTP Status Codes:
        200: Success - valid credentials, API key retrieved
        401: Unauthorized - invalid payload or credentials
        403: Forbidden - AWS permissions error accessing the secret
        500: Internal server error
    """
    segment = xray_service.recorder.current_segment()
    trace_id = segment.trace_id if segment else "No-Trace-Id"
    logger.info(f"Processing authorization request with trace_id: {trace_id}")

    try:
        # envoy is only going to wait 10 seconds for the auth response
        # so let's terminate this after 9s so we can gracefully return a 503 error
        async with asyncio.timeout(9):
            # Extract payload and target host
            body = await request.json()
            raw_payload = body.get("payload", "")
            target_host = body.get("target_host")
            logger.info(
                f"Received authorization request with payload: {
                    raw_payload[:10]
                }... for target: {target_host}"
            )

            # Get API key and principal info (from cache or AWS)
            payload = AuthPayload.from_contents(raw_payload, target_host=None)
            auth_result = await auth_service.authenticate(
                payload, trace_id, target_host
            )

            # If needed by provider, sign request
            signature_headers: Optional[SignatureHeaders] = None
            try:
                signable_request_raw = body.get("signable_request", None)
                signable_request = SignableRequest.model_validate(signable_request_raw)
                if auth_result.signing_key is not None:
                    signature_headers = sign_request(
                        signable_request,
                        auth_result.signing_key,
                        auth_result.api_key,
                        payload.credentials,
                    )
                    logger.info(
                        f"Signed request for '{signable_request.type}' provider"
                    )
            except ValidationError as e:
                # this should only happen if the Envoy proxy is passing invalid
                # parameters
                response.status_code = 500
                segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
                return ErrorResponse(
                    message=f"Invalid request signing parameters passed by proxy: {e}",
                    debug_id=trace_id,
                )

            # Store principal info metadata and publish to Firehose
            timestamp = generate_iso_timestamp()
            principal_info = auth_result.principal_info.to_dict()

            # Publish to Firehose for long-term storage
            try:
                async with asyncio.timeout(3):
                    published = await publish_service.publish_metadata(
                        request_id=trace_id,
                        timestamp=timestamp,
                        principal_info=principal_info,
                        secret_arn=payload.secret_arn,
                    )
                # publish_* returns False (rather than raising) when its stream is
                # unset; surface that drop instead of silently discarding the bool.
                if not published:
                    _record_audit_drop("metadata", "stream_unconfigured", trace_id)
            # There are some synchronous actions happening which can succeed even
            # if the timeout is hit
            except TimeoutError as e:
                # Add exception to X-Ray trace for visibility
                # but don't fail the whole request
                segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
                _record_audit_drop("metadata", "publish_timeout", trace_id)
                logger.critical(
                    f"Publishing metadata to firehose timed out for {trace_id}: {e}, ",
                    "although may have succeeded",
                )
            except Exception as e:
                # Add exception to X-Ray trace for visibility
                # but don't fail the whole request
                segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
                _record_audit_drop("metadata", "publish_error", trace_id)
                logger.critical(
                    f"Failed to publish metadata to Firehose for {trace_id}: {e}"
                )

            # Return successful response
            response.status_code = 200
            return AuthorizationResponse(
                api_key=auth_result.api_key,
                request_id=trace_id,
                signature=signature_headers["Signature"] if signature_headers else None,
                signature_input=signature_headers["Signature-Input"]
                if signature_headers
                else None,
            )

    except PayloadError as e:
        response.status_code = 401
        return ErrorResponse(message=e.message, debug_id=trace_id)
    except CredentialsError as e:
        response.status_code = 401
        return ErrorResponse(message=e.message, debug_id=trace_id)
    except AuthenticationError as e:
        response.status_code = 403
        return ErrorResponse(message=e.message, debug_id=trace_id)
    except FetchSecretError as e:
        response.status_code = e.http_status_code
        return ErrorResponse(message=e.message, debug_id=trace_id)
    except TimeoutError as e:
        logger.critical(f"Authorization processing timed out for {trace_id}")
        segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
        response.status_code = 503
        return ErrorResponse(
            message="Authorization timed out. Proxy overloaded.", debug_id=trace_id
        )
    except Exception as e:
        segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
        logger.error(f"Unexpected error in authorise: {e}")
        response.status_code = 500
        return ErrorResponse(message="Internal server error", debug_id=trace_id)


@portunus_router.post("/log/{request_id}/request/headers")
async def log_request_headers(
    request_id: str,
    content: HeadersPayload,
    response: Response,
) -> Optional[ErrorResponse]:
    """Store request headers.

    Audit publishing is non-blocking: a drop (publish returns ``False``) or a
    publish error is recorded as an observable, alarmable event via
    ``_record_audit_drop`` but never fails the request, so customer
    latency/status stays decoupled from the audit sink.
    """
    segment = xray_service.recorder.current_segment()
    trace_id = segment.trace_id if segment else "No-Trace-Id"
    logger.info(f"Processing authorization request with trace_id: {trace_id}")
    try:
        # Publish to Firehose for long-term storage
        published = await publish_service.publish_request_headers(
            request_id=request_id,
            headers=content.headers,
            timestamp=content.get_iso_timestamp(),
        )
        if not published:
            _record_audit_drop("request_headers", "stream_unconfigured", trace_id)
    except Exception as e:
        segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
        _record_audit_drop("request_headers", "publish_error", trace_id)
        logger.critical(f"Firehose publishing failed for request headers: {e}")

    response.status_code = 200
    return None


@portunus_router.post("/log/{request_id}/request/body")
async def log_request_body(
    request_id: str,
    request: Request,
    response: Response,
) -> Optional[ErrorResponse]:
    """Store request body as raw bytes.

    Audit publishing is non-blocking: a dropped chunk (publish returns
    ``False``) or a publish error is recorded as an observable, alarmable event
    via ``_record_audit_drop`` but never fails the request.
    """
    segment = xray_service.recorder.current_segment()
    trace_id = segment.trace_id if segment else "No-Trace-Id"
    logger.info(f"Processing authorization request with trace_id: {trace_id}")
    body_bytes = await request.body()
    # Body endpoints receive raw binary data, so timestamp must be generated server-side
    # (unlike other endpoints that receive structured payloads with timestamps)
    timestamp = generate_iso_timestamp()

    try:
        # Chunk the body data and publish each chunk
        chunks = chunk_body_data(body_bytes)
        logger.info(f"Publishing request body in {len(chunks)} chunk(s)")

        if chunks:
            for chunk_id, chunk in enumerate(chunks):
                published = await publish_service.publish_request_body(
                    request_id=request_id,
                    body_bytes=chunk,
                    timestamp=timestamp,
                    chunk_id=chunk_id,
                    num_chunks=len(chunks),
                )
                if not published:
                    _record_audit_drop("request_body", "stream_unconfigured", trace_id)
        else:
            # Handle empty body case by sending a single empty chunk
            published = await publish_service.publish_request_body(
                request_id=request_id,
                body_bytes=b"",
                timestamp=timestamp,
                chunk_id=0,
                num_chunks=1,
            )
            if not published:
                _record_audit_drop("request_body", "stream_unconfigured", trace_id)
    except Exception as e:
        segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
        _record_audit_drop("request_body", "publish_error", trace_id)
        logger.critical(f"Firehose publishing failed for request body: {e}")

    response.status_code = 200
    return None


@portunus_router.post("/log/{request_id}/request/trailers")
async def log_request_trailers(
    request_id: str,
    content: TrailersPayload,
    response: Response,
) -> Optional[ErrorResponse]:
    """Store request trailers.

    Audit publishing is non-blocking: a drop (publish returns ``False``) or a
    publish error is recorded as an observable, alarmable event via
    ``_record_audit_drop`` but never fails the request.
    """
    segment = xray_service.recorder.current_segment()
    trace_id = segment.trace_id if segment else "No-Trace-Id"
    logger.info(f"Processing authorization request with trace_id: {trace_id}")
    try:
        # Publish to Firehose
        published = await publish_service.publish_request_trailers(
            request_id=request_id,
            trailers=content.trailers,
            timestamp=content.get_iso_timestamp(),
        )
        if not published:
            _record_audit_drop("request_trailers", "stream_unconfigured", trace_id)
    except Exception as e:
        segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
        _record_audit_drop("request_trailers", "publish_error", trace_id)
        logger.critical(f"Firehose publishing failed for request trailers: {e}")

    response.status_code = 200
    return None


@portunus_router.post("/log/{request_id}/response/headers")
async def log_response_headers(
    request_id: str,
    content: HeadersPayload,
    response: Response,
) -> Optional[ErrorResponse]:
    """Store response headers.

    Audit publishing is non-blocking: a drop (publish returns ``False``) or a
    publish error is recorded as an observable, alarmable event via
    ``_record_audit_drop`` but never fails the request.
    """
    segment = xray_service.recorder.current_segment()
    trace_id = segment.trace_id if segment else "No-Trace-Id"
    logger.info(f"Processing authorization request with trace_id: {trace_id}")
    try:
        # Publish to Firehose
        published = await publish_service.publish_response_headers(
            request_id=request_id,
            headers=content.headers,
            timestamp=content.get_iso_timestamp(),
        )
        if not published:
            _record_audit_drop("response_headers", "stream_unconfigured", trace_id)
    except Exception as e:
        segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
        _record_audit_drop("response_headers", "publish_error", trace_id)
        logger.critical(f"Firehose publishing failed for response headers: {e}")

    response.status_code = 200
    return None


@portunus_router.post("/log/{request_id}/response/body")
async def log_response_body(
    request_id: str,
    request: Request,
    response: Response,
) -> Optional[ErrorResponse]:
    """Store response body as raw bytes.

    Audit publishing is non-blocking: a dropped chunk (publish returns
    ``False``) or a publish error is recorded as an observable, alarmable event
    via ``_record_audit_drop`` but never fails the request.
    """
    segment = xray_service.recorder.current_segment()
    trace_id = segment.trace_id if segment else "No-Trace-Id"
    logger.info(f"Processing authorization request with trace_id: {trace_id}")
    body_bytes = await request.body()
    # Body endpoints receive raw binary data, so timestamp must be generated server-side
    # (unlike other endpoints that receive structured payloads with timestamps)
    timestamp = generate_iso_timestamp()

    try:
        # Chunk the body data and publish each chunk
        chunks = chunk_body_data(body_bytes)
        logger.info(f"Publishing response body in {len(chunks)} chunk(s)")

        if chunks:
            for chunk_id, chunk in enumerate(chunks):
                published = await publish_service.publish_response_body(
                    request_id=request_id,
                    body_bytes=chunk,
                    timestamp=timestamp,
                    chunk_id=chunk_id,
                    num_chunks=len(chunks),
                )
                if not published:
                    _record_audit_drop("response_body", "stream_unconfigured", trace_id)
        else:
            # Handle empty body case by sending a single empty chunk
            published = await publish_service.publish_response_body(
                request_id=request_id,
                body_bytes=b"",
                timestamp=timestamp,
                chunk_id=0,
                num_chunks=1,
            )
            if not published:
                _record_audit_drop("response_body", "stream_unconfigured", trace_id)
    except Exception as e:
        segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
        _record_audit_drop("response_body", "publish_error", trace_id)
        logger.critical(f"Firehose publishing failed for response body: {e}")

    response.status_code = 200
    return None


@portunus_router.post("/log/{request_id}/response/trailers")
async def log_response_trailers(
    request_id: str,
    content: TrailersPayload,
    response: Response,
) -> Optional[ErrorResponse]:
    """Store response trailers.

    Audit publishing is non-blocking: a drop (publish returns ``False``) or a
    publish error is recorded as an observable, alarmable event via
    ``_record_audit_drop`` but never fails the request.
    """
    segment = xray_service.recorder.current_segment()
    trace_id = segment.trace_id if segment else "No-Trace-Id"
    logger.info(f"Processing authorization request with trace_id: {trace_id}")
    try:
        # Publish to Firehose
        published = await publish_service.publish_response_trailers(
            request_id=request_id,
            trailers=content.trailers,
            timestamp=content.get_iso_timestamp(),
        )
        if not published:
            _record_audit_drop("response_trailers", "stream_unconfigured", trace_id)
    except Exception as e:
        segment.add_exception(e, stacktrace.get_stacktrace())  # type: ignore[invalid-argument-type]  # stubs type stack as StackSummary but runtime accepts list[FrameSummary]
        _record_audit_drop("response_trailers", "publish_error", trace_id)
        logger.critical(f"Firehose publishing failed for response trailers: {e}")

    response.status_code = 200
    return None


# Active WebSocket connections tracked for graceful shutdown.
_active_ws_connections: set[asyncio.Task] = set()


@portunus_router.websocket("/{path:path}")
async def ws_relay(websocket: WebSocket, path: str):
    """WebSocket relay endpoint.

    Envoy routes WebSocket upgrade requests (matched by the Upgrade header)
    to Portunus. The path is forwarded to the upstream as-is
    (e.g., /v1/responses -> upstream /v1/responses).

    Authenticates the upgrade request, connects to the upstream WebSocket,
    and relays messages bidirectionally with per-message Firehose logging.
    Rejects with 1013 (Try Again Later) if connection limit is reached.
    """
    max_conns = config.relay.max_connections
    if len(_active_ws_connections) >= max_conns:
        logger.warning(f"WS connection limit reached ({max_conns}), rejecting")
        await websocket.close(
            code=WsCloseCode.TRY_AGAIN_LATER, reason="Try again later"
        )
        return

    segment = xray_service.recorder.current_segment()
    request_id = segment.trace_id if segment else str(uuid.uuid4())

    task = asyncio.current_task()
    if task is not None:
        _active_ws_connections.add(task)
    try:
        await handle_ws_connection(
            websocket=websocket,
            path=path,
            auth_service=auth_service,
            publish_service=publish_service,
            request_id=request_id,
        )
    finally:
        if task is not None:
            _active_ws_connections.discard(task)


class CacheFlushResponse(BaseModel):
    """Response model for cache flush operations.

    Attributes:
        message: Status message
        success: Whether the flush succeeded
    """

    message: str
    success: bool


@portunus_router.post("/cache/flush")
async def flush_cache(
    response: Response,
) -> CacheFlushResponse | ErrorResponse:
    """
    Flush the entire auth cache.

    This endpoint removes all cached authentication responses from Redis,
    forcing all subsequent requests to re-authenticate via AWS. Use this
    when a cached API key may have been compromised.

    Returns:
        CacheFlushResponse on success, ErrorResponse on failure.
    """
    segment = xray_service.recorder.current_segment()
    trace_id = segment.trace_id if segment else "No-Trace-Id"
    logger.info(f"Cache flush requested, trace_id: {trace_id}")

    try:
        success = await cache_service.flush_all()
        if success:
            logger.info(f"Cache flush completed successfully, trace_id: {trace_id}")
            return CacheFlushResponse(
                message="Auth cache flushed successfully",
                success=True,
            )
        else:
            response.status_code = 503
            return ErrorResponse(
                message="Redis unavailable for cache flush",
                debug_id=trace_id,
            )
    except Exception as e:
        logger.error(f"Cache flush failed: {e}, trace_id: {trace_id}")
        response.status_code = 500
        return ErrorResponse(
            message="Failed to flush cache",
            debug_id=trace_id,
        )


@common_router.get("/ping")
async def ping(request: Request, response: Response) -> dict:
    """
    Health/readiness check endpoint for monitoring system status.

    Reports Redis connectivity (informational) and Firehose audit
    configuration (readiness-gating). A missing required Firehose delivery
    stream is a static misconfiguration that would cause silent audit loss, so
    it fails readiness (HTTP 503) and the task is taken out of rotation; a
    transient Redis blip stays informational and does not flip the task
    unhealthy. This complements the hard fail-fast at startup (see ``lifespan``).

    Returns:
        dict: Health status with the following fields:
            - status: Overall readiness ("healthy" or "unhealthy")
            - redis: Redis connection status ("OK" or "FAIL")
            - firehose: Firehose audit config status ("OK" or "FAIL")
            - timestamp: ISO-formatted current timestamp
    """
    redis_health = "OK" if await state_service.health_check() else "FAIL"
    missing_streams = config.firehose.missing_required_streams()
    firehose_health = "OK" if not missing_streams else "FAIL"
    if firehose_health == "FAIL":
        logger.critical(
            "Readiness check failed: missing required Firehose delivery stream "
            f"env vars: {', '.join(missing_streams)}"
        )
        response.status_code = 503
    return {
        "status": "healthy" if firehose_health == "OK" else "unhealthy",
        "redis": redis_health,
        "firehose": firehose_health,
        "timestamp": generate_iso_timestamp(),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle.

    Fails fast at startup if any required Firehose delivery stream is unset,
    so a task whose audit sink is misconfigured (e.g. one still carrying the
    pre-migration ``KINESIS_*`` env vars, leaving ``FIREHOSE_*`` unset) never
    starts serving — instead of silently dropping 100% of audit records while
    returning 200. Then starts the WS log queue on startup, and drains active
    WS connections and cleans up Redis on shutdown.
    """
    missing_streams = config.firehose.missing_required_streams()
    if missing_streams:
        raise RuntimeError(
            "Refusing to start: Firehose audit publishing is misconfigured. "
            f"Missing required delivery stream env vars: {', '.join(missing_streams)}. "
            "Serving with these unset would silently drop 100% of audit records "
            "while returning 200 (most likely a task still carrying the "
            "pre-migration KINESIS_* env vars)."
        )

    await start_log_queue(num_workers=config.relay.max_connections)
    yield

    # Cancel WS connections first so they stop producing log items
    if _active_ws_connections:
        logger.info(
            f"Draining {len(_active_ws_connections)} active WebSocket connections"
        )
        drain_timeout = config.relay.drain_timeout
        for task in list(_active_ws_connections):
            task.cancel()
        if _active_ws_connections:
            await asyncio.sleep(drain_timeout)
        logger.info(
            f"WebSocket drain complete, {len(_active_ws_connections)} remaining"
        )

    # Then drain the log queue (no new items will arrive)
    await stop_log_queue()

    logger.info("Shutting down Redis connections")
    await state_service.close_redis_client()
    logger.info("Redis connections closed")


portunus = FastAPI(title="Portunus", lifespan=lifespan)
portunus.add_middleware(LoggingMiddleware)
portunus.include_router(portunus_router)
portunus.include_router(common_router)
