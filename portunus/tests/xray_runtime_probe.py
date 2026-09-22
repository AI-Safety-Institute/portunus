"""Exercise enabled tracing through the process entrypoint without AWS I/O."""

import asyncio
import os
import signal
import sys
from contextvars import Context
from typing import Any
from unittest.mock import patch

import grpc
from aws_xray_sdk.core import xray_recorder
from grpc_health.v1 import health_pb2, health_pb2_grpc

from portunus.grpc import server
from portunus.services import auth_service, publish_service, state_service
from portunus.services.xray_service import XRayContext, request_id_var, trace_id_var


class Emitter:
    def __init__(self) -> None:
        self.entities: list[Any] = []

    def send_entity(self, entity: Any) -> None:
        self.entities.append(entity)

    def set_daemon_address(self, address: str) -> None:
        pass


class StateService:
    async def close(self) -> None:
        pass

    async def close_redis_client(self) -> None:
        pass


class AuthService:
    def __init__(self, cache_service: Any) -> None:
        pass


class PublishService:
    def __init__(self, state_service: StateService) -> None:
        self.state_service = state_service

    async def put_record_batch(self, stream: str, records: list[bytes]) -> int:
        return 0

    async def close(self) -> None:
        pass


async def check_trace_contexts(emitter: Emitter) -> None:
    recorder: Any = xray_recorder
    release = asyncio.Event()
    tasks: list[asyncio.Task[Any]] = []
    observations: dict[str, tuple[str | None, str | None, str]] = {}
    shared = Context()
    shared.run(request_id_var.set, "shared-initial")
    shared.run(trace_id_var.set, "shared-trace")

    async def child(name: str, ready: asyncio.Event) -> str:
        async with recorder.in_subsegment_async(name) as sub:
            observations[name] = (
                request_id_var.get(),
                trace_id_var.get(),
                sub.parent_id,
            )
            request_id_var.set(name)
            ready.set()
            await release.wait()
            if name == "ordinary-a":

                async def grandchild() -> None:
                    async with recorder.in_subsegment_async("grandchild") as grand:
                        observations["grandchild"] = (
                            request_id_var.get(),
                            trace_id_var.get(),
                            grand.parent_id,
                        )

                await asyncio.create_task(grandchild())
            if name.startswith("shared-"):
                assert request_id_var.get() == "shared-b"
            else:
                assert request_id_var.get() == name
            assert recorder.current_subsegment() is sub
            return sub.id

    request_id_var.set("parent-request")
    trace_id = "1-00000000-000000000000000000000001"
    try:
        async with XRayContext(trace_id, segment_name="context-probe", sampled=True):
            async with recorder.in_subsegment_async("parent") as parent:
                for name in (
                    "ordinary-a",
                    "ordinary-b",
                    "explicit",
                    "shared-a",
                    "shared-b",
                    "cancelled",
                ):
                    ready = asyncio.Event()
                    context = None
                    if name == "explicit":
                        context = Context()
                        context.run(request_id_var.set, "explicit-request")
                        context.run(trace_id_var.set, "explicit-trace")
                    elif name.startswith("shared-"):
                        context = shared
                    task = asyncio.create_task(child(name, ready), context=context)
                    tasks.append(task)
                    await asyncio.wait_for(ready.wait(), timeout=2)
                tasks[-1].cancel()
                try:
                    await tasks[-1]
                except asyncio.CancelledError:
                    pass
                else:
                    raise AssertionError("child cancellation was swallowed")
                assert recorder.current_subsegment() is parent
                assert request_id_var.get() == "parent-request"
                assert trace_id_var.get() == trace_id
                release.set()
                child_ids = await asyncio.gather(*tasks[:-1])
                assert all(
                    item[2] == parent.id
                    for name, item in observations.items()
                    if name != "grandchild"
                )
                assert observations["ordinary-a"][:2] == ("parent-request", trace_id)
                assert observations["ordinary-b"][:2] == ("parent-request", trace_id)
                assert observations["explicit"][:2] == (
                    "explicit-request",
                    "explicit-trace",
                )
                assert observations["shared-a"][:2] == (
                    "shared-initial",
                    "shared-trace",
                )
                assert observations["shared-b"][:2] == ("shared-a", "shared-trace")
                assert shared.get(request_id_var) == "shared-b"
                assert observations["grandchild"] == (
                    "ordinary-a",
                    trace_id,
                    child_ids[0],
                )
                assert recorder.current_subsegment() is parent
            assert recorder.current_subsegment() is None
        assert trace_id_var.get() is None
        assert len(emitter.entities) == 1
        segment = emitter.entities[0]
        assert segment.trace_id == trace_id
        assert [span.name for span in segment.subsegments] == ["parent"]
        siblings = segment.subsegments[0].subsegments
        assert sorted(span.name for span in siblings) == sorted(
            [
                "ordinary-a",
                "ordinary-b",
                "explicit",
                "shared-a",
                "shared-b",
                "cancelled",
            ]
        )
        assert all(not span.in_progress for span in siblings)
        ancestor = next(span for span in siblings if span.name == "ordinary-a")
        assert [span.name for span in ancestor.subsegments] == ["grandchild"]
    finally:
        release.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def main() -> None:
    emitter = Emitter()
    xray_recorder.configure(emitter=emitter)  # type: ignore[arg-type]
    original_start = server.start_grpc_server
    probe: asyncio.Task[None] | None = None

    async def exercise() -> None:
        try:
            async with grpc.aio.insecure_channel(
                f"127.0.0.1:{os.environ['GRPC_PORT']}"
            ) as channel:
                response = await health_pb2_grpc.HealthStub(channel).Check(
                    health_pb2.HealthCheckRequest(), timeout=2
                )
                assert response.status == health_pb2.HealthCheckResponse.SERVING
            await check_trace_contexts(emitter)
        finally:
            os.kill(os.getpid(), signal.SIGTERM)

    async def start_and_exercise(**kwargs: Any) -> Any:
        nonlocal probe
        runtime = await original_start(**kwargs)
        probe = asyncio.create_task(exercise())
        return runtime

    with (
        patch.object(state_service, "StateService", StateService),
        patch.object(auth_service, "AuthService", AuthService),
        patch.object(publish_service, "PublishService", PublishService),
        patch.object(server, "start_grpc_server", start_and_exercise),
    ):
        if sys.argv[1] == "asyncio":
            server.run_event_loop = asyncio.run
        server.main()
    assert probe is not None and probe.done()
    probe.result()


if __name__ == "__main__":
    main()
