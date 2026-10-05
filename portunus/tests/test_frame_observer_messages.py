"""Logical messages survive framing, compression and transport chunking."""

import pytest
from wsproto.connection import Connection, ConnectionType
from wsproto.events import BytesMessage, Ping, TextMessage
from wsproto.extensions import PerMessageDeflate

from portunus.grpc.frame_observer import Direction, build_observer


@pytest.mark.parametrize("direction", [Direction.REQUEST, Direction.RESPONSE])
@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("split_transport", [False, True])
@pytest.mark.parametrize("data", ["", "Grüße 🌍", b"", bytes(range(256))])
def test_complete_and_fragmented_messages_keep_their_contents(
    direction, compressed, split_transport, data
):
    extensions = []
    if compressed:
        extension = PerMessageDeflate()
        extension.finalize("permessage-deflate")
        extensions.append(extension)
    sender = Connection(
        ConnectionType.CLIENT
        if direction == Direction.REQUEST
        else ConnectionType.SERVER,
        extensions=extensions,
    )
    observer = build_observer(
        response_extensions_header="permessage-deflate" if compressed else None
    )
    message_type = TextMessage if isinstance(data, str) else BytesMessage
    wire = b"".join(
        sender.send(event)
        for event in [
            message_type(data=data),
            message_type(data=data, message_finished=False),
            Ping(payload=b"keepalive"),
            message_type(data=data, message_finished=True),
            message_type(data=data),
        ]
    )
    chunks = (
        [wire[index : index + 3] for index in range(0, len(wire), 3)]
        if split_transport
        else [wire]
    )
    frames = [
        frame
        for chunk in chunks
        for frame in observer.observe(direction=direction, chunk=chunk)
    ]
    payload = data.encode("utf-8") if isinstance(data, str) else data
    opcode = "text" if isinstance(data, str) else "binary"
    assert [(frame.opcode, frame.payload) for frame in frames] == [
        (opcode, payload),
        ("ping", b"keepalive"),
        (opcode, payload + payload),
        (opcode, payload),
    ]
    assert all(frame.direction == direction and not frame.truncated for frame in frames)
    assert list(observer.finish(direction)) == []
    assert not observer.desynced(direction)
