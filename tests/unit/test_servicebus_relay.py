"""Unit tests for the Azure Service Bus relay adapter (fake client, no network)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mwa_ad_connector.infrastructure.transport.relay import ServiceBusRelay, TransportError

CONN = "Endpoint=sb://unit.test/;SharedAccessKeyName=k;SharedAccessKey=se=cret"
COMMAND_QUEUE = "ad-commands"
RESULT_QUEUE = "ad-results"


class FakeMessage:
    """Minimal ServiceBusReceivedMessage double: str() yields the JSON body."""

    def __init__(
        self,
        envelope: dict[str, Any] | None = None,
        *,
        message_id: str | None = "",
        delivery_count: int = 1,
        raw_body: str | None = None,
    ) -> None:
        self._body = raw_body if raw_body is not None else json.dumps(envelope)
        self.message_id = message_id
        self.delivery_count = delivery_count

    def __str__(self) -> str:
        return self._body


class FakeReceiver:
    """Async receiver double with open/close, receive and settlement tracking."""

    def __init__(self, messages: list[FakeMessage]) -> None:
        self._messages = list(messages)
        self.completed: list[FakeMessage] = []
        self.abandoned: list[FakeMessage] = []
        self.dead_lettered: list[tuple[FakeMessage, str | None]] = []
        self.receive_calls: list[tuple[int, float | None]] = []
        self.opened = False
        self.closed = False
        self.complete_error = False
        self.dead_letter_error = False

    async def __aenter__(self) -> FakeReceiver:
        self.opened = True
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self.closed = True

    async def receive_messages(
        self, max_message_count: int = 1, max_wait_time: float | None = None
    ) -> list[FakeMessage]:
        self.receive_calls.append((max_message_count, max_wait_time))
        if not self._messages:
            return []
        return [self._messages.pop(0)]

    async def complete_message(self, message: FakeMessage) -> None:
        if self.complete_error:
            raise RuntimeError(f"sdk failure with {CONN}")
        self.completed.append(message)

    async def abandon_message(self, message: FakeMessage) -> None:
        self.abandoned.append(message)

    async def dead_letter_message(self, message: FakeMessage, reason: str | None = None) -> None:
        if self.dead_letter_error:
            raise RuntimeError(f"sdk failure with {CONN}")
        self.dead_lettered.append((message, reason))


class FakeSender:
    """Async sender double capturing the raw messages it is asked to send."""

    def __init__(self) -> None:
        self.sent: list[Any] = []
        self.opened = False
        self.send_error = False

    async def __aenter__(self) -> FakeSender:
        self.opened = True
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def send_messages(self, message: Any) -> None:
        if self.send_error:
            raise RuntimeError(f"sdk failure with {CONN}")
        self.sent.append(message)


class FakeClient:
    """Async ServiceBusClient double routing queues to fakes; never touches network."""

    def __init__(self, command_messages: list[FakeMessage] | None = None, *, receiver_error: bool = False) -> None:
        self.command_receiver = FakeReceiver(list(command_messages or []))
        self.result_receiver = FakeReceiver([])
        self.command_sender = FakeSender()
        self.result_sender = FakeSender()
        self.closed = False
        self.created_receivers: list[str] = []
        self.created_senders: list[str] = []
        self._receiver_error = receiver_error

    def get_queue_receiver(self, queue_name: str) -> FakeReceiver:
        self.created_receivers.append(queue_name)
        if self._receiver_error:
            raise RuntimeError(f"sdk failure with {CONN}")
        return self.command_receiver if queue_name == COMMAND_QUEUE else self.result_receiver

    def get_queue_sender(self, queue_name: str) -> FakeSender:
        self.created_senders.append(queue_name)
        return self.command_sender if queue_name == COMMAND_QUEUE else self.result_sender

    async def close(self) -> None:
        self.closed = True


def _relay(client: FakeClient) -> ServiceBusRelay:
    """Build a relay wired to the injected fake client."""
    return ServiceBusRelay(CONN, COMMAND_QUEUE, RESULT_QUEUE, client_factory=lambda: client)


async def test_receive_decodes_json_and_tracks_pending() -> None:
    """receive() decodes the body and records the handler for settlement."""
    source = FakeMessage({"capability": "ad.user.create"}, message_id="sb-1", delivery_count=3)
    client = FakeClient([source])
    relay = _relay(client)

    message = await relay.receive(timeout_seconds=0.5)

    assert message is not None
    assert message.message_id == "sb-1"
    assert message.envelope == {"capability": "ad.user.create"}
    assert message.delivery_count == 3
    assert client.command_receiver.receive_calls == [(1, 0.5)]


async def test_receive_empty_returns_none() -> None:
    """An empty poll yields None, not an exception."""
    relay = _relay(FakeClient([]))

    assert await relay.receive(timeout_seconds=0.1) is None


async def test_receive_reuses_the_command_receiver() -> None:
    """Repeated receives reuse one opened receiver (no per-poll reconnect)."""
    relay = _relay(FakeClient([]))

    await relay.receive()
    await relay.receive()

    client = relay._client  # noqa: SLF001 - test-owned fake introspection.
    assert client.created_receivers == [COMMAND_QUEUE]


async def test_receive_defaults_delivery_count() -> None:
    """A missing/zero SDK delivery count is reported as the first delivery."""
    client = FakeClient([FakeMessage({"capability": "c"}, message_id="sb-2", delivery_count=0)])
    message = await _relay(client).receive()

    assert message is not None
    assert message.delivery_count == 1


@pytest.mark.parametrize("raw_body", ["{not valid json", "[1, 2, 3]"])
async def test_receive_dead_letters_malformed_body_and_does_not_track(raw_body: str) -> None:
    """A non-JSON-object body is dead-lettered, untracked and never raised."""
    client = FakeClient([FakeMessage(raw_body=raw_body, message_id="sb-bad")])
    relay = _relay(client)

    result = await relay.receive()

    assert result is None
    assert len(client.command_receiver.dead_lettered) == 1
    dead, reason = client.command_receiver.dead_lettered[0]
    assert reason == "MALFORMED_ENVELOPE"
    assert relay._pending == {}  # noqa: SLF001 - test-owned introspection.


async def test_receive_dead_letter_failure_is_swallowed() -> None:
    """A failing dead-letter call must not crash the receive loop."""
    client = FakeClient([FakeMessage(raw_body="not-json", message_id="sb-bad")])
    client.command_receiver.dead_letter_error = True
    relay = _relay(client)

    assert await relay.receive() is None


@pytest.mark.parametrize("sdk_id", [None, ""])
async def test_receive_generates_id_when_sdk_id_missing(sdk_id: str | None) -> None:
    """A missing/empty SDK message id becomes a fresh uuid4, never 'None'."""
    client = FakeClient([FakeMessage({"capability": "c"}, message_id=sdk_id)])
    message = await _relay(client).receive()

    assert message is not None
    assert message.message_id != "None"
    assert message.message_id.startswith("msg-")
    assert len(message.message_id) == len("msg-") + 32


async def test_ack_completes_the_pending_message() -> None:
    """ack() completes the SDK message and clears the pending entry."""
    source = FakeMessage({"capability": "c"}, message_id="sb-3")
    client = FakeClient([source])
    relay = _relay(client)
    received = await relay.receive()
    assert received is not None

    await relay.ack(received.message_id)

    assert client.command_receiver.completed == [source]


async def test_ack_settles_then_pops_even_when_settlement_fails() -> None:
    """A settlement failure still drops the pending handle and suppresses the cause."""
    source = FakeMessage({"capability": "c"}, message_id="sb-fail")
    client = FakeClient([source])
    client.command_receiver.complete_error = True
    relay = _relay(client)
    received = await relay.receive()
    assert received is not None

    with pytest.raises(TransportError) as excinfo:
        await relay.ack(received.message_id)

    assert relay._pending == {}  # noqa: SLF001 - test-owned introspection.
    assert excinfo.value.__cause__ is None
    assert CONN not in str(excinfo.value)


async def test_abandon_abandons_the_pending_message() -> None:
    """abandon() releases the SDK message back to the queue."""
    source = FakeMessage({"capability": "c"}, message_id="sb-4")
    client = FakeClient([source])
    relay = _relay(client)
    received = await relay.receive()
    assert received is not None

    await relay.abandon(received.message_id)

    assert client.command_receiver.abandoned == [source]


async def test_ack_and_abandon_unknown_id_are_noops() -> None:
    """Settling an id we never received is a silent no-op."""
    client = FakeClient([])
    relay = _relay(client)

    await relay.ack("missing")
    await relay.abandon("missing")

    assert client.command_receiver.completed == []
    assert client.command_receiver.abandoned == []


async def test_publish_sends_on_command_queue_and_returns_id() -> None:
    """publish() sends JSON on the command queue and returns the SDK message id."""
    client = FakeClient([])
    relay = _relay(client)

    message_id = await relay.publish({"capability": "c"})

    assert client.created_senders == [COMMAND_QUEUE]
    sent = client.command_sender.sent[0]
    assert sent.message_id == message_id
    assert json.loads(str(sent)) == {"capability": "c"}


async def test_publish_result_sends_on_result_queue_with_correlation() -> None:
    """publish_result() sends on the result queue carrying the correlation id."""
    client = FakeClient([])
    relay = _relay(client)

    await relay.publish_result({"correlation_id": "corr-1", "state": "SUCCEEDED"})

    assert client.created_senders == [RESULT_QUEUE]
    sent = client.result_sender.sent[0]
    assert sent.correlation_id == "corr-1"
    assert json.loads(str(sent))["state"] == "SUCCEEDED"


async def test_close_closes_client_and_receivers() -> None:
    """close() tears down receivers and the underlying client."""
    client = FakeClient([FakeMessage({"capability": "c"}, message_id="sb-5")])
    relay = _relay(client)
    await relay.receive()

    await relay.close()

    assert client.command_receiver.closed is True
    assert client.closed is True


async def test_legacy_queue_name_aliases_default_the_result_queue() -> None:
    """Legacy kwargs route results to the command queue instead of an empty name."""
    client = FakeClient([])
    relay = ServiceBusRelay(CONN, queue_name="legacy-commands", client_factory=lambda: client)

    assert relay.command_queue == "legacy-commands"
    assert relay.result_queue == "legacy-commands"

    await relay.publish_result({"state": "SUCCEEDED"})

    assert client.created_senders == ["legacy-commands"]


async def test_empty_config_fails_closed() -> None:
    """An unconfigured relay refuses every operation (fail-closed)."""
    relay = ServiceBusRelay()

    with pytest.raises(TransportError):
        await relay.receive()
    with pytest.raises(TransportError):
        await relay.ack("m")
    with pytest.raises(TransportError):
        await relay.abandon("m")
    with pytest.raises(TransportError):
        await relay.publish({})
    with pytest.raises(TransportError):
        await relay.publish_result({})


async def test_sdk_failure_is_mapped_without_leaking_details() -> None:
    """SDK exceptions become a generic TransportError (no raw text/secrets/cause)."""
    client = FakeClient(receiver_error=True)
    relay = _relay(client)

    with pytest.raises(TransportError) as excinfo:
        await relay.receive()

    message = str(excinfo.value)
    assert "sdk failure" not in message
    assert "SharedAccessKey" not in message
    assert CONN not in message
    assert excinfo.value.__cause__ is None


async def test_publish_sdk_failure_suppresses_the_exception_chain() -> None:
    """publish() maps SDK faults without retaining the secret-bearing cause."""
    client = FakeClient([])
    client.command_sender.send_error = True
    relay = _relay(client)

    with pytest.raises(TransportError) as excinfo:
        await relay.publish({"capability": "c"})

    assert excinfo.value.__cause__ is None
    assert CONN not in str(excinfo.value)
