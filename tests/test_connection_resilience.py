#!/usr/bin/env python3
"""Tests for connection retry, backoff, reconnect, and ConfigEntryNotReady."""

from __future__ import annotations

import asyncio
import sys
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, ".")

# Stub homeassistant before importing orisec
_ha = types.ModuleType("homeassistant")
_ha_core = types.ModuleType("homeassistant.core")
_ha_ce = types.ModuleType("homeassistant.config_entries")
_ha_huc = types.ModuleType("homeassistant.helpers.update_coordinator")
_ha_helpers = types.ModuleType("homeassistant.helpers")
_ha_ep = types.ModuleType("homeassistant.helpers.entity_platform")
_ha_storage = types.ModuleType("homeassistant.helpers.storage")
_ha_const = types.ModuleType("homeassistant.const")
_ha_exc = types.ModuleType("homeassistant.exceptions")
_ha_comp = types.ModuleType("homeassistant.components")
_ha_frontend = types.ModuleType("homeassistant.components.frontend")
_ha_ws = types.ModuleType("homeassistant.components.websocket_api")
_ha_http = types.ModuleType("homeassistant.components.http")
_ha_panel = types.ModuleType("homeassistant.components.panel_custom")
_vol = types.ModuleType("voluptuous")


class _FakeConfigEntry:
    pass


class _FakeDataUpdateCoordinator:
    def __class_getitem__(cls, item):
        return cls

    def __init__(self, hass, logger, *, name, update_interval):
        self.hass = hass
        self.logger = logger
        self.name = name
        self.update_interval = update_interval

    def async_set_updated_data(self, data):
        pass


class _ConfigEntryNotReady(Exception):
    pass


class _UpdateFailed(Exception):
    pass


class _FakeStore:
    """In-memory stand-in for homeassistant.helpers.storage.Store, keyed like the real one."""

    saved: dict[str, dict] = {}

    def __class_getitem__(cls, item):
        return cls

    def __init__(self, hass, version, key):
        self.key = key

    async def async_load(self):
        return self.saved.get(self.key)

    async def async_save(self, data):
        self.saved[self.key] = data

    def async_delay_save(self, data_func, delay=0):
        self.saved[self.key] = data_func()

    async def async_remove(self):
        self.saved.pop(self.key, None)


_ha_ce.ConfigEntry = _FakeConfigEntry
_ha_ce.ConfigFlow = type("ConfigFlow", (), {"domain": ""})
_ha_ce.ConfigFlowResult = type("ConfigFlowResult", (), {})
_ha_core.HomeAssistant = type("HomeAssistant", (), {})
_ha_core.callback = lambda f: f
_ha_huc.DataUpdateCoordinator = _FakeDataUpdateCoordinator
_ha_huc.UpdateFailed = _UpdateFailed
_ha_ep.AddEntitiesCallback = None
_ha_storage.Store = _FakeStore
_ha_const.CONF_HOST = "host"
_ha_const.CONF_PORT = "port"
_ha_const.CONF_PASSWORD = "password"
_ha_exc.ConfigEntryNotReady = _ConfigEntryNotReady
_ha_http.StaticPathConfig = lambda *a, **kw: None
_ha_panel.async_register_panel = lambda *a, **k: None
_ha_frontend.add_extra_js_url = lambda *a: None
_ha_ws.async_register_command = lambda *a: None
_ha_ws.websocket_command = lambda x: lambda f: f
_ha_ws.async_response = lambda f: f
_ha_ws.event_message = lambda *a: None
_ha_ws.ActiveConnection = type("AC", (), {})
_vol.Required = lambda x, **kw: x
_vol.Optional = lambda x, **kw: x
_vol.Schema = lambda x: x

for mod_name, mod in [
    ("homeassistant", _ha),
    ("homeassistant.core", _ha_core),
    ("homeassistant.config_entries", _ha_ce),
    ("homeassistant.helpers", _ha_helpers),
    ("homeassistant.helpers.update_coordinator", _ha_huc),
    ("homeassistant.helpers.entity_platform", _ha_ep),
    ("homeassistant.helpers.storage", _ha_storage),
    ("homeassistant.const", _ha_const),
    ("homeassistant.exceptions", _ha_exc),
    ("homeassistant.components", _ha_comp),
    ("homeassistant.components.frontend", _ha_frontend),
    ("homeassistant.components.websocket_api", _ha_ws),
    ("homeassistant.components.http", _ha_http),
    ("homeassistant.components.panel_custom", _ha_panel),
    ("voluptuous", _vol),
]:
    sys.modules[mod_name] = mod

from custom_components.orisec.protocol import (
    OrisecConnection,
    OrisecUDPProtocol,
    PanelNoResponseError,
    PanelRefusedError,
    ParsedResponse,
)
from custom_components.orisec.coordinator import OrisecCoordinator
from custom_components.orisec.const import SEND_RETRIES


def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestSendReceiveRetry(unittest.TestCase):

    def test_retries_on_timeout(self):
        async def _test():
            conn = OrisecConnection("127.0.0.1", 44444, timeout=0.05)
            proto = OrisecUDPProtocol()
            mock_transport = MagicMock()
            conn._transport = mock_transport
            conn._protocol = proto

            # sendto does nothing — simulates dropped packets
            send_count = 0

            def fake_sendto(data):
                nonlocal send_count
                send_count += 1

            mock_transport.sendto = fake_sendto
            mock_transport.is_closing.return_value = False

            from custom_components.orisec.protocol import load_udl_pkt
            pkt = load_udl_pkt(1, 1, 1)
            with self.assertRaises(PanelNoResponseError):
                await conn.send_receive(pkt, settle_time=0.01)
            self.assertEqual(send_count, SEND_RETRIES)

        run_async(_test())

    def test_returns_on_first_success(self):
        async def _test():
            conn = OrisecConnection("127.0.0.1", 44444, timeout=1.0)
            proto = OrisecUDPProtocol()
            mock_transport = MagicMock()
            conn._transport = mock_transport
            conn._protocol = proto

            send_count = 0

            def fake_sendto(data):
                nonlocal send_count
                send_count += 1
                proto.responses.append(b"\x04\x00\x00\x00")
                proto.event.set()

            mock_transport.sendto = fake_sendto
            mock_transport.is_closing.return_value = False

            from custom_components.orisec.protocol import load_udl_pkt
            pkt = load_udl_pkt(1, 1, 1)
            responses = await conn.send_receive(pkt, settle_time=0.01)
            self.assertEqual(len(responses), 1)
            self.assertEqual(send_count, 1)

        run_async(_test())

    def test_succeeds_on_second_attempt(self):
        async def _test():
            conn = OrisecConnection("127.0.0.1", 44444, timeout=0.05)
            proto = OrisecUDPProtocol()
            mock_transport = MagicMock()
            conn._transport = mock_transport
            conn._protocol = proto

            call_count = 0

            def fake_sendto(data):
                nonlocal call_count
                call_count += 1
                if call_count >= 2:
                    proto.responses.append(b"\x04\x00\x00\x00")
                    proto.event.set()

            mock_transport.sendto = fake_sendto
            mock_transport.is_closing.return_value = False

            from custom_components.orisec.protocol import load_udl_pkt
            pkt = load_udl_pkt(1, 1, 1)
            responses = await conn.send_receive(pkt, settle_time=0.01)
            self.assertEqual(len(responses), 1)
            self.assertEqual(call_count, 2)

        run_async(_test())


class TestCoordinatorSetupRetry(unittest.TestCase):

    def test_setup_retries_on_failure_then_succeeds(self):
        async def _test():
            hass = MagicMock()
            coord = OrisecCoordinator(hass, "127.0.0.1", 99999, "1234")

            call_count = 0

            async def mock_connect():
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise ConnectionError("refused")

            async def mock_disconnect():
                pass

            async def mock_login():
                coord.panel_type = "CP20"
                coord.max_zones = 10
                coord.max_areas = 2

            async def mock_config():
                pass

            async def mock_initial():
                pass

            coord._conn.connect = mock_connect
            coord._conn.disconnect = mock_disconnect
            coord._do_login = mock_login
            coord._do_config = mock_config
            coord._do_initial_data = mock_initial

            await coord.async_setup()
            self.assertEqual(coord._stage, 3)
            self.assertGreaterEqual(call_count, 3)

        run_async(_test())

    def test_setup_raises_after_all_retries_exhausted(self):
        async def _test():
            hass = MagicMock()
            coord = OrisecCoordinator(hass, "127.0.0.1", 99999, "1234")

            async def mock_connect():
                raise ConnectionError("refused")

            async def mock_disconnect():
                pass

            coord._conn.connect = mock_connect
            coord._conn.disconnect = mock_disconnect

            with self.assertRaises(ConnectionError):
                await coord.async_setup()

        run_async(_test())


class TestConfigEntryNotReady(unittest.TestCase):

    def test_setup_entry_raises_config_entry_not_ready(self):
        async def _test():
            from custom_components.orisec import async_setup_entry
            from custom_components.orisec.const import CONF_PANEL_IP, CONF_PANEL_PORT, CONF_PASSWORD

            hass = MagicMock()
            hass.data = {}
            hass.http = AsyncMock()
            hass.http.async_register_static_paths = AsyncMock()
            hass.config_entries = AsyncMock()

            entry = MagicMock()
            entry.data = {
                CONF_PANEL_IP: "127.0.0.1",
                CONF_PANEL_PORT: 20202,
                CONF_PASSWORD: "bad",
            }
            entry.entry_id = "test_entry"

            with patch(
                "custom_components.orisec.OrisecCoordinator.async_setup",
                side_effect=ConnectionError("refused"),
            ), patch(
                "custom_components.orisec.async_register_panel",
                new_callable=AsyncMock,
            ):
                with self.assertRaises(_ConfigEntryNotReady) as ctx:
                    await async_setup_entry(hass, entry)
                self.assertIn("127.0.0.1", str(ctx.exception))
                self.assertIn("20202", str(ctx.exception))
                self.assertIn("refused", str(ctx.exception))

        run_async(_test())

    def test_failed_setup_releases_local_port_for_retry(self):
        async def _test():
            from custom_components.orisec import async_setup_entry
            from custom_components.orisec.const import CONF_PANEL_IP, CONF_PANEL_PORT, CONF_PASSWORD

            hass = MagicMock()
            hass.data = {}
            hass.http = AsyncMock()
            hass.config_entries = AsyncMock()
            entry = MagicMock()
            entry.data = {
                CONF_PANEL_IP: "127.0.0.1",
                CONF_PANEL_PORT: 44444,
                CONF_PASSWORD: "1234",
            }

            async def connect_then_refuse(coord):
                await coord._conn.connect()
                raise PanelRefusedError("refused")

            with patch(
                "custom_components.orisec.OrisecCoordinator.async_setup",
                autospec=True,
                side_effect=connect_then_refuse,
            ), patch(
                "custom_components.orisec.async_register_panel",
                new_callable=AsyncMock,
            ):
                with self.assertRaises(_ConfigEntryNotReady):
                    await async_setup_entry(hass, entry)
            await asyncio.sleep(0)

            # HA's retry builds a fresh connection; it must get the fixed port back.
            retry = OrisecConnection("127.0.0.1", 44444)
            await retry.connect()
            try:
                self.assertEqual(
                    retry._transport.get_extra_info("sockname")[1], retry.local_port
                )
            finally:
                await retry.disconnect()

        run_async(_test())


class TestReconnectLoop(unittest.TestCase):

    def test_reconnect_retries_then_succeeds(self):
        async def _test():
            hass = MagicMock()
            hass.async_create_task = lambda coro, name=None: asyncio.ensure_future(coro)
            coord = OrisecCoordinator(hass, "127.0.0.1", 99999, "1234")
            coord.max_zones = 10
            coord.max_areas = 2

            attempt = 0

            async def mock_connect():
                nonlocal attempt
                attempt += 1
                if attempt < 3:
                    raise ConnectionError("refused")

            async def mock_disconnect():
                pass

            async def mock_login():
                coord.panel_type = "CP20"

            async def mock_config():
                pass

            async def mock_initial():
                pass

            coord._conn.connect = mock_connect
            coord._conn.disconnect = mock_disconnect
            coord._do_login = mock_login
            coord._do_config = mock_config
            coord._do_initial_data = mock_initial

            # Patch sleep to speed up the test
            with patch("custom_components.orisec.coordinator.asyncio.sleep", new_callable=AsyncMock):
                await coord._reconnect()

            self.assertEqual(coord._stage, 3)
            self.assertEqual(coord._reconnect_attempts, 0)

        run_async(_test())

    def test_shutdown_cancels_reconnect(self):
        async def _test():
            hass = MagicMock()
            coord = OrisecCoordinator(hass, "127.0.0.1", 99999, "1234")

            async def mock_disconnect():
                pass

            coord._conn.disconnect = mock_disconnect

            # Simulate a running reconnect task
            async def long_reconnect():
                await asyncio.sleep(100)

            coord._reconnect_task = asyncio.ensure_future(long_reconnect())
            self.assertFalse(coord._reconnect_task.done())

            await coord.async_shutdown()
            # Task should be cancelled
            self.assertTrue(
                coord._reconnect_task is None
                or coord._reconnect_task.cancelled()
                or coord._reconnect_task.done()
            )

        run_async(_test())


class TestUpdateDataDisconnected(unittest.TestCase):

    def test_update_data_raises_update_failed_when_disconnected(self):
        async def _test():
            hass = MagicMock()
            hass.async_create_task = lambda coro, name=None: asyncio.ensure_future(coro)
            coord = OrisecCoordinator(hass, "127.0.0.1", 99999, "1234")
            coord._stage = 0

            async def mock_disconnect():
                pass

            async def never_connect():
                raise ConnectionError("refused")

            coord._conn.connect = never_connect
            coord._conn.disconnect = mock_disconnect
            coord._conn._transport = None

            with patch("custom_components.orisec.coordinator.asyncio.sleep", new_callable=AsyncMock):
                with self.assertRaises(_UpdateFailed) as ctx:
                    await coord._async_update_data()
                self.assertIn("Not connected", str(ctx.exception))
                # A reconnect task should have been started
                self.assertIsNotNone(coord._reconnect_task)

            # Clean up
            coord._cancel_reconnect()

        run_async(_test())


class TestSocketReuse(unittest.TestCase):

    def test_connect_is_noop_when_socket_open(self):
        async def _test():
            conn = OrisecConnection("127.0.0.1", 44444)
            await conn.connect()
            first = conn._transport
            try:
                await conn.connect()
                self.assertIs(conn._transport, first)
            finally:
                await conn.disconnect()

        run_async(_test())

    def test_connect_recreates_closed_socket(self):
        async def _test():
            conn = OrisecConnection("127.0.0.1", 44444)
            await conn.connect()
            first = conn._transport
            first.close()
            try:
                await conn.connect()
                self.assertIsNot(conn._transport, first)
                self.assertTrue(conn.connected)
            finally:
                await conn.disconnect()

        run_async(_test())

    def test_reconnect_and_poll_failure_keep_socket(self):
        async def _test():
            hass = MagicMock()
            hass.async_create_task = lambda coro, name=None: asyncio.ensure_future(coro)
            coord = OrisecCoordinator(hass, "127.0.0.1", 44444, "1234")
            coord.max_zones = 10
            coord.max_areas = 2
            coord._stage = 3

            disconnect = AsyncMock()
            coord._conn.disconnect = disconnect
            coord._conn._transport = MagicMock()
            coord._conn._transport.is_closing.return_value = False
            coord._conn.multi_query = AsyncMock(side_effect=ConnectionError("boom"))
            coord._conn.connect = AsyncMock()
            coord._do_login = AsyncMock()
            coord._do_config = AsyncMock()
            coord._do_initial_data = AsyncMock()

            with patch("custom_components.orisec.coordinator.asyncio.sleep", new_callable=AsyncMock):
                with self.assertRaises(_UpdateFailed):
                    await coord._async_update_data()
                await coord._reconnect_task

            disconnect.assert_not_called()
            self.assertEqual(coord._stage, 3)

        run_async(_test())


class TestRefusedBackoff(unittest.TestCase):

    def test_send_receive_raises_refused_without_retrying(self):
        async def _test():
            conn = OrisecConnection("127.0.0.1", 44444, timeout=1.0)
            proto = OrisecUDPProtocol()
            transport = MagicMock()
            conn._transport = transport
            conn._protocol = proto

            def fake_sendto(data):
                proto.error_received(ConnectionRefusedError(111, "Connection refused"))

            transport.sendto = MagicMock(side_effect=fake_sendto)

            from custom_components.orisec.protocol import load_udl_pkt
            with self.assertRaises(PanelRefusedError):
                await conn.send_receive(load_udl_pkt(1, 1, 1), settle_time=0.01)
            self.assertEqual(transport.sendto.call_count, 1)

        run_async(_test())

    def test_setup_gives_up_immediately_when_refused(self):
        async def _test():
            coord = OrisecCoordinator(MagicMock(), "127.0.0.1", 44444, "1234")
            coord._conn.connect = AsyncMock()
            coord._do_login = AsyncMock(side_effect=PanelRefusedError("refused"))

            with patch("custom_components.orisec.coordinator.asyncio.sleep", new_callable=AsyncMock):
                with self.assertRaises(PanelRefusedError):
                    await coord.async_setup()
            self.assertEqual(coord._do_login.call_count, 1)

        run_async(_test())

    def test_backoff_is_long_after_refusal_and_capped(self):
        coord = OrisecCoordinator(MagicMock(), "127.0.0.1", 44444, "1234")

        coord._last_error_refused = True
        self.assertTrue(30 <= coord._backoff_delay(1) < 31)
        self.assertTrue(60 <= coord._backoff_delay(2) < 61)
        self.assertTrue(600 <= coord._backoff_delay(10) < 601)

        coord._last_error_refused = False
        self.assertTrue(2 <= coord._backoff_delay(1) < 3)
        self.assertTrue(60 <= coord._backoff_delay(10) < 61)

    def test_reconnect_switches_to_long_backoff_after_refusal(self):
        async def _test():
            hass = MagicMock()
            coord = OrisecCoordinator(hass, "127.0.0.1", 44444, "1234")
            coord._conn.connect = AsyncMock()
            coord._do_login = AsyncMock(side_effect=[PanelRefusedError("refused"), None])
            coord._do_config = AsyncMock()
            coord._do_initial_data = AsyncMock()

            sleep = AsyncMock()
            with patch("custom_components.orisec.coordinator.asyncio.sleep", sleep):
                await coord._reconnect()

            delays = [c.args[0] for c in sleep.call_args_list]
            self.assertLess(delays[0], 4)
            self.assertGreaterEqual(delays[1], 60)
            self.assertEqual(coord._stage, 3)
            self.assertFalse(coord._last_error_refused)

        run_async(_test())


class TestFixedLocalPort(unittest.TestCase):

    def test_local_port_is_stable_and_in_range(self):
        from custom_components.orisec.const import LOCAL_PORT_BASE, LOCAL_PORT_RANGE
        from custom_components.orisec.protocol import local_port_for

        port = local_port_for("192.168.1.15", 10101)
        self.assertEqual(port, local_port_for("192.168.1.15", 10101))
        self.assertTrue(LOCAL_PORT_BASE <= port < LOCAL_PORT_BASE + LOCAL_PORT_RANGE)

    def test_new_connection_reuses_same_local_port(self):
        async def _test():
            first = OrisecConnection("127.0.0.1", 44444)
            await first.connect()
            port_a = first._transport.get_extra_info("sockname")[1]
            await first.disconnect()
            await asyncio.sleep(0)

            # A fresh connection object stands in for HA restarting.
            second = OrisecConnection("127.0.0.1", 44444)
            await second.connect()
            try:
                port_b = second._transport.get_extra_info("sockname")[1]
            finally:
                await second.disconnect()

            self.assertEqual(port_a, first.local_port)
            self.assertEqual(port_a, port_b)

        run_async(_test())

    def test_falls_back_to_random_port_when_in_use(self):
        async def _test():
            holder = OrisecConnection("127.0.0.1", 44444)
            await holder.connect()
            other = OrisecConnection("127.0.0.1", 44444)
            try:
                with self.assertLogs("custom_components.orisec.protocol", "WARNING"):
                    await other.connect()
                self.assertTrue(other.connected)
                self.assertNotEqual(
                    other._transport.get_extra_info("sockname")[1], holder.local_port
                )
            finally:
                await other.disconnect()
                await holder.disconnect()

        run_async(_test())


class TestPollInterval(unittest.TestCase):

    def test_polls_faster_only_while_keypad_open(self):
        from datetime import timedelta
        from custom_components.orisec.const import KEYPAD_POLL_INTERVAL, POLL_INTERVAL

        coord = OrisecCoordinator(MagicMock(), "127.0.0.1", 44444, "1234")
        self.assertEqual(coord.update_interval, timedelta(seconds=POLL_INTERVAL))

        unsub_a = coord.keypad_subscribe(lambda state: None)
        unsub_b = coord.keypad_subscribe(lambda state: None)
        self.assertEqual(coord.update_interval, timedelta(seconds=KEYPAD_POLL_INTERVAL))

        unsub_a()
        self.assertEqual(coord.update_interval, timedelta(seconds=KEYPAD_POLL_INTERVAL))
        unsub_b()
        self.assertEqual(coord.update_interval, timedelta(seconds=POLL_INTERVAL))



def _connected_coordinator() -> OrisecCoordinator:
    coord = OrisecCoordinator(MagicMock(), "127.0.0.1", 44444, "1234")
    coord._conn._transport = MagicMock()
    coord._conn._transport.is_closing.return_value = False
    coord._conn._protocol = OrisecUDPProtocol()
    coord._stage = 3
    coord.max_zones = 10
    coord._start_reconnect = MagicMock()
    return coord


def _status_response(armed_mask: int) -> ParsedResponse:
    from custom_components.orisec.const import QUERY_SYS_OUTPUT_STATE, SOS_ARMED

    result = ParsedResponse()
    result.commands.append({"cmd": QUERY_SYS_OUTPUT_STATE})
    result.sys_output_state[SOS_ARMED] = armed_mask
    return result


class TestSocketLock(unittest.TestCase):

    def test_concurrent_requests_each_get_their_own_reply(self):
        async def _test():
            from custom_components.orisec.protocol import load_udl_pkt, trim_packet

            conn = OrisecConnection("127.0.0.1", 44444, timeout=1.0)
            proto = OrisecUDPProtocol()
            conn._protocol = proto
            conn._transport = MagicMock()
            conn._transport.is_closing.return_value = False
            loop = asyncio.get_event_loop()
            # The panel echoes each request back after a short delay.
            conn._transport.sendto = lambda data: loop.call_later(
                0.02, proto.datagram_received, data, ("127.0.0.1", 44444)
            )

            pkt_a, pkt_b = load_udl_pkt(10, 1, 1), load_udl_pkt(20, 1, 1)
            replies_a, replies_b = await asyncio.gather(
                conn.send_receive(pkt_a, settle_time=0.01),
                conn.send_receive(pkt_b, settle_time=0.01),
            )
            self.assertEqual(replies_a, [trim_packet(pkt_a)])
            self.assertEqual(replies_b, [trim_packet(pkt_b)])

        run_async(_test())


class TestPollRejectsMissingStatus(unittest.TestCase):

    def test_reply_without_status_keeps_last_state_and_reconnects(self):
        async def _test():
            from custom_components.orisec.const import SOS_ARMED

            coord = _connected_coordinator()
            coord.sys_output_state[SOS_ARMED] = 0x01
            coord._conn.multi_query = AsyncMock(return_value=ParsedResponse(error=1))

            with self.assertRaises(_UpdateFailed):
                await coord._async_update_data()
            self.assertEqual(coord.sys_output_state[SOS_ARMED], 0x01)
            self.assertEqual(coord._stage, 0)
            coord._start_reconnect.assert_called_once()

        run_async(_test())

    def test_unanswered_poll_keeps_last_state_and_reconnects(self):
        async def _test():
            from custom_components.orisec.const import SOS_ARMED

            coord = _connected_coordinator()
            coord.sys_output_state[SOS_ARMED] = 0x01
            coord._conn.multi_query = AsyncMock(side_effect=PanelNoResponseError("silent"))

            with self.assertRaises(_UpdateFailed):
                await coord._async_update_data()
            self.assertEqual(coord.sys_output_state[SOS_ARMED], 0x01)
            coord._start_reconnect.assert_called_once()

        run_async(_test())

    def test_reply_with_status_updates_state(self):
        async def _test():
            from custom_components.orisec.const import SOS_ARMED

            coord = _connected_coordinator()
            coord._conn.multi_query = AsyncMock(return_value=_status_response(0x01))

            await coord._async_update_data()
            self.assertEqual(coord.sys_output_state[SOS_ARMED], 0x01)
            coord._start_reconnect.assert_not_called()

        run_async(_test())


class TestReconnectLoad(unittest.TestCase):

    def _coordinator(self) -> OrisecCoordinator:
        coord = OrisecCoordinator(MagicMock(), "127.0.0.1", 44444, "1234")
        coord._conn.connect = AsyncMock()
        coord._do_login = AsyncMock()
        coord._do_config = AsyncMock()
        coord._do_initial_data = AsyncMock()
        coord._do_status = AsyncMock()
        coord.on_metadata_updated = MagicMock()
        return coord

    def test_first_connect_loads_metadata_and_reports_it(self):
        async def _test():
            coord = self._coordinator()
            with patch("custom_components.orisec.coordinator.asyncio.sleep", new_callable=AsyncMock):
                await coord._reconnect()

            coord._do_initial_data.assert_awaited_once()
            coord._do_status.assert_not_awaited()
            coord.on_metadata_updated.assert_called_once()

        run_async(_test())

    def test_reconnect_skips_metadata_once_loaded(self):
        async def _test():
            coord = self._coordinator()
            coord._metadata_fresh = True
            with patch("custom_components.orisec.coordinator.asyncio.sleep", new_callable=AsyncMock):
                await coord._reconnect()

            coord._do_status.assert_awaited_once()
            coord._do_initial_data.assert_not_awaited()
            coord.on_metadata_updated.assert_not_called()
            self.assertEqual(coord._stage, 3)

        run_async(_test())

    def test_status_reply_without_status_block_fails_reconnect_attempt(self):
        async def _test():
            coord = OrisecCoordinator(MagicMock(), "127.0.0.1", 44444, "1234")
            coord._conn.multi_query = AsyncMock(return_value=ParsedResponse())
            with self.assertRaises(_UpdateFailed):
                await coord._do_status()

        run_async(_test())


class TestMetadataCache(unittest.TestCase):

    def setUp(self):
        _FakeStore.saved.clear()

    @staticmethod
    def _entry(entry_id: str):
        from custom_components.orisec.const import CONF_PANEL_IP, CONF_PANEL_PORT, CONF_PASSWORD

        entry = MagicMock()
        entry.entry_id = entry_id
        entry.data = {CONF_PANEL_IP: "127.0.0.1", CONF_PANEL_PORT: 44444, CONF_PASSWORD: "1234"}
        return entry

    @staticmethod
    def _hass():
        hass = MagicMock()
        hass.data = {}
        hass.http = AsyncMock()
        hass.config_entries = AsyncMock()
        hass.async_create_task = lambda coro, name=None: asyncio.ensure_future(coro)
        return hass

    def test_metadata_round_trips_through_json(self):
        import json

        coord = OrisecCoordinator(MagicMock(), "127.0.0.1", 44444, "1234")
        coord.panel_type, coord.serial = "CP20", "ABC123"
        coord.max_zones, coord.max_areas, coord.max_rem_outputs = 20, 2, 4
        coord.zone_names = ["Front Door", "Hall PIR"]
        coord.area_names = ["House", "Garage"]
        coord.zone_types, coord.zone_areas = bytes([1, 2, 0]), bytes([1, 1, 2])

        restored = OrisecCoordinator(MagicMock(), "127.0.0.1", 44444, "1234")
        restored.restore_metadata(json.loads(json.dumps(coord.export_metadata())))

        self.assertEqual(restored.export_metadata(), coord.export_metadata())
        self.assertEqual(restored.zone_types, bytes([1, 2, 0]))
        self.assertFalse(restored._metadata_fresh)

    def test_first_setup_caches_panel_configuration(self):
        async def _test():
            from custom_components.orisec import async_setup_entry

            async def fake_initial_data(coord):
                coord.zone_names = ["Front Door"]

            hass, entry = self._hass(), self._entry("first_setup")
            with patch.object(OrisecConnection, "connect", AsyncMock()), patch.object(
                OrisecCoordinator, "_do_login", AsyncMock()
            ), patch.object(OrisecCoordinator, "_do_config", AsyncMock()), patch.object(
                OrisecCoordinator, "_do_initial_data", autospec=True, side_effect=fake_initial_data
            ), patch(
                "custom_components.orisec.coordinator.asyncio.sleep", new_callable=AsyncMock
            ), patch("custom_components.orisec.async_register_panel", new_callable=AsyncMock):
                await async_setup_entry(hass, entry)

            self.assertEqual(_FakeStore.saved["orisec.first_setup"]["zone_names"], ["Front Door"])

        run_async(_test())

    def test_cached_setup_starts_without_panel_and_connects_in_background(self):
        async def _test():
            from custom_components.orisec import async_setup_entry
            from custom_components.orisec.const import DOMAIN

            _FakeStore.saved["orisec.cached"] = {"max_zones": 20, "zone_names": ["Front Door"]}
            hass, entry = self._hass(), self._entry("cached")

            with patch(
                "custom_components.orisec.OrisecCoordinator.async_setup", new_callable=AsyncMock
            ) as setup, patch("custom_components.orisec.async_register_panel", new_callable=AsyncMock):
                self.assertTrue(await async_setup_entry(hass, entry))

            coord = hass.data[DOMAIN]["cached"]
            try:
                setup.assert_not_awaited()
                self.assertEqual(coord.max_zones, 20)
                self.assertEqual(coord.zone_names, ["Front Door"])
                self.assertFalse(coord.last_update_success)
                self.assertFalse(coord._reconnect_task.done())
                hass.config_entries.async_forward_entry_setups.assert_awaited_once()
            finally:
                await coord.async_shutdown()

        run_async(_test())

    def test_removing_entry_deletes_cache(self):
        async def _test():
            from custom_components.orisec import async_remove_entry

            _FakeStore.saved["orisec.gone"] = {"max_zones": 20}
            await async_remove_entry(self._hass(), self._entry("gone"))
            self.assertNotIn("orisec.gone", _FakeStore.saved)

        run_async(_test())


if __name__ == "__main__":
    unittest.main()
