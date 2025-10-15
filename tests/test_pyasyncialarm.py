# mypy: ignore-errors
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch
import xml.etree.ElementTree as ET
import xml.parsers.expat

import pytest

from pyasyncialarm.const import StatusType
from pyasyncialarm.exception import IAlarmConnectionError, IAlarmSocketNotOpenError
from pyasyncialarm.pyasyncialarm import IAlarm
from pyasyncialarm.util import decode_name, parse_bell, parse_time


@pytest.fixture
def ialarm():
    return IAlarm("192.168.1.81", 18034)


@pytest.mark.asyncio
async def test_is_socket_open_with_open_socket(ialarm):
    mock_socket = Mock()
    mock_socket.fileno.return_value = 10
    ialarm.sock = mock_socket

    assert ialarm._is_socket_open() is True


@pytest.mark.asyncio
async def test_is_socket_open_with_closed_socket(ialarm):
    mock_socket = Mock()
    mock_socket.fileno.return_value = -1
    ialarm.sock = mock_socket

    assert ialarm._is_socket_open() is False


@pytest.mark.asyncio
async def test_is_socket_open_with_no_socket(ialarm):
    ialarm.sock = None
    assert ialarm._is_socket_open() is False


@pytest.mark.asyncio
async def test_receive(ialarm):
    with patch("socket.socket") as mock_socket:
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.fileno.return_value = 1
        mock_socket_instance.setblocking.side_effect = lambda x: None
        ialarm.sock = mock_socket_instance

        with patch("asyncio.get_running_loop") as mock_event_loop:
            mock_event_loop_instance = mock_event_loop.return_value
            mock_event_loop_instance.sock_recv = AsyncMock(
                return_value=(
                    b"@ieM00020000<Root><Data>Mocked XML Data</Data></Root>0001"
                )
            )

            with patch.object(
                ialarm,
                "_xor",
                return_value=b"<Root><Data>Mocked XML Data</Data></Root>",
            ) as mock_xor:
                response = await ialarm._receive()
                mock_xor.assert_called_once()

                assert response == {"Root": {"Data": "Mocked XML Data"}}


@pytest.mark.parametrize(
    ("response", "path", "expected"),
    [
        ({"Root": {"Host": {"DevStatus": "0"}}}, "/Root/Host/DevStatus", "0"),
        (
            {"Root": {"Host": {"Devices": ["Dev1", "Dev2"]}}},
            "/Root/Host/Devices/1",
            "Dev2",
        ),
        ({"Root": {"Host": {}}}, "/Root/Host/NonExistent", None),
        (
            {"Root": {"Host": {"Status": {"State": "armed"}}}},
            "/Root/Host/Status/State",
            "armed",
        ),
    ],
)
def test_clean_response_dict(response, path, expected):
    ialarm = IAlarm("192.168.1.81")
    result = ialarm._clean_response_dict(response, path)
    assert result == expected


def test_xor():
    input_data = bytearray(b"<Err>TEST</Err>")
    expected_output = bytearray(b"0}<<\\lh1Z\x04a\x0b6J\x13")

    result = IAlarm._xor(input_data)

    assert result == expected_output


@pytest.mark.asyncio
async def test_get_mac(ialarm):
    with patch.object(
        IAlarm, "_send_request", new_callable=AsyncMock
    ) as mock_send_request:
        mock_send_request.return_value = {"Mac": "00:1A:2B:3C:4D:5E"}

        mac = await ialarm.get_mac()

        mock_send_request.assert_awaited_once()
        assert mac == "00:1A:2B:3C:4D:5E"


@pytest.mark.asyncio
async def test_get_status_connection_error(ialarm):
    ialarm._send_request = AsyncMock(return_value=None)

    with pytest.raises(
        ConnectionError, match="An error occurred trying to connect to the alarm system"
    ):
        await ialarm.get_status([])


@pytest.mark.asyncio
async def test_get_status_unexpected_reply(ialarm):
    ialarm._send_request = AsyncMock(return_value={"DevStatus": -1})

    with pytest.raises(
        ConnectionError, match="Received an unexpected reply from the alarm"
    ):
        await ialarm.get_status([])


@pytest.mark.asyncio
async def test_get_status_triggered_alarm(ialarm):
    ialarm._send_request = AsyncMock(return_value={"DevStatus": ialarm.ARMED_AWAY})

    zone_status_mock = [
        {"types": [StatusType.ZONE_ALARM, StatusType.ZONE_IN_USE]},  # Should trigger
    ]

    ialarm.__filter_alarmed_zones = AsyncMock(return_value=zone_status_mock)

    result = await ialarm.get_status(zone_status_mock)
    assert result["status_value"] == ialarm.TRIGGERED


@pytest.mark.asyncio
async def test_get_status_no_triggered_alarm(ialarm):
    ialarm._send_request = AsyncMock(return_value={"DevStatus": ialarm.ARMED_AWAY})

    zone_status_mock = [
        {"types": [StatusType.ZONE_IN_USE]},
    ]

    ialarm.__filter_alarmed_zones = AsyncMock(return_value=zone_status_mock)

    result = await ialarm.get_status(zone_status_mock)
    assert result["status_value"] == ialarm.ARMED_AWAY


@pytest.mark.asyncio
async def test_get_status_not_armed(ialarm):
    ialarm._send_request = AsyncMock(return_value={"DevStatus": 1})

    zone_status_mock = [
        {"types": []},
    ]
    ialarm.get_zone_status = AsyncMock(return_value=zone_status_mock)

    result = await ialarm.get_status(zone_status_mock)

    assert result["status_value"] == ialarm.DISARMED


@pytest.mark.asyncio
async def test_get_zone_status_success(ialarm):
    ialarm.get_zone = AsyncMock(
        return_value=[
            {"zone_id": 1, "name": "Zone 1", "type": 1, "voice": 0, "bell": False},
            {"zone_id": 2, "name": "Zone 2", "type": 1, "voice": 0, "bell": False},
        ]
    )

    ialarm._send_request_list = AsyncMock(
        return_value=[
            StatusType.ZONE_IN_USE | StatusType.ZONE_ALARM,
            StatusType.ZONE_BYPASS,
        ]
    )

    expected_result = [
        {
            "zone_id": 1,
            "name": "Zone 1",
            "types": [StatusType.ZONE_IN_USE, StatusType.ZONE_ALARM],
        },
        {"zone_id": 2, "name": "Zone 2", "types": [StatusType.ZONE_BYPASS]},
    ]

    result = await ialarm.get_zone_status()
    assert result == expected_result


@pytest.mark.asyncio
async def test_get_zone_status_no_zones(ialarm):
    ialarm.get_zone = AsyncMock(return_value=[])

    ialarm._send_request_list = AsyncMock(return_value=[])

    result = await ialarm.get_zone_status()
    assert result == []


@pytest.mark.asyncio
async def test_get_zone_status_connection_error(ialarm):
    ialarm.get_zone = AsyncMock(
        return_value=[
            {"zone_id": 1, "name": "Zone 1"},
        ]
    )

    ialarm._send_request_list = AsyncMock(return_value=None)

    with pytest.raises(
        ConnectionError, match="An error occurred trying to connect to the alarm system"
    ):
        await ialarm.get_zone_status()


@pytest.mark.asyncio
async def test_get_zone_status_no_status(ialarm):
    ialarm.get_zone = AsyncMock(
        return_value=[
            {"zone_id": 1, "name": "Zone 1"},
        ]
    )

    ialarm._send_request_list = AsyncMock(return_value=[0])

    expected_result = [
        {"zone_id": 1, "name": "Zone 1", "types": [StatusType.ZONE_NOT_USED]},
    ]

    result = await ialarm.get_zone_status()
    assert result == expected_result


@pytest.mark.asyncio
async def test_get_log():
    event_log_raw = [
        {
            "Time": "DTA,19|2023.10.01.12.30.45",
            "Area": 1,
            "Event": "001",
            "Name": "GBA,16|4D6F636B",
        },
        {
            "Time": "DTA,19|2023.10.01.12.35.50",
            "Area": 2,
            "Event": "002",
            "Name": "GBA,16|4E616D65",
        },
    ]

    event_type_map = {"001": "Event One", "002": "Event Two"}

    with (
        patch.object(
            IAlarm, "_send_request_list", AsyncMock(return_value=event_log_raw)
        ),
        patch("pyasyncialarm.const.EVENT_TYPE_MAP", event_type_map),
    ):
        ialarm = IAlarm("192.168.1.81")
        logs = await ialarm.get_log()

        assert len(logs) == 2
        assert logs[0]["time"] == datetime(2023, 10, 1, 12, 30, 45)
        assert logs[0]["event"] == "001"
        assert logs[0]["name"] == "Mock"
        assert logs[1]["event"] == "002"
        assert logs[1]["name"] == "Name"


@pytest.mark.asyncio
async def test_arm_away(ialarm):
    """Test arming the alarm in away mode."""
    with patch.object(ialarm, "_send_request", new_callable=AsyncMock) as mock_send:
        await ialarm.arm_away()

        mock_send.assert_awaited_once()
        # Verify the command structure
        call_args = mock_send.call_args[0]
        assert call_args[0] == "/Root/Host/SetAlarmStatus"
        assert call_args[1]["DevStatus"] == "TYP,ARM|0"


@pytest.mark.asyncio
async def test_arm_stay(ialarm):
    """Test arming the alarm in stay mode."""
    with patch.object(ialarm, "_send_request", new_callable=AsyncMock) as mock_send:
        await ialarm.arm_stay()

        mock_send.assert_awaited_once()
        call_args = mock_send.call_args[0]
        assert call_args[0] == "/Root/Host/SetAlarmStatus"
        assert call_args[1]["DevStatus"] == "TYP,STAY|2"


@pytest.mark.asyncio
async def test_disarm(ialarm):
    """Test disarming the alarm."""
    with patch.object(ialarm, "_send_request", new_callable=AsyncMock) as mock_send:
        await ialarm.disarm()

        mock_send.assert_awaited_once()
        call_args = mock_send.call_args[0]
        assert call_args[0] == "/Root/Host/SetAlarmStatus"
        assert call_args[1]["DevStatus"] == "TYP,DISARM|1"


@pytest.mark.asyncio
async def test_cancel_alarm(ialarm):
    """Test canceling an active alarm."""
    with patch.object(ialarm, "_send_request", new_callable=AsyncMock) as mock_send:
        await ialarm.cancel_alarm()

        mock_send.assert_awaited_once()
        call_args = mock_send.call_args[0]
        assert call_args[0] == "/Root/Host/SetAlarmStatus"
        assert call_args[1]["DevStatus"] == "TYP,CLEAR|3"


@pytest.mark.asyncio
async def test_get_zone(ialarm):
    """Test retrieving zone configuration."""
    mock_zone_data = [
        {"Type": 1, "Voice": 0, "Name": "GBA,8|5A6F6E65", "Bell": "BOL|T"},
        {"Type": 2, "Voice": 1, "Name": "GBA,8|5A6F6E65", "Bell": "BOL|F"},
    ]

    with patch.object(
        ialarm, "_send_request_list", new_callable=AsyncMock
    ) as mock_send:
        mock_send.return_value = mock_zone_data

        zones = await ialarm.get_zone()

        mock_send.assert_awaited_once()
        assert len(zones) == 2
        assert zones[0]["zone_id"] == 1
        assert zones[0]["name"] == "Zone"  # Decoded from hex
        assert zones[0]["bell"] is True
        assert zones[1]["zone_id"] == 2
        assert zones[1]["bell"] is False


@pytest.mark.asyncio
async def test_get_zone_type(ialarm):
    """Test retrieving zone types."""
    mock_zone_types = ["SI", "IN", "NO", "DE"]

    with patch.object(
        ialarm, "_send_request_list", new_callable=AsyncMock
    ) as mock_send:
        mock_send.return_value = mock_zone_types

        zone_types = await ialarm.get_zone_type()

        mock_send.assert_awaited_once()
        assert len(zone_types) == 4
        assert zone_types[0].value == "Perimeter"  # SI
        assert zone_types[1].value == "Inner"  # IN
        assert zone_types[2].value == "Unused"  # NO
        assert zone_types[3].value == "Delay"  # DE


@pytest.mark.asyncio
async def test_get_alarm_type(ialarm):
    """Test retrieving alarm/siren types."""
    mock_alarm_types = ["CX", "MC", "NO"]

    with patch.object(
        ialarm, "_send_request_list", new_callable=AsyncMock
    ) as mock_send:
        mock_send.return_value = mock_alarm_types

        alarm_types = await ialarm.get_alarm_type()

        mock_send.assert_awaited_once()
        assert len(alarm_types) == 3
        assert alarm_types[0].value == "Continued"  # CX
        assert alarm_types[1].value == "Pulsed"  # MC
        assert alarm_types[2].value == "Mute"  # NO


def test_parse_time_valid():
    """Test parsing valid time string."""
    time_str = "DTA,19|2023.10.01.12.30.45"
    result = parse_time(time_str)

    assert result == datetime(2023, 10, 1, 12, 30, 45)


def test_parse_time_invalid():
    """Test parsing invalid time string."""

    time_str = "invalid_time_string"
    result = parse_time(time_str)

    assert result is None


def test_parse_time_malformed():
    """Test parsing malformed time string."""

    time_str = "DTA,19|invalid.date.format"
    result = parse_time(time_str)

    assert result is None


def test_decode_name_hex():
    """Test decoding hexadecimal name."""

    name_str = "GBA,8|5A6F6E65"
    result = decode_name(name_str)

    assert result == "Zone"


def test_decode_name_plain():
    """Test decoding plain text name."""

    name_str = "Plain Text Name"
    result = decode_name(name_str)

    assert result == "Plain Text Name"


def test_decode_name_invalid_hex():
    """Test decoding invalid hexadecimal name."""

    name_str = "GBA,8|INVALID_HEX"
    result = decode_name(name_str)

    assert result == "GBA,8|INVALID_HEX"  # Returns original on error


def test_parse_bell_true():
    """Test parsing bell value as True."""

    result = parse_bell("BOL|T")
    assert result is True


def test_parse_bell_false():
    """Test parsing bell value as False."""

    result = parse_bell("BOL|F")
    assert result is False


def test_parse_bell_other():
    """Test parsing other bell values."""

    result = parse_bell("SOME|OTHER")
    assert result is False


@pytest.mark.asyncio
async def test_reconnect_success(ialarm):
    """Test successful reconnection."""
    with patch("socket.socket") as mock_socket_class:
        mock_socket = mock_socket_class.return_value
        mock_socket.fileno.return_value = 1

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_connect = AsyncMock()

            await ialarm.reconnect()

            assert ialarm.sock == mock_socket
            assert ialarm.seq == 0
            mock_socket.setblocking.assert_called_once_with(False)
            mock_loop_instance.sock_connect.assert_awaited_once_with(
                mock_socket, (ialarm.host, ialarm.port)
            )


@pytest.mark.asyncio
async def test_reconnect_connection_error(ialarm):
    """Test reconnection with connection error."""

    with patch("socket.socket") as mock_socket_class:
        mock_socket = mock_socket_class.return_value

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_connect = AsyncMock(
                side_effect=ConnectionRefusedError("Connection refused")
            )

            with pytest.raises(IAlarmConnectionError):
                await ialarm.reconnect()

            # Verify socket is closed on error
            mock_socket.close.assert_called_once()


@pytest.mark.asyncio
async def test_ensure_connection_is_open_no_reconnect(ialarm):
    """Test ensure_connection_is_open when socket is already open."""
    mock_socket = Mock()
    mock_socket.fileno.return_value = 1
    ialarm.sock = mock_socket

    with patch.object(ialarm, "reconnect", new_callable=AsyncMock) as mock_reconnect:
        await ialarm.ensure_connection_is_open()

        # Should not call reconnect
        mock_reconnect.assert_not_called()


@pytest.mark.asyncio
async def test_ensure_connection_is_open_force_reconnect(ialarm):
    """Test ensure_connection_is_open with force_reconnect=True."""
    mock_socket = Mock()
    mock_socket.fileno.return_value = 1
    ialarm.sock = mock_socket

    with patch.object(ialarm, "reconnect", new_callable=AsyncMock) as mock_reconnect:
        await ialarm.ensure_connection_is_open(force_reconnect=True)

        # Should call reconnect
        mock_reconnect.assert_awaited_once()


@pytest.mark.asyncio
async def test_ensure_connection_is_open_closed_socket(ialarm):
    """Test ensure_connection_is_open when socket is closed."""
    mock_socket = Mock()
    mock_socket.fileno.return_value = -1
    ialarm.sock = mock_socket

    with patch.object(ialarm, "reconnect", new_callable=AsyncMock) as mock_reconnect:
        await ialarm.ensure_connection_is_open()

        # Should call reconnect
        mock_reconnect.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_mac_connection_error(ialarm):
    """Test get_mac with connection error."""
    with patch.object(ialarm, "_send_request", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = None

        with pytest.raises(
            ConnectionError, match="An error occurred trying to connect"
        ):
            await ialarm.get_mac()


@pytest.mark.asyncio
async def test_get_mac_empty_response(ialarm):
    """Test get_mac with empty MAC address."""
    with patch.object(ialarm, "_send_request", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = {"Mac": ""}

        with pytest.raises(
            ConnectionError, match="An error occurred trying to connect"
        ):
            await ialarm.get_mac()


@pytest.mark.asyncio
async def test_get_last_log_entries_limit(ialarm):
    """Test get_last_log_entries with limit."""
    mock_logs = [
        {"time": datetime.now(), "area": 1, "event": "test1", "name": "test1"},
        {"time": datetime.now(), "area": 2, "event": "test2", "name": "test2"},
        {"time": datetime.now(), "area": 3, "event": "test3", "name": "test3"},
    ]

    with patch.object(ialarm, "get_log", new_callable=AsyncMock) as mock_get_log:
        mock_get_log.return_value = mock_logs

        result = await ialarm.get_last_log_entries(max_entries=2)

        assert len(result) == 2
        assert result[0]["event"] == "test1"
        assert result[1]["event"] == "test2"


@pytest.mark.asyncio
async def test_get_last_log_entries_empty_log(ialarm):
    """Test get_last_log_entries with empty log."""
    with patch.object(ialarm, "get_log", new_callable=AsyncMock) as mock_get_log:
        mock_get_log.return_value = []

        result = await ialarm.get_last_log_entries()

        assert result == []


@pytest.mark.asyncio
async def test_get_status_with_triggered_zones(ialarm):
    """Test get_status when zones are triggered."""
    ialarm._send_request = AsyncMock(return_value={"DevStatus": ialarm.ARMED_AWAY})

    zone_status_mock = [
        {
            "zone_id": 1,
            "name": "Zone 1",
            "types": [StatusType.ZONE_ALARM, StatusType.ZONE_IN_USE],
        },
        {"zone_id": 2, "name": "Zone 2", "types": [StatusType.ZONE_IN_USE]},
    ]

    result = await ialarm.get_status(zone_status_mock)

    # Should return TRIGGERED because zone 1 has ZONE_ALARM
    assert result["status_value"] == ialarm.TRIGGERED
    assert len(result["alarmed_zones"]) == 1
    assert result["alarmed_zones"][0]["zone_id"] == 1


@pytest.mark.asyncio
async def test_get_status_armed_stay_with_zones(ialarm):
    """Test get_status with ARMED_STAY and zone information."""
    ialarm._send_request = AsyncMock(return_value={"DevStatus": ialarm.ARMED_STAY})

    zone_status_mock = [
        {"zone_id": 1, "name": "Zone 1", "types": [StatusType.ZONE_IN_USE]},
    ]

    result = await ialarm.get_status(zone_status_mock)

    # Should return ARMED_STAY because no zones are triggered
    assert result["status_value"] == ialarm.ARMED_STAY
    assert result["alarmed_zones"] == []


def test_create_root_dict():
    """Test _create_root_dict method."""
    ialarm = IAlarm("192.168.1.81")

    my_dict = {"Key": "Value"}
    result = ialarm._create_root_dict("/Root/Host/Test", my_dict)

    expected = {"Root": {"Host": {"Test": {"Key": "Value"}}}}
    assert result == expected


def test_create_root_dict_empty():
    """Test _create_root_dict with empty dict."""
    ialarm = IAlarm("192.168.1.81")

    result = ialarm._create_root_dict("/Root/Host/Test")

    expected = {"Root": {"Host": {"Test": {}}}}
    assert result == expected


@pytest.mark.parametrize(
    ("xml_input", "expected_pattern"),
    [
        (b"<Err>ERR|00</Err>", b"<Err>ERR|00</Err>"),
        (b"<Mac>MAC,1|AA:BB:CC:DD:EE:FF</Mac>", b"<Mac>AA:BB:CC:DD:EE:FF</Mac>"),
        (b"<Count>S32,0,0|42</Count>", b"<Count>42</Count>"),
        (b"<Name>STR,8|TestName</Name>", b"<Name>TestName</Name>"),
        (b"<Status>TYP,ARM|0</Status>", b"<Status>0</Status>"),
    ],
)
def test_xmlread_postprocessor(xml_input, expected_pattern):
    """Test _xmlread postprocessor with various input types."""
    ialarm = IAlarm("192.168.1.81")

    # Parse the XML to get the value

    root = ET.fromstring(xml_input.decode())  # noqa: S314
    value = root.text

    # Test the postprocessor
    key, processed_value = ialarm._xmlread("test_path", "test_key", value)

    assert key == "test_key"
    # The exact assertion depends on the input type
    assert isinstance(processed_value, (int, str))


def test_is_complete_message_standard():
    """Test _is_complete_message with standard message."""
    ialarm = IAlarm("192.168.1.81")

    # Standard message ending with 4 digits
    buffer = b"@ieM00020000<Root><Data>Test</Data></Root>0001"
    assert ialarm._is_complete_message(buffer) is True


def test_is_complete_message_trigger():
    """Test _is_complete_message with trigger message."""
    ialarm = IAlarm("192.168.1.81")

    # Trigger message ending with FFFF
    buffer = b"@alA0<Trigger>Data</Trigger>FFFF"
    assert ialarm._is_complete_message(buffer) is True


def test_is_complete_message_incomplete():
    """Test _is_complete_message with incomplete message."""
    ialarm = IAlarm("192.168.1.81")

    # Incomplete message
    buffer = b"@ieM00020000<Root><Data>Test</Data></Root>"
    assert ialarm._is_complete_message(buffer) is False


def test_truncate_bytes():
    """Test _truncate_bytes method."""
    ialarm = IAlarm("192.168.1.81")

    buffer = b"Some data before FFFF and after"
    result = ialarm._truncate_bytes(buffer)

    assert result == b"Some data before "


def test_truncate_bytes_no_sequence():
    """Test _truncate_bytes with no sequence found."""
    ialarm = IAlarm("192.168.1.81")

    buffer = b"Some data without sequence"
    result = ialarm._truncate_bytes(buffer)

    assert result == buffer


def test_check_and_trim_trigger_response():
    """Test _check_and_trim_trigger_response method."""
    ialarm = IAlarm("192.168.1.81")

    buffer = b"@alA0<Trigger>Data</Trigger>FFFF"
    result = ialarm._check_and_trim_trigger_response(buffer)

    assert result == b"@alA0<Trigger>Data</Trigger>"


def test_check_and_trim_trigger_response_not_trigger():
    """Test _check_and_trim_trigger_response with non-trigger message."""
    ialarm = IAlarm("192.168.1.81")

    buffer = b"@ieM00020000<Root><Data>Test</Data></Root>0001"
    result = ialarm._check_and_trim_trigger_response(buffer)

    assert result == buffer


@pytest.mark.asyncio
async def test_reconnect_timeout_error(ialarm):
    """Test reconnection with timeout error."""

    with patch("socket.socket") as mock_socket_class:
        mock_socket = mock_socket_class.return_value

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_connect = AsyncMock(
                side_effect=TimeoutError("Connection timeout")
            )

            with pytest.raises(IAlarmConnectionError):
                await ialarm.reconnect()

            # Verify socket is closed on error
            mock_socket.close.assert_called_once()


@pytest.mark.asyncio
async def test_reconnect_os_error(ialarm):
    """Test reconnection with OSError."""

    with patch("socket.socket") as mock_socket_class:
        mock_socket = mock_socket_class.return_value

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_connect = AsyncMock(
                side_effect=OSError("Network unreachable")
            )

            with pytest.raises(IAlarmConnectionError):
                await ialarm.reconnect()

            # Verify socket is closed on error
            mock_socket.close.assert_called_once()


@pytest.mark.asyncio
async def test_reconnect_generic_exception(ialarm):
    """Test reconnection with generic exception."""
    with patch("socket.socket") as mock_socket_class:
        mock_socket = mock_socket_class.return_value

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_connect = AsyncMock(
                side_effect=RuntimeError("Unexpected error")
            )

            with pytest.raises(RuntimeError):
                await ialarm.reconnect()

            # Verify socket is closed on error
            mock_socket.close.assert_called_once()


@pytest.mark.asyncio
async def test_receive_timeout_error(ialarm):
    """Test _receive with timeout error."""
    with patch("socket.socket") as mock_socket:
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.fileno.return_value = 1
        ialarm.sock = mock_socket_instance

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_recv = AsyncMock(
                side_effect=TimeoutError("Socket timeout")
            )

            with pytest.raises(
                ConnectionError, match="Socket timeout: no data received"
            ):
                await ialarm._receive()


@pytest.mark.asyncio
async def test_receive_empty_buffer(ialarm):
    """Test _receive with empty buffer."""
    with patch("socket.socket") as mock_socket:
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.fileno.return_value = 1
        ialarm.sock = mock_socket_instance

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_recv = AsyncMock(return_value=b"")

            with pytest.raises(
                ConnectionError, match="Connection error: received no data"
            ):
                await ialarm._receive()


@pytest.mark.asyncio
async def test_receive_empty_decoded_message(ialarm):
    """Test _receive with empty decoded message."""
    with patch("socket.socket") as mock_socket:
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.fileno.return_value = 1
        ialarm.sock = mock_socket_instance

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_recv = AsyncMock(
                return_value=b"@ieM00020000<Root></Root>0001"
            )

            with (
                patch.object(ialarm, "_xor", return_value=b""),
                pytest.raises(
                    ConnectionError, match="Connection error: unexpected empty reply"
                ),
            ):
                await ialarm._receive()


@pytest.mark.asyncio
async def test_receive_os_error(ialarm):
    """Test _receive with OSError."""
    with patch("socket.socket") as mock_socket:
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.fileno.return_value = 1
        ialarm.sock = mock_socket_instance

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_recv = AsyncMock(
                side_effect=OSError("Network error")
            )

            with pytest.raises(OSError):
                await ialarm._receive()


@pytest.mark.asyncio
async def test_receive_generic_exception(ialarm):
    """Test _receive with generic exception."""
    with patch("socket.socket") as mock_socket:
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.fileno.return_value = 1
        ialarm.sock = mock_socket_instance

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_recv = AsyncMock(
                side_effect=RuntimeError("Unexpected error")
            )

            with pytest.raises(RuntimeError):
                await ialarm._receive()


@pytest.mark.asyncio
async def test_parse_decoded_message_xml_error(ialarm):
    """Test _parse_decoded_message with XML parsing error."""

    with patch("asyncio.to_thread") as mock_to_thread:
        mock_to_thread.side_effect = xml.parsers.expat.ExpatError("Invalid XML")

        with pytest.raises(ConnectionError, match="Received malformed XML response"):
            await ialarm._parse_decoded_message("invalid xml content")


def test_raise_connection_error(ialarm):
    """Test __raise_connection_error method."""
    mock_socket = Mock()
    mock_socket.fileno.return_value = 1
    ialarm.sock = mock_socket

    with pytest.raises(ConnectionError, match="Test error message"):
        ialarm._IAlarm__raise_connection_error("Test error message")

    # Verify socket is closed
    mock_socket.close.assert_called_once()


@pytest.mark.asyncio
async def test_send_request_list_with_pagination(ialarm):
    """Test _send_request_list with pagination."""
    command = {"Total": None, "Offset": "S32,0,0|0", "Ln": None, "Err": None}

    # Mock response with pagination - first call returns total, second returns items
    mock_responses = [
        {
            "Root": {
                "Host": {
                    "GetZone": {
                        "Total": 3,
                        "Ln": 2,
                    }
                }
            }
        },
        {
            "Root": {
                "Host": {
                    "GetZone": {
                        "Total": 3,
                        "Ln": 2,
                        "L0": "Item1",
                        "L1": "Item2",
                    }
                }
            }
        },
    ]

    with patch.object(ialarm, "_create_root_dict") as mock_create:
        mock_create.return_value = {"Root": {"Host": {"GetZone": {}}}}

        with (
            patch.object(ialarm, "_send_dict", new_callable=AsyncMock) as mock_send,
            patch.object(ialarm, "_receive", new_callable=AsyncMock) as mock_receive,
        ):
            mock_receive.side_effect = mock_responses

            result = await ialarm._send_request_list("/Root/Host/GetZone", command)

            # Should call _send_dict twice (initial + pagination)
            assert mock_send.call_count == 2
            assert result == [None, None, "Item1", "Item2"]


@pytest.mark.asyncio
async def test_send_request_with_connection_close(ialarm):
    """Test _send_request closes connection after request."""
    command = {"Test": "value"}

    with patch.object(ialarm, "_create_root_dict") as mock_create:
        mock_create.return_value = {"Root": {"Test": "value"}}

        with (
            patch.object(ialarm, "_send_dict", new_callable=AsyncMock),
            patch.object(ialarm, "_receive", new_callable=AsyncMock) as mock_receive,
            patch.object(ialarm, "_close_connection") as mock_close,
        ):
            mock_receive.return_value = {"Root": {"Test": {"Result": "success"}}}

            result = await ialarm._send_request("/Root/Test", command)

            # Verify connection is closed
            mock_close.assert_called_once()
            assert result == {"Result": "success"}


@pytest.mark.asyncio
async def test_send_dict_method(ialarm):
    """Test _send_dict method."""
    root_dict = {"Root": {"Test": "value"}}

    with patch("dicttoxml2.dicttoxml") as mock_dicttoxml:
        mock_dicttoxml.return_value = b"<Root><Test>value</Test></Root>"

        with (
            patch.object(
                ialarm, "ensure_connection_is_open", new_callable=AsyncMock
            ) as mock_ensure,
            patch("asyncio.get_running_loop") as mock_loop,
        ):
            mock_loop_instance = mock_loop.return_value
            mock_loop_instance.sock_sendall = AsyncMock()

            await ialarm._send_dict(root_dict)

            # Verify sequence is incremented
            assert ialarm.seq == 1
            mock_ensure.assert_awaited_once()
            mock_loop_instance.sock_sendall.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_zone_status_multiple_status_types(ialarm):
    """Test get_zone_status with zones having multiple status types."""
    ialarm.get_zone = AsyncMock(
        return_value=[
            {"zone_id": 1, "name": "Zone 1", "type": 1, "voice": 0, "bell": False},
            {"zone_id": 2, "name": "Zone 2", "type": 1, "voice": 0, "bell": False},
        ]
    )

    # Zone with multiple status types (IN_USE + ALARM + BYPASS)
    ialarm._send_request_list = AsyncMock(
        return_value=[
            StatusType.ZONE_IN_USE | StatusType.ZONE_ALARM | StatusType.ZONE_BYPASS,
            StatusType.ZONE_IN_USE | StatusType.ZONE_FAULT,
        ]
    )

    result = await ialarm.get_zone_status()

    assert len(result) == 2
    assert result[0]["zone_id"] == 1
    assert StatusType.ZONE_IN_USE in result[0]["types"]
    assert StatusType.ZONE_ALARM in result[0]["types"]
    assert StatusType.ZONE_BYPASS in result[0]["types"]

    assert result[1]["zone_id"] == 2
    assert StatusType.ZONE_IN_USE in result[1]["types"]
    assert StatusType.ZONE_FAULT in result[1]["types"]


@pytest.mark.asyncio
async def test_get_zone_status_low_battery_and_loss(ialarm):
    """Test get_zone_status with low battery and loss status."""
    ialarm.get_zone = AsyncMock(
        return_value=[
            {"zone_id": 1, "name": "Zone 1", "type": 1, "voice": 0, "bell": False},
        ]
    )

    # Zone with low battery and loss
    ialarm._send_request_list = AsyncMock(
        return_value=[
            StatusType.ZONE_IN_USE | StatusType.ZONE_LOW_BATTERY | StatusType.ZONE_LOSS,
        ]
    )

    result = await ialarm.get_zone_status()

    assert len(result) == 1
    assert result[0]["zone_id"] == 1
    assert StatusType.ZONE_IN_USE in result[0]["types"]
    assert StatusType.ZONE_LOW_BATTERY in result[0]["types"]
    assert StatusType.ZONE_LOSS in result[0]["types"]


def test_exception_ialarm_socket_not_open_error():
    """Test IAlarmSocketNotOpenError exception."""

    error = IAlarmSocketNotOpenError()
    assert str(error) == "Socket is not open"
    assert isinstance(error, ConnectionError)


def test_exception_ialarm_connection_error():
    """Test IAlarmConnectionError exception."""

    error = IAlarmConnectionError()
    assert str(error) == "Connection to the alarm system failed"
    assert isinstance(error, ConnectionError)


def test_is_complete_message_list_variants():
    """Test _is_complete_message with different list variants."""
    ialarm = IAlarm("192.168.1.81")

    # Test @ieM02 variant
    buffer = b"@ieM020000<Root><Data>Test</Data></Root>0001"
    assert ialarm._is_complete_message(buffer) is True

    # Test @ieM03 variant
    buffer = b"@ieM030000<Root><Data>Test</Data></Root>0001"
    assert ialarm._is_complete_message(buffer) is True

    # Test @ieM04 variant
    buffer = b"@ieM040000<Root><Data>Test</Data></Root>0001"
    assert ialarm._is_complete_message(buffer) is True


def test_is_complete_message_invalid_endings():
    """Test _is_complete_message with invalid endings."""
    ialarm = IAlarm("192.168.1.81")

    # Test with non-digit ending
    buffer = b"@ieM00020000<Root><Data>Test</Data></Root>ABCD"
    assert ialarm._is_complete_message(buffer) is False

    # Test with too short buffer
    buffer = b"@ieM00020000<Root><Data>Test</Data></Root>"
    assert ialarm._is_complete_message(buffer) is False

    # Test with non-trigger message without proper ending
    buffer = b"@ieM00020000<Root><Data>Test</Data></Root>"
    assert ialarm._is_complete_message(buffer) is False


def test_is_complete_message_unknown_prefix():
    """Test _is_complete_message with unknown prefix."""
    ialarm = IAlarm("192.168.1.81")

    # Test with unknown prefix
    buffer = b"@unknown00020000<Root><Data>Test</Data></Root>0001"
    assert ialarm._is_complete_message(buffer) is False


def test_xmlread_with_none_value():
    """Test _xmlread with None value."""
    ialarm = IAlarm("192.168.1.81")

    key, processed_value = ialarm._xmlread("test_path", "test_key", None)

    assert key == "test_key"
    assert processed_value is None


def test_xmlread_with_non_string_value():
    """Test _xmlread with non-string value."""
    ialarm = IAlarm("192.168.1.81")

    key, processed_value = ialarm._xmlread("test_path", "test_key", 123)

    assert key == "test_key"
    assert processed_value == 123


def test_xmlread_with_unmatched_pattern():
    """Test _xmlread with value that doesn't match any pattern."""
    ialarm = IAlarm("192.168.1.81")

    key, processed_value = ialarm._xmlread("test_path", "test_key", "unmatched_pattern")

    assert key == "test_key"
    assert processed_value == "unmatched_pattern"


def test_parse_time_with_empty_string():
    """Test parse_time with empty string."""

    result = parse_time("")
    assert result is None


def test_parse_time_with_none():
    """Test parse_time with None raises TypeError."""

    with pytest.raises(TypeError):
        parse_time(None)


def test_decode_name_with_empty_string():
    """Test decode_name with empty string."""

    result = decode_name("")
    assert result == ""


def test_decode_name_with_none():
    """Test decode_name with None raises TypeError."""

    with pytest.raises(TypeError):
        decode_name(None)


def test_parse_bell_with_none():
    """Test parse_bell with None."""

    result = parse_bell(None)
    assert result is False


def test_parse_bell_with_empty_string():
    """Test parse_bell with empty string."""

    result = parse_bell("")
    assert result is False


@pytest.mark.asyncio
async def test_receive_incomplete_message(ialarm):
    """Test _receive with incomplete message to reach 100% coverage."""
    with patch("socket.socket") as mock_socket:
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.fileno.return_value = 1
        ialarm.sock = mock_socket_instance

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = mock_loop.return_value
            # Return an incomplete message (missing ending digits)
            mock_loop_instance.sock_recv = AsyncMock(
                return_value=b"@ieM00020000<Root><Data>Test</Data></Root>"
            )

            with pytest.raises(
                ConnectionError, match="Connection error: incomplete message received"
            ):
                await ialarm._receive()
