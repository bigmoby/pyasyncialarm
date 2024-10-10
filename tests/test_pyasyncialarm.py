# mypy: ignore-errors
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from pyasyncialarm.const import StatusType
from pyasyncialarm.pyasyncialarm import IAlarm


@pytest.fixture
def ialarm():
    """Crea un'istanza di IAlarm per i test."""
    return IAlarm("192.168.1.81", 18034)


@pytest.mark.asyncio
async def test_is_socket_open_with_open_socket(ialarm):
    # Mock the socket object
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
        await ialarm.get_status()


@pytest.mark.asyncio
async def test_get_status_unexpected_reply(ialarm):
    ialarm._send_request = AsyncMock(return_value={"DevStatus": -1})

    with pytest.raises(
        ConnectionError, match="Received an unexpected reply from the alarm"
    ):
        await ialarm.get_status()


@pytest.mark.asyncio
async def test_get_status_triggered_alarm(ialarm):
    ialarm._send_request = AsyncMock(return_value={"DevStatus": ialarm.ARMED_AWAY})

    zone_status_mock = [
        {"types": [StatusType.ZONE_ALARM]},
    ]
    ialarm.get_zone_status = AsyncMock(return_value=zone_status_mock)

    status = await ialarm.get_status()
    assert status == ialarm.TRIGGERED


@pytest.mark.asyncio
async def test_get_status_no_triggered_alarm(ialarm):
    ialarm._send_request = AsyncMock(return_value={"DevStatus": ialarm.ARMED_AWAY})

    zone_status_mock = [
        {"types": []},
    ]
    ialarm.get_zone_status = AsyncMock(return_value=zone_status_mock)

    status = await ialarm.get_status()
    assert status == ialarm.ARMED_AWAY


@pytest.mark.asyncio
async def test_get_status_not_armed(ialarm):
    ialarm._send_request = AsyncMock(return_value={"DevStatus": 0})

    zone_status_mock = [
        {"types": []},
    ]
    ialarm.get_zone_status = AsyncMock(return_value=zone_status_mock)

    status = await ialarm.get_status()
    assert status == 0


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
