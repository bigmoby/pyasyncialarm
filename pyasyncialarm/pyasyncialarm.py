import asyncio
from collections import OrderedDict
import logging
import re
import socket
from typing import Any, Optional
import xml.parsers.expat

import dicttoxml2
import xmltodict

from pyasyncialarm.const import (
    ALARM_TYPE_MAP,
    EVENT_TYPE_MAP,
    RECV_BUF_SIZE,
    SOCKET_TIMEOUT,
    ZONE_TYPE_MAP,
    LogEntryType,
    LogEntryTypeRaw,
    SirenSoundTypeEnum,
    StatusType,
    ZoneStatusType,
    ZoneType,
    ZoneTypeEnum,
    ZoneTypeRaw,
)
from pyasyncialarm.exception import IAlarmConnectionError
from pyasyncialarm.util import decode_name, parse_bell, parse_time

log = logging.getLogger(__name__)
# dicttoxml is very verbose at INFO level
logging.getLogger("dicttoxml").setLevel(logging.CRITICAL)


class IAlarm:
    """Interface the iAlarm security systems."""

    ARMED_AWAY = 0
    DISARMED = 1
    ARMED_STAY = 2
    CANCEL = 3
    TRIGGERED = 4

    def __init__(self, host, port=18034):
        """:param host: host of the iAlarm security system (e.g. its IP address)
        :param port: port of the iAlarm security system (should be '18034')
        """
        self.host = host
        self.port = port
        self.seq = 0
        self.sock = None

    def _is_socket_open(self) -> bool:
        return self.sock is not None and self.sock.fileno() != -1

    async def ensure_connection_is_open(self) -> None:
        if not self._is_socket_open():
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(SOCKET_TIMEOUT)

            self.seq = 0
            loop = asyncio.get_running_loop()
            try:
                await loop.sock_connect(self.sock, (self.host, self.port))
            except (TimeoutError, OSError, ConnectionRefusedError) as err:
                self._close_connection()
                raise IAlarmConnectionError from err
            except Exception:
                self._close_connection()
                raise
        else:
            log.debug("Socket is already connected.")

    def _close_connection(self) -> None:
        if self.sock and self.sock.fileno() != -1:
            self.sock.close()

    def _is_complete_message(self, buffer: bytes) -> bool:
        """Check if the buffer contains a complete message based on the delimiters."""

        start_delimiter_type_standard = b"@ieM"
        start_delimiter_type_list_2 = b"@ieM02"
        start_delimiter_type_list_3 = b"@ieM03"
        start_delimiter_type_list_4 = b"@ieM04"
        end_delimiter = b"0001"

        if buffer.startswith(start_delimiter_type_standard):
            if buffer.startswith(
                (
                    start_delimiter_type_list_2,
                    start_delimiter_type_list_3,
                    start_delimiter_type_list_4,
                )
            ):
                return bool(len(buffer) >= 4 and buffer[-4:].isdigit())

            # Se inizia con '@ieM', controlla solo l'end_delimiter
            return buffer.endswith(end_delimiter)

        return False

    def __raise_connection_error(self, msg: str):
        self._close_connection()
        raise ConnectionError(msg)

    async def _receive(self):
        """Receive and decode the message from the socket."""

        def raise_connection_error(msg: str):
            """Chiude la connessione e solleva un'eccezione di connessione."""
            self._close_connection()
            raise ConnectionError(msg)

        try:
            buffer = b""
            await self.ensure_connection_is_open()
            log.debug("Attempting to receive data from the socket...")
            loop = asyncio.get_running_loop()
            buffer = await asyncio.wait_for(
                loop.sock_recv(self.sock, RECV_BUF_SIZE), timeout=SOCKET_TIMEOUT
            )

            if not buffer:
                raise_connection_error("Connection error: received no data.")

            log.debug("Received buffer of size %d", len(buffer))

            if not self._is_complete_message(buffer):
                raise_connection_error("Connection error: incomplete message received.")

            log.debug("Extracting payload from buffer of size %d", len(buffer))
            payload = buffer[16:-4]

            decoded = (
                self._xor(payload)
                .decode(errors="ignore")
                .replace("<Err>ERR|00</Err>", "")
            )

            log.debug("Decoded message: %s", decoded)

            if not decoded:
                raise_connection_error("Connection error: unexpected empty reply.")

            return await self._parse_decoded_message(decoded)

        except OSError as e:
            self._close_connection()
            log.error("OSError occurred: %s", e)
            raise

        except Exception as e:
            self._close_connection()
            log.error("Exception occurred: %s", e)
            raise

    async def _parse_decoded_message(self, decoded):
        """Parse the decoded message using xmltodict in a separate thread."""
        try:
            return await asyncio.to_thread(
                xmltodict.parse,
                decoded,
                xml_attribs=False,
                dict_constructor=dict,
                postprocessor=self._xmlread,
            )
        except xml.parsers.expat.ExpatError as e:
            log.error("XML Parsing error: %s", e)
            self.__raise_connection_error("Received malformed XML response")

    async def _send_request_list(
        self,
        xpath: str,
        command: OrderedDict[str, Optional[Any]],
        offset: int = 0,
        partial_list: Optional[list[Any]] = None,
    ) -> list[Any]:
        if offset > 0:
            command["Offset"] = "S32,0,0|%d" % offset
        root_dict: dict[str, Any] = self._create_root_dict(xpath, command)
        await self._send_dict(root_dict)
        response: dict[str, Any] = await self._receive()

        if partial_list is None:
            partial_list = []
        total: int = self._clean_response_dict(response, f"{xpath}/Total")
        ln: int = self._clean_response_dict(response, f"{xpath}/Ln")
        for i in range(ln):
            partial_list.append(self._clean_response_dict(response, f"{xpath}/L{i}"))
        offset += ln
        if total > offset:
            await self._send_request_list(xpath, command, offset, partial_list)

        return partial_list

    async def _send_request(
        self, xpath: str, command: OrderedDict[str, Optional[Any]]
    ) -> dict[str, Any]:
        root_dict = self._create_root_dict(xpath, command)
        await self._send_dict(root_dict)
        response = await self._receive()
        self._close_connection()
        return self._clean_response_dict(response, xpath)

    async def get_mac(self) -> str:
        mac = ""
        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["Mac"] = None
        command["Name"] = None
        command["Ip"] = None
        command["Gate"] = None
        command["Subnet"] = None
        command["Dns1"] = None
        command["Dns2"] = None
        command["Err"] = None
        network_info = await self._send_request("/Root/Host/GetNet", command)

        if network_info is not None:
            mac = network_info.get("Mac", "")

        if mac:
            return mac
        error_message = (
            "An error occurred trying to connect to the alarm system or received an"
            " unexpected reply"
        )
        raise ConnectionError(error_message)

    async def get_last_log_entries(self, max_entries: int = 25) -> list[LogEntryType]:
        log_list = await self.get_log()
        if not log_list:
            return []
        return log_list[:max_entries]

    async def get_zone_status(self) -> list[ZoneStatusType]:
        zones: list[ZoneType] = await self.get_zone()

        zone_name_map = {zone["zone_id"]: zone["name"] for zone in zones}

        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None
        zone_status: list[int] = await self._send_request_list(
            "/Root/Host/GetByWay", command
        )

        if zone_status is None:
            error_message = "An error occurred trying to connect to the alarm system"
            raise ConnectionError(error_message)

        result = []
        for i, status in enumerate(zone_status):
            zone_id = i + 1

            status_list = []

            if status & StatusType.ZONE_IN_USE:
                status_list.append(StatusType.ZONE_IN_USE)
            if status & StatusType.ZONE_ALARM:
                status_list.append(StatusType.ZONE_ALARM)
            if status & StatusType.ZONE_BYPASS:
                status_list.append(StatusType.ZONE_BYPASS)
            if status & StatusType.ZONE_FAULT:
                status_list.append(StatusType.ZONE_FAULT)
            if status & StatusType.ZONE_LOW_BATTERY:
                status_list.append(StatusType.ZONE_LOW_BATTERY)
            if status & StatusType.ZONE_LOSS:
                status_list.append(StatusType.ZONE_LOSS)

            if not status_list:
                status_list.append(StatusType.ZONE_NOT_USED)

            zone_name = zone_name_map.get(zone_id, "Unknown")

            zone_item: ZoneStatusType = {
                "zone_id": zone_id,
                "name": zone_name,
                "types": status_list,
            }
            result.append(zone_item)

        return result

    async def get_status(self) -> int:
        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["DevStatus"] = None
        command["Err"] = None

        alarm_status: dict[str, Any] = await self._send_request(
            "/Root/Host/GetAlarmStatus", command
        )

        if alarm_status is None:
            error_message = "An error occurred trying to connect to the alarm system"
            raise ConnectionError(error_message)

        status = int(alarm_status.get("DevStatus", -1))
        if status == -1:
            error_message = "Received an unexpected reply from the alarm"
            raise ConnectionError(error_message)

        if status in {self.ARMED_AWAY, self.ARMED_STAY}:
            zone_status: list[ZoneStatusType] = await self.get_zone_status()
            zone_alarm = any(
                StatusType.ZONE_ALARM in zone["types"] for zone in zone_status
            )

            if zone_alarm:
                return self.TRIGGERED

        return status

    async def get_log(self) -> list[LogEntryType]:
        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        event_log_raw: list[LogEntryTypeRaw] = await self._send_request_list(
            "/Root/Host/GetLog", command
        )

        logs = [
            LogEntryType(
                time=parse_time(event["Time"]),
                area=event["Area"],
                event=EVENT_TYPE_MAP.get(event["Event"], event["Event"]),
                name=decode_name(event["Name"]),
            )
            for event in event_log_raw
        ]

        return logs

    def __extract_zones(self, zone_data_raw: list[ZoneTypeRaw]) -> list[ZoneType]:
        return [
            ZoneType(
                zone_id=i,
                type=zone["Type"],
                voice=zone["Voice"],
                name=decode_name(zone["Name"]),
                bell=parse_bell(zone["Bell"]),
            )
            for i, zone in enumerate(zone_data_raw, start=1)
        ]

    async def get_zone(self) -> list[ZoneType]:
        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        raw_zone_data: list[ZoneTypeRaw] = await self._send_request_list(
            "/Root/Host/GetZone", command
        )
        zone: list[ZoneType] = self.__extract_zones(raw_zone_data)

        return zone

    async def get_zone_type(self) -> list[ZoneTypeEnum]:
        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        zone_type_codes = await self._send_request_list(
            "/Root/Host/GetZoneType", command
        )
        zone_types = [
            ZONE_TYPE_MAP.get(code, ZoneTypeEnum.UNUSED) for code in zone_type_codes
        ]

        return zone_types

    async def get_alarm_type(self) -> list[SirenSoundTypeEnum]:
        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        alarm_type_codes = await self._send_request_list(
            "/Root/Host/GetVoiceType", command
        )
        zone_types = [
            ALARM_TYPE_MAP.get(code, SirenSoundTypeEnum.CONTINUED)
            for code in alarm_type_codes
        ]

        return zone_types

    async def arm_away(self) -> None:
        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["DevStatus"] = "TYP,ARM|0"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def arm_stay(self) -> None:
        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["DevStatus"] = "TYP,STAY|2"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def disarm(self) -> None:
        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["DevStatus"] = "TYP,DISARM|1"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def cancel_alarm(self) -> None:
        command: OrderedDict[str, Optional[Any]] = OrderedDict()
        command["DevStatus"] = "TYP,CLEAR|3"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def _send_dict(self, root_dict) -> None:
        xml = dicttoxml2.dicttoxml(root_dict, attr_type=False, root=False)

        await self.ensure_connection_is_open()

        self.seq += 1
        msg = b"@ieM%04d%04d0000%s%04d" % (len(xml), self.seq, self._xor(xml), self.seq)

        loop = asyncio.get_running_loop()
        await loop.sock_sendall(self.sock, msg)

    @staticmethod
    def _xmlread(_path, key, value):
        if value is None or not isinstance(value, str):
            return key, value

        err_re = re.compile(r"ERR\|(\d{2})")
        mac_re = re.compile(r"MAC,(\d+)\|(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))")
        s32_re = re.compile(r"S32,(\d+),(\d+)\|(\d*)")
        str_re = re.compile(r"STR,(\d+)\|(.*)")
        typ_re = re.compile(r"TYP,(\w+)\|(\d+)")
        if err_re.match(value):
            value = int(err_re.search(value).groups()[0])
        elif mac_re.match(value):
            value = str(mac_re.search(value).groups()[1])
        elif s32_re.match(value):
            value = int(s32_re.search(value).groups()[2])
        elif str_re.match(value):
            value = str(str_re.search(value).groups()[1])
        elif typ_re.match(value):
            value = int(typ_re.search(value).groups()[1])
        # Else: we are not interested in this value, just keep it as is

        return key, value

    @staticmethod
    def _create_root_dict(path, my_dict=None):
        if my_dict is None:
            my_dict = {}
        root = {}
        elem = root
        plist = path.strip("/").split("/")
        k = len(plist) - 1
        for i, j in enumerate(plist):
            elem[j] = {}
            if i == k:
                elem[j] = my_dict
            elem = elem.get(j)
        return root

    @staticmethod
    def _clean_response_dict(response, path):
        for i in path.strip("/").split("/"):
            try:
                i = int(i)
                response = response[i]
            except ValueError:
                response = response.get(i)
        return response

    @staticmethod
    def _xor(xml):
        sz = bytearray.fromhex(
            "0c384e4e62382d620e384e4e44382d300f382b382b0c5a6234384e304e4c372b10535a0c20432d171142444e58422c421157322a204036172056446262382b5f0c384e4e62382d620e385858082e232c0f382b382b0c5a62343830304e2e362b10545a0c3e432e1711384e625824371c1157324220402c17204c444e624c2e12"
        )
        buf = bytearray(xml)
        for i in range(len(xml)):
            ki = i & 0x7F
            buf[i] = buf[i] ^ sz[ki]

        return buf
