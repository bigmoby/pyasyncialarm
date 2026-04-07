import asyncio
from collections import OrderedDict
import logging
import re
import socket
from typing import Any
import xml.parsers.expat

import dicttoxml2
import xmltodict

from pyasyncialarm.const import (
    ALARM_TYPE_MAP,
    EVENT_TYPE_MAP,
    RECV_BUF_SIZE,
    SOCKET_TIMEOUT,
    ZONE_TYPE_MAP,
    AlarmStatusType,
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
        self._lock = asyncio.Lock()

    def _is_socket_open(self) -> bool:
        return self.sock is not None and self.sock.fileno() != -1

    async def reconnect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(False)
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

    async def ensure_connection_is_open(self, force_reconnect: bool = False) -> None:
        if force_reconnect:
            log.debug("Forcing reconnect the socket...")
            await self.reconnect()
        elif not self._is_socket_open():
            await self.reconnect()
        else:
            log.debug("Socket is already connected.")

    def _close_connection(self) -> None:
        if self.sock and self.sock.fileno() != -1:
            self.sock.close()

    async def shutdown(self) -> None:
        """Close the socket cleanly. Call this when HA stops."""
        self._close_connection()

    # ------------------------------------------------------------------
    # Frame detection helpers
    # ------------------------------------------------------------------

    def _is_trigger_frame(self, buffer: bytes) -> bool:
        """Return True if the buffer starts with an alarm-trigger frame."""
        return buffer.startswith(b"@alA0")

    def _is_standard_frame(self, buffer: bytes) -> bool:
        """Return True if the buffer starts with a standard @ieM frame."""
        return buffer.startswith(b"@ieM")

    def _trigger_frame_complete(self, buffer: bytes) -> bool:
        """Return True when the buffer contains a complete trigger frame (ends with FFFF)."""
        return b"FFFF" in buffer

    def _standard_frame_complete(self, buffer: bytes) -> bool:
        """Return True when the buffer contains a complete standard @ieM frame.

        A complete frame ends with a 4-digit decimal sequence number that
        matches the one in the header.

        Frame layout:
          @ieM<len:4><seq:4>0000<XOR(payload)><seq:4>
          0    4      8     12   16            16+len
          ← ──────── 16 bytes header ────────→

        Total expected size = 16 (header) + len + 4 (trailing seq)
        """
        if len(buffer) < 16:
            return False
        try:
            msg_len = int(buffer[4:8])
        except ValueError:
            return False
        expected_total = 16 + msg_len + 4
        if len(buffer) < expected_total:
            return False
        # Verify the trailing seq matches the header seq
        header_seq = buffer[8:12]
        trailing_seq = buffer[expected_total - 4 : expected_total]
        return header_seq == trailing_seq

    def _frame_complete(self, buffer: bytes) -> bool:
        """Check whether the accumulated buffer contains a complete frame."""
        if not buffer:
            return False
        if self._is_trigger_frame(buffer):
            return self._trigger_frame_complete(buffer)
        if self._is_standard_frame(buffer):
            return self._standard_frame_complete(buffer)
        return False

    def _strip_leading_trigger_frames(self, buffer: bytes) -> bytes:
        """When the alarm is sounding the centralina may send one or more
        unsolicited trigger frames (@alA0...FFFF) before or interleaved
        with the actual command response.

        This method discards all leading trigger frames so that
        _extract_payload can work on a clean @ieM frame.
        """
        while buffer.startswith(b"@alA0"):
            ffff_pos = buffer.find(b"FFFF")
            if ffff_pos == -1:
                # Trigger frame not yet complete — caller should read more data
                log.debug("Incomplete trigger frame in buffer, need more data")
                return buffer
            end = ffff_pos + 4
            log.debug("Discarding trigger frame of %d bytes", end)
            buffer = buffer[end:]
            # Skip any whitespace / null bytes between frames
            buffer = buffer.lstrip(b"\x00")
        return buffer

    # ------------------------------------------------------------------
    # Payload extraction
    # ------------------------------------------------------------------

    def _extract_payload(self, buffer: bytes) -> bytes:
        """Extract the XOR-obfuscated payload from a complete @ieM frame.

        Frame layout:
          @ieM<len:4><seq:4>0000  → 16 bytes header
          <XOR(payload)>          → len bytes
          <seq:4>                 → 4 bytes trailer
        """
        try:
            msg_len = int(buffer[4:8])
        except ValueError as e:
            raise ConnectionError(
                f"Cannot parse frame length from buffer: {buffer[:16]!r}"
            ) from e
        return buffer[16 : 16 + msg_len]

    # ------------------------------------------------------------------
    # Core receive loop
    # ------------------------------------------------------------------

    async def _receive(self):
        """Receive a complete frame from the socket, accumulating chunks
        until the frame is complete.

        Key improvements over the previous single-recv approach:
        - Accumulates data across multiple recv() calls (TCP fragmentation)
        - Discards unsolicited trigger frames (@alA0...FFFF) that arrive
          while the alarm is sounding, before or mixed with the response
        - Validates frame length from the header rather than relying on
          heuristics like buffer[-4:].isdigit()
        """
        try:
            await self.ensure_connection_is_open()
            loop = asyncio.get_running_loop()
            buffer = b""
            deadline = loop.time() + SOCKET_TIMEOUT

            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    self.__raise_connection_error(
                        "Socket timeout: no complete frame received within "
                        f"{SOCKET_TIMEOUT}s. Buffer so far: {buffer[:64]!r}"
                    )

                try:
                    chunk = await asyncio.wait_for(
                        loop.sock_recv(self.sock, RECV_BUF_SIZE),
                        timeout=remaining,
                    )
                except TimeoutError:
                    self.__raise_connection_error(
                        "Socket timeout: no complete frame received within "
                        f"{SOCKET_TIMEOUT}s. Buffer so far: {buffer[:64]!r}"
                    )

                if not chunk:
                    self.__raise_connection_error(
                        "Connection closed by remote host while receiving frame."
                    )

                buffer += chunk
                log.debug("Accumulated %d bytes (chunk: %d)", len(buffer), len(chunk))

                # Discard leading trigger frames so we can assess the
                # real response underneath.
                buffer = self._strip_leading_trigger_frames(buffer)

                if not buffer:
                    # Everything received so far was trigger frames;
                    # keep reading until we get the actual response.
                    log.debug(
                        "Buffer empty after stripping trigger frames, reading more"
                    )
                    continue

                if not self._is_standard_frame(buffer):
                    # Unexpected frame start — log and bail out
                    self.__raise_connection_error(
                        f"Unexpected frame start: {buffer[:16]!r}"
                    )

                if self._standard_frame_complete(buffer):
                    log.debug("Complete @ieM frame received (%d bytes)", len(buffer))
                    break

                log.debug("Frame incomplete, reading more data...")

            payload = self._extract_payload(buffer)

            decoded = (
                self._xor(payload)
                .decode(errors="ignore")
                .replace("<Err>ERR|00</Err>", "")
            )

            log.debug("Decoded message: %s", decoded)

            if not decoded:
                self.__raise_connection_error(
                    "Connection error: unexpected empty reply after XOR decode."
                )

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
            log.error("Tried to decode [%s]", decoded)
            self.__raise_connection_error("Received malformed XML response")

    def __raise_connection_error(self, msg: str):
        """Close the connection and raises a connection error."""
        self._close_connection()
        raise ConnectionError(msg)

    # ------------------------------------------------------------------
    # Send helpers
    # ------------------------------------------------------------------

    async def _send_dict(self, root_dict) -> None:
        xml = dicttoxml2.dicttoxml(root_dict, attr_type=False, root=False)

        await self.ensure_connection_is_open()

        self.seq += 1
        msg = b"@ieM%04d%04d0000%s%04d" % (len(xml), self.seq, self._xor(xml), self.seq)

        loop = asyncio.get_running_loop()
        await loop.sock_sendall(self.sock, msg)

    async def _send_request_list(
        self,
        xpath: str,
        command: OrderedDict[str, Any | None],
        offset: int = 0,
        partial_list: list[Any] | None = None,
    ) -> list[Any]:
        """Send a paginated list request.

        Must be called from within an acquired self._lock context,
        with an open connection already established.
        Pagination is handled internally via recursion without reopening
        the socket between pages.
        Does NOT close the connection — the caller is responsible for that.
        """
        if offset > 0:
            command["Offset"] = f"S32,0,0|{offset}"
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

    async def _send_request_list_locked(
        self,
        xpath: str,
        command: OrderedDict[str, Any | None],
    ) -> list[Any]:
        """Acquire the lock, open a fresh connection, run a full paginated
        list request, then close the connection regardless of outcome.
        """
        async with self._lock:
            try:
                await self.ensure_connection_is_open(force_reconnect=True)
                return await self._send_request_list(xpath, command)
            finally:
                self._close_connection()

    async def _send_request(
        self, xpath: str, command: OrderedDict[str, Any | None]
    ) -> dict[str, Any]:
        """Acquire the lock, send a single request and return the parsed response."""
        async with self._lock:
            await self.ensure_connection_is_open(force_reconnect=True)
            root_dict = self._create_root_dict(xpath, command)
            await self._send_dict(root_dict)
            response = await self._receive()
            self._close_connection()
            return self._clean_response_dict(response, xpath)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_mac(self) -> str:
        mac = ""
        command: OrderedDict[str, Any | None] = OrderedDict()
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
        """Fetch zone names and zone status in a single locked TCP session.

        Previously this called get_zone() and GetByWay in two separate
        sessions, leaving the socket in an inconsistent state between them.
        Now both paginated requests share one connection under one lock
        acquisition, which also halves the number of TCP handshakes.
        """
        zone_command: OrderedDict[str, Any | None] = OrderedDict()
        zone_command["Total"] = None
        zone_command["Offset"] = "S32,0,0|0"
        zone_command["Ln"] = None
        zone_command["Err"] = None

        status_command: OrderedDict[str, Any | None] = OrderedDict()
        status_command["Total"] = None
        status_command["Offset"] = "S32,0,0|0"
        status_command["Ln"] = None
        status_command["Err"] = None

        async with self._lock:
            try:
                await self.ensure_connection_is_open(force_reconnect=True)
                raw_zone_data: list[ZoneTypeRaw] = await self._send_request_list(
                    "/Root/Host/GetZone", zone_command
                )
                zone_status: list[int] = await self._send_request_list(
                    "/Root/Host/GetByWay", status_command
                )
            finally:
                self._close_connection()

        zone_name_map = {
            i + 1: decode_name(zone["Name"]) for i, zone in enumerate(raw_zone_data)
        }

        if zone_status is None:
            raise ConnectionError(
                "An error occurred trying to connect to the alarm system"
            )

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

            zone_item: ZoneStatusType = {
                "zone_id": zone_id,
                "name": zone_name_map.get(zone_id, "Unknown"),
                "types": status_list,
            }
            result.append(zone_item)

        return result

    def __create_ialarm_status(
        self, status_value: int, zones: list[ZoneStatusType] | None = None
    ) -> AlarmStatusType:
        alarm_status: AlarmStatusType = {
            "status_value": status_value,
            "alarmed_zones": zones if zones is not None else [],
        }
        return alarm_status

    async def get_status(
        self, extra_info_zone_status: list[ZoneStatusType]
    ) -> AlarmStatusType:
        command: OrderedDict[str, Any | None] = OrderedDict()
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

        if status in {self.ARMED_AWAY, self.ARMED_STAY} and extra_info_zone_status:
            alarmed_zones: list[ZoneStatusType] = self.__filter_alarmed_zones(
                extra_info_zone_status
            )
            if any(StatusType.ZONE_ALARM in zone["types"] for zone in alarmed_zones):
                return self.__create_ialarm_status(self.TRIGGERED, alarmed_zones)

        return self.__create_ialarm_status(status)

    def __filter_alarmed_zones(
        self, extra_info_zone_status: list[ZoneStatusType]
    ) -> list[ZoneStatusType]:
        return [
            zone
            for zone in extra_info_zone_status
            if StatusType.ZONE_ALARM in zone["types"]
            and StatusType.ZONE_IN_USE in zone["types"]
        ]

    async def get_log(self) -> list[LogEntryType]:
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        event_log_raw: list[LogEntryTypeRaw] = await self._send_request_list_locked(
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
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        raw_zone_data: list[ZoneTypeRaw] = await self._send_request_list_locked(
            "/Root/Host/GetZone", command
        )
        zone: list[ZoneType] = self.__extract_zones(raw_zone_data)

        return zone

    async def get_zone_type(self) -> list[ZoneTypeEnum]:
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        zone_type_codes = await self._send_request_list_locked(
            "/Root/Host/GetZoneType", command
        )
        zone_types = [
            ZONE_TYPE_MAP.get(code, ZoneTypeEnum.UNUSED) for code in zone_type_codes
        ]

        return zone_types

    async def get_alarm_type(self) -> list[SirenSoundTypeEnum]:
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None

        alarm_type_codes = await self._send_request_list_locked(
            "/Root/Host/GetVoiceType", command
        )
        zone_types = [
            ALARM_TYPE_MAP.get(code, SirenSoundTypeEnum.CONTINUED)
            for code in alarm_type_codes
        ]

        return zone_types

    async def arm_away(self) -> None:
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["DevStatus"] = "TYP,ARM|0"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def arm_stay(self) -> None:
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["DevStatus"] = "TYP,STAY|2"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def disarm(self) -> None:
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["DevStatus"] = "TYP,DISARM|1"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def cancel_alarm(self) -> None:
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["DevStatus"] = "TYP,CLEAR|3"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

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
