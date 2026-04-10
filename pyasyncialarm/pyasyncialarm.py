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

# Pre-compiled regex patterns used by _xmlread to parse iAlarm XML value tokens.
_RE_ERR = re.compile(r"ERR\|(\d{2})")
_RE_MAC = re.compile(r"MAC,(\d+)\|(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))")
_RE_S32 = re.compile(r"S32,(\d+),(\d+)\|(\d*)")
_RE_STR = re.compile(r"STR,(\d+)\|(.*)")
_RE_TYP = re.compile(r"TYP,(\w+)\|(\d+)")

# How long to wait before attempting to reconnect after a connection drop
_RECONNECT_DELAY = 2.0


class IAlarm:
    """Interface the iAlarm security systems.

    Uses a single persistent TCP connection that is shared across all
    requests. The connection is opened on first use and automatically
    re-established if it drops. All send/receive operations are
    serialised via an asyncio.Lock to prevent frame interleaving.
    """

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

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _is_socket_open(self) -> bool:
        return self.sock is not None and self.sock.fileno() != -1

    async def reconnect(self) -> None:
        """Open a fresh TCP connection, resetting the sequence counter."""
        self._close_connection()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(False)
        self.seq = 0
        loop = asyncio.get_running_loop()
        try:
            await loop.sock_connect(self.sock, (self.host, self.port))
            log.debug("Connected to %s:%s", self.host, self.port)
        except (TimeoutError, OSError, ConnectionRefusedError) as err:
            self._close_connection()
            raise IAlarmConnectionError from err
        except Exception:
            self._close_connection()
            raise

    async def ensure_connection_is_open(self, force_reconnect: bool = False) -> None:
        """Ensure the socket is open, reconnecting if necessary."""
        if force_reconnect or not self._is_socket_open():
            await self.reconnect()
        else:
            log.debug("Socket is already connected.")

    def _close_connection(self) -> None:
        if self.sock and self.sock.fileno() != -1:
            self.sock.close()
        self.sock = None

    async def shutdown(self) -> None:
        """Close the socket cleanly. Call this when HA stops."""
        self._close_connection()

    # ------------------------------------------------------------------
    # Frame detection helpers
    # ------------------------------------------------------------------

    def _is_trigger_frame(self, buffer: bytes) -> bool:
        return buffer.startswith(b"@alA0")

    def _is_standard_frame(self, buffer: bytes) -> bool:
        return buffer.startswith(b"@ieM")

    def _trigger_frame_complete(self, buffer: bytes) -> bool:
        return b"FFFF" in buffer

    def _standard_frame_complete(self, buffer: bytes) -> bool:
        """Return True when buffer contains a complete @ieM frame.

        Frame layout:
          @ieM<len:4><seq:4>0000<XOR(payload)><seq:4>
          0    4      8     12   16            16+len
          Total = 16 (header) + len + 4 (trailing seq)
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
        header_seq = buffer[8:12]
        trailing_seq = buffer[expected_total - 4 : expected_total]
        return header_seq == trailing_seq

    def _frame_complete(self, buffer: bytes) -> bool:
        if not buffer:
            return False
        if self._is_trigger_frame(buffer):
            return self._trigger_frame_complete(buffer)
        if self._is_standard_frame(buffer):
            return self._standard_frame_complete(buffer)
        return False

    def _strip_leading_trigger_frames(self, buffer: bytes) -> bytes:
        """Discard all leading trigger frames (@alA0...FFFF) from buffer."""
        while buffer.startswith(b"@alA0"):
            ffff_pos = buffer.find(b"FFFF")
            if ffff_pos == -1:
                log.debug("Incomplete trigger frame in buffer, need more data")
                return buffer
            end = ffff_pos + 4
            log.debug("Discarding trigger frame of %d bytes", end)
            buffer = buffer[end:]
            buffer = buffer.lstrip(b"\x00")
        return buffer

    # ------------------------------------------------------------------
    # Payload extraction
    # ------------------------------------------------------------------

    def _extract_payload(self, buffer: bytes) -> bytes:
        try:
            msg_len = int(buffer[4:8])
        except ValueError as e:
            raise ConnectionError(
                f"Cannot parse frame length from buffer: {buffer[:16]!r}"
            ) from e
        return buffer[16 : 16 + msg_len]

    # ------------------------------------------------------------------
    # Core receive — uses the persistent socket, no open/close
    # ------------------------------------------------------------------

    async def _receive(self):
        """Receive a complete frame from the persistent socket.

        Accumulates chunks until the frame is complete. Trigger frames
        (@alA0...FFFF) arriving while the alarm is sounding are discarded
        transparently. On any socket error the connection is closed so
        the next request will trigger a reconnect.
        """
        try:
            loop = asyncio.get_running_loop()
            buffer = b""
            deadline = loop.time() + SOCKET_TIMEOUT

            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    self.__raise_connection_error(
                        f"Socket timeout: no complete frame received within "
                        f"{SOCKET_TIMEOUT}s. Buffer so far: {buffer[:64]!r}"
                    )

                try:
                    chunk = await asyncio.wait_for(
                        loop.sock_recv(self.sock, RECV_BUF_SIZE),
                        timeout=remaining,
                    )
                except TimeoutError:
                    self.__raise_connection_error(
                        f"Socket timeout: no complete frame received within "
                        f"{SOCKET_TIMEOUT}s. Buffer so far: {buffer[:64]!r}"
                    )

                if not chunk:
                    self.__raise_connection_error(
                        "Connection closed by remote host while receiving frame."
                    )

                buffer += chunk
                log.debug("Accumulated %d bytes (chunk: %d)", len(buffer), len(chunk))

                buffer = self._strip_leading_trigger_frames(buffer)

                if not buffer:
                    log.debug(
                        "Buffer empty after stripping trigger frames, reading more"
                    )
                    continue

                if not self._is_standard_frame(buffer):
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

        except ConnectionError:
            raise
        except OSError as e:
            self._close_connection()
            log.error("OSError in _receive: %s", e)
            raise ConnectionError(str(e)) from e
        except Exception as e:
            self._close_connection()
            log.error("Exception in _receive: %s", e)
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
        """Close the connection and raise a ConnectionError."""
        self._close_connection()
        raise ConnectionError(msg)

    # ------------------------------------------------------------------
    # Send helpers — persistent connection, reconnect on failure
    # ------------------------------------------------------------------

    async def _send_dict(self, root_dict) -> None:
        """Serialise root_dict to XML, XOR-encode and send over the socket."""
        xml = dicttoxml2.dicttoxml(root_dict, attr_type=False, root=False)
        self.seq += 1
        msg = b"@ieM%04d%04d0000%s%04d" % (len(xml), self.seq, self._xor(xml), self.seq)
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(self.sock, msg)

    async def _execute(
        self, xpath: str, command: OrderedDict[str, Any | None]
    ) -> dict[str, Any]:
        """Send one request and return the full parsed response subtree.

        Uses the persistent connection. If the connection is closed,
        reconnects once before giving up.
        Called exclusively from within an acquired self._lock context.
        """
        await self.ensure_connection_is_open()
        root_dict = self._create_root_dict(xpath, command)
        try:
            await self._send_dict(root_dict)
            response = await self._receive()
        except ConnectionError:
            # Connection dropped mid-request — reconnect and retry once
            log.warning("Connection lost during request, reconnecting and retrying...")
            await self.reconnect()
            await self._send_dict(root_dict)
            response = await self._receive()
        return self._clean_response_dict(response, xpath) or {}

    async def _send_request(
        self, xpath: str, command: OrderedDict[str, Any | None]
    ) -> dict[str, Any]:
        """Acquire the lock, execute a single request, return the xpath subtree."""
        async with self._lock:
            return await self._execute(xpath, command)

    async def _send_request_raw(
        self, xpath: str, command: OrderedDict[str, Any | None]
    ) -> dict[str, Any]:
        """Like _send_request but returns the xpath subtree (same as _send_request).

        Kept as a separate method for API clarity — callers that need
        DevStatus + Err from SetAlarmStatus responses use this explicitly.
        """
        async with self._lock:
            return await self._execute(xpath, command)

    async def _send_request_list(
        self,
        xpath: str,
        command: OrderedDict[str, Any | None],
        offset: int = 0,
        partial_list: list[Any] | None = None,
    ) -> list[Any]:
        """Send a paginated list request on the already-open persistent connection.

        Must be called from within an acquired self._lock context.
        Does NOT manage the lock itself.
        """
        if offset > 0:
            command["Offset"] = f"S32,0,0|{offset}"
        root_dict: dict[str, Any] = self._create_root_dict(xpath, command)
        try:
            await self._send_dict(root_dict)
            response: dict[str, Any] = await self._receive()
        except ConnectionError:
            log.warning(
                "Connection lost during list request, reconnecting and retrying..."
            )
            await self.reconnect()
            await self._send_dict(root_dict)
            response = await self._receive()

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
        """Acquire the lock and run a full paginated list request."""
        async with self._lock:
            await self.ensure_connection_is_open()
            return await self._send_request_list(xpath, command)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_mac(self) -> str:
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

        raise ConnectionError(
            "An error occurred trying to connect to the alarm system or received an"
            " unexpected reply"
        )

    async def get_last_log_entries(self, max_entries: int = 25) -> list[LogEntryType]:
        log_list = await self.get_log()
        if not log_list:
            return []
        return log_list[:max_entries]

    async def get_zone_status(self) -> list[ZoneStatusType]:
        """Fetch zone names and zone status in a single locked session."""
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
            await self.ensure_connection_is_open()
            raw_zone_data: list[ZoneTypeRaw] = await self._send_request_list(
                "/Root/Host/GetZone", zone_command
            )
            zone_status: list[int] = await self._send_request_list(
                "/Root/Host/GetByWay", status_command
            )

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
            result.append(
                ZoneStatusType(
                    zone_id=zone_id,
                    name=zone_name_map.get(zone_id, "Unknown"),
                    types=status_list,
                )
            )
        return result

    def __create_ialarm_status(
        self, status_value: int, zones: list[ZoneStatusType] | None = None
    ) -> AlarmStatusType:
        return AlarmStatusType(
            status_value=status_value,
            alarmed_zones=zones if zones is not None else [],
        )

    async def get_status(
        self, extra_info_zone_status: list[ZoneStatusType]
    ) -> AlarmStatusType:
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["DevStatus"] = None
        command["Err"] = None

        alarm_status = await self._send_request("/Root/Host/GetAlarmStatus", command)

        if alarm_status is None:
            raise ConnectionError(
                "An error occurred trying to connect to the alarm system"
            )

        status = int(alarm_status.get("DevStatus", -1))
        if status == -1:
            raise ConnectionError("Received an unexpected reply from the alarm")

        if status in {self.ARMED_AWAY, self.ARMED_STAY} and extra_info_zone_status:
            alarmed_zones = self.__filter_alarmed_zones(extra_info_zone_status)
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

        return [
            LogEntryType(
                time=parse_time(event["Time"]),
                area=event["Area"],
                event=EVENT_TYPE_MAP.get(event["Event"], event["Event"]),
                name=decode_name(event["Name"]),
            )
            for event in event_log_raw
        ]

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

    async def _get_zone(self) -> list[ZoneType]:
        """Fetch zone definitions. Internal use only."""
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None
        raw_zone_data: list[ZoneTypeRaw] = await self._send_request_list_locked(
            "/Root/Host/GetZone", command
        )
        return self.__extract_zones(raw_zone_data)

    async def get_zone_type(self) -> list[ZoneTypeEnum]:
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None
        zone_type_codes = await self._send_request_list_locked(
            "/Root/Host/GetZoneType", command
        )
        return [
            ZONE_TYPE_MAP.get(code, ZoneTypeEnum.UNUSED) for code in zone_type_codes
        ]

    async def get_alarm_type(self) -> list[SirenSoundTypeEnum]:
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["Total"] = None
        command["Offset"] = "S32,0,0|0"
        command["Ln"] = None
        command["Err"] = None
        alarm_type_codes = await self._send_request_list_locked(
            "/Root/Host/GetVoiceType", command
        )
        return [
            ALARM_TYPE_MAP.get(code, SirenSoundTypeEnum.CONTINUED)
            for code in alarm_type_codes
        ]

    async def arm_away(self) -> None:
        """Arm the alarm system in away mode."""
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["DevStatus"] = "TYP,ARM|0"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def arm_stay(self) -> None:
        """Arm the alarm system in stay (home) mode."""
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["DevStatus"] = "TYP,STAY|2"
        command["Err"] = None
        await self._send_request("/Root/Host/SetAlarmStatus", command)

    async def disarm(self) -> int:
        """Send the disarm command and return the DevStatus from the response.

        Returns:
            DevStatus integer (0=armed away, 1=disarmed, 2=armed stay,
            3=cancel, 4=triggered), or -1 if no valid status was returned.

        """
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["DevStatus"] = "TYP,DISARM|1"
        command["Err"] = None
        response = await self._send_request_raw("/Root/Host/SetAlarmStatus", command)
        return int(response.get("DevStatus", -1))

    async def cancel_alarm(self) -> int:
        """Send the cancel/clear command and return the DevStatus from the response.

        Returns:
            DevStatus integer, or -1 if no valid status was returned.

        """
        command: OrderedDict[str, Any | None] = OrderedDict()
        command["DevStatus"] = "TYP,CLEAR|3"
        command["Err"] = None
        response = await self._send_request_raw("/Root/Host/SetAlarmStatus", command)
        return int(response.get("DevStatus", -1))

    async def disarm_and_cancel(
        self,
        max_attempts: int = 3,
        retry_delay: float = 1.0,
    ) -> bool:
        """Disarm the panel and ensure any active alarm is cleared.

        Sends a disarm command, reads DevStatus from the response, and if
        the panel is still triggered retries cancel_alarm up to max_attempts
        times with retry_delay seconds between each attempt.

        Returns:
            True if the panel confirmed a non-triggered state, False otherwise.

        """
        log.debug("disarm_and_cancel: sending disarm")
        dev_status = await self.disarm()
        log.debug("disarm_and_cancel: disarm response DevStatus=%s", dev_status)

        if dev_status in {self.DISARMED, self.CANCEL}:
            log.debug("disarm_and_cancel: panel already disarmed, no cancel needed")
            return True

        for attempt in range(1, max_attempts + 1):
            log.debug(
                "disarm_and_cancel: cancel attempt %d/%d (DevStatus=%s)",
                attempt,
                max_attempts,
                dev_status,
            )
            await asyncio.sleep(retry_delay)
            dev_status = await self.cancel_alarm()
            log.debug(
                "disarm_and_cancel: cancel attempt %d response DevStatus=%s",
                attempt,
                dev_status,
            )
            if dev_status in {self.DISARMED, self.CANCEL}:
                log.debug("disarm_and_cancel: panel confirmed disarmed")
                return True

        log.warning(
            "disarm_and_cancel: panel still in status %s after %d attempts",
            dev_status,
            max_attempts,
        )
        return False

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _xmlread(_path, key, value):
        if value is None or not isinstance(value, str):
            return key, value
        if _RE_ERR.match(value):
            value = int(_RE_ERR.search(value).groups()[0])
        elif _RE_MAC.match(value):
            value = str(_RE_MAC.search(value).groups()[1])
        elif _RE_S32.match(value):
            value = int(_RE_S32.search(value).groups()[2])
        elif _RE_STR.match(value):
            value = str(_RE_STR.search(value).groups()[1])
        elif _RE_TYP.match(value):
            value = int(_RE_TYP.search(value).groups()[1])
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
