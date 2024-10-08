"""Utils for iAlarm Home Assistant Integration."""

from datetime import datetime
from typing import Optional


def parse_time(time_str: str) -> Optional[datetime]:
    """Convert a time string to a datetime object."""
    if "DTA,19" in time_str:
        try:
            return datetime.strptime(time_str.split("|")[1], "%Y.%m.%d.%H.%M.%S")
        except (ValueError, IndexError):
            return None
    return None


def decode_name(name_str: str) -> str:
    """Decode a hexadecimal name."""
    if "GBA" in name_str:
        try:
            return bytes.fromhex(name_str.split("|")[1]).decode(
                "utf-8", errors="ignore"
            )
        except (ValueError, IndexError):
            return name_str
    return name_str


def parse_bell(bell_value: str) -> bool:
    """Convert the value 'Bell' to a boolean, checking 'BOL|T' for True."""
    return bell_value == "BOL|T"
