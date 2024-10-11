"""Constants for iAlarm Home Assistant Integration."""

from datetime import datetime
from enum import Enum, IntEnum
from typing import Optional, TypedDict


class LogEntryType(TypedDict):
    time: Optional[datetime]
    area: int
    event: str
    name: str


class LogEntryTypeRaw(TypedDict):
    Time: str
    Area: int
    Event: str
    Name: str


EVENT_TYPE_MAP = {
    "0000": "Unused",
    "1100": "Personal ambulance",
    "1101": "Emergency",
    "1110": "Fire",
    "1113": "Water",
    "1120": "Emergency",
    "1121": "Duress alarm",
    "1122": "Personal ambulance",
    "1131": "Perimeter",
    "1132": "Burglary",
    "1133": "24 hour",
    "1134": "Delay",
    "1137": "Dismantled",
    "1151": "Gas",
    "1154": "Water intrusion alarm",
    "1301": "System AC fault",
    "1302": "System battery failure",
    "1306": "Programming changes",
    "1321": "Siren fault",
    "1350": "Communication failure",
    "1351": "Telephone line fault",
    "1370": "Circuit fault",
    "1381": "Detector lost",
    "1384": "Detector low battery",
    "1401": "Disarm report",
    "1406": "Alarm canceled",
    "1455": "Automatic arming failed",
    "1570": "Bypass Report",
    "1601": "Manual communication test reports",
    "1602": "Communications test reports",
    "1901": "Gate magnetic switch open",
    "3100": "Personal ambulance recovery",
    "3110": "Fire recovery",
    "3120": "Emergency recovery",
    "3122": "Personal Ambulance Recovery",
    "3131": "Perimeter recovery",
    "3132": "Burglary recovery",
    "3133": "24 hour recovery",
    "3134": "Alarm delay recovery",
    "3137": "Dismantled recovery",
    "3301": "System AC recovery",
    "3302": "System battery recovery",
    "3321": "Siren recovery",
    "3350": "Communication recovery",
    "3351": "Telephone line to restore",
    "3370": "Circuit recovery",
    "3381": "Detector loss recovery",
    "3384": "Detector low voltage recovery",
    "3401": "Arming Report",
    "3441": "Staying Report",
    "3570": "Bypass recovery",
    "3901": "Gate magnetic switch close",
    "3994": "Video lost recovery",
    "3995": "Video cover recovery",
    "9984": "Video lost",
    "9988": "Full hard disk",
    "9991": "Hard disk format",
    "9994": "Video lost",
    "9995": "Video cover",
    "9996": "Hard disk lost",
    "9997": "Hard disk error",
    "9999": "Motion detection",
}


class StatusType(IntEnum):
    ZONE_NOT_USED = 0
    ZONE_IN_USE = 1 << 0
    ZONE_ALARM = 1 << 1
    ZONE_BYPASS = 1 << 2
    ZONE_FAULT = 1 << 3
    ZONE_LOW_BATTERY = 1 << 4
    ZONE_LOSS = 1 << 5


class ZoneStatusType(TypedDict):
    zone_id: int
    name: str
    types: list[StatusType]


class ZoneTypeEnum(str, Enum):
    UNUSED = "Unused"
    DELAY = "Delay"
    PERIMETER = "Perimeter"
    INNER = "Inner"
    EMERGENCY = "Emergency"
    HOUR_24 = "24 Hour"
    FIRE = "Fire"
    KEY = "Key"
    GAS = "Gas"
    WATER = "Water"


class SirenSoundTypeEnum(str, Enum):
    CONTINUED = "Continued"
    PULSED = "Pulsed"
    MUTE = "Mute"


TYPE_MAPPING = {
    0: ZoneTypeEnum.UNUSED,
    1: ZoneTypeEnum.DELAY,
    2: ZoneTypeEnum.PERIMETER,
    3: ZoneTypeEnum.INNER,
    4: ZoneTypeEnum.EMERGENCY,
    5: ZoneTypeEnum.HOUR_24,
    6: ZoneTypeEnum.FIRE,
    7: ZoneTypeEnum.KEY,
    8: ZoneTypeEnum.GAS,
    9: ZoneTypeEnum.WATER,
}

ZONE_TYPE_MAP = {
    "NO": ZoneTypeEnum.UNUSED,
    "DE": ZoneTypeEnum.DELAY,
    "SI": ZoneTypeEnum.PERIMETER,
    "IN": ZoneTypeEnum.INNER,
    "FO": ZoneTypeEnum.EMERGENCY,
    "HO24": ZoneTypeEnum.HOUR_24,
    "FI": ZoneTypeEnum.FIRE,
    "KE": ZoneTypeEnum.KEY,
    "GAS": ZoneTypeEnum.GAS,
    "WT": ZoneTypeEnum.WATER,
}

ALARM_TYPE_MAP = {
    "CX": SirenSoundTypeEnum.CONTINUED,
    "MC": SirenSoundTypeEnum.PULSED,
    "NO": SirenSoundTypeEnum.MUTE,
}


class ZoneType(TypedDict):
    zone_id: int
    type: int
    voice: int
    name: str
    bell: bool


class ZoneTypeRaw(TypedDict):
    Type: int
    Voice: int
    Name: str
    Bell: str


RECV_BUF_SIZE = 1024
SOCKET_TIMEOUT = 10.0
