"""Python Library for interacting with IAlarm aka antifurto365 alarm."""

from pyasyncialarm.exception import IAlarmConnectionError
from pyasyncialarm.pyasyncialarm import IAlarm

name = "pyasyncialarm"

__all__ = ["IAlarm", "IAlarmConnectionError"]
