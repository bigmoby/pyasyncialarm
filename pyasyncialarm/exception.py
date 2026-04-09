"""Exceptions for iAlarm Home Assistant Integration."""


class IAlarmConnectionError(ConnectionError):
    """Exception raised when socket is not open."""

    def __init__(self):
        super().__init__("Connection to the alarm system failed")
