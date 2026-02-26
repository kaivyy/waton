from enum import IntEnum
from typing import Optional

class PywaError(Exception):
    """Base exception for pywa."""
    pass


class ConnectionError(PywaError):
    """Raised when there is a connection issue."""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class DisconnectReason(IntEnum):
    """Port of Baileys DisconnectReason."""
    CONNECTION_CLOSED = 428
    CONNECTION_LOST = 408
    CONNECTION_REPLACED = 440
    LOGGED_OUT = 401
    BAD_SESSION = 500
    RESTART_REQUIRED = 515
    MULTIDEVICE_MISMATCH = 411
    TIMED_OUT = 408
    CONNECTION_ERROR = 429
