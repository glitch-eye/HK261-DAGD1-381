"""Thread-safe in-process emergency stop for gateway adapters."""
from __future__ import annotations
import threading

class KillSwitch:
    """State holder; persistence and remote control belong to adapters."""
    def __init__(self, enabled: bool = False) -> None:
        self._enabled = bool(enabled)
        self._lock = threading.Lock()

    def enable(self) -> None:
        with self._lock:
            self._enabled = True

    def disable(self) -> None:
        with self._lock:
            self._enabled = False

    def is_enabled(self) -> bool:
        with self._lock:
            return self._enabled
