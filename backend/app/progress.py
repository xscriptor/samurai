"""Progress sink abstraction.

Scan engines stream status lines. In the HTTP path, the sink is a WebSocket.
In the Celery path, there is no client — messages go to the logger instead.
Both shapes implement the same duck-typed interface used by the engines.
"""
import logging
from typing import Protocol

logger = logging.getLogger("samurai.scan")


class ProgressSink(Protocol):
    async def send_text(self, text: str) -> None: ...
    async def close(self, code: int = 1000, reason: str = "") -> None: ...


class NullSink:
    """Drop-in replacement for WebSocket when no client is attached."""

    def __init__(self, prefix: str = ""):
        self._prefix = prefix

    async def send_text(self, text: str) -> None:
        logger.info("%s%s", self._prefix, text)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        return None
