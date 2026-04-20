from datetime import datetime
from typing import Any

from ..progress import ProgressSink


class ReconStreamLogger:
    def __init__(self, websocket: ProgressSink) -> None:
        self.websocket = websocket

    async def line(self, message: str) -> None:
        await self.websocket.send_text(f"[LOG] {message}\n")

    async def phase(self, title: str) -> None:
        await self.line("")
        await self.line(title)
        await self.line("-" * 68)

    async def banner(self, target: str) -> None:
        started = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        await self.line("+------------------------------------------------------------------+")
        await self.line("|                  SAMURAI WEB RECON ENGINE                        |")
        await self.line(f"| Target: {target:<56}|")
        await self.line(f"| Started: {started:<55}|")
        await self.line("+------------------------------------------------------------------+")
