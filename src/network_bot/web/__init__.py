# network_bot.web – FastAPI web GUI
from typing import Dict
import asyncio

# Shared active scans dict so scheduler_service can push progress events
active_scans: Dict[int, asyncio.Queue] = {}
