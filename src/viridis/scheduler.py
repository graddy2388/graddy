import logging
import threading
import time
from typing import Callable, Optional

import schedule

logger = logging.getLogger(__name__)


class BotScheduler:
    """Scheduler that runs network checks at a configurable interval."""

    def __init__(self, bot: "Viridis", interval_minutes: int) -> None:  # type: ignore[name-defined]
        self._bot = bot
        self._interval_minutes = interval_minutes
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def run_once(self) -> None:
        """Run all checks once and generate a report."""
        logger.info("Starting scheduled check run")
        try:
            self._bot.run_checks()
        except Exception as exc:
            logger.exception("Unhandled error during scheduled run: %s", exc)

    def start(self) -> None:
        """Run checks immediately, then schedule recurring runs."""
        logger.info(
            "Scheduler starting: running immediately, then every %d minute(s)",
            self._interval_minutes,
        )

        # Run immediately in the calling thread
        self.run_once()

        # Schedule future runs
        schedule.every(self._interval_minutes).minutes.do(self.run_once)

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="scheduler")
        self._thread.start()
        logger.info("Scheduler thread started (interval: %d minutes)", self._interval_minutes)

    def stop(self) -> None:
        """Signal the scheduler to stop and wait for the thread to finish."""
        logger.info("Stopping scheduler")
        self._stop_event.set()
        schedule.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        logger.info("Scheduler stopped")

    def _loop(self) -> None:
        """Internal loop that runs pending scheduled jobs until stopped."""
        while not self._stop_event.is_set():
            schedule.run_pending()
            # Sleep in short increments so we can respond to stop quickly
            self._stop_event.wait(timeout=1)
