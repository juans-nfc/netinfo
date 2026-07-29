"""In-process scan coordinator.

Ensures only one scan runs at a time and exposes live progress for the UI. The
scan itself runs as an asyncio task on the app event loop so it survives the
triggering HTTP request.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging

from .database import SessionLocal
from .scanner.orchestrator import run_scan

log = logging.getLogger("netview.manager")


class ScanManager:
    def __init__(self) -> None:
        self._task = None  # concurrent.futures.Future for the running scan
        self._loop: asyncio.AbstractEventLoop | None = None
        self._progress: dict = {"state": "idle"}

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Called once at app startup so scans can be scheduled from any thread
        (sync HTTP handlers run in a threadpool; scheduler jobs may too)."""
        self._loop = loop

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def progress(self) -> dict:
        return dict(self._progress)

    def _on_progress(self, info: dict) -> None:
        self._progress.update(info)
        self._progress["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()

    async def _run(self, trigger: str) -> None:
        self._progress = {"state": "running", "trigger": trigger,
                          "started_at": dt.datetime.now(dt.timezone.utc).isoformat()}
        try:
            run_id = await run_scan(SessionLocal, trigger=trigger, progress_cb=self._on_progress)
            self._progress["state"] = "finished"
            self._progress["run_id"] = run_id
        except Exception as exc:  # noqa: BLE001
            log.exception("scan crashed")
            self._progress["state"] = "error"
            self._progress["error"] = str(exc)

    def start(self, trigger: str = "manual") -> bool:
        """Start a scan. Returns False if one is already running. Safe to call
        from any thread."""
        if self.running:
            return False
        loop = self._loop
        if loop is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                log.error("No event loop available to start scan")
                return False
        # run_coroutine_threadsafe schedules on the main loop and returns a
        # concurrent.futures.Future; works whether or not we're on that loop.
        self._task = asyncio.run_coroutine_threadsafe(self._run(trigger), loop)
        return True


manager = ScanManager()
