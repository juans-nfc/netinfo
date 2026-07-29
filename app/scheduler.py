"""Optional scheduled scans via APScheduler (cron expression)."""
from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from .config import get_settings
from .scan_manager import manager

log = logging.getLogger("netview.scheduler")

_scheduler: AsyncIOScheduler | None = None


def _kickoff():
    started = manager.start(trigger="scheduled")
    if not started:
        log.info("Scheduled scan skipped: a scan is already running")


def start_scheduler() -> None:
    global _scheduler
    cron = get_settings().scan_cron.strip()
    if not cron:
        log.info("No scan_cron configured; scheduler disabled")
        return
    try:
        trigger = CronTrigger.from_crontab(cron)
    except ValueError as exc:
        log.error("Invalid scan_cron %r: %s", cron, exc)
        return
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(_kickoff, trigger, id="scheduled_scan", replace_existing=True)
    _scheduler.start()
    log.info("Scheduler started with cron %r", cron)


def stop_scheduler() -> None:
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
