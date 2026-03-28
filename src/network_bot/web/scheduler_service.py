"""
network_bot.web.scheduler_service – Persistent scan scheduling using APScheduler.

Schedules survive container restarts because jobs are stored in SQLite via
APScheduler's SQLAlchemyJobStore.

Cron expression format used here is standard 5-field: minute hour dom month dow
Special shortcuts for common patterns are handled by cron_human_to_expr().
"""
from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

_scheduler_instance = None
_scheduler_lock = threading.Lock()


def cron_human_to_expr(human: str) -> str:
    """
    Convert human-readable schedule strings to cron expressions.

    Examples:
        "2nd Tuesday at 02:00"  → "0 2 8-14 * 2"  (approximate)
        "every day at 03:00"    → "0 3 * * *"
        "every monday at 09:00" → "0 9 * * 1"
        "0 2 * * 2"             → "0 2 * * 2"  (pass-through)
    """
    import re

    h = human.strip().lower()

    # Already a valid cron expression (5 fields)
    if re.match(r'^[\d*/,\-]+ [\d*/,\-]+ [\d*/,\-]+ [\d*/,\-]+ [\d*/,\-]+$', h):
        return human.strip()

    # Parse time component "at HH:MM"
    time_match = re.search(r'at\s+(\d{1,2}):(\d{2})', h)
    hour = int(time_match.group(1)) if time_match else 2
    minute = int(time_match.group(2)) if time_match else 0

    dow_map = {
        "sunday": 0, "monday": 1, "tuesday": 2, "wednesday": 3,
        "thursday": 4, "friday": 5, "saturday": 6,
        "sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
    }

    ordinal_map = {
        "1st": "1-7", "2nd": "8-14", "3rd": "15-21", "4th": "22-28",
        "first": "1-7", "second": "8-14", "third": "15-21", "fourth": "22-28",
        "last": "22-28",
    }

    # "every day" / "daily"
    if "every day" in h or h.startswith("daily"):
        return f"{minute} {hour} * * *"

    # "every week" / "weekly"
    if "every week" in h or h.startswith("weekly"):
        return f"{minute} {hour} * * 1"

    # "every month" / "monthly"
    if "every month" in h or h.startswith("monthly"):
        return f"{minute} {hour} 1 * *"

    # "Nth DayOfWeek [of month]" e.g. "2nd Tuesday" → day-of-month range + dow
    for ordinal, dom_range in ordinal_map.items():
        if ordinal in h:
            for day_name, dow in dow_map.items():
                if day_name in h:
                    return f"{minute} {hour} {dom_range} * {dow}"

    # "every DayOfWeek" e.g. "every tuesday"
    for day_name, dow in dow_map.items():
        if f"every {day_name}" in h or h.startswith(day_name):
            return f"{minute} {hour} * * {dow}"

    # Fallback: weekly on Monday
    logger.warning("Could not parse schedule '%s', defaulting to weekly Monday 02:00", human)
    return f"0 2 * * 1"


def get_scheduler(db_path: str):
    """Return the singleton APScheduler instance, creating it if needed."""
    global _scheduler_instance
    with _scheduler_lock:
        if _scheduler_instance is None:
            _scheduler_instance = _create_scheduler(db_path)
    return _scheduler_instance


def _create_scheduler(db_path: str):
    """Create and start a BackgroundScheduler with SQLite job store."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
        from apscheduler.executors.pool import ThreadPoolExecutor as APSThreadPool

        jobstore_url = f"sqlite:///{db_path.replace('network_bot.db', 'scheduler.db')}"

        jobstores = {
            "default": SQLAlchemyJobStore(url=jobstore_url),
        }
        executors = {
            "default": APSThreadPool(max_workers=3),
        }
        job_defaults = {
            "coalesce": True,   # merge missed runs into one
            "max_instances": 1,
            "misfire_grace_time": 300,
        }

        scheduler = BackgroundScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
        )
        scheduler.start()
        logger.info("APScheduler started with SQLite job store: %s", jobstore_url)
        return scheduler

    except ImportError:
        logger.warning("APScheduler not installed – scheduled scans disabled")
        return None
    except Exception as exc:
        logger.error("Failed to start APScheduler: %s", exc)
        return None


def _make_scan_job(db_path: str, config: Dict[str, Any], target_filter: str, profile_id: Optional[int]):
    """Return the callable that APScheduler will invoke at schedule time."""
    def _job():
        from .db.schema import get_db
        from .db.crud import get_targets, create_scan

        logger.info("Scheduled scan triggered: filter=%s profile=%s", target_filter, profile_id)
        try:
            with get_db(db_path) as db:
                if target_filter.startswith("group:"):
                    gid = int(target_filter.split(":")[1])
                    targets = get_targets(db, group_id=gid)
                elif target_filter.startswith("tag:"):
                    tid = int(target_filter.split(":")[1])
                    targets = get_targets(db, tag_id=tid)
                else:
                    targets = get_targets(db, enabled_only=True)

                if not targets:
                    logger.warning("Scheduled scan: no targets matched filter %s", target_filter)
                    return

                scan = create_scan(
                    db,
                    triggered_by="scheduler",
                    filter_group=target_filter if target_filter.startswith("group:") else None,
                    filter_tag=target_filter if target_filter.startswith("tag:") else None,
                    profile_id=profile_id,
                )
                scan_id = scan["id"]

            from .api.scans import run_checks_for_web
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()

            import queue as _queue
            q: asyncio.Queue = asyncio.Queue()

            from . import active_scans as _active_scans
            _active_scans[scan_id] = q

            run_checks_for_web(targets, config, db_path, scan_id, q, loop)

            import time
            time.sleep(2)
            _active_scans.pop(scan_id, None)

            # Update schedule last_run
            with get_db(db_path) as db:
                db.execute(
                    "UPDATE schedules SET last_run = ? WHERE target_filter = ? AND enabled = 1",
                    (datetime.now(timezone.utc).isoformat(), target_filter),
                )

        except Exception as exc:
            logger.error("Scheduled scan failed: %s", exc, exc_info=True)

    return _job


def register_schedule(
    scheduler,
    schedule_id: int,
    cron_expr: str,
    db_path: str,
    config: Dict[str, Any],
    target_filter: str,
    profile_id: Optional[int],
) -> None:
    """Add or replace a scheduled scan job."""
    if scheduler is None:
        return

    try:
        from apscheduler.triggers.cron import CronTrigger

        fields = cron_expr.strip().split()
        if len(fields) != 5:
            logger.warning("Invalid cron expression '%s' for schedule %d", cron_expr, schedule_id)
            return

        minute, hour, dom, month, dow = fields
        trigger = CronTrigger(
            minute=minute, hour=hour, day=dom, month=month, day_of_week=dow
        )

        job_id = f"schedule_{schedule_id}"
        job_fn = _make_scan_job(db_path, config, target_filter, profile_id)

        # Replace existing job if present
        existing = scheduler.get_job(job_id)
        if existing:
            existing.remove()

        scheduler.add_job(
            job_fn,
            trigger=trigger,
            id=job_id,
            name=f"Scheduled scan #{schedule_id}",
            replace_existing=True,
        )
        logger.info("Registered schedule job %s: %s", job_id, cron_expr)

    except Exception as exc:
        logger.error("Failed to register schedule %d: %s", schedule_id, exc)


def remove_schedule(scheduler, schedule_id: int) -> None:
    if scheduler is None:
        return
    try:
        job_id = f"schedule_{schedule_id}"
        job = scheduler.get_job(job_id)
        if job:
            job.remove()
    except Exception as exc:
        logger.warning("Failed to remove schedule job %d: %s", schedule_id, exc)


def reload_all_schedules(
    scheduler,
    db_path: str,
    config: Dict[str, Any],
) -> None:
    """Load all enabled schedules from the DB and register them with the scheduler."""
    if scheduler is None:
        return
    try:
        from .db.schema import get_db
        from .db.crud import get_schedules

        with get_db(db_path) as db:
            schedules = get_schedules(db)

        for sched in schedules:
            if not sched.get("enabled"):
                continue
            register_schedule(
                scheduler,
                schedule_id=sched["id"],
                cron_expr=sched["cron_expr"],
                db_path=db_path,
                config=config,
                target_filter=sched.get("target_filter", "all"),
                profile_id=sched.get("profile_id"),
            )

        logger.info("Reloaded %d schedule(s)", len([s for s in schedules if s.get("enabled")]))
    except Exception as exc:
        logger.error("Failed to reload schedules: %s", exc)
