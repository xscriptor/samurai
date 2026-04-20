"""Celery tasks for scheduled scans.

Two tasks:
- `dispatch_due_schedules`: Beat runs this every ~30s. It finds enabled
  schedules whose `next_run_at` has passed and enqueues `run_scheduled_scan`
  for each. Reschedules `next_run_at` to the next cron occurrence.
- `run_scheduled_scan`: Worker executes the scan engine (port / recon /
  vuln) using a NullSink (no WebSocket), persists results via the existing
  SQLAlchemy models, and updates the schedule's `last_run_at`/`last_scan_id`.
"""
import asyncio
import json
import logging
from datetime import datetime

from croniter import croniter
from sqlalchemy.orm import Session

from . import models
from .celery_app import celery_app
from .database import SessionLocal
from .progress import NullSink
from .recon import perform_web_recon
from .scanner import perform_nmap_scan
from .crawler import perform_crawl


logger = logging.getLogger("samurai.tasks")


def _next_run(cron_expression: str) -> datetime:
    return croniter(cron_expression, datetime.utcnow()).get_next(datetime)


@celery_app.task(name="app.tasks.dispatch_due_schedules", ignore_result=True)
def dispatch_due_schedules() -> int:
    """Find and enqueue due schedules. Returns count dispatched."""
    db: Session = SessionLocal()
    dispatched = 0
    try:
        now = datetime.utcnow()
        due = (
            db.query(models.ScheduledScan)
            .filter(models.ScheduledScan.is_enabled.is_(True))
            .filter(models.ScheduledScan.next_run_at <= now)
            .all()
        )
        for schedule in due:
            # Reschedule BEFORE enqueueing to avoid double-runs if the task
            # takes longer than the Beat interval.
            schedule.next_run_at = _next_run(schedule.cron_expression)
            db.commit()
            run_scheduled_scan.delay(schedule.id)
            dispatched += 1
            logger.info("Dispatched schedule #%s (%s)", schedule.id, schedule.name)
    finally:
        db.close()
    return dispatched


@celery_app.task(name="app.tasks.run_scheduled_scan", bind=True, ignore_result=True)
def run_scheduled_scan(self, schedule_id: int) -> None:
    db: Session = SessionLocal()
    try:
        schedule = (
            db.query(models.ScheduledScan)
            .filter(models.ScheduledScan.id == schedule_id)
            .first()
        )
        if not schedule:
            logger.warning("run_scheduled_scan: schedule #%s not found", schedule_id)
            return
        if not schedule.is_enabled:
            logger.info("run_scheduled_scan: schedule #%s disabled, skipping", schedule_id)
            return

        started_at = datetime.utcnow()
        sink = NullSink(prefix=f"[schedule#{schedule.id}] ")
        config = _load_config(schedule.config_json)

        try:
            scan_id = asyncio.run(_execute(schedule, sink, db, config))
        except Exception as exc:  # noqa: BLE001 — log and continue, don't crash worker
            logger.exception("run_scheduled_scan #%s failed: %s", schedule_id, exc)
            scan_id = None

        # Refresh schedule row in case `next_run_at` was updated by the dispatcher
        db.refresh(schedule)
        schedule.last_run_at = started_at
        if scan_id is not None:
            schedule.last_scan_id = scan_id
        db.commit()
    finally:
        db.close()


async def _execute(
    schedule: models.ScheduledScan,
    sink: NullSink,
    db: Session,
    config: dict,
) -> int | None:
    """Dispatch to the right engine. Returns the created scan id or None."""
    if schedule.scan_type == "port_scan":
        await perform_nmap_scan(
            schedule.target,
            sink,
            db,
            profile=config.get("profile", "quick"),
            timeout_seconds=int(config.get("timeout", 180)),
            web_scan=bool(config.get("web_scan", False)),
            collect_contacts=bool(config.get("collect_contacts", False)),
            scan_unsanitized=bool(config.get("scan_unsanitized", False)),
            max_pages=int(config.get("max_pages", 10)),
        )
        return _latest_scan_id(db, schedule.target, prefix="port_scan")

    if schedule.scan_type == "vuln_crawl":
        modules = config.get("modules", "all")
        if not isinstance(modules, str):
            modules = ",".join(map(str, modules))
        await perform_crawl(schedule.target, modules, sink, db, auth_context=None)
        return _latest_scan_id(db, schedule.target, prefix="crawler")

    if schedule.scan_type == "web_recon":
        scan_record = models.Scan(
            domain_target=schedule.target,
            status="RUNNING",
            scan_type="web_recon",
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        recon_types = config.get("recon_types", "all")
        if isinstance(recon_types, str):
            recon_list = recon_types.split(",") if recon_types != "all" else ["all"]
        else:
            recon_list = list(recon_types)
        timeout = int(config.get("timeout", 300))

        try:
            results = await perform_web_recon(schedule.target, recon_list, sink, timeout_seconds=timeout)
            if results:
                finding = models.Finding(
                    scan_id=scan_record.id,
                    severity="info",
                    finding_type="web_recon_results",
                    description=f"Web reconnaissance results for {schedule.target}",
                    poc_payload=json.dumps(results, indent=2),
                )
                db.add(finding)
            scan_record.status = "COMPLETED"
            db.commit()
        except Exception:
            scan_record.status = "ERROR"
            db.commit()
            raise

        return scan_record.id

    logger.warning("Unknown scan_type '%s' for schedule #%s", schedule.scan_type, schedule.id)
    return None


def _load_config(config_json: str | None) -> dict:
    if not config_json:
        return {}
    try:
        loaded = json.loads(config_json)
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _latest_scan_id(db: Session, target: str, prefix: str) -> int | None:
    record = (
        db.query(models.Scan)
        .filter(models.Scan.domain_target == target)
        .filter(models.Scan.scan_type.like(f"{prefix}%"))
        .order_by(models.Scan.id.desc())
        .first()
    )
    return record.id if record else None
