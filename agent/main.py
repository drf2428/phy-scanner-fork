"""PHY Scanner Agent — main entry point.

Runs two concurrent asyncio tasks:
1. Poll loop: every poll_interval seconds, check for new jobs
2. Heartbeat loop: every heartbeat_interval seconds, send health telemetry

State machine per job:
  no_job -> poll -> claimed -> scanning -> uploading -> submitting -> done/failed
  -> back to no_job

Single-job semantics: if a job is in_progress, don't poll for new ones.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from typing import Optional

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

from .client import PhyClient, PhyApiError, NoJobAvailable
from .config import load_config, AgentConfig
from .scanner import run_scan
from .state import AgentState, JobStatus

logger = logging.getLogger(__name__)


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
        stream=sys.stdout,
    )


def _disk_free_gb() -> float:
    if not _HAS_PSUTIL:
        return 0.0
    try:
        usage = psutil.disk_usage("/")
        return round(usage.free / (1024 ** 3), 2)
    except Exception:
        return 0.0


def _ram_used_pct() -> float:
    if not _HAS_PSUTIL:
        return 0.0
    try:
        return round(psutil.virtual_memory().percent, 1)
    except Exception:
        return 0.0


async def _run_job(
    job: dict,
    client: PhyClient,
    state: AgentState,
    config: AgentConfig,
) -> None:
    """Execute a single scan job through the full state machine."""
    job_id = job["job_id"]
    logger.info("Starting job job_id=%s", job_id)

    # Transition: claimed -> scanning
    state.upsert_job(job_id, JobStatus.SCANNING)
    await client.send_heartbeat(job_id=job_id, progress_pct=0.0)

    # Fetch the tenant CIDR allowlist. The §51/legal control FAILS CLOSED:
    #   - fetch EXCEPTION       -> cidrs_allowed stays None -> filter_scope scans
    #                              NOTHING (better no scan than an unauthorized one).
    #   - fetch SUCCESS, []     -> tenant has no allowlist -> filter_scope restricts
    #                              to RFC1918 private space (never public IPs).
    #   - fetch SUCCESS, [..]   -> intersect with the validated allowlist.
    # None therefore means "scope unavailable", distinct from [] ("no allowlist").
    cidrs_allowed: Optional[list] = None
    try:
        config_resp = await client.get_config()
        fetched = config_resp.get("cidrs_allowed")
        # A successful fetch yields a list (possibly empty). Only an absent key
        # leaves it None, which we treat as unavailable -> fail closed.
        cidrs_allowed = fetched if isinstance(fetched, list) else None
        if cidrs_allowed is None:
            logger.warning("get_config returned no cidrs_allowed — failing closed")
    except Exception as exc:  # noqa: BLE001 — config fetch is best-effort
        logger.warning("get_config failed (scope unavailable, failing closed): %s", exc)

    try:
        result = await run_scan(job, config, cidrs_allowed=cidrs_allowed)
    except Exception as exc:
        logger.exception("Scan failed for job_id=%s: %s", job_id, exc)
        state.mark_failed(job_id, str(exc))
        await client.send_log("error", f"Scan failed: {exc}", {"job_id": job_id})
        return

    # Report what was scanned vs dropped by the scope filter (best-effort log).
    await client.send_log(
        "info",
        f"Scan scope applied: scanned={result.kept_targets} dropped={result.dropped_targets}",
        {"job_id": job_id},
    )
    if result.kept_targets is not None and not result.kept_targets:
        logger.warning("No in-scope targets for job_id=%s — reported 0 findings", job_id)

    await client.send_heartbeat(job_id=job_id, progress_pct=80.0)

    # Transition: scanning -> uploading
    state.upsert_job(job_id, JobStatus.UPLOADING)
    raw_report_s3_key: Optional[str] = None

    if result.raw_report_path and os.path.exists(result.raw_report_path):
        upload_info = await client.get_upload_url(job_id)
        if upload_info:
            upload_url, raw_report_s3_key = upload_info
            try:
                import httpx
                async with httpx.AsyncClient(timeout=120.0) as http:
                    with open(result.raw_report_path, "rb") as fh:
                        await http.put(upload_url, content=fh.read())
                logger.info("Uploaded raw report job_id=%s s3_key=%s", job_id, raw_report_s3_key)
            except Exception as exc:
                logger.warning("Raw report upload failed (non-fatal): %s", exc)
                raw_report_s3_key = None

    # Transition: uploading -> submitting
    state.upsert_job(job_id, JobStatus.SUBMITTING)
    await client.send_heartbeat(job_id=job_id, progress_pct=95.0)

    try:
        ack = await client.submit_result(
            job_id=job_id,
            findings=result.findings,
            raw_report_s3_key=raw_report_s3_key,
            host_count=result.host_count,
            started_at=result.started_at,
            completed_at=result.completed_at,
        )
        logger.info("Job submitted successfully job_id=%s ack=%s", job_id, ack)
        state.mark_done(job_id)
        await client.send_heartbeat(job_id=job_id, progress_pct=100.0)
    except PhyApiError as exc:
        logger.error("submit_result failed for job_id=%s: %s", job_id, exc)
        state.mark_failed(job_id, str(exc))
        await client.send_log("error", f"submit_result failed: {exc}", {"job_id": job_id})


async def _poll_loop(
    client: PhyClient,
    state: AgentState,
    config: AgentConfig,
    stop_event: asyncio.Event,
) -> None:
    """Poll for new jobs every poll_interval seconds."""
    logger.info("Poll loop started (interval=%ds)", config.poll_interval)
    while not stop_event.is_set():
        active = state.get_active_job()
        if active:
            logger.debug("Job in progress (job_id=%s), skipping poll", active.get("job_id"))
        else:
            try:
                job = await client.poll_job()
                if job:
                    job_id = job.get("job_id", "unknown")
                    logger.info("Received job job_id=%s", job_id)
                    state.upsert_job(job_id, JobStatus.CLAIMED, **{
                        k: v for k, v in job.items() if k != "job_id"
                    })
                    await _run_job(job, client, state, config)
            except PhyApiError as exc:
                logger.warning("poll_job error (will retry): %s", exc)
            except Exception as exc:
                logger.exception("Unexpected error in poll loop: %s", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=config.poll_interval)
        except asyncio.TimeoutError:
            pass


async def _heartbeat_loop(
    client: PhyClient,
    state: AgentState,
    config: AgentConfig,
    stop_event: asyncio.Event,
) -> None:
    """Send heartbeat every heartbeat_interval seconds."""
    logger.info("Heartbeat loop started (interval=%ds)", config.heartbeat_interval)
    while not stop_event.is_set():
        active = state.get_active_job()
        job_id = active.get("job_id") if active else None
        try:
            await client.send_heartbeat(
                job_id=job_id,
                disk_free_gb=_disk_free_gb(),
                ram_used_pct=_ram_used_pct(),
            )
            logger.debug("Heartbeat sent job_id=%s", job_id)
        except Exception as exc:
            logger.warning("Heartbeat send failed (non-fatal): %s", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=config.heartbeat_interval)
        except asyncio.TimeoutError:
            pass


async def _amain() -> None:
    config = load_config()
    _setup_logging(config.log_level)

    logger.info(
        "PHY Scanner Agent v%s starting — api_url=%s",
        config.appliance_version,
        config.api_url,
    )

    os.makedirs(config.data_dir, exist_ok=True)
    db_path = os.path.join(config.data_dir, "agent.db")
    state = AgentState(db_path)
    client = PhyClient(config)

    # Resume any in-progress job from a previous run
    active = state.get_active_job()
    if active:
        logger.warning(
            "Resuming in-progress job from previous run: job_id=%s status=%s",
            active.get("job_id"),
            active.get("status"),
        )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _handle_signal(sig: int) -> None:
        logger.info("Received signal %s — initiating graceful shutdown", sig)
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_signal, sig)

    poll_task = asyncio.create_task(
        _poll_loop(client, state, config, stop_event), name="poll-loop"
    )
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(client, state, config, stop_event), name="heartbeat-loop"
    )

    await asyncio.gather(poll_task, heartbeat_task, return_exceptions=True)

    state.close()
    logger.info("PHY Scanner Agent stopped.")


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
