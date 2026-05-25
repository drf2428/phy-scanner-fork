"""Local state machine for scan jobs (SQLite at {data_dir}/agent.db)."""
from __future__ import annotations

import json
import logging
import sqlite3
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id      TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    error       TEXT,
    extra       TEXT,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class JobStatus(str, Enum):
    CLAIMED = "claimed"
    SCANNING = "scanning"
    UPLOADING = "uploading"
    SUBMITTING = "submitting"
    DONE = "done"
    FAILED = "failed"


_ACTIVE_STATUSES = {
    JobStatus.CLAIMED,
    JobStatus.SCANNING,
    JobStatus.UPLOADING,
    JobStatus.SUBMITTING,
}


class AgentState:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_CREATE_TABLE)
        self._conn.commit()

    def upsert_job(self, job_id: str, status: JobStatus, **extra: Any) -> None:
        """Insert or update a job record."""
        extra_json = json.dumps(extra) if extra else None
        self._conn.execute(
            """
            INSERT INTO jobs (job_id, status, extra, updated_at)
            VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(job_id) DO UPDATE SET
                status     = excluded.status,
                extra      = excluded.extra,
                updated_at = excluded.updated_at
            """,
            (job_id, status.value, extra_json),
        )
        self._conn.commit()
        logger.debug("upsert_job job_id=%s status=%s", job_id, status.value)

    def get_active_job(self) -> Optional[dict]:
        """Return the most recently updated active job, or None."""
        placeholders = ",".join("?" * len(_ACTIVE_STATUSES))
        row = self._conn.execute(
            f"""
            SELECT job_id, status, extra, updated_at
            FROM jobs
            WHERE status IN ({placeholders})
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            [s.value for s in _ACTIVE_STATUSES],
        ).fetchone()
        if row is None:
            return None
        result: dict[str, Any] = dict(row)
        if result.get("extra"):
            result.update(json.loads(result["extra"]))
        del result["extra"]
        return result

    def mark_done(self, job_id: str) -> None:
        """Transition job to DONE status."""
        self._conn.execute(
            "UPDATE jobs SET status = ?, error = NULL, updated_at = datetime('now') WHERE job_id = ?",
            (JobStatus.DONE.value, job_id),
        )
        self._conn.commit()
        logger.debug("mark_done job_id=%s", job_id)

    def mark_failed(self, job_id: str, error: str) -> None:
        """Transition job to FAILED status, persisting the error message."""
        self._conn.execute(
            "UPDATE jobs SET status = ?, error = ?, updated_at = datetime('now') WHERE job_id = ?",
            (JobStatus.FAILED.value, error, job_id),
        )
        self._conn.commit()
        logger.debug("mark_failed job_id=%s error=%s", job_id, error)

    def close(self) -> None:
        self._conn.close()
