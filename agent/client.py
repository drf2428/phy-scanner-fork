"""PHY API client — implements the 5 agent endpoint calls."""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from .config import AgentConfig

logger = logging.getLogger(__name__)


class PhyApiError(Exception):
    """Raised when the PHY API returns an unexpected error response."""


class NoJobAvailable(Exception):
    """Raised when poll returns 204 — no pending job."""


class PhyClient:
    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._base_url = config.api_url
        self._headers = {
            "Authorization": f"Bearer {config.token}",
            "Content-Type": "application/json",
            "User-Agent": f"phy-scanner-agent/{config.appliance_version}",
        }

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=30.0,
        )

    async def poll_job(self) -> Optional[dict]:
        """GET /agent/poll. Returns job dict or None if 204."""
        async with self._make_client() as client:
            resp = await client.get("/agent/poll")
            if resp.status_code == 204:
                return None
            if resp.status_code == 200:
                return resp.json()
            raise PhyApiError(f"poll_job unexpected status {resp.status_code}: {resp.text}")

    async def submit_result(
        self,
        job_id: str,
        findings: list[dict],
        raw_report_s3_key: str | None,
        host_count: int,
        started_at: str,
        completed_at: str,
    ) -> dict:
        """POST /agent/result."""
        payload: dict[str, Any] = {
            "job_id": job_id,
            "findings": findings,
            "finding_count": len(findings),
            "raw_report_s3_key": raw_report_s3_key,
            "host_count": host_count,
            "started_at": started_at,
            "completed_at": completed_at,
        }
        async with self._make_client() as client:
            resp = await client.post("/agent/result", json=payload)
            if resp.status_code == 200:
                return resp.json()
            raise PhyApiError(f"submit_result unexpected status {resp.status_code}: {resp.text}")

    async def send_heartbeat(
        self,
        job_id: Optional[str] = None,
        progress_pct: float = 0.0,
        disk_free_gb: float = 0.0,
        ram_used_pct: float = 0.0,
    ) -> None:
        """POST /agent/heartbeat. 204 expected."""
        payload: dict[str, Any] = {
            "appliance_version": self._config.appliance_version,
            "appliance_os": self._config.appliance_os,
            "feed_version_nvt": self._config.feed_version_nvt,
            "feed_version_scap": self._config.feed_version_scap,
            "progress_pct": progress_pct,
            "disk_free_gb": disk_free_gb,
            "ram_used_pct": ram_used_pct,
        }
        if job_id is not None:
            payload["job_id"] = job_id

        async with self._make_client() as client:
            resp = await client.post("/agent/heartbeat", json=payload)
            if resp.status_code not in (200, 204):
                logger.warning("send_heartbeat unexpected status %s", resp.status_code)

    async def get_config(self) -> dict:
        """GET /agent/config. Returns cidrs_allowed, schedule_cron, production_enabled."""
        async with self._make_client() as client:
            resp = await client.get("/agent/config")
            if resp.status_code == 200:
                return resp.json()
            raise PhyApiError(f"get_config unexpected status {resp.status_code}: {resp.text}")

    async def send_log(
        self,
        level: str,
        message: str,
        context: Optional[dict] = None,
    ) -> None:
        """POST /agent/log. Best-effort, never raises."""
        payload: dict[str, Any] = {
            "level": level,
            "message": message,
            "context": context or {},
        }
        try:
            async with self._make_client() as client:
                await client.post("/agent/log", json=payload)
        except Exception as exc:  # noqa: BLE001
            logger.debug("send_log failed (best-effort): %s", exc)

    async def get_upload_url(self, job_id: str) -> Optional[tuple[str, str]]:
        """GET /agent/upload-url?job_id=. Returns (url, s3_key) or None on error."""
        try:
            async with self._make_client() as client:
                resp = await client.get("/agent/upload-url", params={"job_id": job_id})
                if resp.status_code == 200:
                    data = resp.json()
                    return data["upload_url"], data["upload_s3_key"]
                logger.warning("get_upload_url unexpected status %s", resp.status_code)
                return None
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_upload_url failed: %s", exc)
            return None
