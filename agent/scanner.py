"""OpenVAS engine interface — STUB for F2.4 scaffold.

Real OpenVAS integration (gvm-python-lib calls) is future scope.
This stub generates synthetic findings to validate the agent<->Physeter handshake.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Severity constants aligned with PHY FindingPayload
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_INFO = "info"


@dataclass
class ScanResult:
    findings: list[dict]
    host_count: int
    started_at: str
    completed_at: str
    raw_report_path: Optional[str]  # local .xml path; None in stub


def _make_synthetic_findings(target_scope: str) -> list[dict]:
    """Return 3 deterministic synthetic findings for any target scope."""
    return [
        {
            "title": "Open port 22/tcp (SSH)",
            "severity": SEVERITY_HIGH,
            "cvss_score": 7.5,
            "cve_ids": [],
            "host": target_scope.split(",")[0].strip() if target_scope else "10.0.0.1",
            "port": "22/tcp",
            "description": (
                "SSH service detected on port 22. "
                "Ensure key-based auth is enforced and password auth is disabled."
            ),
            "solution": "Disable root login and enforce SSH key authentication.",
            "plugin_id": "STUB-001",
            "source": "phy-scanner-stub",
        },
        {
            "title": "TLS certificate expiring within 30 days",
            "severity": SEVERITY_MEDIUM,
            "cvss_score": 4.3,
            "cve_ids": [],
            "host": target_scope.split(",")[0].strip() if target_scope else "10.0.0.1",
            "port": "443/tcp",
            "description": (
                "The TLS certificate for this host expires within 30 days. "
                "Renew it to avoid service disruption."
            ),
            "solution": "Renew the TLS certificate before expiry.",
            "plugin_id": "STUB-002",
            "source": "phy-scanner-stub",
        },
        {
            "title": "HTTP server banner disclosure",
            "severity": SEVERITY_INFO,
            "cvss_score": 0.0,
            "cve_ids": [],
            "host": target_scope.split(",")[0].strip() if target_scope else "10.0.0.1",
            "port": "80/tcp",
            "description": (
                "The HTTP server is disclosing its version in the Server header. "
                "This can assist attackers in fingerprinting the software stack."
            ),
            "solution": "Configure the web server to suppress version information in headers.",
            "plugin_id": "STUB-003",
            "source": "phy-scanner-stub",
        },
    ]


async def run_scan(job: dict, config) -> ScanResult:
    """Trigger scan and return results.

    STUB: simulates a short scan delay and returns 3 synthetic findings.
    Real OpenVAS integration (gvm-python-lib) is future scope.
    """
    job_id = job.get("job_id", "unknown")
    target_scope = job.get("target_scope", "")

    logger.info(
        "STUB scanner starting for job_id=%s target_scope=%s",
        job_id,
        target_scope,
    )

    started_at = datetime.now(timezone.utc).isoformat()

    # Simulate scan work (short delay so tests remain fast)
    await asyncio.sleep(0.05)

    completed_at = datetime.now(timezone.utc).isoformat()
    findings = _make_synthetic_findings(target_scope)

    logger.info(
        "STUB scanner completed job_id=%s findings=%d",
        job_id,
        len(findings),
    )

    return ScanResult(
        findings=findings,
        host_count=1,
        started_at=started_at,
        completed_at=completed_at,
        raw_report_path=None,
    )
