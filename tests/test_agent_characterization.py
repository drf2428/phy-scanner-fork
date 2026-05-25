"""Characterization tests for the phy-scanner-fork agent.

These tests pin the *current observable behavior* of the agent so future
transformations can be verified safe.  They are intentionally conservative —
if a characterization assertion breaks, it means behavior changed and the
change must be explicitly reviewed.

Pattern: unittest.TestCase + asyncio.run() for async paths, plus pytest
async tests where pytest-asyncio is available, so the suite runs in both modes.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest

import httpx

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config():
    from agent.config import AgentConfig
    return AgentConfig(
        api_url="https://app.physeter.cloud",
        token="char-test-token",
        poll_interval=30,
        heartbeat_interval=300,
        appliance_version="0.1.0",
        log_level="DEBUG",
        data_dir="/tmp/phy-scanner-char-test",
        appliance_os="Linux-5.15.0-test",
        feed_version_nvt="stub",
        feed_version_scap="stub",
    )


# ---------------------------------------------------------------------------
# A: AgentConfig.load_config() characterization
# ---------------------------------------------------------------------------

class TestLoadConfigCharacterization(unittest.TestCase):
    """Characterize load_config() error behavior when env vars are absent."""

    def _clear_required(self):
        for key in ("PHY_API_URL", "PHY_TOKEN"):
            os.environ.pop(key, None)

    def test_missing_api_url_raises_value_error(self):
        """When PHY_API_URL is absent, load_config raises ValueError."""
        self._clear_required()
        from agent.config import load_config
        with self.assertRaises(ValueError) as ctx:
            load_config()
        self.assertIn("PHY_API_URL", str(ctx.exception))

    def test_missing_token_raises_value_error(self):
        """When PHY_API_URL is set but PHY_TOKEN is absent, raises ValueError."""
        self._clear_required()
        os.environ["PHY_API_URL"] = "https://app.physeter.cloud"
        try:
            from agent.config import load_config
            with self.assertRaises(ValueError) as ctx:
                load_config()
            self.assertIn("PHY_TOKEN", str(ctx.exception))
        finally:
            os.environ.pop("PHY_API_URL", None)

    def test_invalid_poll_interval_raises_value_error(self):
        """Non-integer PHY_POLL_INTERVAL_SECONDS raises ValueError."""
        os.environ["PHY_API_URL"] = "https://app.physeter.cloud"
        os.environ["PHY_TOKEN"] = "tok"
        os.environ["PHY_POLL_INTERVAL_SECONDS"] = "not-a-number"
        try:
            from agent.config import load_config
            with self.assertRaises(ValueError):
                load_config()
        finally:
            for k in ("PHY_API_URL", "PHY_TOKEN", "PHY_POLL_INTERVAL_SECONDS"):
                os.environ.pop(k, None)

    def test_trailing_slash_stripped_from_api_url(self):
        """load_config strips trailing slash from PHY_API_URL."""
        os.environ["PHY_API_URL"] = "https://app.physeter.cloud/"
        os.environ["PHY_TOKEN"] = "tok"
        try:
            from agent.config import load_config
            cfg = load_config()
            self.assertEqual(cfg.api_url, "https://app.physeter.cloud")
        finally:
            os.environ.pop("PHY_API_URL", None)
            os.environ.pop("PHY_TOKEN", None)

    def test_defaults_are_applied(self):
        """When optional vars are absent, defaults are: poll=30, heartbeat=300, version=0.1.0."""
        os.environ["PHY_API_URL"] = "https://app.physeter.cloud"
        os.environ["PHY_TOKEN"] = "tok"
        for k in ("PHY_POLL_INTERVAL_SECONDS", "PHY_HEARTBEAT_INTERVAL_SECONDS",
                  "PHY_APPLIANCE_VERSION", "PHY_LOG_LEVEL", "PHY_DATA_DIR"):
            os.environ.pop(k, None)
        try:
            from agent.config import load_config
            cfg = load_config()
            self.assertEqual(cfg.poll_interval, 30)
            self.assertEqual(cfg.heartbeat_interval, 300)
            self.assertEqual(cfg.appliance_version, "0.1.0")
            self.assertEqual(cfg.log_level, "INFO")
            self.assertEqual(cfg.data_dir, "/var/lib/phy-scanner")
        finally:
            os.environ.pop("PHY_API_URL", None)
            os.environ.pop("PHY_TOKEN", None)


# ---------------------------------------------------------------------------
# B: PhyClient.poll_job() response shape characterization
# ---------------------------------------------------------------------------

class TestPollJobResponseShape(unittest.TestCase):
    """Characterize the shape of a poll_job() 200 response."""

    def test_poll_200_returns_dict_with_job_id_and_target_scope(self):
        """poll_job() on HTTP 200 returns a dict preserving all server-sent fields."""
        job_payload = {
            "job_id": "char-job-001",
            "target_scope": "192.168.1.0/24",
            "tenant_id": "t-abc",
            "scan_profile": "full",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=job_payload)

        from agent.client import PhyClient
        client = PhyClient(_make_config())

        mock_transport = httpx.MockTransport(handler)

        async def _run():
            original_make_client = client._make_client
            client._make_client = lambda: httpx.AsyncClient(
                base_url="https://app.physeter.cloud",
                transport=mock_transport,
            )
            try:
                return await client.poll_job()
            finally:
                client._make_client = original_make_client

        result = asyncio.run(_run())
        self.assertIsInstance(result, dict)
        self.assertEqual(result["job_id"], "char-job-001")
        self.assertEqual(result["target_scope"], "192.168.1.0/24")
        self.assertIn("tenant_id", result)
        self.assertIn("scan_profile", result)

    def test_poll_204_returns_none(self):
        """poll_job() on HTTP 204 returns None (no job available)."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(204)

        from agent.client import PhyClient
        client = PhyClient(_make_config())
        mock_transport = httpx.MockTransport(handler)

        async def _run():
            client._make_client = lambda: httpx.AsyncClient(
                base_url="https://app.physeter.cloud",
                transport=mock_transport,
            )
            return await client.poll_job()

        result = asyncio.run(_run())
        self.assertIsNone(result)

    def test_poll_500_raises_phy_api_error(self):
        """poll_job() on HTTP 500 raises PhyApiError."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal error")

        from agent.client import PhyClient, PhyApiError
        client = PhyClient(_make_config())
        mock_transport = httpx.MockTransport(handler)

        async def _run():
            client._make_client = lambda: httpx.AsyncClient(
                base_url="https://app.physeter.cloud",
                transport=mock_transport,
            )
            return await client.poll_job()

        with self.assertRaises(PhyApiError):
            asyncio.run(_run())


# ---------------------------------------------------------------------------
# C: AgentState job lifecycle characterization (CLAIMED -> SCANNING -> DONE)
# ---------------------------------------------------------------------------

class TestAgentStateLifecycle(unittest.TestCase):
    """Characterize AgentState job status transitions."""

    def setUp(self):
        self._tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._db_path = self._tmpfile.name
        self._tmpfile.close()

    def tearDown(self):
        import os
        try:
            os.unlink(self._db_path)
        except FileNotFoundError:
            pass

    def _make_state(self):
        from agent.state import AgentState
        return AgentState(self._db_path)

    def test_claimed_is_active(self):
        """A job in CLAIMED status is returned by get_active_job()."""
        from agent.state import JobStatus
        state = self._make_state()
        state.upsert_job("j-001", JobStatus.CLAIMED)
        active = state.get_active_job()
        self.assertIsNotNone(active)
        self.assertEqual(active["job_id"], "j-001")
        self.assertEqual(active["status"], "claimed")
        state.close()

    def test_claimed_to_scanning_transition(self):
        """Upserting SCANNING on an existing CLAIMED job updates the status."""
        from agent.state import JobStatus
        state = self._make_state()
        state.upsert_job("j-002", JobStatus.CLAIMED)
        state.upsert_job("j-002", JobStatus.SCANNING, progress_pct=25.0)
        active = state.get_active_job()
        self.assertIsNotNone(active)
        self.assertEqual(active["status"], "scanning")
        self.assertEqual(active["progress_pct"], 25.0)
        state.close()

    def test_scanning_to_done_clears_active(self):
        """mark_done() on a SCANNING job means get_active_job() returns None."""
        from agent.state import JobStatus
        state = self._make_state()
        state.upsert_job("j-003", JobStatus.SCANNING)
        state.mark_done("j-003")
        self.assertIsNone(state.get_active_job())
        state.close()

    def test_full_lifecycle_claimed_scanning_done(self):
        """Full lifecycle: CLAIMED -> SCANNING -> DONE; each intermediate step has correct status."""
        from agent.state import JobStatus
        state = self._make_state()
        job_id = "j-lifecycle"

        state.upsert_job(job_id, JobStatus.CLAIMED)
        self.assertEqual(state.get_active_job()["status"], "claimed")

        state.upsert_job(job_id, JobStatus.SCANNING)
        self.assertEqual(state.get_active_job()["status"], "scanning")

        state.mark_done(job_id)
        self.assertIsNone(state.get_active_job())

        # Row still exists with DONE status
        row = state._conn.execute(
            "SELECT status FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "done")
        state.close()

    def test_failed_status_is_not_active(self):
        """A FAILED job is not returned by get_active_job()."""
        from agent.state import JobStatus
        state = self._make_state()
        state.upsert_job("j-fail", JobStatus.SCANNING)
        state.mark_failed("j-fail", "timeout after 3600s")
        self.assertIsNone(state.get_active_job())

        row = state._conn.execute(
            "SELECT status, error FROM jobs WHERE job_id = ?", ("j-fail",)
        ).fetchone()
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["error"], "timeout after 3600s")
        state.close()


# ---------------------------------------------------------------------------
# D: Scanner stub output characterization
# ---------------------------------------------------------------------------

class TestScannerStubOutput(unittest.TestCase):
    """Characterize _make_synthetic_findings() output shape and content."""

    def test_stub_returns_exactly_3_findings(self):
        """The stub scanner always returns exactly 3 findings."""
        from agent.scanner import _make_synthetic_findings
        findings = _make_synthetic_findings("10.0.0.1")
        self.assertEqual(len(findings), 3)

    def test_each_finding_has_required_keys(self):
        """Every finding has the keys expected by PHY FindingPayload."""
        from agent.scanner import _make_synthetic_findings
        required_keys = {
            "title", "severity", "cvss_score", "cve_ids",
            "host", "port", "description", "solution",
            "plugin_id", "source",
        }
        findings = _make_synthetic_findings("10.0.0.1")
        for finding in findings:
            missing = required_keys - finding.keys()
            self.assertEqual(missing, set(), f"Finding missing keys: {missing}")

    def test_severity_values_are_valid(self):
        """Severities are one of: high, medium, info."""
        from agent.scanner import _make_synthetic_findings, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_INFO
        valid = {SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_INFO}
        findings = _make_synthetic_findings("10.0.0.1")
        for f in findings:
            self.assertIn(f["severity"], valid)

    def test_host_extracted_from_target_scope(self):
        """The host field is the first element of a comma-separated target_scope."""
        from agent.scanner import _make_synthetic_findings
        findings = _make_synthetic_findings("192.168.10.5, 192.168.10.6")
        for f in findings:
            self.assertEqual(f["host"], "192.168.10.5")

    def test_host_defaults_to_10_0_0_1_when_empty(self):
        """When target_scope is empty, host defaults to '10.0.0.1'."""
        from agent.scanner import _make_synthetic_findings
        findings = _make_synthetic_findings("")
        for f in findings:
            self.assertEqual(f["host"], "10.0.0.1")

    def test_cve_ids_is_list(self):
        """cve_ids is always a list (empty for stub findings)."""
        from agent.scanner import _make_synthetic_findings
        findings = _make_synthetic_findings("10.0.0.1")
        for f in findings:
            self.assertIsInstance(f["cve_ids"], list)

    def test_run_scan_async_returns_scan_result(self):
        """run_scan() returns a ScanResult with 3 findings and host_count=1."""
        from agent.scanner import run_scan
        job = {"job_id": "char-scan-001", "target_scope": "10.0.0.1"}
        result = asyncio.run(run_scan(job, _make_config()))
        self.assertEqual(len(result.findings), 3)
        self.assertEqual(result.host_count, 1)
        self.assertIsNotNone(result.started_at)
        self.assertIsNotNone(result.completed_at)
        self.assertIsNone(result.raw_report_path)


# ---------------------------------------------------------------------------
# E: send_heartbeat() payload shape characterization
# ---------------------------------------------------------------------------

class TestHeartbeatPayloadShape(unittest.TestCase):
    """Characterize the payload sent by send_heartbeat()."""

    def test_heartbeat_payload_contains_required_fields(self):
        """send_heartbeat() POST body contains all telemetry fields."""
        captured_body: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(204)

        from agent.client import PhyClient
        cfg = _make_config()
        client = PhyClient(cfg)
        mock_transport = httpx.MockTransport(handler)

        async def _run():
            client._make_client = lambda: httpx.AsyncClient(
                base_url="https://app.physeter.cloud",
                transport=mock_transport,
            )
            await client.send_heartbeat(
                job_id="char-hb-001",
                progress_pct=42.5,
                disk_free_gb=18.3,
                ram_used_pct=55.0,
            )

        asyncio.run(_run())

        required = {
            "appliance_version", "appliance_os",
            "feed_version_nvt", "feed_version_scap",
            "progress_pct", "disk_free_gb", "ram_used_pct",
            "job_id",
        }
        missing = required - captured_body.keys()
        self.assertEqual(missing, set(), f"Heartbeat payload missing fields: {missing}")

    def test_heartbeat_without_job_id_omits_job_id_field(self):
        """When job_id is None, the heartbeat payload does NOT include 'job_id'."""
        captured_body: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(204)

        from agent.client import PhyClient
        client = PhyClient(_make_config())
        mock_transport = httpx.MockTransport(handler)

        async def _run():
            client._make_client = lambda: httpx.AsyncClient(
                base_url="https://app.physeter.cloud",
                transport=mock_transport,
            )
            await client.send_heartbeat(job_id=None)

        asyncio.run(_run())
        self.assertNotIn("job_id", captured_body)

    def test_heartbeat_payload_values_match_config(self):
        """Heartbeat appliance_version and appliance_os reflect the AgentConfig values."""
        captured_body: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(204)

        from agent.client import PhyClient
        cfg = _make_config()
        client = PhyClient(cfg)
        mock_transport = httpx.MockTransport(handler)

        async def _run():
            client._make_client = lambda: httpx.AsyncClient(
                base_url="https://app.physeter.cloud",
                transport=mock_transport,
            )
            await client.send_heartbeat()

        asyncio.run(_run())
        self.assertEqual(captured_body["appliance_version"], cfg.appliance_version)
        self.assertEqual(captured_body["appliance_os"], cfg.appliance_os)
        self.assertEqual(captured_body["feed_version_nvt"], "stub")
        self.assertEqual(captured_body["feed_version_scap"], "stub")


if __name__ == "__main__":
    unittest.main()
