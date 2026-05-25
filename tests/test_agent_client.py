"""Tests for PhyClient using httpx.MockTransport."""
from __future__ import annotations

import json
from typing import Optional

import pytest
import httpx

from agent.config import AgentConfig
from agent.client import PhyClient, PhyApiError


def _make_config() -> AgentConfig:
    return AgentConfig(
        api_url="https://app.physeter.cloud",
        token="test-token",
        poll_interval=30,
        heartbeat_interval=300,
        appliance_version="0.1.0",
        log_level="DEBUG",
        data_dir="/tmp/phy-scanner-test",
    )


def _mock_transport(status: int, body: Optional[dict] = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        content = json.dumps(body).encode() if body is not None else b""
        return httpx.Response(status_code=status, content=content)
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_poll_returns_job(monkeypatch):
    """GET /agent/poll 200 returns job dict."""
    job_payload = {"job_id": "abc123", "target_scope": "10.0.0.0/24"}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/agent/poll"
        return httpx.Response(200, json=job_payload)

    client = PhyClient(_make_config())
    monkeypatch.setattr(client, "_make_client", lambda: httpx.AsyncClient(
        base_url="https://app.physeter.cloud",
        transport=httpx.MockTransport(handler),
    ))

    result = await client.poll_job()
    assert result == job_payload


@pytest.mark.asyncio
async def test_poll_returns_none_on_204(monkeypatch):
    """GET /agent/poll 204 returns None."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204)

    client = PhyClient(_make_config())
    monkeypatch.setattr(client, "_make_client", lambda: httpx.AsyncClient(
        base_url="https://app.physeter.cloud",
        transport=httpx.MockTransport(handler),
    ))

    result = await client.poll_job()
    assert result is None


@pytest.mark.asyncio
async def test_submit_result_success(monkeypatch):
    """POST /agent/result 200 returns ack dict."""
    ack_payload = {"status": "accepted", "job_id": "abc123"}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/agent/result"
        body = json.loads(request.content)
        assert body["job_id"] == "abc123"
        return httpx.Response(200, json=ack_payload)

    client = PhyClient(_make_config())
    monkeypatch.setattr(client, "_make_client", lambda: httpx.AsyncClient(
        base_url="https://app.physeter.cloud",
        transport=httpx.MockTransport(handler),
    ))

    result = await client.submit_result(
        job_id="abc123",
        findings=[{"title": "test", "severity": "high"}],
        raw_report_s3_key=None,
        host_count=1,
        started_at="2026-05-25T00:00:00Z",
        completed_at="2026-05-25T00:01:00Z",
    )
    assert result == ack_payload


@pytest.mark.asyncio
async def test_heartbeat_204(monkeypatch):
    """POST /agent/heartbeat 204 raises no exception."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/agent/heartbeat"
        return httpx.Response(204)

    client = PhyClient(_make_config())
    monkeypatch.setattr(client, "_make_client", lambda: httpx.AsyncClient(
        base_url="https://app.physeter.cloud",
        transport=httpx.MockTransport(handler),
    ))

    # Should complete without raising
    await client.send_heartbeat(job_id=None, status="idle")


@pytest.mark.asyncio
async def test_send_log_never_raises(monkeypatch):
    """POST /agent/log NetworkError is swallowed (best-effort)."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.NetworkError("connection refused")

    client = PhyClient(_make_config())
    monkeypatch.setattr(client, "_make_client", lambda: httpx.AsyncClient(
        base_url="https://app.physeter.cloud",
        transport=httpx.MockTransport(handler),
    ))

    # Must NOT raise even when network fails
    await client.send_log("error", "something went wrong", {"context": "test"})
