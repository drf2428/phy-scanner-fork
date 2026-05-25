"""Tests for AgentState using a temporary SQLite database."""
import os
import tempfile

import pytest

from agent.state import AgentState, JobStatus


@pytest.fixture
def state():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    s = AgentState(db_path)
    yield s
    s.close()
    os.unlink(db_path)


def test_upsert_and_get_active_job(state: AgentState):
    """Upserting a job in SCANNING status makes it the active job."""
    state.upsert_job("job-001", JobStatus.SCANNING, target_scope="10.0.0.0/24")

    active = state.get_active_job()
    assert active is not None
    assert active["job_id"] == "job-001"
    assert active["status"] == JobStatus.SCANNING.value
    assert active["target_scope"] == "10.0.0.0/24"


def test_mark_done_clears_active(state: AgentState):
    """Marking a job DONE means get_active_job returns None."""
    state.upsert_job("job-002", JobStatus.CLAIMED)
    assert state.get_active_job() is not None

    state.mark_done("job-002")
    active = state.get_active_job()
    assert active is None


def test_mark_failed_persists_error(state: AgentState):
    """mark_failed stores the error string and status transitions to FAILED."""
    state.upsert_job("job-003", JobStatus.SCANNING)
    state.mark_failed("job-003", "OpenVAS timed out")

    # FAILED is not an active status, so get_active_job returns None
    assert state.get_active_job() is None

    # Verify the row directly
    row = state._conn.execute(
        "SELECT status, error FROM jobs WHERE job_id = ?", ("job-003",)
    ).fetchone()
    assert row is not None
    assert row["status"] == JobStatus.FAILED.value
    assert row["error"] == "OpenVAS timed out"
