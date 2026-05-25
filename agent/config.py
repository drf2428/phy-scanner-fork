"""Agent configuration — loaded from environment or /etc/phy-scanner/config.env."""
import os
from dataclasses import dataclass


@dataclass
class AgentConfig:
    api_url: str           # PHY_API_URL e.g. "https://app.physeter.cloud"
    token: str             # PHY_TOKEN (bcrypt-matched per-tenant)
    poll_interval: int     # PHY_POLL_INTERVAL_SECONDS default 30
    heartbeat_interval: int  # PHY_HEARTBEAT_INTERVAL_SECONDS default 300
    appliance_version: str  # PHY_APPLIANCE_VERSION default "0.1.0"
    log_level: str         # PHY_LOG_LEVEL default "INFO"
    data_dir: str          # PHY_DATA_DIR default "/var/lib/phy-scanner"


def load_config() -> AgentConfig:
    """Load config from env vars. Raise ValueError if required vars missing."""
    api_url = os.environ.get("PHY_API_URL", "").strip()
    if not api_url:
        raise ValueError("PHY_API_URL is required but not set")

    token = os.environ.get("PHY_TOKEN", "").strip()
    if not token:
        raise ValueError("PHY_TOKEN is required but not set")

    try:
        poll_interval = int(os.environ.get("PHY_POLL_INTERVAL_SECONDS", "30"))
    except ValueError:
        raise ValueError("PHY_POLL_INTERVAL_SECONDS must be an integer")

    try:
        heartbeat_interval = int(os.environ.get("PHY_HEARTBEAT_INTERVAL_SECONDS", "300"))
    except ValueError:
        raise ValueError("PHY_HEARTBEAT_INTERVAL_SECONDS must be an integer")

    appliance_version = os.environ.get("PHY_APPLIANCE_VERSION", "0.1.0")
    log_level = os.environ.get("PHY_LOG_LEVEL", "INFO").upper()
    data_dir = os.environ.get("PHY_DATA_DIR", "/var/lib/phy-scanner")

    return AgentConfig(
        api_url=api_url.rstrip("/"),
        token=token,
        poll_interval=poll_interval,
        heartbeat_interval=heartbeat_interval,
        appliance_version=appliance_version,
        log_level=log_level,
        data_dir=data_dir,
    )
