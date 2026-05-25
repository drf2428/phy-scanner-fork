# Physeter Scanner

Open-source fork of [Greenbone Community Edition (OpenVAS)](https://github.com/greenbone) used as the internal Attack Surface Management scan engine of the [Physeter](https://physeter.cloud) platform.

## What is this?

Physeter is a hub and correlator of organizational risk analysis sources. This repository hosts:

- A lightweight **Python agent** (`agent/`) that runs inside the appliance VM, polls the Physeter platform for scan tasks, invokes OpenVAS/GVM, and reports results back.
- A **build scaffold** (`scripts/`) for producing the OVA appliance image.
- The **systemd unit** (`systemd/`) that keeps the agent running.

The agent communicates exclusively outbound over HTTPS — no inbound ports are required on the customer network.

## Agent service

The agent lives in `agent/` and is a self-contained Python 3.11 package:

| File | Purpose |
|------|---------|
| `agent/main.py` | Entry point — polling loop and heartbeat |
| `agent/client.py` | HTTPS client for the Physeter platform API |
| `agent/scanner.py` | OpenVAS/GVM integration stub |
| `agent/state.py` | SQLite-backed local state (deduplication, last-seen) |
| `agent/config.py` | Configuration from environment variables |
| `agent/version.txt` | Semver version string |

Runtime dependencies: `httpx`, `psutil` (see `agent/requirements.txt`).

## Getting the appliance OVA

Pre-built appliance images are distributed via CloudFront:

```
https://artifacts.physeter.cloud/phy-scanner/latest/phy-internal-scanner.ova
```

> Note: CloudFront distribution is pending operator setup. Until then, build locally with `scripts/build-appliance.sh`.

Import the OVA into your hypervisor (VMware ESXi, VirtualBox, Proxmox, etc.) and supply the cloud-init user-data on first boot (see below).

## Building the OVA locally

Requires a Debian/Ubuntu Linux host with root access:

```bash
sudo apt-get install debootstrap qemu-utils parted e2fsprogs
sudo ./scripts/build-appliance.sh [VERSION]
# Output: dist/phy-internal-scanner-v<VERSION>.ova
```

See `scripts/build-appliance.sh` for the full annotated build steps.

## Quick start — development with Docker

No hypervisor needed. The dev image runs the agent process directly (no real OpenVAS):

```bash
# Build
docker build -f scripts/Dockerfile.dev -t phy-scanner-dev .

# Run (requires a valid token from the Physeter admin panel)
docker run --rm \
  -e PHY_API_URL=https://app.physeter.cloud \
  -e PHY_TOKEN=<your-token> \
  phy-scanner-dev
```

The agent will connect, register itself, and begin polling for scan tasks.

## First-boot cloud-init token setup

When deploying the OVA, inject the following user-data through your hypervisor's cloud-init mechanism (vSphere, Proxmox `cicustom`, VirtualBox cloud-init ISO, etc.):

```yaml
#cloud-config
phy_scanner:
  api_url: "https://app.physeter.cloud"
  token: "your-token-here"
```

The token is generated in the Physeter **Admin > Appliances** wizard. On first boot, cloud-init writes the values to `/etc/phy-scanner/config.env` (mode `0600`) and starts the `phy-scanner-agent` systemd service.

See `scripts/cloud-init-template.yaml` for the full cloud-init configuration reference.

## Repository layout

```
agent/              Python agent package
scripts/
  build-appliance.sh       OVA build script (Linux, requires root)
  cloud-init-template.yaml cloud-init reference config
  Dockerfile.dev           Dev/test image (no real OpenVAS)
systemd/
  phy-scanner-agent.service  systemd unit installed in the appliance
tests/              Unit tests for the agent
```

## License

This project is licensed under the **GNU General Public License v2 (GPL-2.0)**, matching the upstream Greenbone Community Edition license. See [LICENSE](LICENSE).

## Upstream credits

See [UPSTREAM_CREDITS.md](UPSTREAM_CREDITS.md) for full credits to the Greenbone Networks team and contributors.

## Contributing

This repository is a downstream fork maintained for Physeter integration. For changes to the upstream scanner, contribute directly to the [Greenbone Community Edition project](https://github.com/greenbone).
