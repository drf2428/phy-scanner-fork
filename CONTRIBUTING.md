# Contributing to phy-scanner-fork

This is a fork of the Greenbone Community Edition (OpenVAS), maintained by the Physeter team. All contributions are subject to the terms of the GPL-2.0 license.

## License Agreement

By submitting a contribution (pull request, patch, or issue), you agree that your work will be licensed under the **GNU General Public License v2.0**. See `LICENSE` for the full text. There is no separate CLA — the GPL-2.0 itself governs contributions.

## Development Environment Setup

```bash
# 1. Clone the repo
git clone https://github.com/drf2428/phy-scanner-fork.git
cd phy-scanner-fork

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r agent/requirements.txt

# 4. Install test dependencies
pip install pytest pytest-asyncio
```

## Running Tests

```bash
python3 -m pytest tests/ -v
```

All tests must pass before a pull request is reviewed. Do not submit pull requests that break existing tests.

## Branch Naming Convention

| Type | Pattern | Example |
|------|---------|---------|
| New feature | `feature/<short-description>` | `feature/openvas-nvt-feed-sync` |
| Bug fix | `fix/<short-description>` | `fix/heartbeat-retry-backoff` |
| Documentation | `docs/<short-description>` | `docs/update-deployment-guide` |
| Dependency update | `chore/<short-description>` | `chore/bump-httpx-0.28` |

## Pull Request Guidelines

- Keep PRs focused on a single concern.
- Add or update tests for any behavior change.
- Update `oss-disclosures.md` if you add a new third-party dependency.
- Do not modify `LICENSE`, `UPSTREAM.md`, or `UPSTREAM_CREDITS.md` without prior discussion.

## Upstream Relationship

This is a fork of the Greenbone Community Edition. When syncing from upstream, use `scripts/sync-upstream.sh`. Do not manually cherry-pick from upstream without documenting the change in `UPSTREAM_CREDITS.md`.

## Security Issues

Do **not** open public GitHub issues for security vulnerabilities. See `SECURITY.md` for the responsible disclosure process.
