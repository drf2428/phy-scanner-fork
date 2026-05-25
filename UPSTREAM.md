# Upstream tracking

This document specifies which upstream version of Greenbone Community Edition this fork is based on, and how to sync.

## Upstream sources

| Component | Upstream repo | Pinned version | Last sync |
|---|---|---|---|
| `gvm-libs` | https://github.com/greenbone/gvm-libs | `v22.10.0` | TBD by F2 |
| `openvas-scanner` | https://github.com/greenbone/openvas-scanner | `v22.10.0` | TBD by F2 |
| `gvmd` | https://github.com/greenbone/gvmd | `v22.10.0` | TBD by F2 |
| `gsa` (UI) | https://github.com/greenbone/gsa | `v22.10.0` | TBD by F2 |
| `gsad` | https://github.com/greenbone/gsad | `v22.10.0` | TBD by F2 |

## How to sync upstream

Run `scripts/sync-upstream.sh` to fetch each upstream repo into `./build/upstream/<component>` at the pinned tag.

The script:
1. Reads pinned versions from this file (parsed from the table).
2. Clones each repo (`--depth 1 --branch <tag>`) into `./build/upstream/`.
3. Verifies SHA-256 of the source archive against `UPSTREAM_CHECKSUMS.txt` (created in F2).

## How to bump a version

1. Edit the table above with the new pinned version.
2. Run `scripts/sync-upstream.sh` to fetch.
3. Apply Physeter overlay patches from `overlay/` (introduced in F2).
4. Run full build + characterization tests.
5. Commit table + checksums file change.

## Why pinned versions, not branches

Greenbone moves fast and breaking changes happen between minor releases. Pinning lets Physeter test each bump in DEV before tenant appliances pull the update.
