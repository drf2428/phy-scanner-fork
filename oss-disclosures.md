# OSS Disclosures — phy-scanner-fork

This document lists all open-source software components used in this repository, in compliance with GPL-2.0 obligations and as a best practice for third-party license transparency.

## License Obligations Summary

This repository is licensed under the **GNU General Public License v2.0 (GPL-2.0)**. Components marked GPL-2.0 below impose reciprocal licensing requirements on any derivative works distributed to third parties. The `scan-worker-openvas` deployment container derived from this code is distributed as GPL-2.0; the Physeter platform communicates with it exclusively over HTTPS and is not a derivative work.

## Component Table

| Component | License | Copyright | Source URL | Usage |
|-----------|---------|-----------|------------|-------|
| gvm-python-lib | GPL-2.0 | Greenbone Networks GmbH | https://github.com/greenbone/python-gvm | OpenVAS/GVM protocol client (planned F3 integration; stub in F2.4) |
| httpx | BSD-3-Clause | Encode, Tom Christie | https://github.com/encode/httpx | HTTP client for Physeter API calls (agent/client.py) |
| psutil | BSD-3-Clause | Giampaolo Rodolà | https://github.com/giampaolo/psutil | System metrics for heartbeat (disk_free_gb, ram_used_pct) |
| lxml | BSD-3-Clause | lxml dev team | https://github.com/lxml/lxml | XML parsing of GVM scan reports (planned F3; not yet in requirements) |
| Python 3.11 standard library | PSF License 2.0 | Python Software Foundation | https://www.python.org | asyncio, sqlite3, dataclasses, os, json, logging, enum, typing |
| pytest | MIT | Holger Krekel and contributors | https://github.com/pytest-dev/pytest | Test runner (dev/CI only, not deployed) |
| pytest-asyncio | Apache-2.0 | pytest-asyncio contributors | https://github.com/pytest-dev/pytest-asyncio | Async test support (dev/CI only, not deployed) |

## BSD-3-Clause Text (httpx, psutil, lxml)

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## GPL-2.0 Compliance Statement

This fork is derived from the Greenbone Community Edition (OpenVAS), which is licensed under GPL-2.0. In accordance with GPL-2.0:

- The full source code of this fork is publicly available at: https://github.com/drf2428/phy-scanner-fork
- The GPL-2.0 license text is included at `LICENSE` in this repository.
- Any modifications to GPL-2.0 covered files are noted in `UPSTREAM_CREDITS.md`.
- The corresponding upstream source is documented in `UPSTREAM.md`.
