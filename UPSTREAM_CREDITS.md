# Upstream credits

This repository is a downstream fork of the **Greenbone Community Edition (OpenVAS)** project, originally developed and maintained by **Greenbone Networks GmbH** and its contributors.

## Upstream project

- **Project name:** Greenbone Community Edition
- **Engine name:** OpenVAS (Open Vulnerability Assessment Scanner)
- **Upstream organization:** [Greenbone Networks GmbH](https://www.greenbone.net/)
- **Upstream repositories:** [github.com/greenbone](https://github.com/greenbone)
- **Original license:** GNU General Public License v2 (GPL-2.0)

## License compliance

In accordance with GPL v2 Section 2, all modifications made in this fork are licensed under the same GPL v2 terms. The modified source code is available publicly in this repository.

Users of this software retain all rights granted by GPL v2, including the right to:

- Use the software for any purpose
- Study how the software works and modify it
- Redistribute copies of the software
- Distribute modified versions of the software

## Physeter modifications

Modifications made by Physeter to this fork include (non-exhaustive):

- Rebranding (removal of "OpenVAS" / "Greenbone" strings from user-facing surfaces)
- Agent service for outbound HTTPS communication with the Physeter SaaS backend
- Tenant on-prem appliance packaging (OVA / qcow2 / AMI / ISO)
- Integration with Physeter scoring and correlation pipeline
- Customized NVT update channels (stable / lts)

These modifications do not change the core detection engine or vulnerability test logic (NVTs), which remain functionally equivalent to upstream.

## Acknowledgments

We are grateful to **Greenbone Networks** and the broader OpenVAS community for years of open-source contributions to the vulnerability scanning ecosystem. Without their work, this project would not exist.

If you find this fork useful, consider also supporting Greenbone Networks and the OpenVAS community.
