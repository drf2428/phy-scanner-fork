# Security Policy — phy-scanner-fork

## Reporting a Vulnerability

If you discover a security vulnerability in this repository, please **do not open a public GitHub issue**. Public disclosure before a fix is available can put users at risk.

Instead, report the vulnerability by email to:

**security@physeter.cloud**

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (as detailed as possible)
- Any suggested mitigations you are aware of

## PGP Key

A PGP public key for encrypting sensitive reports will be published at:

`https://physeter.cloud/.well-known/security.txt` (placeholder — key pending)

## Responsible Disclosure Policy

We follow a **90-day responsible disclosure window**:

1. You report the vulnerability to security@physeter.cloud.
2. We acknowledge receipt within **5 business days**.
3. We assess severity and scope within **14 days** and communicate our timeline to you.
4. We aim to release a fix within **90 days** of the initial report.
5. If we cannot fix within 90 days, we will notify you and agree on a coordinated disclosure date.
6. We will credit you in the release notes (unless you prefer anonymity).

## Scope

This policy covers security vulnerabilities in the `phy-scanner-fork` agent code itself. For vulnerabilities in upstream Greenbone Community Edition / OpenVAS, please also report to [Greenbone's security team](https://www.greenbone.net/en/responsible-disclosure/).

## Out of Scope

- Vulnerabilities in dependencies (report to the upstream maintainer; cc us if the impact is significant)
- Issues that require physical access to a deployed appliance
- Social engineering or phishing attacks against Physeter users
