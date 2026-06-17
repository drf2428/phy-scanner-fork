"""Scanner engine — real nmap service detection (Mode-1, non-destructive).

Runs ``nmap -sV --open -T4 -Pn --script=<_NSE_SCRIPTS>`` over the
backend-authorized target scope, parses the XML report (stdlib
``xml.etree``) into ``FindingPayload``-shaped findings, and writes the raw
XML to a temp file for upload to PHY S3.

Security / §51:
  - Only nmap (local network) + reverse-DNS via the local resolver. No third-
    party calls (no NVD / telemetry / exploit modules).
  - Detection only: ``-sV --open -T4 -Pn`` plus a FROZEN, CURATED allowlist
    of safe+no-egress NSE scripts (``_NSE_SCRIPTS``). ALL scripts are in
    nmap's ``safe`` category — no authentication attempts, no exploitation,
    no external callbacks. ``ssl-enum-ciphers`` was intentionally excluded
    because it is ``intrusive``, not ``safe``. The allowlist is a module-level
    constant; it is NEVER sourced from config/env/backend (gate fix #2 —
    prevents config-injection bypass of §51). No ``-A``, no ``--script vuln``
    wholesale, no ``brute``/``dos``/``exploit``/``intrusive``/``external``
    category tokens ever enter the nmap argv.
  - ``filter_scope`` is the legal control: the agent never runs nmap outside
    the CIDR allowlist (defense-in-depth — target_scope is already backend-
    authorized, but the agent does not trust it blindly).
  - CVE references found in safe script output (offline regex, no network
    call) are captured in ``cve_ids`` so PHY's 1b enrichment can resolve
    CWE/EPSS/KEV/ATT&CK from ti_advisories offline. Cap of 10 CVE-ids per
    finding prevents attacker-controlled output injecting unbounded data.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# §51 NSE allowlist — FROZEN, curated, hardcoded (gate fix #2).
#
# This tuple is the ONLY source of NSE script names that ever reach nmap.
# It must NEVER be derived from config / env / backend responses — doing so
# would make the no-exfil / no-exploitation gate bypassable by config
# injection.  Tests assert that the effective argv script set equals exactly
# this constant.
#
# All scripts are nmap category ``safe`` (no-DoS, no-auth, no-exploitation)
# AND no-egress (no outbound connections to third-party services).
# ``ssl-enum-ciphers`` was intentionally dropped — it is ``intrusive``, not
# ``safe``.  ``vulners`` and ``vulscan`` are excluded because they are
# ``external`` (call vulners.com/third-party DB) — §51 prohibits them.
# No ``brute``, ``dos``, ``exploit``, or ``intrusive`` script/category is
# present or permitted.
# ---------------------------------------------------------------------------
_NSE_SCRIPTS: tuple[str, ...] = (
    "smb-os-discovery",    # safe: NetBIOS/SMB name + OS (already proven E2E)
    "smb2-security-mode",  # safe: SMB signing required/not-required (attack-path signal)
    "smb-protocols",       # safe: enumerate supported SMB dialects
    "ssl-cert",            # safe: TLS cert details, expiry, weak-key detection
    "ssh2-enum-algos",     # safe: SSH key-exchange / cipher / MAC algorithm lists
    "rdp-ntlm-info",       # safe: RDP NTLM authentication info banner (Windows targets)
    "http-headers",        # safe: HTTP response headers (security-header gaps)
    "http-title",          # safe: page title for fingerprinting
    "http-server-header",  # safe: Server header (version fingerprint)
    "snmp-info",           # safe: SNMP system info (sysDescr, sysObjectID)
    "ftp-anon",            # safe: anonymous FTP login detection
    "smtp-commands",       # safe: SMTP EHLO banner + supported commands
    "banner",              # safe: raw TCP banner grab (generic service fingerprint)
)

# The comma-joined script list is pre-computed once at import time so it can
# be tested as a constant and never reconstructed from mutable data.
_NSE_SCRIPTS_ARG: str = "--script=" + ",".join(_NSE_SCRIPTS)

# Severity constants aligned with PHY FindingPayload
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

# Bounded nmap runtime (seconds).
# With 13 NSE scripts the scan takes substantially longer than the single
# smb-os-discovery run.  Per-host overhead for the full script set on a lab
# subnet (10–50 hosts) is roughly 5–15 s extra vs. service detection alone.
# A /24 (254 live hosts, worst-case) with all scripts: ~30–45 min.  The
# timeout is raised to 1800 s (30 min) to avoid partial results for
# medium-sized subnets while still bounding runaway scans.
# Operators who need a longer cap can set the ``nmap_timeout_seconds``
# attribute on the config object; the constant is the fallback floor.
NMAP_TIMEOUT_SECONDS = 1800

# Reject IPv4 networks broader than this prefix (too-broad / abuse guard).
MIN_IPV4_PREFIX = 16

# Hard cap on total expanded hosts across all kept targets per scan.
MAX_HOSTS_PER_SCAN = 65536

# Networks that are always rejected regardless of side.
_REJECTED_NETWORKS = ("0.0.0.0/0", "::/0")

# RFC1918 private space — the built-in floor used when the tenant has NO
# allowlist configured (empty list from a SUCCESSFUL get_config). An internal
# appliance must never touch public IPs without an explicit allowlist, so even
# the no-allowlist fallback is restricted to private space.
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# port -> (severity, title, description, solution)
# Mirrors the proven lab appliance map (already validated E2E -> 7 findings).
SVC = {
    80: (
        SEVERITY_HIGH,
        "Aplicación web deliberadamente vulnerable (DVWA)",
        "Servidor HTTP sirviendo DVWA — expuesto a SQL Injection, XSS y Command Injection.",
        "Retirar la app vulnerable; WAF, autenticación y validación de entrada.",
    ),
    443: (
        SEVERITY_HIGH,
        "Aplicación web vulnerable sobre TLS",
        "Servicio HTTPS de una app web vulnerable.",
        "Mismo tratamiento que el HTTP; verificar TLS.",
    ),
    3306: (
        SEVERITY_HIGH,
        "MySQL expuesto con credenciales débiles",
        "MySQL accesible en la red interna; root con contraseña débil/por defecto.",
        "Firewall de red, rotar credenciales, deshabilitar root remoto.",
    ),
    445: (
        SEVERITY_HIGH,
        "Recurso compartido SMB con acceso anónimo",
        "Samba con share anónimo accesible — exposición de datos sin autenticación.",
        "Deshabilitar guest/anónimo; ACLs por usuario.",
    ),
    139: (
        SEVERITY_MEDIUM,
        "NetBIOS/SMB legacy expuesto",
        "Puerto NetBIOS (139) abierto — SMB legacy susceptible a enumeración.",
        "Deshabilitar NetBIOS sobre TCP; SMB moderno con firma.",
    ),
    22: (
        SEVERITY_MEDIUM,
        "SSH expuesto (riesgo de escalada de privilegios)",
        "OpenSSH accesible; el host tiene sudo misconfig + SUID + reuso de credenciales.",
        "Restringir SSH por red, deshabilitar password auth, corregir sudoers/SUID.",
    ),
    389: (
        SEVERITY_MEDIUM,
        "OpenLDAP expuesto sin cifrado",
        "Directorio LDAP accesible en 389/tcp sin TLS — exposición de identidad.",
        "Forzar LDAPS (636), restringir bind anónimo, segmentar la red.",
    ),
    636: (
        SEVERITY_INFO,
        "Servicio LDAPS detectado",
        "Puerto LDAP sobre TLS (636) detectado.",
        "Verificar certificado y suites de cifrado.",
    ),
}


@dataclass
class ScanResult:
    findings: list[dict]
    host_count: int
    started_at: str
    completed_at: str
    raw_report_path: Optional[str]  # local .xml path uploaded to PHY S3 by main.py
    kept_targets: Optional[list[str]] = None  # validated in-scope targets scanned
    dropped_targets: Optional[list[str]] = None  # targets rejected by filter_scope


def _parse_network(value: str) -> Optional["ipaddress.IPv4Network"]:
    """Parse a target/allowlist entry into a validated IPv4 network.

    Returns None (caller logs "dropped") when the entry is:
      - malformed,
      - IPv6 (the nmap parse path is ipv4-only for now),
      - the catch-all 0.0.0.0/0 or ::/0,
      - an IPv4 prefix broader than MIN_IPV4_PREFIX (too-broad).
    """
    entry = (value or "").strip()
    if not entry:
        return None
    if entry in _REJECTED_NETWORKS:
        return None
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None
    if net.version != 4:
        # Drop IPv6 — the nmap parse path is ipv4. Logged as out-of-scope.
        return None
    if net.prefixlen < MIN_IPV4_PREFIX:
        # Broader than /16 — abuse / DoS guard.
        return None
    return net


def _canonical_or_none(value: str) -> Optional[str]:
    """Return the canonical ``str(network)`` for a target, or None if invalid.

    Used to reconcile the raw target strings with ``filter_scope`` output
    (which is canonicalized) so the dropped-list reflects the raw input.
    """
    net = _parse_network(value)
    return str(net) if net is not None else None


def filter_scope(
    target_scope: str,
    cidrs_allowed: Optional[list[str]],
) -> list[str]:
    """Return the validated, in-scope target strings for the nmap argv.

    This is the §51/legal control — it FAILS CLOSED and an internal appliance
    NEVER scans public IPs without an explicit allowlist. Behaviour by
    ``cidrs_allowed``:

    - ``None`` (``get_config`` failed / scope unavailable): return ``[]`` —
      scan nothing. Better no scan than an unauthorized one.
    - ``[]`` (successful fetch, tenant genuinely has no allowlist): fall back
      to the RFC1918 private-space floor (``_PRIVATE_NETWORKS``). Only private
      targets are kept; public IPs are dropped.
    - non-empty: intersect with the validated allowlist. If every entry is
      rejected (catch-all/oversized/IPv6/malformed — a misconfiguration), fall
      back to the private floor rather than scanning everything.

    In all cases, malformed / catch-all (0.0.0.0/0 / ::/0) / too-broad (> /16)
    / IPv6 entries are rejected on BOTH the target and allowlist sides.

    Returns the kept target strings in canonical ``str(network)`` form.
    """
    # Fail closed: scope unavailable -> scan nothing.
    if cidrs_allowed is None:
        logger.warning("filter_scope: scope unavailable (cidrs_allowed=None) — failing closed, scanning nothing")
        return []

    raw_targets = [t.strip() for t in (target_scope or "").split(",") if t.strip()]

    # Validate the allowlist (reject catch-all/oversized/IPv6/malformed too).
    allowed_nets: list[ipaddress.IPv4Network] = []
    for entry in cidrs_allowed:
        net = _parse_network(entry)
        if net is None:
            logger.warning("filter_scope: dropping invalid allowlist entry %r", entry)
            continue
        allowed_nets.append(net)

    # No usable allowlist (genuinely empty, or all entries rejected) -> the
    # built-in RFC1918 private floor. An internal scanner only ever touches
    # private space without an explicit allowlist; public IPs are never scanned.
    if not allowed_nets:
        logger.info("filter_scope: no allowlist configured — restricting to RFC1918 private space")
        allowed_nets = list(_PRIVATE_NETWORKS)

    kept: list[str] = []
    total_hosts = 0
    for raw in raw_targets:
        net = _parse_network(raw)
        if net is None:
            logger.warning("filter_scope: dropping out-of-scope/invalid target %r", raw)
            continue

        # Intersection with the (always non-empty) effective allowlist.
        if not any(net.subnet_of(a) for a in allowed_nets):
            logger.warning(
                "filter_scope: dropping target %r — not within any allowed CIDR", raw
            )
            continue

        # Host cap — skip the offending target if it blows the budget.
        net_hosts = net.num_addresses
        if net_hosts > MAX_HOSTS_PER_SCAN or total_hosts + net_hosts > MAX_HOSTS_PER_SCAN:
            logger.warning(
                "filter_scope: skipping target %r — would exceed host cap (%d)",
                raw,
                MAX_HOSTS_PER_SCAN,
            )
            continue
        total_hosts += net_hosts
        kept.append(str(net))

    return kept


# ---------------------------------------------------------------------------
# Script output sanitization (attacker-controlled data)
# ---------------------------------------------------------------------------
# NSE script outputs are FULLY attacker-controlled: a rogue or compromised
# scan target can return arbitrary bytes in its service banner / SMB negotiate
# response / SSL certificate fields / etc.  We sanitize at the trust boundary
# before the data enters finding evidence — defense-in-depth on top of the
# backend's own truncation and parameterized INSERT.
#
# Strip C0/C1-ish control chars + DEL (incl. NUL/newlines so nothing can
# inject extra lines into the single-line evidence string).
_SMB_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# nmap renders non-printable bytes in <elem> text / `output` as the LITERAL
# 4-char escape "\xNN" (NetBIOS names are NUL-padded → "DC01LAB\x00"). Strip
# those artifacts too so the hostname/OS are clean (verified E2E vs Samba).
_SMB_NMAP_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")

# Hostname cap mirrors the backend column bound (hostname[:255]).
_SMB_NAME_MAX = 255
# OS string is annotated into evidence text only; bound it independently.
_SMB_OS_MAX = 256

# Maximum characters taken from any single script's ``output`` attribute when
# appended to finding evidence.  Script output is attacker-controlled; a rogue
# target can emit arbitrarily long strings.  This bounds the per-script
# contribution to ~one line of context without truncating useful signal.
_SCRIPT_OUTPUT_MAX = 200

# CVE reference regex.  Matches CVE-YYYY-NNNNN (1–7 digits) as reported by
# safe NSE scripts (e.g. ssl-cert reporting a cert with a known CVE).
# BOUNDED: we capture at most _CVE_CAP matches per finding to prevent a
# compromised target injecting thousands of CVE IDs.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{1,7}", re.IGNORECASE)
_CVE_CAP = 10


def _sanitize_smb_field(value: Optional[str], max_len: int) -> Optional[str]:
    """Strip control chars/newlines/NUL from an attacker-controlled SMB value
    and cap its length. Returns None when empty after stripping (so callers
    fall back to existing behaviour rather than using an empty string)."""
    if not value:
        return None
    cleaned = _SMB_NMAP_ESCAPE.sub("", value)
    cleaned = _SMB_CONTROL_CHARS.sub("", cleaned).strip()[:max_len]
    return cleaned or None


def _extract_smb_os_discovery(host: "ET.Element") -> tuple[Optional[str], Optional[str]]:
    """Extract (computer_name, os_string) from smb-os-discovery hostscript output.

    Returns (None, None) when the script did not run or produced no output —
    callers must treat absence as a no-op (§50: absent → do not fabricate).

    Both values are attacker-controlled (the scan target supplies them), so each
    is sanitized (control chars/newlines/NUL stripped) and length-bounded before
    return. A field that is empty after sanitization is returned as None so the
    caller falls back to its existing logic.

    Real nmap (verified E2E vs Samba) emits LOWERCASE structured <elem> keys:
      - ``server`` = NetBIOS computer name (e.g. "DC01LAB\\x00")
      - ``os``     = OS string (e.g. "Windows 6.1 (Samba 4.12.2)")
    The human-readable labels ("Computer name:", "NetBIOS computer name:", "OS:")
    only appear in the script's ``output`` attribute, NOT as <elem> keys. Read the
    structured elems first (most precise), then fall back to parsing ``output``
    (stable across nmap-version drift). Legacy/alternate keys are still accepted.
    """
    for script_el in host.findall("hostscript/script[@id='smb-os-discovery']"):
        computer_name: Optional[str] = None
        os_string: Optional[str] = None
        # 1) Structured <elem key="...">, matched case-insensitively. Prefer the
        #    NetBIOS name (`server`) for the hostname and `os` for the OS.
        for elem in script_el.findall("elem"):
            key = (elem.get("key") or "").strip().lower()
            val = (elem.text or "").strip()
            if not val:
                continue
            if key in ("server", "netbios computer name", "computer name") and not computer_name:
                computer_name = val
            elif key == "os" and not os_string:
                os_string = val
        # 2) Fallback: parse the human-readable `output` attribute. Prefer the
        #    NetBIOS short name over the FQDN-ish "Computer name".
        output = script_el.get("output") or ""
        if not computer_name:
            m = (re.search(r"NetBIOS computer name:\s*([^\r\n]+)", output)
                 or re.search(r"Computer name:\s*([^\r\n]+)", output))
            if m:
                computer_name = m.group(1)
        if not os_string:
            m = re.search(r"\bOS:\s*([^\r\n]+)", output)
            if m:
                os_string = m.group(1)
        return (
            _sanitize_smb_field(computer_name, _SMB_NAME_MAX),
            _sanitize_smb_field(os_string, _SMB_OS_MAX),
        )
    return None, None


def _sanitize_script_output(raw: Optional[str]) -> Optional[str]:
    """Sanitize a single NSE script's ``output`` attribute for use in evidence.

    Script output is attacker-controlled (the scan target controls what the
    service returns).  We:
      1. Strip C0/C1 control chars + DEL (same range as ``_sanitize_smb_field``
         — prevents newline injection into the single-line evidence string).
      2. Strip nmap's literal ``\\xNN`` escape sequences (same as SMB path).
      3. Cap at ``_SCRIPT_OUTPUT_MAX`` characters.
      4. Return None if nothing remains after stripping.
    """
    if not raw:
        return None
    cleaned = _SMB_NMAP_ESCAPE.sub("", raw)
    cleaned = _SMB_CONTROL_CHARS.sub("", cleaned).strip()[:_SCRIPT_OUTPUT_MAX]
    return cleaned or None


def _extract_script_intel(
    scripts: list["ET.Element"],
) -> tuple[list[str], list[str]]:
    """Extract (evidence_fragments, cve_ids) from a list of <script> elements.

    For each script whose id is in ``_NSE_SCRIPTS`` (allowlist gate):
      - Take the first line of the sanitized ``output`` attribute and append
        as ``" | <id>: <output>"`` to the evidence fragments list.
      - Regex-search the raw output for CVE references (offline, §51) and
        collect at most ``_CVE_CAP`` unique CVE-IDs across all scripts.

    Scripts whose id is NOT in ``_NSE_SCRIPTS`` are silently ignored —
    this is a defense-in-depth gate even though nmap only runs the allowlist.
    The ``smb-os-discovery`` id is included in ``_NSE_SCRIPTS`` but its
    hostname/OS extraction is handled by ``_extract_smb_os_discovery``; its
    output attribute is still searched for CVE references here.

    Returns (evidence_fragments, cve_ids) — both may be empty lists.
    """
    _allowed = frozenset(_NSE_SCRIPTS)
    evidence_parts: list[str] = []
    cve_ids: list[str] = []
    seen_cves: set[str] = set()

    for script_el in scripts:
        sid = script_el.get("id", "")
        if sid not in _allowed:
            continue
        raw_output = script_el.get("output") or ""

        # Evidence fragment: sanitized first line only.
        sanitized = _sanitize_script_output(raw_output)
        if sanitized:
            evidence_parts.append(f" | {sid}: {sanitized}")

        # CVE catch (offline — no network): bounded by _CVE_CAP.
        if len(seen_cves) < _CVE_CAP:
            for m in _CVE_RE.finditer(raw_output):
                cve = m.group(0).upper()
                if cve not in seen_cves:
                    seen_cves.add(cve)
                    cve_ids.append(cve)
                    if len(seen_cves) >= _CVE_CAP:
                        break

    return evidence_parts, cve_ids


def parse_nmap(xml_text: str) -> list[dict]:
    """Parse nmap XML into FindingPayload-shaped findings (ipv4 hosts).

    Mirrors the proven lab appliance: ipv4 address, hostname via
    ``hostnames/hostname`` then ``socket.gethostbyaddr`` short-name, open
    ports -> severity/title/description/solution from SVC (defaults for
    unmapped ports).

    NSE script output enrichment (v0.4.0):
      - For each open port, host-level ``<hostscript>/<script>`` elements AND
        port-level ``<port>/<script>`` elements whose id is in ``_NSE_SCRIPTS``
        are collected.  Their sanitized first-line output is appended to the
        finding's ``evidence`` as ``" | <script-id>: <output>"``.
      - CVE references found in script output are collected into ``cve_ids``
        (capped at ``_CVE_CAP``; offline only — §51).
      - The existing smb-os-discovery hostname/OS extraction is preserved.
      - ``FindingPayload`` shape stays stable — no new top-level keys.
    """
    findings: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.error("nmap XML parse error: %s", exc)
        return findings

    for host in root.findall(".//host"):
        ael = host.find("address[@addrtype='ipv4']")
        if ael is None:
            ael = host.find("address")
        ip = ael.get("addr") if ael is not None else "?"

        # Reverse-DNS hostname (shown as "Nombre" in the console).
        hostname = None
        hn_el = host.find("hostnames/hostname")
        if hn_el is not None and hn_el.get("name"):
            hostname = hn_el.get("name")
        if not hostname:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:  # noqa: BLE001 — resolver miss is expected
                hostname = None
        if hostname and "." in hostname:
            hostname = hostname.split(".")[0]

        # SMB computer name (higher quality than reverse-DNS) + OS annotation.
        smb_computer_name, smb_os = _extract_smb_os_discovery(host)
        if smb_computer_name:
            hostname = smb_computer_name

        # Collect host-level script elements (apply to every port finding).
        host_scripts: list["ET.Element"] = host.findall("hostscript/script")
        host_evidence_parts, host_cve_ids = _extract_script_intel(host_scripts)

        for port in host.findall(".//port"):
            stt = port.find("state")
            if stt is None or stt.get("state") != "open":
                continue
            pid = int(port.get("portid"))
            proto = port.get("protocol", "tcp")
            sel = port.find("service")
            prod = ""
            if sel is not None:
                prod = (sel.get("product", "") + " " + sel.get("version", "")).strip()
            sev, title, desc, sol = SVC.get(
                pid,
                (
                    SEVERITY_LOW,
                    f"Puerto {pid}/{proto} abierto",
                    f"Servicio detectado en {pid}/{proto}.",
                    "Revisar exposición.",
                ),
            )
            evidence = f"nmap -sV {ip} -p{pid} -> open ({prod or 'service'})"
            if smb_os:
                evidence += f" | OS: {smb_os} (smb-os-discovery)"

            # Port-level script elements (e.g. ssl-cert, ftp-anon on 443/21).
            port_scripts: list["ET.Element"] = port.findall("script")
            port_evidence_parts, port_cve_ids = _extract_script_intel(port_scripts)

            # Merge: host-level intel applies to every port; port-level is additive.
            all_evidence_parts = host_evidence_parts + port_evidence_parts
            evidence += "".join(all_evidence_parts)

            all_cve_ids: list[str] = []
            seen: set[str] = set()
            for cve in host_cve_ids + port_cve_ids:
                if cve not in seen and len(seen) < _CVE_CAP:
                    seen.add(cve)
                    all_cve_ids.append(cve)

            finding: dict = {
                "host": ip,
                "hostname": hostname,
                "port": pid,
                "protocol": proto,
                "severity": sev,
                "nvt_oid": f"1.3.6.1.4.1.25623.1.0.phy.nmap.{pid}",
                "detector_signature": "phy-scanner:nmap-service-detection",
                "title": title,
                "description": desc + (f" Versión detectada: {prod}." if prod else ""),
                "solution": sol,
                "evidence": evidence,
            }
            if all_cve_ids:
                finding["cve_ids"] = all_cve_ids
                finding["cve_id"] = all_cve_ids[0]
            findings.append(finding)
    return findings


async def _run_nmap(targets: list[str], timeout: int) -> str:
    """Run ``nmap -sV --open -T4 -Pn -oX - -- <targets>`` and return the XML.

    Non-shell (``create_subprocess_exec``) — targets are validated IP/CIDR
    strings from ``filter_scope`` and passed as argv, so there is no shell
    injection surface. The ``--`` end-of-options separator makes that safety
    local here (a target can never be parsed as a flag) rather than dependent
    on ``filter_scope`` upstream. Returns "" on timeout or non-zero exit.
    """
    cmd = ["nmap", "-sV", "--open", "-T4", "-Pn", _NSE_SCRIPTS_ARG, "-oX", "-", "--", *targets]
    logger.info("Running nmap over %d in-scope target(s)", len(targets))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.error("nmap timed out after %ds", timeout)
        return ""
    if proc.returncode != 0:
        logger.error(
            "nmap exited %s: %s",
            proc.returncode,
            (stderr or b"").decode(errors="replace")[:500],
        )
        return ""
    return (stdout or b"").decode(errors="replace")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def run_scan(
    job: dict,
    config,
    cidrs_allowed: Optional[list[str]] = None,
) -> ScanResult:
    """Run a real nmap service-detection scan over the in-scope targets.

    Applies ``filter_scope`` first (the legal control). If no in-scope
    targets remain, returns a ScanResult with 0 findings and does NOT run
    nmap.
    """
    job_id = job.get("job_id", "unknown")
    target_scope = job.get("target_scope", "")
    if isinstance(target_scope, list):
        target_scope = ",".join(str(t) for t in target_scope)

    started_at = _now_iso()
    kept = filter_scope(target_scope, cidrs_allowed)
    raw_targets = [t.strip() for t in (target_scope or "").split(",") if t.strip()]
    # A raw target is "dropped" when its canonical network form is not kept.
    kept_set = set(kept)
    dropped = [t for t in raw_targets if _canonical_or_none(t) not in kept_set]

    if not kept:
        logger.warning(
            "run_scan job_id=%s — no in-scope targets after filter_scope "
            "(requested=%s); skipping nmap, reporting 0 findings",
            job_id,
            raw_targets,
        )
        return ScanResult(
            findings=[],
            host_count=0,
            started_at=started_at,
            completed_at=_now_iso(),
            raw_report_path=None,
            kept_targets=[],
            dropped_targets=dropped,
        )

    timeout = getattr(config, "nmap_timeout_seconds", NMAP_TIMEOUT_SECONDS)
    logger.info("run_scan job_id=%s scanning=%s dropped=%s", job_id, kept, dropped)
    xml_text = await _run_nmap(kept, timeout)
    findings = parse_nmap(xml_text)
    completed_at = _now_iso()

    raw_report_path: Optional[str] = None
    if xml_text:
        try:
            fd, raw_report_path = tempfile.mkstemp(
                prefix=f"phy-nmap-{job_id}-", suffix=".xml"
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(xml_text)
        except OSError as exc:
            logger.warning("Could not write raw nmap XML to temp file: %s", exc)
            raw_report_path = None

    host_count = len({f["host"] for f in findings}) or len(kept)
    logger.info(
        "run_scan job_id=%s complete — findings=%d hosts=%d",
        job_id,
        len(findings),
        host_count,
    )
    return ScanResult(
        findings=findings,
        host_count=host_count,
        started_at=started_at,
        completed_at=completed_at,
        raw_report_path=raw_report_path,
        kept_targets=kept,
        dropped_targets=dropped,
    )
