"""Scanner engine — real nmap service detection (Mode-1, non-destructive).

Runs ``nmap -sV --open -T4 -Pn --script=smb-os-discovery`` over the
backend-authorized target scope, parses the XML report (stdlib
``xml.etree``) into ``FindingPayload``-shaped findings, and writes the raw
XML to a temp file for upload to PHY S3.

Security / §51:
  - Only nmap (local network) + reverse-DNS via the local resolver. No third-
    party calls (no NVD / telemetry / exploit modules).
  - Detection only: ``-sV --open -T4 -Pn`` plus ONE safe NSE script
    ``smb-os-discovery`` (category: safe+discovery — read-only NetBIOS/SMB
    banner read, no authentication attempts, no exploitation). The script
    runs only against hosts where 139/tcp or 445/tcp is already open (nmap
    applies it automatically per its port rules). No ``-A``, no other
    ``--script`` flags, no Mode-2/3 capabilities.
  - ``filter_scope`` is the legal control: the agent never runs nmap outside
    the CIDR allowlist (defense-in-depth — target_scope is already backend-
    authorized, but the agent does not trust it blindly).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Severity constants aligned with PHY FindingPayload
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

# Bounded nmap runtime (seconds). Mirrors the proven lab appliance.
NMAP_TIMEOUT_SECONDS = 900

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


def _extract_smb_os_discovery(host: "ET.Element") -> tuple[Optional[str], Optional[str]]:
    """Extract (computer_name, os_string) from smb-os-discovery hostscript output.

    Returns (None, None) when the script did not run or produced no output —
    callers must treat absence as a no-op (§50: absent → do not fabricate).

    Handles both key names emitted by different nmap/script versions:
      - ``Computer Name`` (common) or ``NetBIOS computer name`` (alternate).
      - ``OS`` for the OS string.
    """
    for script_el in host.findall("hostscript/script[@id='smb-os-discovery']"):
        computer_name: Optional[str] = None
        os_string: Optional[str] = None
        for elem in script_el.findall("elem"):
            key = (elem.get("key") or "").strip()
            val = (elem.text or "").strip()
            if not val:
                continue
            if key in ("Computer Name", "NetBIOS computer name"):
                computer_name = val
            elif key == "OS":
                os_string = val
        return computer_name, os_string
    return None, None


def parse_nmap(xml_text: str) -> list[dict]:
    """Parse nmap XML into FindingPayload-shaped findings (ipv4 hosts).

    Mirrors the proven lab appliance: ipv4 address, hostname via
    ``hostnames/hostname`` then ``socket.gethostbyaddr`` short-name, open
    ports -> severity/title/description/solution from SVC (defaults for
    unmapped ports).

    When smb-os-discovery hostscript output is present for a host:
      - ``Computer Name`` (or ``NetBIOS computer name``) overrides the
        reverse-DNS short-name as the ``hostname`` (higher quality).
      - ``OS`` is appended to every finding's ``evidence`` as
        ``"OS: <os> (smb-os-discovery)"`` — no new top-level field is
        added; the FindingPayload shape stays stable.
    Both are optional: absent smb output leaves behaviour unchanged.
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
            findings.append(
                {
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
            )
    return findings


async def _run_nmap(targets: list[str], timeout: int) -> str:
    """Run ``nmap -sV --open -T4 -Pn -oX - -- <targets>`` and return the XML.

    Non-shell (``create_subprocess_exec``) — targets are validated IP/CIDR
    strings from ``filter_scope`` and passed as argv, so there is no shell
    injection surface. The ``--`` end-of-options separator makes that safety
    local here (a target can never be parsed as a flag) rather than dependent
    on ``filter_scope`` upstream. Returns "" on timeout or non-zero exit.
    """
    cmd = ["nmap", "-sV", "--open", "-T4", "-Pn", "--script=smb-os-discovery", "-oX", "-", "--", *targets]
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
