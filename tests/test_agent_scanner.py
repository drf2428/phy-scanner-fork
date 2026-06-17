"""Tests for the real-nmap scanner: filter_scope, parse_nmap, run_scan.

filter_scope is the §51/legal control — it must never let nmap run outside
the CIDR allowlist, and must reject malformed / catch-all (0.0.0.0/0) /
too-broad (> /16) / IPv6 entries on BOTH the target and allowlist sides.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass

import pytest

from agent.scanner import (
    MAX_HOSTS_PER_SCAN,
    _NSE_SCRIPTS,
    _NSE_SCRIPTS_ARG,
    filter_scope,
    parse_nmap,
    run_scan,
)
import agent.scanner as scanner


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@dataclass
class _Cfg:
    nmap_timeout_seconds: int = 5


# A small, realistic nmap -oX XML fixture: two hosts, one with a hostname and
# two open ports (22 known, 8080 unmapped), one with a single open port (80)
# plus a closed port that must be ignored.
_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -Pn 10.0.0.5 10.0.0.6 -oX -">
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="web01.lab.internal" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy" product="" version=""/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.6" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25.0"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


# ---------------------------------------------------------------------------
# filter_scope — the legal control
# ---------------------------------------------------------------------------

def test_filter_scope_in_scope_target_kept():
    """A target inside an allowed CIDR is kept."""
    kept = filter_scope("10.0.0.5", ["10.0.0.0/24"])
    assert kept == ["10.0.0.5/32"]


def test_filter_scope_out_of_scope_target_dropped():
    """A target outside every allowed CIDR is dropped."""
    kept = filter_scope("192.168.99.5", ["10.0.0.0/24"])
    assert kept == []


def test_filter_scope_cidr_target_within_allowlist_kept():
    """A CIDR target fully contained in an allowed CIDR is kept."""
    kept = filter_scope("10.0.0.0/28", ["10.0.0.0/24"])
    assert kept == ["10.0.0.0/28"]


def test_filter_scope_cidr_target_not_subnet_dropped():
    """A CIDR target broader than the allowed CIDR is NOT a subnet -> dropped."""
    kept = filter_scope("10.0.0.0/16", ["10.0.0.0/24"])
    assert kept == []


def test_filter_scope_malformed_target_dropped():
    """A malformed target is dropped (not crash)."""
    kept = filter_scope("not-an-ip, 10.0.0.5", ["10.0.0.0/24"])
    assert kept == ["10.0.0.5/32"]


def test_filter_scope_rejects_catch_all_on_target_side():
    """0.0.0.0/0 as a target is rejected even with a permissive allowlist."""
    kept = filter_scope("0.0.0.0/0", ["10.0.0.0/24"])
    assert kept == []


def test_filter_scope_rejects_catch_all_on_allowlist_side():
    """0.0.0.0/0 in the allowlist is rejected (cannot authorize the world)."""
    # 0.0.0.0/0 dropped -> validated allowlist empty -> RFC1918 private floor.
    # A public target (8.8.8.8) is NOT private -> dropped (fail-closed, never
    # authorized by the discarded catch-all).
    kept = filter_scope("8.8.8.8", ["0.0.0.0/0"])
    assert kept == []


def test_filter_scope_rejects_oversized_target():
    """An IPv4 prefix broader than /16 is rejected on the target side."""
    kept = filter_scope("10.0.0.0/8", ["10.0.0.0/8"])
    assert kept == []


def test_filter_scope_rejects_oversized_allowlist_entry():
    """A > /16 allowlist entry is discarded; the private floor applies instead."""
    # /8 allowlist entry dropped -> validated allowlist empty -> private floor.
    # 172.16.5.0/24 is within 172.16.0.0/12 (private) -> kept. It is NOT
    # authorized by the rejected /8 — it survives because it is private space.
    kept = filter_scope("172.16.5.0/24", ["10.0.0.0/8"])
    assert kept == ["172.16.5.0/24"]
    # A PUBLIC /24 with the same bad allowlist is dropped (private floor).
    assert filter_scope("8.8.8.0/24", ["10.0.0.0/8"]) == []


def test_filter_scope_drops_ipv6_target():
    """IPv6 targets are dropped (ipv4-only parse path)."""
    kept = filter_scope("2001:db8::1, 10.0.0.5", ["10.0.0.0/24"])
    assert kept == ["10.0.0.5/32"]


def test_filter_scope_drops_ipv6_allowlist_entry():
    """IPv6 allowlist entries are discarded."""
    kept = filter_scope("10.0.0.5", ["2001:db8::/32"])
    # ipv6 allow entry dropped -> empty allowlist -> private floor; 10.0.0.5 is
    # private -> kept.
    assert kept == ["10.0.0.5/32"]


def test_filter_scope_host_cap_skips_offending_target():
    """A target whose cumulative host count exceeds the cap is skipped."""
    # [] -> private floor; both /16s are private (10.0.0.0/8), so the cap (not
    # the floor) is what trims the second one.
    kept = filter_scope("10.0.0.0/16, 10.1.0.0/16", [])
    # First /16 (65536) fits exactly; the second would exceed the cumulative cap.
    assert kept == ["10.0.0.0/16"]


def test_filter_scope_single_slash16_at_cap_allowed():
    """A single private /16 (== cap) is allowed (no allowlist -> private floor)."""
    kept = filter_scope("10.0.0.0/16", [])
    assert kept == ["10.0.0.0/16"]
    # Sanity: the cap constant is exactly a /16 worth of addresses.
    assert MAX_HOSTS_PER_SCAN == 65536


def test_filter_scope_cidrs_none_fails_closed():
    """cidrs_allowed=None (get_config failed/unknown) -> scan NOTHING."""
    # Fail closed: even well-formed PRIVATE targets are dropped when the scope
    # is unavailable. Better no scan than a possibly-unauthorized one.
    kept = filter_scope("10.0.0.5, 192.168.1.0/24", None)
    assert kept == []


def test_filter_scope_public_ip_dropped_in_private_floor():
    """No allowlist ([]) -> public IPs are dropped; private kept (private floor)."""
    kept = filter_scope("8.8.8.8/32, 10.0.0.5/32", [])
    assert kept == ["10.0.0.5/32"]


def test_filter_scope_public_ip_alone_with_none_is_empty():
    """The review's canary: filter_scope('8.8.8.8/32', None) == []."""
    assert filter_scope("8.8.8.8/32", None) == []


def test_filter_scope_cidrs_empty_list_private_floor():
    """cidrs_allowed=[] (no allowlist) -> RFC1918 private floor."""
    kept = filter_scope("10.0.0.5", [])
    assert kept == ["10.0.0.5/32"]
    # All three RFC1918 ranges are honored.
    assert filter_scope("172.16.0.1, 192.168.1.1", []) == ["172.16.0.1/32", "192.168.1.1/32"]


# ---------------------------------------------------------------------------
# parse_nmap — FindingPayload shape
# ---------------------------------------------------------------------------

def test_parse_nmap_returns_findings_for_open_ports_only():
    """Closed ports are ignored; only open ports produce findings."""
    findings = parse_nmap(_NMAP_XML)
    # host1: 22 + 8080 ; host2: 80 (3389 closed -> ignored) = 3 findings
    assert len(findings) == 3
    ports = sorted(f["port"] for f in findings)
    assert ports == [22, 80, 8080]


def test_parse_nmap_port_is_int():
    """port must be an int (FindingPayload expects int|None, not '22/tcp')."""
    findings = parse_nmap(_NMAP_XML)
    for f in findings:
        assert isinstance(f["port"], int)


def test_parse_nmap_hostname_short_name():
    """hostname is the short name (FQDN split on first dot)."""
    findings = parse_nmap(_NMAP_XML)
    host1 = [f for f in findings if f["host"] == "10.0.0.5"][0]
    assert host1["hostname"] == "web01"


def test_parse_nmap_nvt_oid_and_signature_present():
    """Every finding has nvt_oid + detector_signature (required by FindingPayload)."""
    findings = parse_nmap(_NMAP_XML)
    for f in findings:
        assert f["nvt_oid"].startswith("1.3.6.1.4.1.25623.1.0.phy.nmap.")
        assert f["detector_signature"] == "phy-scanner:nmap-service-detection"


def test_parse_nmap_known_port_uses_svc_map():
    """A known port (22) uses the SVC severity/title (medium SSH)."""
    findings = parse_nmap(_NMAP_XML)
    ssh = [f for f in findings if f["port"] == 22][0]
    assert ssh["severity"] == "medium"
    assert "SSH" in ssh["title"]


def test_parse_nmap_unknown_port_defaults_low():
    """An unmapped port (8080) defaults to low severity + generic title."""
    findings = parse_nmap(_NMAP_XML)
    proxy = [f for f in findings if f["port"] == 8080][0]
    assert proxy["severity"] == "low"
    assert "8080" in proxy["title"]


def test_parse_nmap_version_appended_to_description():
    """Detected product/version is appended to the description."""
    findings = parse_nmap(_NMAP_XML)
    ssh = [f for f in findings if f["port"] == 22][0]
    assert "OpenSSH 8.9p1" in ssh["description"]


def test_parse_nmap_matches_finding_payload_shape():
    """Emitted keys are a subset of FindingPayload fields (extra='forbid')."""
    # The PHY FindingPayload fields (asm/app/schemas/asm_internal.py).
    allowed = {
        "host", "hostname", "port", "protocol", "severity",
        "cvss_score", "cve_id", "cve_ids", "nvt_oid", "detector_signature",
        "title", "description", "solution", "evidence", "references",
    }
    findings = parse_nmap(_NMAP_XML)
    assert findings
    for f in findings:
        extra = set(f.keys()) - allowed
        assert extra == set(), f"emits keys outside FindingPayload: {extra}"
        # The old synthetic shape must NOT appear.
        assert "plugin_id" not in f
        assert "source" not in f
        assert f["severity"] in {"critical", "high", "medium", "low", "info"}


def test_parse_nmap_malformed_xml_returns_empty():
    """Malformed XML returns [] (no crash)."""
    assert parse_nmap("<not-valid-xml") == []


# ---------------------------------------------------------------------------
# smb-os-discovery parsing
# ---------------------------------------------------------------------------

# Fixture: host with smb-os-discovery hostscript output (Computer Name + OS).
_NMAP_XML_WITH_SMB = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -Pn --script=smb-os-discovery 10.0.1.5">
  <host>
    <status state="up"/>
    <address addr="10.0.1.5" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Samba smbd" version="4.x"/>
      </port>
      <port protocol="tcp" portid="139">
        <state state="open"/>
        <service name="netbios-ssn" product="Samba smbd" version="3.x-4.x"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-os-discovery" output="OS: Windows 10 Pro; Computer Name: FILESERVER01">
        <elem key="OS">Windows 10 Pro</elem>
        <elem key="Computer Name">FILESERVER01</elem>
        <elem key="Domain Name">lab.internal</elem>
        <elem key="FQDN">FILESERVER01.lab.internal</elem>
      </script>
    </hostscript>
  </host>
</nmaprun>
"""

# Fixture: host WITHOUT smb-os-discovery (should behave exactly as before).
_NMAP_XML_NO_SMB = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -Pn --script=smb-os-discovery 10.0.1.6">
  <host>
    <status state="up"/>
    <address addr="10.0.1.6" addrtype="ipv4"/>
    <hostnames>
      <hostname name="db01.corp.example" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Samba smbd" version="4.x"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Fixture: host with the alternate key name "NetBIOS computer name".
_NMAP_XML_NETBIOS_KEY = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -Pn --script=smb-os-discovery 10.0.1.7">
  <host>
    <status state="up"/>
    <address addr="10.0.1.7" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="139">
        <state state="open"/>
        <service name="netbios-ssn" product="Samba smbd" version="3.x"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-os-discovery" output="NetBIOS computer name: LEGACYBOX">
        <elem key="NetBIOS computer name">LEGACYBOX</elem>
        <elem key="OS">Windows Server 2003</elem>
      </script>
    </hostscript>
  </host>
</nmaprun>
"""


def test_parse_nmap_smb_computer_name_overrides_hostname():
    """smb-os-discovery Computer Name is used as hostname (higher quality)."""
    findings = parse_nmap(_NMAP_XML_WITH_SMB)
    assert findings, "expected at least one finding for host with open 445/139"
    for f in findings:
        assert f["host"] == "10.0.1.5"
        assert f["hostname"] == "FILESERVER01", (
            f"expected SMB computer name 'FILESERVER01', got {f['hostname']!r}"
        )


def test_parse_nmap_smb_os_appended_to_evidence():
    """smb-os-discovery OS is appended to finding evidence; shape stays stable."""
    findings = parse_nmap(_NMAP_XML_WITH_SMB)
    assert findings
    for f in findings:
        assert "OS: Windows 10 Pro (smb-os-discovery)" in f["evidence"], (
            f"expected OS annotation in evidence, got: {f['evidence']!r}"
        )
    # Shape stays stable — no new top-level field.
    allowed = {
        "host", "hostname", "port", "protocol", "severity",
        "cvss_score", "cve_id", "cve_ids", "nvt_oid", "detector_signature",
        "title", "description", "solution", "evidence", "references",
    }
    for f in findings:
        extra = set(f.keys()) - allowed
        assert extra == set(), f"emits keys outside FindingPayload: {extra}"


def test_parse_nmap_no_smb_output_behaves_as_before():
    """Hosts without smb-os-discovery output are unaffected (no crash, DNS hostname kept)."""
    findings = parse_nmap(_NMAP_XML_NO_SMB)
    assert len(findings) == 1
    f = findings[0]
    assert f["host"] == "10.0.1.6"
    # Hostname should come from reverse-DNS / hostnames element (short name).
    assert f["hostname"] == "db01", (
        f"expected DNS short name 'db01' without SMB, got {f['hostname']!r}"
    )
    # No OS annotation in evidence.
    assert "smb-os-discovery" not in f["evidence"]


def test_parse_nmap_smb_netbios_key_alternate_name():
    """'NetBIOS computer name' key (alternate spelling) is accepted as hostname."""
    findings = parse_nmap(_NMAP_XML_NETBIOS_KEY)
    assert findings
    for f in findings:
        assert f["hostname"] == "LEGACYBOX"
        assert "OS: Windows Server 2003 (smb-os-discovery)" in f["evidence"]


def test_sanitize_smb_field_strips_full_control_range_and_bounds():
    """Unit: _sanitize_smb_field strips the FULL C0/C1-ish + DEL range (incl.
    NUL, BEL, ESC — bytes that XML itself forbids but could arrive via any
    future non-XML path) and caps length; empty-after-strip -> None."""
    # Every control byte in [0x00, 0x1f] plus DEL, interleaved with printables.
    evil = "A" + "".join(chr(c) for c in range(0x00, 0x20)) + "\x7f" + "B"
    out = scanner._sanitize_smb_field(evil, 255)
    assert out == "AB", f"control chars not fully stripped: {out!r}"

    # Length bound is enforced.
    long_clean = "C" * 10000
    assert scanner._sanitize_smb_field(long_clean, 255) == "C" * 255
    assert scanner._sanitize_smb_field("D" * 10000, 256) == "D" * 256

    # All-control-chars / empty / None -> None (caller falls back).
    assert scanner._sanitize_smb_field("\x00\x07\x1b\x7f", 255) is None
    assert scanner._sanitize_smb_field("   ", 255) is None
    assert scanner._sanitize_smb_field("", 255) is None
    assert scanner._sanitize_smb_field(None, 255) is None


def test_parse_nmap_smb_fields_sanitized_and_bounded():
    """A hostile target controls smb-os-discovery elem text — it must be
    control-char-stripped + length-bounded before becoming hostname/evidence.

    Uses the control chars that are VALID in XML 1.0 text (TAB/LF/CR/DEL) — the
    exact newline/whitespace-injection vectors that could forge extra evidence
    lines — since those are what actually reach parse_nmap through the XML layer.
    """
    # ~10k-char computer name with embedded newline / CR / tab / DEL, and a
    # malicious OS string trying to inject a newline + a forged extra line.
    evil_name = "EVIL\tBOX\n\rPWN\x7f" + ("A" * 10000)
    evil_os = "Linux\nInjected: critical\r\t" + ("B" * 5000)
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -Pn --script=smb-os-discovery 10.0.2.9">
  <host>
    <status state="up"/>
    <address addr="10.0.2.9" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Samba smbd" version="4.x"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-os-discovery">
        <elem key="Computer Name">{evil_name}</elem>
        <elem key="OS">{evil_os}</elem>
      </script>
    </hostscript>
  </host>
</nmaprun>
"""
    findings = parse_nmap(xml)
    assert len(findings) == 1
    f = findings[0]

    # Hostname is bounded at 255 and contains no control chars / newlines.
    hn = f["hostname"]
    assert hn is not None
    assert len(hn) <= 255, f"hostname not bounded: len={len(hn)}"
    assert "\n" not in hn and "\r" not in hn and "\t" not in hn and "\x7f" not in hn
    # The control chars are stripped, leaving the surrounding printable text glued.
    assert hn.startswith("EVILBOX")
    assert "PWN" in hn

    # OS annotation is present but bounded + stripped; it cannot inject a newline
    # (which would forge a second evidence line) nor other control bytes.
    ev = f["evidence"]
    assert "(smb-os-discovery)" in ev
    assert "\n" not in ev and "\r" not in ev and "\t" not in ev and "\x7f" not in ev
    # The bounded OS substring (<=256) sits inside the single-line evidence.
    assert "OS: Linux" in ev
    # Evidence stays a single logical line (no injected extra lines).
    assert ev.count("\n") == 0

    # Shape stays stable — no new top-level field from the hostile input.
    allowed = {
        "host", "hostname", "port", "protocol", "severity",
        "cvss_score", "cve_id", "cve_ids", "nvt_oid", "detector_signature",
        "title", "description", "solution", "evidence", "references",
    }
    assert set(f.keys()) - allowed == set()


def test_parse_nmap_smb_name_all_control_chars_falls_back():
    """A computer name that is ALL (XML-valid) control chars sanitizes to empty
    -> None -> fall back to the existing reverse-DNS hostname (no empty
    hostname, §50: absent/unusable smb output behaves as today)."""
    # TAB/LF/CR/DEL are valid in XML 1.0 text but all stripped by the sanitizer.
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -Pn --script=smb-os-discovery 10.0.2.10">
  <host>
    <status state="up"/>
    <address addr="10.0.2.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="realdns.corp.example" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Samba smbd" version="4.x"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-os-discovery">
        <elem key="Computer Name">\t\r\x7f</elem>
      </script>
    </hostscript>
  </host>
</nmaprun>
"""
    findings = parse_nmap(xml)
    assert len(findings) == 1
    f = findings[0]
    # SMB name was all control chars -> dropped -> DNS short name kept.
    assert f["hostname"] == "realdns", (
        f"expected fallback to DNS short name, got {f['hostname']!r}"
    )
    # No OS elem -> no OS annotation.
    assert "smb-os-discovery" not in f["evidence"]


def test_run_scan_script_arg_present_and_scope_unchanged(monkeypatch):
    """The frozen _NSE_SCRIPTS_ARG is in nmap argv; filter_scope is unaffected."""
    captured_argv = {}

    async def fake_exec(*cmd, **kwargs):
        captured_argv["cmd"] = cmd
        return _FakeProc(_NMAP_XML_WITH_SMB.encode())

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_exec)

    job = {"job_id": "job-smb", "target_scope": "10.0.1.5"}
    result = asyncio.run(run_scan(job, _Cfg(), cidrs_allowed=["10.0.1.0/24"]))

    cmd = captured_argv["cmd"]
    # The script argument equals the pre-computed frozen constant — no more, no less.
    assert _NSE_SCRIPTS_ARG in cmd
    # smb-os-discovery is still present (it's in _NSE_SCRIPTS).
    assert "smb-os-discovery" in _NSE_SCRIPTS_ARG
    # The -- separator still precedes targets; no target looks like a flag.
    sep = cmd.index("--")
    assert all(not t.startswith("-") for t in cmd[sep + 1:])
    # Only in-scope target was passed to nmap.
    assert "10.0.1.5/32" in cmd
    # Findings populated (445 + 139 both open).
    assert len(result.findings) == 2
    assert result.kept_targets == ["10.0.1.5/32"]
    if result.raw_report_path:
        import os
        os.unlink(result.raw_report_path)


def test_filter_scope_unchanged_by_smb_script():
    """Adding smb-os-discovery to _run_nmap does NOT alter filter_scope behaviour."""
    # Out-of-scope targets still dropped — scope control is independent of NSE.
    assert filter_scope("8.8.8.8", ["10.0.0.0/24"]) == []
    assert filter_scope("10.0.0.5", ["10.0.0.0/24"]) == ["10.0.0.5/32"]
    # cidrs_allowed=None still fails closed.
    assert filter_scope("10.0.0.5", None) == []


# ---------------------------------------------------------------------------
# run_scan — nmap mocked
# ---------------------------------------------------------------------------

class _FakeProc:
    """Minimal asyncio subprocess stand-in returning a fixed XML on stdout."""

    def __init__(self, stdout: bytes, returncode: int = 0):
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, b""

    def kill(self):  # pragma: no cover - not exercised in happy path
        pass

    async def wait(self):  # pragma: no cover
        return self.returncode


def test_run_scan_with_mocked_nmap(monkeypatch):
    """run_scan with nmap mocked -> findings parsed + raw report written."""
    captured_argv = {}

    async def fake_exec(*cmd, **kwargs):
        captured_argv["cmd"] = cmd
        return _FakeProc(_NMAP_XML.encode())

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_exec)

    job = {"job_id": "job-1", "target_scope": "10.0.0.5, 10.0.0.6"}
    result = asyncio.run(run_scan(job, _Cfg(), cidrs_allowed=["10.0.0.0/24"]))

    assert len(result.findings) == 3
    assert result.host_count == 2
    assert result.kept_targets == ["10.0.0.5/32", "10.0.0.6/32"]
    assert result.dropped_targets == []
    # Raw XML written to a temp file for S3 upload.
    assert result.raw_report_path and os.path.exists(result.raw_report_path)
    with open(result.raw_report_path, encoding="utf-8") as fh:
        assert "<nmaprun" in fh.read()
    os.unlink(result.raw_report_path)

    # nmap invoked with the Mode-1 flags + frozen allowlist, then -oX - -- ,
    # then ONLY in-scope targets.
    cmd = captured_argv["cmd"]
    assert cmd[:9] == (
        "nmap", "-sV", "--open", "-T4", "-Pn",
        _NSE_SCRIPTS_ARG,
        "-oX", "-", "--",
    )
    assert cmd[9:] == ("10.0.0.5/32", "10.0.0.6/32")
    # The -- end-of-options separator precedes every target.
    sep = cmd.index("--")
    assert all(not t.startswith("-") for t in cmd[sep + 1:])
    # No exploitation / aggressive flags.
    assert "-A" not in cmd
    # Exactly one --script argument: the frozen allowlist constant.
    script_args = [a for a in cmd if a.startswith("--script")]
    assert len(script_args) == 1 and script_args[0] == _NSE_SCRIPTS_ARG


def test_run_scan_filter_drops_out_of_scope_targets(monkeypatch):
    """Out-of-scope targets are dropped before nmap is invoked."""
    captured_argv = {}

    async def fake_exec(*cmd, **kwargs):
        captured_argv["cmd"] = cmd
        return _FakeProc(_NMAP_XML.encode())

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_exec)

    job = {"job_id": "job-2", "target_scope": "10.0.0.5, 192.168.99.9"}
    result = asyncio.run(run_scan(job, _Cfg(), cidrs_allowed=["10.0.0.0/24"]))

    assert result.kept_targets == ["10.0.0.5/32"]
    assert result.dropped_targets == ["192.168.99.9"]
    # The out-of-scope IP must NOT be in the nmap argv.
    assert "192.168.99.9" not in captured_argv["cmd"]
    if result.raw_report_path:
        os.unlink(result.raw_report_path)


def test_run_scan_no_in_scope_targets_skips_nmap(monkeypatch):
    """When nothing is in-scope, nmap is NOT run and 0 findings are reported."""
    called = {"exec": False}

    async def fake_exec(*cmd, **kwargs):  # pragma: no cover - must not run
        called["exec"] = True
        return _FakeProc(b"")

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_exec)

    job = {"job_id": "job-3", "target_scope": "192.168.99.9"}
    result = asyncio.run(run_scan(job, _Cfg(), cidrs_allowed=["10.0.0.0/24"]))

    assert called["exec"] is False
    assert result.findings == []
    assert result.host_count == 0
    assert result.raw_report_path is None
    assert result.kept_targets == []
    assert result.dropped_targets == ["192.168.99.9"]


def test_run_scan_accepts_list_target_scope(monkeypatch):
    """target_scope may arrive as a list (PollResponse shape) — normalized."""
    async def fake_exec(*cmd, **kwargs):
        return _FakeProc(_NMAP_XML.encode())

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_exec)

    job = {"job_id": "job-4", "target_scope": ["10.0.0.5", "10.0.0.6"]}
    # [] -> RFC1918 private floor; both targets are private so both are kept.
    result = asyncio.run(run_scan(job, _Cfg(), cidrs_allowed=[]))
    assert result.kept_targets == ["10.0.0.5/32", "10.0.0.6/32"]
    if result.raw_report_path:
        os.unlink(result.raw_report_path)


def test_run_scan_nmap_nonzero_exit_no_report(monkeypatch):
    """nmap non-zero exit -> empty XML -> 0 findings, no raw report."""
    async def fake_exec(*cmd, **kwargs):
        return _FakeProc(b"", returncode=1)

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_exec)

    job = {"job_id": "job-5", "target_scope": "10.0.0.5"}
    result = asyncio.run(run_scan(job, _Cfg(), cidrs_allowed=[]))
    assert result.findings == []
    assert result.raw_report_path is None


def test_run_scan_cidrs_none_fails_closed_no_nmap(monkeypatch):
    """run_scan with cidrs_allowed=None (scope unavailable) -> no nmap, 0 findings."""
    called = {"exec": False}

    async def fake_exec(*cmd, **kwargs):  # pragma: no cover - must not run
        called["exec"] = True
        return _FakeProc(b"")

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_exec)

    # A private, otherwise-valid target is STILL not scanned when scope is unknown.
    job = {"job_id": "job-6", "target_scope": "10.0.0.5"}
    result = asyncio.run(run_scan(job, _Cfg(), cidrs_allowed=None))
    assert called["exec"] is False
    assert result.findings == []
    assert result.kept_targets == []
    assert result.dropped_targets == ["10.0.0.5"]


# Fixture: REAL nmap smb-os-discovery output (verified E2E vs Samba, 2026-06-17).
# Real nmap uses LOWERCASE <elem key="server"|"os">; the NetBIOS name is NUL-padded
# and rendered as the literal escape "\x00"; the "Computer name:"/"OS:" labels live
# only in the `output` attribute. This pins the ACTUAL format (the original fixture
# used assumed keys "Computer Name"/"OS" that real nmap never emits).
_NMAP_XML_SMB_REAL = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV --script=smb-os-discovery 172.20.0.2">
  <host>
    <address addr="172.20.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445"><state state="open"/>
        <service name="microsoft-ds" product="Samba smbd" version="4.12.2"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-os-discovery" output="&#10;  OS: Windows 6.1 (Samba 4.12.2)&#10;  Computer name: box123&#10;  NetBIOS computer name: DC01LAB\\x00&#10;">
        <elem key="os">Windows 6.1</elem>
        <elem key="lanmanager">Samba 4.12.2</elem>
        <elem key="server">DC01LAB\\x00</elem>
        <elem key="fqdn">box123</elem>
      </script>
    </hostscript>
  </host>
</nmaprun>"""


def test_parse_nmap_smb_real_format_server_elem_and_nul_stripped():
    """Real nmap emits lowercase key='server' (NetBIOS name, NUL-padded as literal
    '\\x00') + key='os' — NOT 'Computer Name'/'OS'. parse_nmap must read the real
    keys and strip the '\\x00' artifact from the hostname."""
    findings = parse_nmap(_NMAP_XML_SMB_REAL)
    assert findings, "expected at least one finding"
    f = findings[0]
    hn = f["hostname"] if isinstance(f, dict) else f.hostname
    ev = f["evidence"] if isinstance(f, dict) else f.evidence
    assert hn == "DC01LAB", f"hostname should be the clean SMB Computer Name, got {hn!r}"
    assert "Windows 6.1" in ev, f"OS should be annotated in evidence, got {ev!r}"


# ===========================================================================
# NSE deepening v0.4.0 — new tests
# §51 allowlist gate, script-output enrichment, CVE offline catch,
# sanitization of attacker-controlled output, filter_scope unchanged.
# ===========================================================================

# ---------------------------------------------------------------------------
# §51-critical: argv allowlist guard
# ---------------------------------------------------------------------------

_FORBIDDEN_CATEGORY_TOKENS = ("vuln", "external", "intrusive", "brute", "dos", "exploit")


def test_nse_scripts_constant_is_frozen_tuple():
    """_NSE_SCRIPTS is an immutable tuple — not a list, not sourced from config."""
    assert isinstance(_NSE_SCRIPTS, tuple), "_NSE_SCRIPTS must be a tuple (immutable)"
    assert len(_NSE_SCRIPTS) > 0


def test_nse_scripts_no_forbidden_categories():
    """No NSE category token (vuln/external/intrusive/brute/dos/exploit) in allowlist."""
    for name in _NSE_SCRIPTS:
        for forbidden in _FORBIDDEN_CATEGORY_TOKENS:
            assert forbidden not in name, (
                f"Forbidden category token {forbidden!r} found in _NSE_SCRIPTS entry {name!r}"
            )


def test_nse_scripts_smb_os_discovery_present():
    """smb-os-discovery must remain in the allowlist (hostname/OS extraction depends on it)."""
    assert "smb-os-discovery" in _NSE_SCRIPTS


def test_nse_scripts_ssl_enum_ciphers_absent():
    """ssl-enum-ciphers is DROPPED (intrusive, not safe) — must not appear."""
    assert "ssl-enum-ciphers" not in _NSE_SCRIPTS


def test_nse_scripts_arg_equals_constant_joined():
    """_NSE_SCRIPTS_ARG is exactly '--script=' + ','.join(_NSE_SCRIPTS)."""
    expected = "--script=" + ",".join(_NSE_SCRIPTS)
    assert _NSE_SCRIPTS_ARG == expected


def test_run_scan_argv_allowlist_exact(monkeypatch):
    """The script set passed to nmap equals _NSE_SCRIPTS exactly.

    No forbidden category token (vuln/external/intrusive/brute/dos/exploit)
    and no unlisted script name appears in nmap argv.  The allowlist is sourced
    from the constant, not from config.
    """
    captured_argv = {}

    async def fake_exec(*cmd, **kwargs):
        captured_argv["cmd"] = cmd
        return _FakeProc(_NMAP_XML.encode())

    monkeypatch.setattr(scanner.asyncio, "create_subprocess_exec", fake_exec)

    job = {"job_id": "job-allowlist", "target_scope": "10.0.0.5"}
    asyncio.run(run_scan(job, _Cfg(), cidrs_allowed=["10.0.0.0/24"]))

    cmd = captured_argv["cmd"]

    # Exactly one --script argument.
    script_args = [a for a in cmd if a.startswith("--script")]
    assert len(script_args) == 1, f"expected exactly 1 --script arg, got: {script_args}"

    # That argument equals the constant exactly.
    assert script_args[0] == _NSE_SCRIPTS_ARG, (
        f"nmap argv script arg diverges from constant:\n"
        f"  got:      {script_args[0]}\n"
        f"  expected: {_NSE_SCRIPTS_ARG}"
    )

    # No forbidden category token anywhere in the full argv.
    full_argv_str = " ".join(cmd)
    for forbidden in _FORBIDDEN_CATEGORY_TOKENS:
        assert forbidden not in full_argv_str, (
            f"Forbidden token {forbidden!r} found in nmap argv"
        )


# ---------------------------------------------------------------------------
# Script output enrichment: parse_nmap reads hostscript + port-script elements
# ---------------------------------------------------------------------------

# Fixture: ftp-anon on port 21 (port-level script).
_NMAP_XML_FTP_ANON = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -Pn 10.0.3.1">
  <host>
    <address addr="10.0.3.1" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="3.0.3"/>
        <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Fixture: ssl-cert on port 443 (port-level script).
_NMAP_XML_SSL_CERT = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -Pn 10.0.3.2">
  <host>
    <address addr="10.0.3.2" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25.0"/>
        <script id="ssl-cert" output="Subject: CN=example.com; Issuer: CN=Let's Encrypt; Not valid after: 2024-01-01"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Fixture: smb2-security-mode on port 445 (port-level script).
_NMAP_XML_SMB2_MODE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -Pn 10.0.3.3">
  <host>
    <address addr="10.0.3.3" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Samba smbd" version="4.x"/>
        <script id="smb2-security-mode" output="2.02: Message signing enabled but not required"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Fixture: http-headers on port 80 (port-level script).
_NMAP_XML_HTTP_HEADERS = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -Pn 10.0.3.4">
  <host>
    <address addr="10.0.3.4" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.50"/>
        <script id="http-headers" output="X-Powered-By: PHP/7.2.0&#10;Server: Apache/2.4.50"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_ftp_anon_evidence_enriched():
    """ftp-anon port-level script output is appended to evidence; shape stable."""
    findings = parse_nmap(_NMAP_XML_FTP_ANON)
    assert len(findings) == 1
    f = findings[0]
    assert f["port"] == 21
    assert "ftp-anon" in f["evidence"], f"evidence: {f['evidence']!r}"
    assert "Anonymous FTP login allowed" in f["evidence"]
    # Shape stable — no new top-level keys.
    allowed = {
        "host", "hostname", "port", "protocol", "severity",
        "cvss_score", "cve_id", "cve_ids", "nvt_oid", "detector_signature",
        "title", "description", "solution", "evidence", "references",
    }
    assert set(f.keys()) - allowed == set()


def test_parse_nmap_ssl_cert_evidence_enriched():
    """ssl-cert port-level script output is appended to evidence."""
    findings = parse_nmap(_NMAP_XML_SSL_CERT)
    assert len(findings) == 1
    f = findings[0]
    assert f["port"] == 443
    assert "ssl-cert" in f["evidence"]
    assert "CN=example.com" in f["evidence"]


def test_parse_nmap_smb2_security_mode_evidence_enriched():
    """smb2-security-mode script output (signing not required) appended to evidence."""
    findings = parse_nmap(_NMAP_XML_SMB2_MODE)
    assert len(findings) == 1
    f = findings[0]
    assert f["port"] == 445
    assert "smb2-security-mode" in f["evidence"]
    assert "signing enabled but not required" in f["evidence"]


def test_parse_nmap_http_headers_newline_stripped_from_evidence():
    """http-headers output with embedded newlines is sanitized to a single line."""
    findings = parse_nmap(_NMAP_XML_HTTP_HEADERS)
    assert len(findings) == 1
    f = findings[0]
    assert "http-headers" in f["evidence"]
    # Evidence must be a single line — no newlines injected by the script output.
    assert "\n" not in f["evidence"]
    assert "\r" not in f["evidence"]


def test_parse_nmap_host_level_script_applied_to_all_ports():
    """A host-level script (in hostscript) is applied to every open-port finding."""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open 10.0.3.5">
  <host>
    <address addr="10.0.3.5" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.20"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb2-security-mode" output="2.02: Message signing enabled but not required"/>
    </hostscript>
  </host>
</nmaprun>
"""
    findings = parse_nmap(xml)
    assert len(findings) == 2
    for f in findings:
        assert "smb2-security-mode" in f["evidence"], (
            f"host-level script missing from port {f['port']} evidence"
        )


def test_parse_nmap_unlisted_script_ignored():
    """A script NOT in _NSE_SCRIPTS is silently ignored (allowlist gate)."""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open 10.0.3.6">
  <host>
    <address addr="10.0.3.6" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4"/>
        <script id="vulners" output="CVE-2021-41773: 7.5"/>
        <script id="http-headers" output="X-Content-Type-Options: nosniff"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    findings = parse_nmap(xml)
    assert len(findings) == 1
    f = findings[0]
    # "vulners" is NOT in _NSE_SCRIPTS — its output must NOT appear.
    assert "vulners" not in f["evidence"]
    # "http-headers" IS in _NSE_SCRIPTS — it must appear.
    assert "http-headers" in f["evidence"]


def test_parse_nmap_finding_payload_shape_stable_with_scripts():
    """parse_nmap still emits only FindingPayload-allowed keys when scripts present."""
    allowed = {
        "host", "hostname", "port", "protocol", "severity",
        "cvss_score", "cve_id", "cve_ids", "nvt_oid", "detector_signature",
        "title", "description", "solution", "evidence", "references",
    }
    # Use the FTP fixture which adds a port-level script.
    findings = parse_nmap(_NMAP_XML_FTP_ANON)
    assert findings
    for f in findings:
        extra = set(f.keys()) - allowed
        assert extra == set(), f"emits keys outside FindingPayload: {extra}"


# ---------------------------------------------------------------------------
# CVE offline catch (§51 — no external calls)
# ---------------------------------------------------------------------------

_NMAP_XML_CVE_IN_SCRIPT = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open 10.0.4.1">
  <host>
    <address addr="10.0.4.1" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.14.0"/>
        <script id="ssl-cert" output="Weak key: CVE-2008-0166 RSA key generated by Debian OpenSSL"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_NMAP_XML_NO_CVE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open 10.0.4.2">
  <host>
    <address addr="10.0.4.2" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="3.0.3"/>
        <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_cve_from_script_output_captured():
    """A CVE referenced in safe script output is captured in cve_ids/cve_id."""
    findings = parse_nmap(_NMAP_XML_CVE_IN_SCRIPT)
    assert len(findings) == 1
    f = findings[0]
    assert "cve_ids" in f, "cve_ids should be set when script output contains a CVE"
    assert "CVE-2008-0166" in f["cve_ids"]
    assert f["cve_id"] == "CVE-2008-0166"


def test_parse_nmap_no_cve_no_field():
    """When no CVE appears in script output, cve_id/cve_ids are absent (§50)."""
    findings = parse_nmap(_NMAP_XML_NO_CVE)
    assert len(findings) == 1
    f = findings[0]
    assert "cve_ids" not in f
    assert "cve_id" not in f


def test_parse_nmap_cve_cap_enforced():
    """More than _CVE_CAP CVEs in script output are capped (attacker-controlled)."""
    # Build a script output with 30 fake CVE IDs (well above the cap of 10).
    cve_list = " ".join(f"CVE-2024-{i:05d}" for i in range(1, 31))
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open 10.0.4.3">
  <host>
    <address addr="10.0.4.3" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25.0"/>
        <script id="ssl-cert" output="{cve_list}"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    findings = parse_nmap(xml)
    assert len(findings) == 1
    f = findings[0]
    assert "cve_ids" in f
    assert len(f["cve_ids"]) <= scanner._CVE_CAP, (
        f"CVE cap not enforced: got {len(f['cve_ids'])} IDs"
    )


def test_parse_nmap_cve_ids_deduplicated():
    """Duplicate CVE IDs from multiple scripts are deduplicated."""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open 10.0.4.4">
  <host>
    <address addr="10.0.4.4" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25.0"/>
        <script id="ssl-cert" output="CVE-2008-0166 repeated CVE-2008-0166"/>
        <script id="http-headers" output="See also CVE-2008-0166"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    findings = parse_nmap(xml)
    assert len(findings) == 1
    f = findings[0]
    assert "cve_ids" in f
    assert f["cve_ids"].count("CVE-2008-0166") == 1, "CVE IDs must be deduplicated"


# ---------------------------------------------------------------------------
# Sanitization of attacker-controlled script output
# ---------------------------------------------------------------------------

def test_sanitize_script_output_strips_control_chars():
    """_sanitize_script_output strips control chars/newlines from attacker output."""
    evil = "normal\x00text\ninjected_line\r\x1bESC\x7f"
    result = scanner._sanitize_script_output(evil)
    assert result is not None
    assert "\n" not in result
    assert "\r" not in result
    assert "\x00" not in result
    assert "\x1b" not in result
    assert "\x7f" not in result
    assert "normaltext" in result


def test_sanitize_script_output_caps_length():
    """_sanitize_script_output caps at _SCRIPT_OUTPUT_MAX characters."""
    long_output = "A" * 5000
    result = scanner._sanitize_script_output(long_output)
    assert result is not None
    assert len(result) <= scanner._SCRIPT_OUTPUT_MAX


def test_sanitize_script_output_empty_returns_none():
    """All-control-char or empty input returns None."""
    assert scanner._sanitize_script_output("") is None
    assert scanner._sanitize_script_output(None) is None
    assert scanner._sanitize_script_output("\x00\x01\x1f\x7f") is None
    assert scanner._sanitize_script_output("   ") is None


def test_parse_nmap_script_output_attacker_controlled_sanitized():
    """Evidence from a hostile script output has no control chars + is bounded.

    XML 1.0 only allows TAB (&#9;), LF (&#10;), CR (&#13;) and \\x7f (DEL is
    NOT a restricted char in attribute values but IS in nmap output) as the
    whitespace / newline injection vectors that actually reach parse_nmap via
    the XML layer — the same approach as the existing smb-fields sanitization
    test.  C0 bytes other than TAB/LF/CR are invalid in XML 1.0 and are
    rejected by the parser before our code sees them; we therefore test only
    the chars that DO reach us and that our sanitizer must strip.
    """
    # Use XML entity references for the XML-valid control chars that ARE the
    # real injection surface: TAB (\t), LF (\n), CR (\r), DEL (\x7f).
    # We embed them in the output attribute value via XML numeric references.
    evil_output_xml = (
        "safe_prefix&#9;tab&#10;INJECTED_LINE&#13;cr&#127;del" + "X" * 5000
    )
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open 10.0.5.1">
  <host>
    <address addr="10.0.5.1" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="3.0.3"/>
        <script id="ftp-anon" output="{evil_output_xml}"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    findings = parse_nmap(xml)
    assert len(findings) == 1, "XML should be valid and produce one finding"
    f = findings[0]
    ev = f["evidence"]
    # Sanitizer strips TAB/LF/CR/DEL — none may appear in the evidence string.
    assert "\n" not in ev
    assert "\r" not in ev
    assert "\t" not in ev
    assert "\x7f" not in ev
    # Total evidence is bounded (base evidence + capped script contribution).
    assert len(ev) < 1000, f"evidence too long: {len(ev)}"
    # "ftp-anon" label still present in evidence.
    assert "ftp-anon" in ev


# ---------------------------------------------------------------------------
# filter_scope unchanged (regression guard)
# ---------------------------------------------------------------------------

def test_filter_scope_still_fails_closed_after_nse_deepening():
    """filter_scope is unchanged: cidrs_allowed=None still returns [] after v0.4.0."""
    assert filter_scope("10.0.0.5", None) == []
    assert filter_scope("10.0.0.5", ["10.0.0.0/24"]) == ["10.0.0.5/32"]
    assert filter_scope("8.8.8.8", ["10.0.0.0/24"]) == []
    assert filter_scope("10.0.0.5", []) == ["10.0.0.5/32"]
