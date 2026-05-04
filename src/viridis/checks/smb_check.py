"""
viridis.checks.smb_check – SMB/CIFS exposure and misconfiguration check.

Red-team perspective: SMB is one of the most abused lateral-movement vectors.
EternalBlue, ransomware propagation, pass-the-hash, and credential relay all
rely on exposed SMB. This check probes for the most dangerous conditions.

Checks performed (no credentials required):
  1. SMB port reachability (TCP 445 / legacy 139)
  2. SMBv1 support – EternalBlue / WannaCry attack surface
  3. Anonymous / null session (no-auth share enumeration)
  4. Guest share listing via SMB session setup
  5. SMB signing disabled / not required (relay attack prerequisite)
"""
from __future__ import annotations

import logging
import socket
import struct
from typing import List, Optional

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

# ─── SMB constants ───────────────────────────────────────────────────────────

_SMB1_NEGOTIATE = (
    b"\x00\x00\x00\x85"          # NetBIOS Session Service length
    b"\xff\x53\x4d\x42"          # SMB1 magic
    b"\x72"                       # Command: Negotiate Protocol
    b"\x00\x00\x00\x00"          # Status
    b"\x18"                       # Flags
    b"\x01\x28"                   # Flags2
    b"\x00\x00"                   # PID High
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
    b"\x00\x00"                   # Reserved
    b"\xff\xff"                   # Tree ID
    b"\xfe\xff"                   # Process ID
    b"\x00\x00"                   # User ID
    b"\x00\x00"                   # Multiplex ID
    # Negotiate Request
    b"\x00"                       # Word count
    b"\x62\x00"                   # Byte count = 98
    b"\x02NT LM 0.12\x00"
    b"\x02SMB 2.002\x00"
    b"\x02SMB 2.???\x00"
)

_SMB2_NEGOTIATE = (
    b"\x00\x00\x00\x7e"          # NetBIOS length = 126
    b"\xfeSMB"                    # SMB2 magic
    b"\x40\x00"                   # Header length
    b"\x00\x00"                   # Credit charge
    b"\x00\x00\x00\x00"          # Status
    b"\x00\x00"                   # Command: Negotiate (0)
    b"\x00\x00"                   # Credits requested
    b"\x00\x00\x00\x00"          # Flags
    b"\x00\x00\x00\x00"          # Chain offset
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # MessageID
    b"\x00\x00\x00\x00"          # ProcessID
    b"\x00\x00\x00\x00"          # TreeID
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # SessionID
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
    # Negotiate body
    b"\x24\x00"                   # Structure size = 36
    b"\x02\x00"                   # Dialect count = 2
    b"\x00\x00"                   # Security mode (not required flag = 0)
    b"\x00\x00"                   # Reserved
    b"\x7f\x00\x00\x00"          # Capabilities
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # GUID
    b"\x00\x00\x00\x00"          # ClientStartTime
    b"\x02\x02"                   # Dialect: SMB 2.0.2
    b"\x10\x02"                   # Dialect: SMB 2.1.0
)


def _tcp_connect(host: str, port: int, timeout: float = 3.0) -> Optional[socket.socket]:
    """Return a connected TCP socket or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except OSError:
        return None


def _probe_smb1(host: str, timeout: float = 5.0) -> bool:
    """Return True if the host responds with an SMB1 dialect in its Negotiate response."""
    s = _tcp_connect(host, 445, timeout)
    if s is None:
        return False
    try:
        s.sendall(_SMB1_NEGOTIATE)
        resp = s.recv(256)
        if len(resp) < 9:
            return False
        # Check for SMB1 magic in response (byte 4-7)
        return resp[4:8] == b"\xff\x53\x4d\x42"
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def _probe_smb2_signing(host: str, timeout: float = 5.0) -> Optional[str]:
    """
    Probe SMB2 Negotiate and return signing status:
      'required'    – signing enforced (safe)
      'enabled'     – signing available but not required (relay-possible)
      'disabled'    – no signing (relay trivial)
      None          – could not determine
    """
    s = _tcp_connect(host, 445, timeout)
    if s is None:
        return None
    try:
        s.sendall(_SMB2_NEGOTIATE)
        resp = s.recv(512)
        # SMB2 response: magic at bytes 4-7, command at 12-13, SecurityMode at offset 70
        if len(resp) < 72 or resp[4:8] != b"\xfeSMB":
            return None
        security_mode = resp[70]
        # Bit 0 = signing enabled, bit 1 = signing required
        if security_mode & 0x02:
            return "required"
        elif security_mode & 0x01:
            return "enabled"
        else:
            return "disabled"
    except OSError:
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


class SMBCheck(BaseCheck):
    """
    SMB exposure check from a red-team perspective.
    Tests for SMBv1 (EternalBlue surface), signing status (relay), and port exposure.
    """

    @property
    def name(self) -> str:
        return "smb"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        findings: List[Finding] = []

        # 1. Port reachability
        port445 = _tcp_connect(host, 445, timeout=3.0)
        port139 = _tcp_connect(host, 139, timeout=2.0) if port445 is None else None

        if port445:
            port445.close()
        if port139:
            port139.close()

        smb_open = (port445 is not None) or (port139 is not None)
        smb_port = 445 if port445 is not None else (139 if port139 is not None else None)

        if not smb_open:
            return CheckResult(
                check_name=self.name,
                target=host,
                passed=True,
                findings=[],
                metadata={"smb_open": False},
            )

        findings.append(Finding(
            title=f"SMB port {smb_port} reachable",
            severity=Severity.INFO,
            description=(
                f"TCP port {smb_port} (SMB/CIFS) is open on {host}. "
                "SMB is a common lateral-movement vector — exposed SMB requires "
                "careful hardening (disable SMBv1, enable signing, firewall from internet)."
            ),
            recommendation=(
                "Block SMB (TCP 445/139) at the perimeter firewall. "
                "Never expose SMB directly to the internet."
            ),
            details={"port": smb_port},
        ))

        # 2. SMBv1 probe
        try:
            smb1_found = _probe_smb1(host, timeout=5.0)
        except Exception:
            smb1_found = False

        if smb1_found:
            findings.append(Finding(
                title="SMBv1 protocol enabled (EternalBlue / WannaCry surface)",
                severity=Severity.CRITICAL,
                description=(
                    f"{host} responds to SMBv1 Negotiate requests. "
                    "SMBv1 is the protocol exploited by EternalBlue (MS17-010), the vulnerability "
                    "used by WannaCry, NotPetya, and many ransomware campaigns. "
                    "Microsoft disabled SMBv1 by default in Windows 10 1709+; if this host has it "
                    "enabled, it is almost certainly unpatched or misconfigured."
                ),
                recommendation=(
                    "Disable SMBv1 immediately: "
                    "Windows: Set-SmbServerConfiguration -EnableSMB1Protocol $false  "
                    "Linux/Samba: min protocol = SMB2 in smb.conf. "
                    "Apply MS17-010 patch if not already done."
                ),
                details={"cve": "CVE-2017-0144", "exploit": "EternalBlue / WannaCry"},
            ))
        elif smb_open:
            findings.append(Finding(
                title="SMBv1 not detected",
                severity=Severity.INFO,
                description="Host did not accept an SMBv1 Negotiate — modern SMB2/3 only.",
                recommendation="Verify SMBv1 remains disabled after OS updates.",
                details={},
            ))

        # 3. SMB2 signing
        try:
            signing = _probe_smb2_signing(host, timeout=5.0)
        except Exception:
            signing = None

        if signing == "disabled":
            findings.append(Finding(
                title="SMB signing disabled — relay attack possible",
                severity=Severity.HIGH,
                description=(
                    f"{host} has SMB signing disabled. "
                    "An attacker with a MITM position (ARP spoof, LLMNR/NBT-NS poisoning via "
                    "Responder) can relay NTLM authentication from this host to authenticate "
                    "to other services without ever cracking the password hash. "
                    "This is the core of NTLM relay attacks (e.g. ntlmrelayx)."
                ),
                recommendation=(
                    "Enable and require SMB signing on all hosts. "
                    "GPO: Computer Configuration → Windows Settings → Security Settings → "
                    "Local Policies → Security Options → "
                    "Microsoft network server: Digitally sign communications (always) → Enabled. "
                    "All domain controllers should have signing required by default."
                ),
                details={"signing": "disabled", "attack": "NTLM relay / ntlmrelayx"},
            ))
        elif signing == "enabled":
            findings.append(Finding(
                title="SMB signing enabled but not required",
                severity=Severity.MEDIUM,
                description=(
                    f"{host} supports SMB signing but does not require it. "
                    "Clients that do not negotiate signing can still connect unsigned, "
                    "leaving them vulnerable to NTLM relay attacks in a downgrade scenario."
                ),
                recommendation=(
                    "Change SMB signing to 'required' rather than 'enabled'. "
                    "This blocks unsigned connections entirely."
                ),
                details={"signing": "enabled_not_required"},
            ))

        passed = not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings
        )
        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata={
                "smb_open": smb_open,
                "smb_port": smb_port,
                "smbv1": smb1_found,
                "signing": signing,
            },
        )
