"""
network_bot.hostname_resolver – Multi-method non-invasive hostname resolution.

Tries each method in order and returns the first result:
  1. Reverse DNS PTR  (socket.gethostbyaddr)   – any host, uses local DNS
  2. NetBIOS Node Status (UDP/137)              – Windows / Samba hosts
  3. mDNS unicast PTR query (UDP/5353)          – macOS / avahi-daemon hosts

Every method is a single packet or syscall with a short timeout.
No active probing beyond the single query per method.
"""
from __future__ import annotations

import logging
import random
import socket
import struct

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_hostname(ip: str, timeout: float = 2.0) -> str:
    """Return the best hostname found for *ip*, or '' if none found."""
    for method in (_ptr_lookup, _nbns_lookup, _mdns_lookup):
        try:
            name = method(ip, timeout)
            if name:
                logger.debug("hostname_resolver: %s → %s (via %s)", ip, name, method.__name__)
                return name
        except Exception as exc:
            logger.debug("hostname_resolver: %s failed for %s: %s", method.__name__, ip, exc)
    return ""


# ---------------------------------------------------------------------------
# Method 1: Reverse DNS PTR
# ---------------------------------------------------------------------------

def _ptr_lookup(ip: str, timeout: float = 2.0) -> str:
    import threading

    result: list[str] = [""]

    def _do():
        try:
            result[0] = socket.gethostbyaddr(ip)[0] or ""
        except Exception:
            pass

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout)
    return result[0]


# ---------------------------------------------------------------------------
# Method 2: NetBIOS Node Status Request (RFC 1002)
# Sends a single UDP packet to port 137; parses the workstation name.
# ---------------------------------------------------------------------------

def _nbns_lookup(ip: str, timeout: float = 1.5) -> str:
    # Encode the wildcard name '*\x00…\x00' (16 bytes) in NBNS Level 2 format.
    # Each byte becomes two chars: high_nibble+'A', low_nibble+'A'.
    raw = b'*' + b'\x00' * 15
    enc = bytearray()
    for b in raw:
        enc.append(((b >> 4) & 0xF) + ord('A'))
        enc.append((b & 0xF) + ord('A'))

    txid = random.randint(1, 0xFFFF)
    # DNS-style header: TxID, Flags=0, QDCOUNT=1, AN/NS/AR=0
    pkt = struct.pack('>6H', txid, 0x0000, 1, 0, 0, 0)
    # Question: length(0x20) + encoded-name + null + NBSTAT(0x0021) + IN(0x0001)
    pkt += bytes([0x20]) + bytes(enc) + b'\x00'
    pkt += struct.pack('>HH', 0x0021, 0x0001)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 137))
        resp, _ = s.recvfrom(1024)
        s.close()
    except Exception:
        return ""

    # Response layout (assuming name-pointer in answer section):
    # [0:12]  DNS header
    # [12:50] Question (34 name + 4 type/class)
    # [50:62] Answer RR header (2 ptr + 2 type + 2 class + 4 ttl + 2 rdlen)
    # [62:]   RDATA: num_names (1 byte) + N×18-byte entries
    # Each entry: name[15] + type[1] + flags[2]
    try:
        if len(resp) < 63:
            return ""
        num_names = resp[62]
        if not (1 <= num_names <= 30):
            return ""
        for i in range(num_names):
            base = 63 + i * 18
            if base + 16 > len(resp):
                break
            nb_type = resp[base + 15]
            # 0x00 = workstation/redirector, 0x20 = file server — both are the machine name
            if nb_type in (0x00, 0x20):
                raw_name = resp[base:base + 15]
                name = raw_name.decode('ascii', errors='replace').rstrip()
                name = name.strip()
                if name and name != '*':
                    return name.lower()
    except Exception:
        pass

    return ""


# ---------------------------------------------------------------------------
# Method 3: mDNS unicast PTR query (RFC 6762)
# Sends a DNS PTR query to port 5353 on the target IP directly (unicast).
# Many avahi-daemon and macOS hosts respond to unicast mDNS queries.
# ---------------------------------------------------------------------------

def _mdns_lookup(ip: str, timeout: float = 1.5) -> str:
    # Build a standard DNS PTR query for the reverse IP in .in-addr.arpa.
    # e.g. 192.168.1.5 → 5.1.168.192.in-addr.arpa
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return ""
        rev = '.'.join(reversed(parts)) + '.in-addr.arpa'
    except Exception:
        return ""

    txid = random.randint(1, 0xFFFF)
    # DNS header: TxID, Flags=0x0000 (standard query), QDCOUNT=1
    pkt = struct.pack('>HHHHHH', txid, 0x0000, 1, 0, 0, 0)
    # Encode QNAME
    for label in rev.split('.'):
        pkt += bytes([len(label)]) + label.encode('ascii')
    pkt += b'\x00'                           # root label
    pkt += struct.pack('>HH', 12, 1)         # PTR (12), IN (1)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 5353))
        resp, _ = s.recvfrom(512)
        s.close()
    except Exception:
        return ""

    # Parse the PTR answer from the response.
    # Skip header (12 bytes) + question section, then read first answer.
    try:
        if len(resp) < 13:
            return ""
        ancount = struct.unpack('>H', resp[6:8])[0]
        if ancount == 0:
            return ""

        # Skip question section: find the end of QNAME, then skip QTYPE+QCLASS
        pos = 12
        while pos < len(resp) and resp[pos] != 0:
            pos += resp[pos] + 1
        pos += 5  # null byte + QTYPE(2) + QCLASS(2)

        # Answer section: skip name (pointer or labels), type, class, ttl, rdlen
        if pos >= len(resp):
            return ""
        # Skip name (usually a pointer = 2 bytes, or labels)
        if resp[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while pos < len(resp) and resp[pos] != 0:
                pos += resp[pos] + 1
            pos += 1
        # type(2) + class(2) + ttl(4) + rdlen(2)
        if pos + 10 > len(resp):
            return ""
        rtype = struct.unpack('>H', resp[pos:pos + 2])[0]
        rdlen = struct.unpack('>H', resp[pos + 8:pos + 10])[0]
        pos += 10
        if rtype != 12:  # Not PTR
            return ""
        if pos + rdlen > len(resp):
            return ""

        # Decode PTR name (may use compression pointers)
        name = _decode_dns_name(resp, pos)
        # Strip trailing .local. or .
        name = name.rstrip('.')
        if name.endswith('.local'):
            name = name[:-6]
        return name if name else ""

    except Exception:
        return ""


def _decode_dns_name(data: bytes, offset: int) -> str:
    """Decode a DNS name at *offset* in *data*, following compression pointers."""
    parts: list[str] = []
    visited: set[int] = set()
    pos = offset
    while pos < len(data):
        if pos in visited:
            break
        visited.add(pos)
        length = data[pos]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            # Compression pointer
            if pos + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            pos = ptr
            continue
        pos += 1
        if pos + length > len(data):
            break
        parts.append(data[pos:pos + length].decode('ascii', errors='replace'))
        pos += length
    return '.'.join(parts)
