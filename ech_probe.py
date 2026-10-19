#!/usr/bin/env python3
"""Discover Encrypted ClientHello (ECH) signals using DNS HTTPS records and TLS probes.

Usage:
  python3 ech_probe.py domains.txt
  python3 ech_probe.py domains.txt -o results.csv -j 30
  python3 ech_probe.py domains.txt --dns-timeout 3 --timeout 5

This is an observational scanner, not a proof that every client connection will use ECH.
A published DNS ECHConfigList is evidence that ECH is advertised in DNS. The active probe
sends a GREASE ClientHello and reports observed TLS behavior; it does not validate ECH acceptance.
A failed or negative probe is not proof that a service does not support ECH.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import csv
import ipaddress
import shutil
import json
import os
import random
import socket
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

DNS_SERVERS_DEFAULT = ("1.1.1.1", "8.8.8.8")
DNS_TYPE_CNAME = 5
DNS_TYPE_HTTPS = 65
DNS_TYPE_OPT = 41
DNS_UDP_PAYLOAD_SIZE = 1232
DNS_CLASS_IN = 1
ECH_EXTENSION = 0xFE0D
MAX_DNS_PACKET = 65535
MAX_CNAME_DEPTH = 5
MAX_HTTPS_ALIAS_DEPTH = 5


def _u8(n: int) -> bytes:
    return struct.pack("!B", n)


def _u16(n: int) -> bytes:
    return struct.pack("!H", n)


def _u24(n: int) -> bytes:
    if not 0 <= n <= 0xFFFFFF:
        raise ValueError("24-bit integer out of range")
    return n.to_bytes(3, "big")


def _rand(n: int) -> bytes:
    return os.urandom(n)


def _x25519_public_key_from_private(private_key: bytes) -> bytes:
    """Derive an X25519 public key using the RFC 7748 Montgomery ladder.

    This is used only to make the GREASE ECH `enc` field a structurally valid,
    freshly generated X25519 encapsulated-key value; it is not an ECH encryption
    implementation and the corresponding private scalar is discarded immediately.
    """
    if len(private_key) != 32:
        raise ValueError("X25519 private key must be exactly 32 bytes")
    scalar_bytes = bytearray(private_key)
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 127
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")

    prime = (1 << 255) - 19
    x1 = 9  # X25519 basepoint u-coordinate
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for bit in reversed(range(255)):
        k_bit = (scalar >> bit) & 1
        swap ^= k_bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_bit

        a = (x2 + z2) % prime
        aa = (a * a) % prime
        b = (x2 - z2) % prime
        bb = (b * b) % prime
        e = (aa - bb) % prime
        c = (x3 + z3) % prime
        d = (x3 - z3) % prime
        da = (d * a) % prime
        cb = (c * b) % prime
        x3 = ((da + cb) * (da + cb)) % prime
        diff = (da - cb) % prime
        z3 = (x1 * diff * diff) % prime
        x2 = (aa * bb) % prime
        z2 = (e * (aa + 121665 * e)) % prime

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = (x2 * pow(z2, prime - 2, prime)) % prime
    return result.to_bytes(32, "little")


def normalize_domain(name: str) -> str:
    """Normalize an input hostname to an ASCII IDNA name; reject malformed names."""
    name = name.strip().rstrip(".")
    if not name or any(ch.isspace() for ch in name) or "/" in name:
        raise ValueError("empty or malformed hostname")
    try:
        ipaddress.ip_address(name.strip("[]"))
        raise ValueError("IP addresses are not domain names; provide a hostname")
    except ValueError as exc:
        if str(exc).startswith("IP addresses"):
            raise
    ascii_name = name.encode("idna").decode("ascii").lower()
    if len(ascii_name) > 253:
        raise ValueError("hostname exceeds 253 characters")
    labels = ascii_name.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("hostname contains an empty or overlong label")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError("hostname labels cannot start or end with '-'")
    if any(not all(c.isalnum() or c == "-" for c in label) for label in labels):
        raise ValueError("hostname contains invalid characters")
    return ascii_name


def _encode_dns_name(name: str) -> bytes:
    if name == ".":
        return b"\x00"
    labels = name.rstrip(".").split(".")
    out = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError("invalid DNS label length")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _read_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name, safely handling compression pointers and pointer loops."""
    labels: list[str] = []
    pos = offset
    next_offset: int | None = None
    visited: set[int] = set()
    jumps = 0

    while True:
        if pos >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[pos + 1]
            if pointer >= len(packet) or pointer in visited:
                raise ValueError("invalid DNS compression pointer")
            visited.add(pointer)
            if next_offset is None:
                next_offset = pos + 2
            pos = pointer
            jumps += 1
            if jumps > 128:
                raise ValueError("too many DNS compression pointers")
            continue
        if length & 0xC0:
            raise ValueError("invalid DNS label encoding")
        pos += 1
        if length == 0:
            return ".".join(labels) or ".", next_offset if next_offset is not None else pos
        if length > 63 or pos + length > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[pos:pos + length].decode("ascii", errors="strict"))
        pos += length


def _dns_name_key(name: str) -> str:
    """Return a comparable DNS owner name, preserving the root name as '.'."""
    return "." if name == "." else name.rstrip(".").lower()


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly size bytes from a stream socket or raise on early EOF."""
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ValueError("truncated DNS TCP response")
        chunks.extend(chunk)
    return bytes(chunks)


def _dns_exchange(server: str, packet: bytes, timeout: float, tcp: bool = False) -> bytes:
    """Send one DNS packet over UDP or TCP, supporting IPv4/IPv6 resolver addresses."""
    socktype = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    addresses = socket.getaddrinfo(server, 53, type=socktype)
    if not addresses:
        raise OSError(f"could not resolve DNS server {server}")

    last_error: OSError | None = None
    for family, resolved_socktype, proto, _, sockaddr in addresses:
        try:
            with socket.socket(family, resolved_socktype, proto) as sock:
                sock.settimeout(timeout)
                if tcp:
                    sock.connect(sockaddr)
                    sock.sendall(_u16(len(packet)) + packet)
                    length = struct.unpack("!H", _recv_exact(sock, 2))[0]
                    if length < 12:
                        raise ValueError("DNS TCP response shorter than header")
                    return _recv_exact(sock, length)
                sock.sendto(packet, sockaddr)
                response, _ = sock.recvfrom(MAX_DNS_PACKET)
                return response
        except OSError as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise OSError(f"could not contact DNS server {server}")


def _parse_dns_response(response: bytes, tid: int, expected_name: str) -> dict[str, Any]:
    """Parse a DNS response while retaining each RR's owner and section."""
    if len(response) < 12:
        raise ValueError("DNS response shorter than header")
    r_tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", response[:12])
    if r_tid != tid:
        raise ValueError("DNS transaction ID mismatch")
    if not flags & 0x8000:
        raise ValueError("DNS packet is not a response")
    if flags & 0x0200:
        raise RuntimeError("DNS response remains truncated after TCP fallback")
    rcode = flags & 0x000F
    if rcode not in (0, 3):
        names = {1: "FORMERR", 2: "SERVFAIL", 4: "NOTIMP", 5: "REFUSED"}
        raise RuntimeError(f"DNS {names.get(rcode, 'RCODE_' + str(rcode))}")
    if qdcount < 1:
        raise ValueError("DNS response has no question")

    off = 12
    questions: list[tuple[str, int, int]] = []
    for _ in range(qdcount):
        qname, off = _read_dns_name(response, off)
        if off + 4 > len(response):
            raise ValueError("truncated DNS question")
        qtype, qclass = struct.unpack("!HH", response[off:off + 4])
        off += 4
        questions.append((_dns_name_key(qname), qtype, qclass))
    if not any(name == _dns_name_key(expected_name) and qtype == DNS_TYPE_HTTPS and qclass == DNS_CLASS_IN
               for name, qtype, qclass in questions):
        raise ValueError("DNS response question does not match HTTPS query")

    https_records: list[dict[str, Any]] = []
    cnames: list[dict[str, Any]] = []
    for section, count in (("answer", ancount), ("authority", nscount), ("additional", arcount)):
        for _ in range(count):
            owner, off = _read_dns_name(response, off)
            if off + 10 > len(response):
                raise ValueError("truncated DNS resource-record header")
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", response[off:off + 10])
            off += 10
            end = off + rdlength
            if end > len(response):
                raise ValueError("truncated DNS resource-record data")
            rdata_offset = off
            rdata = response[off:end]
            owner_key = _dns_name_key(owner)
            if rclass == DNS_CLASS_IN and rtype == DNS_TYPE_HTTPS:
                https_records.append({
                    "owner": owner_key, "rdata": rdata, "ttl": ttl, "section": section,
                })
            elif rclass == DNS_CLASS_IN and rtype == DNS_TYPE_CNAME:
                target, target_end = _read_dns_name(response, rdata_offset)
                if target_end != end:
                    raise ValueError("invalid CNAME RDATA length")
                cnames.append({
                    "owner": owner_key, "target": _dns_name_key(target), "ttl": ttl, "section": section,
                })
            off = end

    return {
        "https_records": https_records,
        "cnames": cnames,
        "rcode": rcode,
        "flags": flags,
    }


def _dns_query_type65(name: str, server: str = "1.1.1.1", timeout: float = 4.0) -> dict[str, Any]:
    """Query HTTPS records over EDNS/UDP, falling back to TCP when truncated."""
    tid = random.SystemRandom().randrange(65536)
    question = _encode_dns_name(name) + struct.pack("!HH", DNS_TYPE_HTTPS, DNS_CLASS_IN)
    # EDNS(0), advertising a conservative 1232-byte UDP payload to reduce IP fragmentation.
    opt_record = b"\x00" + struct.pack("!HHIH", DNS_TYPE_OPT, DNS_UDP_PAYLOAD_SIZE, 0, 0)
    packet = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 1) + question + opt_record

    response = _dns_exchange(server, packet, timeout, tcp=False)
    if len(response) < 12:
        raise ValueError("DNS response shorter than header")
    r_tid, flags = struct.unpack("!HH", response[:4])
    if r_tid != tid:
        raise ValueError("DNS transaction ID mismatch")
    if not flags & 0x8000:
        raise ValueError("DNS packet is not a response")
    if flags & 0x0200:
        response = _dns_exchange(server, packet, timeout, tcp=True)
    return _parse_dns_response(response, tid, name)


def _parse_https_rdata(rdata: bytes) -> dict[str, Any]:
    """Parse an HTTPS/SVCB RDATA and validate each service parameter boundary."""
    if len(rdata) < 3:
        raise ValueError("HTTPS/SVCB RDATA too short")
    priority = struct.unpack("!H", rdata[:2])[0]
    target, off = _read_dns_name(rdata, 2)
    if priority == 0:
        # AliasMode recipients MUST ignore SvcParams; these bytes are not evidence.
        return {
            "priority": priority,
            "target": target,
            "has_ech": False,
            "ech_b64": "",
            "mandatory_keys": [],
            "info": f"pri={priority} tgt={target}",
        }
    params: dict[int, bytes] = {}
    last_key = -1
    while off < len(rdata):
        if off + 4 > len(rdata):
            raise ValueError("truncated SVCB parameter header")
        key, plen = struct.unpack("!HH", rdata[off:off + 4])
        off += 4
        end = off + plen
        if end > len(rdata):
            raise ValueError("truncated SVCB parameter value")
        if key <= last_key:
            raise ValueError("SVCB parameters are duplicated or not in key order")
        params[key] = rdata[off:end]
        last_key = key
        off = end

    # Mandatory parameter (key 0) is a list of 16-bit keys. Unknown mandatory
    # keys mean a client cannot safely use this record, so expose them in metadata.
    mandatory = []
    if 0 in params:
        raw = params[0]
        if not raw or len(raw) % 2:
            raise ValueError("invalid mandatory SVCB parameter")
        mandatory = [struct.unpack("!H", raw[i:i + 2])[0] for i in range(0, len(raw), 2)]
        if 0 in mandatory or len(set(mandatory)) != len(mandatory):
            raise ValueError("invalid mandatory SVCB key list")

    ech = params.get(5, b"")
    return {
        "priority": priority,
        "target": target,
        "has_ech": 5 in params and len(ech) > 0,
        "ech_b64": base64.b64encode(ech).decode("ascii") if ech else "",
        "mandatory_keys": mandatory,
        "info": f"pri={priority} tgt={target}",
    }


def check_dns_ech(domain: str, timeout: float = 4.0, servers: tuple[str, ...] = DNS_SERVERS_DEFAULT) -> dict[str, Any]:
    """Inspect HTTPS ECH parameters, following only matching CNAME/AliasMode chains."""
    out: dict[str, Any] = {
        "has_https": False, "has_ech": False, "ech_b64": "",
        "raw": "", "error": "", "resolver": "", "record_count": 0,
        "lookup_complete": False,
    }
    visited: set[str] = set()
    infos: list[str] = []
    configs: list[str] = []
    current = _dns_name_key(domain)
    cname_depth = 0
    alias_depth = 0

    try:
        while True:
            if current in visited:
                raise ValueError(f"DNS alias loop detected at {current}")
            visited.add(current)

            answer = None
            query_errors: list[str] = []
            for server in servers:
                try:
                    answer = _dns_query_type65(current, server=server, timeout=timeout)
                    out["resolver"] = server
                    break
                except (OSError, ValueError, RuntimeError) as exc:
                    query_errors.append(f"{server}:{exc}")
            if answer is None:
                out["error"] = "; ".join(query_errors[-4:]) or "DNS query failed"
                out["raw"] = " | ".join(infos)[:1000]
                return out

            # Only answer-section records whose owner is the name being resolved are evidence.
            cname_matches = [
                rr for rr in answer["cnames"]
                if rr["section"] == "answer" and rr["owner"] == current
            ]
            if cname_matches:
                if cname_depth >= MAX_CNAME_DEPTH:
                    out["error"] = "CNAME depth limit exceeded"
                    break
                target = cname_matches[0]["target"]
                if target == ".":
                    out["error"] = "CNAME target is the DNS root, not a usable hostname"
                    break
                infos.append(f"CNAME {current}->{target}")
                cname_depth += 1
                current = target
                continue

            records = [
                rr for rr in answer["https_records"]
                if rr["section"] == "answer" and rr["owner"] == current
            ]
            if not records:
                out["lookup_complete"] = True
                out["error"] = "NXDOMAIN" if answer["rcode"] == 3 else "no HTTPS record"
                break

            out["has_https"] = True
            out["record_count"] += len(records)
            parsed_records = [_parse_https_rdata(rr["rdata"]) for rr in records]
            for parsed in parsed_records:
                infos.append(f"{current}:{parsed['info']}")

            # RFC 9460: if AliasMode is present, ignore ServiceMode records in the same RRset.
            aliases = [parsed for parsed in parsed_records if parsed["priority"] == 0]
            if aliases:
                if alias_depth >= MAX_HTTPS_ALIAS_DEPTH:
                    out["error"] = "HTTPS AliasMode depth limit exceeded"
                    break
                target = _dns_name_key(aliases[0]["target"])
                if target == ".":
                    out["lookup_complete"] = True
                    out["error"] = "HTTPS AliasMode target is '.' (service unavailable)"
                    break
                if target == current:
                    out["error"] = f"HTTPS AliasMode loop detected at {current}"
                    break
                infos.append(f"HTTPS-Alias {current}->{target}")
                alias_depth += 1
                current = target
                continue

            service_records = [parsed for parsed in parsed_records if parsed["priority"] > 0]
            if not service_records:
                out["error"] = "HTTPS RRset has no usable ServiceMode records"
                break
            out["lookup_complete"] = True
            for parsed in service_records:
                if parsed["has_ech"]:
                    out["has_ech"] = True
                    configs.append(parsed["ech_b64"])
            if configs:
                # Preserve every ECHConfigList found; JSON keeps this unambiguous.
                out["ech_b64"] = json.dumps(configs, separators=(",", ":"))
            break
    except socket.timeout:
        out["error"] = "DNS timeout"
    except Exception as exc:
        out["error"] = f"DNS parse error: {exc}"

    out["raw"] = " | ".join(infos)[:1000]
    return out


# Active GREASE ClientHello probe. This is intentionally a low-level probe;
# it does not complete a TLS handshake or prove that ordinary clients use ECH.
def build_grease_client_hello(sni: str) -> bytes:
    exts = bytearray()
    host = sni.encode("ascii")
    name = _u8(0) + _u16(len(host)) + host
    sni_list = _u16(len(name)) + name
    exts += _u16(0x0000) + _u16(len(sni_list)) + sni_list

    vers = _u8(2) + _u16(0x0304)
    exts += _u16(0x002B) + _u16(len(vers)) + vers

    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501]
    sig_body = _u16(len(sigs) * 2) + b"".join(_u16(s) for s in sigs)
    exts += _u16(0x000D) + _u16(len(sig_body)) + sig_body

    groups = [0x001D, 0x0017]
    gbody = _u16(len(groups) * 2) + b"".join(_u16(g) for g in groups)
    exts += _u16(0x000A) + _u16(len(gbody)) + gbody

    share = _u16(0x001D) + _u16(32) + _rand(32)
    ks = _u16(len(share)) + share
    exts += _u16(0x0033) + _u16(len(ks)) + ks

    # GREASE only: current RFC 9849 ECHClientHello outer variant, not real ECH.
    # Wire layout: type=outer(0), cipher_suite, config_id, enc<2>, payload<2>.
    kdf_id, aead_id = 0x0001, 0x0001
    ech_type = _u8(0)  # ECHClientHelloType.outer
    config_id = _u8(random.SystemRandom().randrange(256))
    enc = _x25519_public_key_from_private(_rand(32))
    payload = _rand(120)
    ech = ech_type + _u16(kdf_id) + _u16(aead_id) + config_id + _u16(len(enc)) + enc + _u16(len(payload)) + payload
    exts += _u16(ECH_EXTENSION) + _u16(len(ech)) + ech

    body = _u16(0x0303) + _rand(32)
    body += _u8(0)
    ciphers = [0x1301, 0x1302, 0x1303]
    body += _u16(len(ciphers) * 2) + b"".join(_u16(c) for c in ciphers)
    body += _u8(1) + _u8(0)
    body += _u16(len(exts)) + bytes(exts)

    hs = _u8(0x01) + _u24(len(body)) + body
    return _u8(0x16) + _u16(0x0301) + _u16(len(hs)) + hs


def _parse_extensions(data: bytes) -> dict[int, bytes]:
    extensions: dict[int, bytes] = {}
    off = 0
    while off < len(data):
        if off + 4 > len(data):
            raise ValueError("truncated TLS extension header")
        typ, length = struct.unpack("!HH", data[off:off + 4])
        off += 4
        end = off + length
        if end > len(data):
            raise ValueError("truncated TLS extension value")
        if typ in extensions:
            raise ValueError(f"duplicate TLS extension {typ:#06x}")
        extensions[typ] = data[off:end]
        off = end
    return extensions


def parse_server_hello_for_ech(data: bytes) -> dict[str, Any]:
    """Parse visible ECH-related TLS behavior without claiming ECH acceptance.

    This scanner sends only a GREASE ClientHello. It lacks a real ECHConfig, HPKE
    context, and inner-handshake transcript, so it cannot cryptographically validate
    the RFC 9849 acceptance confirmation in ServerHello.random or an HRR extension.
    """
    result: dict[str, Any] = {
        "got_sh": False,
        "is_hrr": False,
        "hrr_ech_extension": False,
        "hrr_ech_extension_len": 0,
        "server_hello_ech_extension": False,
        "ech_acceptance_validated": False,
        "alert": None,
        "info": "",
        "error": "",
    }
    if not data:
        result["info"] = "empty"
        return result

    hrr_magic = bytes.fromhex(
        "cf21ad74e59a6111be1d8c021e65b891"
        "c2a211167abb8c5e079e09e2c8a8339c"
    )
    off = 0
    handshake_buffer = bytearray()
    infos: list[str] = []

    # TLS handshake messages can span multiple records.
    while off < len(data):
        if off + 5 > len(data):
            result["error"] = "truncated TLS record header"
            break
        ctype = data[off]
        length = struct.unpack("!H", data[off + 3:off + 5])[0]
        end = off + 5 + length
        if end > len(data):
            result["error"] = "truncated TLS record"
            break
        payload = data[off + 5:end]
        off = end

        if ctype == 0x15:
            if len(payload) >= 2:
                result["alert"] = payload[1]
                infos.append(f"alert/{payload[1]}")
            continue
        if ctype != 0x16:
            continue
        handshake_buffer.extend(payload)

        while len(handshake_buffer) >= 4:
            hs_len = int.from_bytes(handshake_buffer[1:4], "big")
            total = 4 + hs_len
            if len(handshake_buffer) < total:
                break
            hs_type = handshake_buffer[0]
            body = bytes(handshake_buffer[4:total])
            del handshake_buffer[:total]
            if hs_type != 2:
                infos.append(f"hs{hs_type}")
                continue
            if len(body) < 38:
                result["error"] = "short ServerHello"
                continue

            result["got_sh"] = True
            is_hrr = body[2:34] == hrr_magic
            result["is_hrr"] = is_hrr
            sid_len = body[34]
            p = 35 + sid_len
            if p + 5 > len(body):
                result["error"] = "malformed ServerHello fields"
                continue
            # Skip cipher_suite (2) and legacy_compression_method (1).
            p += 3
            if p + 2 > len(body):
                result["error"] = "missing ServerHello extensions length"
                continue
            ext_len = struct.unpack("!H", body[p:p + 2])[0]
            p += 2
            if p + ext_len != len(body):
                result["error"] = "invalid ServerHello extensions length"
                continue
            try:
                extensions = _parse_extensions(body[p:p + ext_len])
            except ValueError as exc:
                result["error"] = str(exc)
                continue

            ech_value = extensions.get(ECH_EXTENSION)
            if is_hrr:
                result["hrr_ech_extension"] = ech_value is not None
                result["hrr_ech_extension_len"] = len(ech_value) if ech_value is not None else 0
                infos.append("HRR" + (f"+ECH-extension-observed(len={len(ech_value)})" if ech_value is not None else ""))
            else:
                result["server_hello_ech_extension"] = ech_value is not None
                infos.append("SH" + ("+ECH-extension-observed" if ech_value is not None else ""))
            # Do not set ech_acceptance_validated from an extension's mere presence.

    if handshake_buffer and not result["error"]:
        result["error"] = "incomplete TLS handshake message"
    result["info"] = ",".join(infos) if infos else f"bytes={len(data)}"
    return result


def _recv_tls_records(sock: socket.socket, max_bytes: int = 65536) -> bytes:
    """Read complete TLS records until a ServerHello, alert, EOF, or bounded limit."""
    received = bytearray()
    handshake = bytearray()
    record_pos = 0

    while len(received) < max_bytes:
        try:
            chunk = sock.recv(16384)
        except socket.timeout:
            if received:
                break
            raise
        if not chunk:
            break
        received.extend(chunk)

        # Process only newly complete records. Do not re-append records already parsed.
        while record_pos + 5 <= len(received):
            record_len = int.from_bytes(received[record_pos + 3:record_pos + 5], "big")
            end = record_pos + 5 + record_len
            if end > len(received):
                break
            ctype = received[record_pos]
            payload = received[record_pos + 5:end]
            record_pos = end

            if ctype == 0x15:
                return bytes(received)
            if ctype != 0x16:
                continue
            handshake.extend(payload)
            while len(handshake) >= 4:
                total = 4 + int.from_bytes(handshake[1:4], "big")
                if len(handshake) < total:
                    break
                hs_type = handshake[0]
                del handshake[:total]
                if hs_type == 2:
                    return bytes(received)

    return bytes(received)


def check_active_ech(domain: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Send one GREASE ClientHello and report observable TLS behavior only."""
    out: dict[str, Any] = {
        "active_ok": False,
        "hrr_ech_extension": False,
        "hrr_ech_extension_len": 0,
        "ech_acceptance_validated": False,
        "is_hrr": False,
        "alert": None,
        "info": "",
        "error": "",
        "latency_ms": 0.0,
        "address": "",
    }
    try:
        infos = socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        out["error"] = f"resolution: {exc}"
        return out
    if not infos:
        out["error"] = "resolution returned no addresses"
        return out

    started = time.monotonic()
    errors: list[str] = []
    seen_addresses: set[tuple[int, str]] = set()
    for family, socktype, proto, _, sockaddr in infos:
        address_key = (family, str(sockaddr[0]))
        if address_key in seen_addresses:
            continue
        seen_addresses.add(address_key)
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                sock.sendall(build_grease_client_hello(domain))
                data = _recv_tls_records(sock)
            out["address"] = str(sockaddr[0])
            out["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
            if not data:
                errors.append("no response")
                continue
            parsed = parse_server_hello_for_ech(data)
            out["active_ok"] = parsed["got_sh"]
            out["hrr_ech_extension"] = parsed["hrr_ech_extension"]
            out["hrr_ech_extension_len"] = parsed["hrr_ech_extension_len"]
            out["ech_acceptance_validated"] = parsed["ech_acceptance_validated"]
            out["is_hrr"] = parsed["is_hrr"]
            out["alert"] = parsed["alert"]
            out["info"] = parsed["info"]
            out["error"] = parsed["error"] or (f"alert/{parsed['alert']}" if parsed["alert"] is not None else "")
            # A ServerHello is useful observational evidence even without ECH signals.
            if parsed["got_sh"] or parsed["alert"] is not None:
                return out
            errors.append(parsed["error"] or parsed["info"])
        except socket.timeout:
            errors.append("timeout")
        except ConnectionRefusedError:
            errors.append("refused")
        except OSError as exc:
            errors.append(str(exc))
    out["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
    out["error"] = "; ".join(errors[-4:]) or "no usable address"
    return out


def parse_dns_servers(value: str) -> tuple[str, ...]:
    """Parse a comma-separated list of DNS resolver addresses or hostnames."""
    parts = [part.strip() for part in value.split(",")]
    if not parts or all(not part for part in parts):
        raise ValueError("at least one DNS server is required")
    if any(not part for part in parts):
        raise ValueError("invalid empty DNS server entry")
    servers = tuple(parts)
    for server in servers:
        if any(ch.isspace() for ch in server) or "/" in server:
            raise ValueError(f"invalid DNS server: {server!r}")
    return tuple(dict.fromkeys(servers))


def probe(
    domain: str,
    port: int = 443,
    timeout: float = 5.0,
    dns_timeout: float | None = None,
    dns_servers: tuple[str, ...] = DNS_SERVERS_DEFAULT,
) -> dict[str, Any]:
    dns = check_dns_ech(
        domain,
        timeout=dns_timeout if dns_timeout is not None else timeout,
        servers=dns_servers,
    )
    active = check_active_ech(domain, port, timeout=timeout)

    # This scanner's active GREASE probe cannot validate ECH acceptance. The positive
    # verdict therefore means an ECHConfigList was advertised in a relevant DNS answer.
    advertised = bool(dns["has_ech"])
    if advertised:
        verdict = "positive"
    elif not dns["lookup_complete"]:
        # A GREASE-only TLS response cannot compensate for an unavailable DNS answer.
        verdict = "inconclusive"
    else:
        verdict = "not_observed"
    return {
        "domain": domain,
        "port": port,
        "ech_advertised": advertised,
        "ech_supported": advertised,  # Legacy compatibility alias; prefer ech_advertised.
        "verdict": verdict,
        "dns_https": dns["has_https"],
        "dns_lookup_complete": dns["lookup_complete"],
        "dns_ech": dns["has_ech"],
        "dns_ech_b64": dns["ech_b64"],
        "dns_resolver": dns["resolver"],
        "dns_record_count": dns["record_count"],
        "active_sh": active["active_ok"],
        "active_hrr_ech_extension": active["hrr_ech_extension"],
        "active_hrr_ech_extension_len": active["hrr_ech_extension_len"],
        "active_ech_acceptance_validated": active["ech_acceptance_validated"],
        "active_hrr": active["is_hrr"],
        "active_address": active["address"],
        "latency_ms": active["latency_ms"],
        "error": "; ".join(x for x in (dns["error"], active["error"]) if x),
        "dns_raw": dns["raw"],
        "active_info": active["info"],
    }


def load_domains(path: str) -> list[tuple[str, int | None]]:
    """Read domains, optional host:port entries, comments, and blank lines."""
    entries: list[tuple[str, int | None]] = []
    seen: set[tuple[str, int | None]] = set()
    for line_no, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        host, port = line, None
        if line.count(":") == 1:
            possible_host, possible_port = line.rsplit(":", 1)
            if possible_port.isdigit():
                host, port = possible_host, int(possible_port)
                if not 1 <= port <= 65535:
                    raise ValueError(f"{path}:{line_no}: port must be between 1 and 65535")
        host = normalize_domain(host)
        entry = (host, port)
        if entry not in seen:
            seen.add(entry)
            entries.append(entry)
    return entries


def _safe_probe(
    entry: tuple[str, int | None], default_port: int, timeout: float, dns_timeout: float,
    dns_servers: tuple[str, ...] = DNS_SERVERS_DEFAULT,
) -> dict[str, Any]:
    host, port = entry
    try:
        return probe(host, port if port is not None else default_port, timeout, dns_timeout, dns_servers)
    except Exception as exc:
        return {
            "domain": host, "port": port if port is not None else default_port,
            "ech_advertised": False, "ech_supported": False, "verdict": "inconclusive",
            "dns_https": False, "dns_lookup_complete": False,
            "dns_ech": False, "dns_ech_b64": "",
            "dns_resolver": "", "dns_record_count": 0, "active_sh": False,
            "active_hrr_ech_extension": False, "active_hrr_ech_extension_len": 0,
            "active_ech_acceptance_validated": False, "active_hrr": False,
            "active_address": "", "latency_ms": 0.0,
            "error": f"unhandled probe error: {type(exc).__name__}: {exc}",
            "dns_raw": "", "active_info": "",
        }


def _write_csv_atomic(path: str, results: list[dict[str, Any]], fields: list[str]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", newline="", encoding="utf-8", dir=destination.parent,
            prefix=f".{destination.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temp_name = handle.name
            writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, destination)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def _render_progress(completed: int, total: int, started: float, width: int = 28) -> str:
    """Build a compact, single-line terminal progress bar."""
    ratio = completed / total if total else 1.0
    filled = int(width * ratio)
    bar = "#" * filled + "-" * (width - filled)
    elapsed = time.monotonic() - started
    rate = completed / elapsed if elapsed > 0 else 0.0
    remaining = (total - completed) / rate if rate > 0 else 0.0
    return f"[{bar}] {completed}/{total} {ratio:6.1%} | {rate:5.1f}/s | ETA {remaining:5.0f}s"


def _terminal_width(default: int = 100) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except OSError:
        return default


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover ECH signals (DNS HTTPS/SVCB + active TLS probe)")
    parser.add_argument("domains_file")
    parser.add_argument("-o", "--output", default="ech_results.csv")
    parser.add_argument("-j", "--jobs", type=int, default=20)
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="TLS timeout in seconds (default: 5)")
    parser.add_argument("--dns-timeout", type=float, default=4.0, help="DNS timeout per resolver in seconds")
    parser.add_argument(
        "--dns-servers", default=",".join(DNS_SERVERS_DEFAULT),
        help="comma-separated DNS resolvers (IPv4, IPv6, or resolver hostnames)",
    )
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--jsonl", help="also write full results as JSON Lines to this path")
    args = parser.parse_args()

    if args.jobs < 1:
        parser.error("--jobs must be >= 1")
    if args.timeout <= 0 or args.dns_timeout <= 0:
        parser.error("timeouts must be > 0")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        dns_servers = parse_dns_servers(args.dns_servers)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        domains = load_domains(args.domains_file)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    if not domains:
        parser.error("No valid domains in file")

    fields = [
        "domain", "port", "ech_advertised", "ech_supported", "verdict",
        "dns_https", "dns_lookup_complete", "dns_ech", "dns_ech_b64", "dns_resolver", "dns_record_count",
        "active_sh", "active_hrr_ech_extension", "active_hrr_ech_extension_len",
        "active_ech_acceptance_validated", "active_hrr", "active_address", "latency_ms",
        "error", "dns_raw", "active_info",
    ]
    results: list[dict[str, Any]] = []
    started = time.monotonic()
    total = len(domains)
    last_progress_len = 0
    width = _terminal_width()
    progress_width = max(12, min(28, width - 62))

    # Keep terminal output quiet: only domains with DNS ECH advertisement are printed as they finish.
    # Progress is updated in-place on stderr, so stdout remains useful for scripting.
    if sys.stderr.isatty():
        print(f"Scanning {total} unique domains for ECH...", file=sys.stderr)
        print(_render_progress(0, total, started, progress_width), end="", file=sys.stderr, flush=True)
    else:
        print(f"Scanning {total} unique domains for ECH...", file=sys.stderr)

    iterator = iter(domains)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        pending: dict[concurrent.futures.Future[dict[str, Any]], tuple[str, int | None]] = {}
        for _ in range(min(len(domains), args.jobs * 2)):
            entry = next(iterator, None)
            if entry is not None:
                pending[pool.submit(_safe_probe, entry, args.port, args.timeout, args.dns_timeout, dns_servers)] = entry

        completed = 0
        while pending:
            done, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                pending.pop(future, None)
                try:
                    result = future.result()
                except Exception as exc:
                    entry = ("<unknown>", args.port)
                    result = _safe_probe(entry, args.port, args.timeout, args.dns_timeout, dns_servers)
                    result["error"] = f"worker failure: {type(exc).__name__}: {exc}"
                    result["verdict"] = "inconclusive"

                results.append(result)
                completed += 1

                if result["ech_advertised"]:
                    evidence = []
                    if result["dns_ech"]:
                        evidence.append("DNS HTTPS/ECH")
                    evidence_text = "+".join(evidence) if evidence else "DNS ECH advertised"
                    print(
                        f"\n[DNS-ECH] {result['domain']}:{result['port']} "
                        f"| evidence={evidence_text} | active_acceptance_validated=no "
                        f"| {result['latency_ms']:.1f} ms",
                        file=sys.stdout,
                        flush=True,
                    )

                if sys.stderr.isatty():
                    progress = _render_progress(completed, total, started, progress_width)
                    padding = max(0, last_progress_len - len(progress))
                    print("\r" + progress + (" " * padding), end="", file=sys.stderr, flush=True)
                    last_progress_len = len(progress)
                elif completed == total or completed % max(1, total // 100) == 0:
                    # Non-interactive logs get occasional progress lines instead of a spinner.
                    print(f"Progress: {completed}/{total} ({completed / total:.1%})", file=sys.stderr)

                entry = next(iterator, None)
                if entry is not None:
                    pending[pool.submit(_safe_probe, entry, args.port, args.timeout, args.dns_timeout, dns_servers)] = entry

    if sys.stderr.isatty():
        print(file=sys.stderr)

    results.sort(key=lambda item: (item["domain"], item["port"]))
    try:
        _write_csv_atomic(args.output, results, fields)
        if args.jsonl:
            json_path = Path(args.jsonl)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    "w", encoding="utf-8", dir=json_path.parent,
                    prefix=f".{json_path.name}.", suffix=".tmp", delete=False,
                ) as handle:
                    temp_path = handle.name
                    for result in results:
                        handle.write(json.dumps(result, ensure_ascii=False) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_path, json_path)
            finally:
                if temp_path and os.path.exists(temp_path):
                    os.unlink(temp_path)
    except OSError as exc:
        sys.exit(f"Could not write output: {exc}")

    positive = sum(1 for result in results if result["ech_advertised"])
    inconclusive = sum(1 for result in results if result["verdict"] == "inconclusive")
    print(f"\nFinished: {positive} domain(s) advertising ECH in DNS out of {total}; {inconclusive} inconclusive.")
    print(f"CSV: {args.output}")
    if args.jsonl:
        print(f"JSONL: {args.jsonl}")


if __name__ == "__main__":
    main()
