"""A level-4 run's recorded traffic → the hosts it contacted and whether bait left.

The recording is made on the HOST, on the microVM's TAP device (``tcpdump -w``),
so nothing in the guest can edit it. This module reads that classic pcap file
(Ethernet frames, IPv4 — the egress policy drops IPv6) with the standard
library only, deterministically, and reports from the guest's side:

* ``hosts`` — every name the guest asked DNS for, every TLS server name (SNI)
  it sent, and every address it opened a TCP connection to that no DNS answer
  it received explains (a connection to a resolved name is already listed by
  that name). Sorted, de-duplicated: the same recording is the same answer.
* ``bait_seen`` — True when an outbound payload (each TCP flow's bytes joined
  in order, each UDP datagram) carries a bait marker (:mod:`threat_lab.bait`).
  False means only "not seen in clear text": TLS hides payloads, so the
  runner never reports a False as "no bait sent" (LES-011).

Malformed or truncated packets are skipped, never fatal: the recording is
attacker-shaped. The curator's extractor still validates every host.

Usage::

    seen = read_pcap(pcap_bytes, guest_address="172.30.4.10")
    seen.hosts, seen.bait_seen
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .bait import bait_markers

#: The most of a recording read; a run that sends more is cut off here.
MAX_PCAP_BYTES = 64 * 1024 * 1024
_ETHERNET, _IPV4, _VLAN = 1, 0x0800, 0x8100
_TCP, _UDP = 6, 17
_DNS_PORT = 53
_A_RECORD, _IN_CLASS = 1, 1
_MAX_NAME_JUMPS = 16
_MAGIC = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}


@dataclass(frozen=True)
class Traffic:
    """What the recording shows the guest did on the network."""

    hosts: tuple[str, ...]
    bait_seen: bool


def is_recording(data: bytes) -> bool:
    """Whether *data* is a classic pcap of Ethernet frames — a recording that
    was made, even if empty. Anything else is no recording at all."""
    endian = _MAGIC.get(data[:4])
    return endian is not None and len(data) >= 24 and struct.unpack(endian + "I", data[20:24])[0] == _ETHERNET


def read_pcap(data: bytes, guest_address: str) -> Traffic:
    """The :class:`Traffic` in pcap *data* for the guest at *guest_address*.
    Data that is not a classic Ethernet pcap reads as no traffic."""
    guest = ipaddress.IPv4Address(guest_address).packed
    names: set[str] = set()
    connected: set[bytes] = set()
    resolved: set[bytes] = set()
    flows: dict[tuple[bytes, int, int], list[bytes]] = {}
    datagrams: list[bytes] = []
    for source, destination, protocol, segment in _ipv4_packets(data[:MAX_PCAP_BYTES]):
        if protocol == _UDP and len(segment) >= 8:
            source_port, destination_port = struct.unpack("!HH", segment[:4])
            payload = segment[8:]
            if source == guest and destination_port == _DNS_PORT:
                datagrams.append(payload)
                name = _question_name(payload)
                if name:
                    names.add(name)
            elif destination == guest and source_port == _DNS_PORT:
                resolved.update(_answer_addresses(payload))
            elif source == guest:
                datagrams.append(payload)
        elif protocol == _TCP and len(segment) >= 20 and source == guest:
            source_port, destination_port = struct.unpack("!HH", segment[:4])
            offset, flags = (segment[12] >> 4) * 4, segment[13]
            if flags & 0x02 and not flags & 0x10:          # SYN without ACK: a new connection
                connected.add(destination)
            payload = segment[offset:]
            if payload:
                flows.setdefault((destination, destination_port, source_port), []).append(payload)
                server_name = _client_hello_server_name(payload)
                if server_name:
                    names.add(server_name)
    hosts = names | {str(ipaddress.IPv4Address(address)) for address in connected - resolved}
    outbound = [b"".join(parts) for parts in flows.values()] + datagrams
    markers = bait_markers()
    return Traffic(tuple(sorted(hosts)), any(marker in blob for blob in outbound for marker in markers))


def _ipv4_packets(data: bytes) -> Iterator[tuple[bytes, bytes, int, bytes]]:
    """``(source, destination, protocol, transport segment)`` per first-fragment IPv4 frame."""
    if not is_recording(data):
        return
    endian = _MAGIC[data[:4]]
    position = 24
    while position + 16 <= len(data):
        captured = struct.unpack(endian + "I", data[position + 8:position + 12])[0]
        frame = data[position + 16:position + 16 + captured]
        position += 16 + captured
        packet = _ipv4_in(frame)
        if packet is not None:
            yield packet


def _ipv4_in(frame: bytes) -> Optional[tuple[bytes, bytes, int, bytes]]:
    if len(frame) < 14:
        return None
    ethertype, header = struct.unpack("!H", frame[12:14])[0], 14
    if ethertype == _VLAN and len(frame) >= 18:
        ethertype, header = struct.unpack("!H", frame[16:18])[0], 18
    ip = frame[header:]
    if ethertype != _IPV4 or len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    header_length = (ip[0] & 0x0F) * 4
    total_length = struct.unpack("!H", ip[2:4])[0]
    if struct.unpack("!H", ip[6:8])[0] & 0x1FFF:      # a later fragment carries no transport header
        return None
    return ip[12:16], ip[16:20], ip[9], ip[header_length:max(header_length, total_length)]


def _read_name(message: bytes, offset: int) -> tuple[Optional[str], int]:
    """A DNS name at *offset* and the offset after it (compression pointers followed, bounded)."""
    labels: list[str] = []
    after: Optional[int] = None
    for _ in range(_MAX_NAME_JUMPS * 8):
        if offset >= len(message):
            return None, len(message)
        length = message[offset]
        if length == 0:
            return ".".join(labels).lower() or None, after if after is not None else offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                return None, len(message)
            after = after if after is not None else offset + 2
            offset = ((length & 0x3F) << 8) | message[offset + 1]
            continue
        label = message[offset + 1:offset + 1 + length]
        try:
            labels.append(label.decode("ascii"))
        except UnicodeDecodeError:
            return None, len(message)
        offset += 1 + length
    return None, len(message)


def _question_name(message: bytes) -> Optional[str]:
    if len(message) < 12 or struct.unpack("!H", message[4:6])[0] < 1:
        return None
    return _read_name(message, 12)[0]


def _answer_addresses(message: bytes) -> set[bytes]:
    """The IPv4 addresses in a DNS response's A records."""
    if len(message) < 12:
        return set()
    questions, answers = struct.unpack("!HH", message[4:8])
    offset = 12
    for _ in range(questions):
        offset = _read_name(message, offset)[1] + 4
    addresses: set[bytes] = set()
    for _ in range(answers):
        offset = _read_name(message, offset)[1]
        if offset + 10 > len(message):
            break
        record_type, record_class, _ttl, length = struct.unpack("!HHIH", message[offset:offset + 10])
        data = message[offset + 10:offset + 10 + length]
        if record_type == _A_RECORD and record_class == _IN_CLASS and len(data) == 4:
            addresses.add(data)
        offset += 10 + length
    return addresses


def _client_hello_server_name(payload: bytes) -> Optional[str]:
    """The SNI host name of a TLS ClientHello that starts *payload*, if it does."""
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    position = 9 + 2 + 32                               # record + handshake headers, version, random
    try:
        position += 1 + payload[position]               # session id
        position += 2 + struct.unpack("!H", payload[position:position + 2])[0]   # cipher suites
        position += 1 + payload[position]               # compression methods
        end = position + 2 + struct.unpack("!H", payload[position:position + 2])[0]
        position += 2
        while position + 4 <= min(end, len(payload)):
            kind, length = struct.unpack("!HH", payload[position:position + 4])
            if kind == 0:                               # server_name: list length, type, name length, name
                name_length = struct.unpack("!H", payload[position + 7:position + 9])[0]
                name = payload[position + 9:position + 9 + name_length]
                return name.decode("ascii").lower() or None
            position += 4 + length
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None
