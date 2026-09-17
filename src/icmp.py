import os
import socket
import struct

# ============================================================
# CONFIGURATION
# ============================================================

FORMAT            = "!BBHHH"
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0
ICMP_HEADER_SIZE  = 8
IP_HEADER_SIZE    = 20
ICMP_ID           = os.getpid() % 65535


# ============================================================
# PACKET
# ============================================================

def calculate_checksum(packet: bytes) -> int:
    checksum = 0
    if len(packet) % 2:
        packet += b"\x00"
    for i in range(0, len(packet), 2):
        checksum += int.from_bytes(packet[i:i + 2], byteorder="big")
    while checksum >> 16:
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
    return (~checksum) & 0xFFFF


def create_icmp(payload: bytes, sequence: int, icmp_id: int = ICMP_ID,
                icmp_type: int = ICMP_ECHO_REQUEST) -> bytes:
    """Build an ICMP packet whose data field is the given payload."""
    code      = 0
    checksum  = 0
    header    = struct.pack(FORMAT, icmp_type, code, checksum, icmp_id, sequence)
    packet    = header + payload
    checksum  = calculate_checksum(packet)
    header    = struct.pack(FORMAT, icmp_type, code, checksum, icmp_id, sequence)
    return header + payload


def parse_icmp(raw: bytes):
    """
    Parse a raw IP datagram and return the ICMP fields.

    Returns a dict with type, code, checksum, icmp_id, icmp_seq, payload,
    or None if the packet is too short.
    """
    if len(raw) < IP_HEADER_SIZE + ICMP_HEADER_SIZE:
        return None

    icmp = raw[IP_HEADER_SIZE:]
    icmp_type, code, checksum, icmp_id, icmp_seq = struct.unpack(
        FORMAT, icmp[:ICMP_HEADER_SIZE]
    )
    return {
        "type":     icmp_type,
        "code":     code,
        "checksum": checksum,
        "icmp_id":  icmp_id,
        "icmp_seq": icmp_seq,
        "payload":  icmp[ICMP_HEADER_SIZE:],
    }


def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    return s
