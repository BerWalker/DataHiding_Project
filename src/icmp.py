import os
import socket
import struct

# ============================================================
# CONFIGURATION
# ============================================================

FORMATO           = "!BBHHH"
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0
ICMP_HEADER_SIZE  = 8
IP_HEADER_SIZE    = 20
ICMP_ID           = os.getpid() % 65535


# ============================================================
# PACKET
# ============================================================

def calcula_checksum(pacote: bytes) -> int:
    checksum = 0
    if len(pacote) % 2:
        pacote += b"\x00"
    for i in range(0, len(pacote), 2):
        checksum += int.from_bytes(pacote[i:i + 2], byteorder="big")
    while checksum >> 16:
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
    return (~checksum) & 0xFFFF


def cria_icmp(payload: bytes, sequence: int, icmp_id: int = ICMP_ID,
              tipo: int = ICMP_ECHO_REQUEST) -> bytes:
    """Build an ICMP packet whose data field is the given payload."""
    codigo    = 0
    checksum  = 0
    cabecalho = struct.pack(FORMATO, tipo, codigo, checksum, icmp_id, sequence)
    pacote    = cabecalho + payload
    checksum  = calcula_checksum(pacote)
    cabecalho = struct.pack(FORMATO, tipo, codigo, checksum, icmp_id, sequence)
    return cabecalho + payload


def parse_icmp(dados: bytes):
    """
    Parse a raw IP datagram and return the ICMP fields.

    Returns a dict with tipo, codigo, checksum, icmp_id, icmp_seq, payload,
    or None if the packet is too short.
    """
    if len(dados) < IP_HEADER_SIZE + ICMP_HEADER_SIZE:
        return None

    icmp = dados[IP_HEADER_SIZE:]
    tipo, codigo, checksum, icmp_id, icmp_seq = struct.unpack(
        FORMATO, icmp[:ICMP_HEADER_SIZE]
    )
    return {
        "tipo":     tipo,
        "codigo":   codigo,
        "checksum": checksum,
        "icmp_id":  icmp_id,
        "icmp_seq": icmp_seq,
        "payload":  icmp[ICMP_HEADER_SIZE:],
    }


def cria_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    return s
