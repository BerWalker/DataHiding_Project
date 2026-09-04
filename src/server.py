import os
import socket
import struct

from stego import decode, reassemble

# ============================================================
# CONFIGURATION
# ============================================================

HOST              = "0.0.0.0"
FORMATO           = "!BBHHH"
ICMP_ECHO_REQUEST = 8
TIMEOUT           = int(os.environ.get("TIMEOUT", "10"))  # seconds without a new packet before giving up


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    received    = {}   # frag_seq → raw stego bytes
    total_frags = None

    print("=" * 60)
    print("SERVER — WAITING FOR FRAGMENTS")
    print("=" * 60)
    print(f"Listening on {HOST}  (timeout: {TIMEOUT}s)")
    print()

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.bind((HOST, 0))
        s.settimeout(TIMEOUT)

        while True:
            try:
                dados, addr = s.recvfrom(65535)
            except socket.timeout:
                print("[TIMEOUT] No more packets received")
                break

            # IP header is always 20 bytes → ICMP starts at offset 20
            icmp = dados[20:]
            if len(icmp) < 8:
                continue

            tipo, codigo, checksum, icmp_id, icmp_seq = struct.unpack(FORMATO, icmp[:8])

            # Only process Echo Requests (type 8)
            if tipo != ICMP_ECHO_REQUEST:
                continue

            stego_payload = icmp[8:]
            data          = decode(stego_payload)

            # Ignore packets that aren't valid stego carriers
            if data is None:
                continue

            frag_seq = data["seq"]

            # Ignore duplicates
            if frag_seq in received:
                continue

            received[frag_seq] = stego_payload
            total_frags        = data["total"]

            print(f"  [RECV] from={addr[0]}"
                  f" | icmp_id=0x{icmp_id:04X}"
                  f" | icmp_seq={icmp_seq}"
                  f" | stego={frag_seq + 1}/{total_frags}"
                  f" | fragment={data['message']!r}")

            if len(received) == total_frags:
                print()
                print(f"[OK] All {total_frags} fragment(s) received")
                continue

    print()
    print("-" * 60)
    print("REASSEMBLY")
    print("-" * 60)

    if not received:
        print("[ERROR] No fragments received")
    else:
        recovered = reassemble(list(received.values()))

        if recovered is not None:
            print(f"[OK] Message recovered: {recovered!r}")
        else:
            print("[ERROR] Reassembly failed")

    print("=" * 60)