import os
import socket

from icmp import ICMP_ECHO_REQUEST, cria_socket, parse_icmp
from stego import decode, reassemble

# ============================================================
# CONFIGURATION
# ============================================================

HOST    = "0.0.0.0"
TIMEOUT = int(os.environ.get("TIMEOUT", "10"))  # seconds without a new packet before giving up


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

    with cria_socket() as s:
        s.bind((HOST, 0))
        s.settimeout(TIMEOUT)

        while True:
            try:
                dados, addr = s.recvfrom(65535)
            except socket.timeout:
                print("[TIMEOUT] No more packets received")
                break

            icmp = parse_icmp(dados)
            if icmp is None:
                continue

            # Only process Echo Requests (type 8)
            if icmp["tipo"] != ICMP_ECHO_REQUEST:
                continue

            stego_payload = icmp["payload"]
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
                  f" | icmp_id=0x{icmp['icmp_id']:04X}"
                  f" | icmp_seq={icmp['icmp_seq']}"
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
