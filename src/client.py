import os

from icmp import ICMP_ID, cria_icmp, cria_socket
from stego import capacity, encode_message, decode

# ============================================================
# CONFIGURATION
# ============================================================

SERVER_HOST  = os.environ.get("SERVER_HOST", "127.0.0.1")

MESSAGE      = b"Hello, World!"
CARRIER      = b"\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037 !\"#$%&'()*+,-./01234567"
CARRIER_SIZE = 80  # Only used if CARRIER is None


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    carrier = CARRIER or os.urandom(CARRIER_SIZE)

    print("=" * 60)
    print("CLIENT — ENCODING")
    print("=" * 60)
    print(f"Carrier:     {len(carrier)} bytes")
    print(f"Capacity:    {capacity(carrier)} bytes/fragment")
    print(f"Message:     {MESSAGE!r}")
    print(f"Size:        {len(MESSAGE)} bytes")
    print(f"ICMP ID:     0x{ICMP_ID:04X}")
    print()
    print("Original carrier:")
    print(f"  HEX:   {carrier.hex(' ')}")
    print(f"  ASCII: {''.join(chr(b) if 32 <= b <= 126 else '.' for b in carrier)}")

    payloads = encode_message(MESSAGE, carrier)
    total    = len(payloads)

    print()
    print(f"Fragments: {total}")
    print()

    with cria_socket() as s:
        s.bind(("0.0.0.0", 0))

        for seq, payload in enumerate(payloads):
            pacote = cria_icmp(payload, seq)
            s.sendto(pacote, (SERVER_HOST, 0))
            data = decode(payload)
            print(f"  [{seq + 1}/{total}] Echo Request → {SERVER_HOST}"
                  f" | {len(pacote)} bytes"
                  f" | icmp_seq={seq}"
                  f" | stego_seq={data['seq']}/{data['total']}"
                  f" | fragment={data['message']!r}")

    print()
    print("[OK] All fragments sent")
    print("=" * 60)
