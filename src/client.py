import os
import sys

from icmp         import ICMP_ID, create_icmp, create_socket
from stego        import capacity, encode_message, decode
from file_payload import pack_file, payload_summary

# ============================================================
# CONFIGURATION
# ============================================================

SERVER_HOST = os.environ.get("SERVER_HOST", "127.0.0.1")

# Fixed original carrier — the entire file is hidden in it,
# split across multiple ICMP packets.
CARRIER = b"\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037 !\"#$%&'()*+,-./01234567"

# Modo arquivo:  defina FILE_PATH com o caminho do arquivo a enviar.
# Modo texto:    deixe FILE_PATH vazio e defina MESSAGE (retrocompatível).
FILE_PATH    = os.environ.get("FILE_PATH",  "")
MESSAGE_TEXT = os.environ.get("MESSAGE",    "Hello, World!")


# ============================================================
# HELPERS
# ============================================================

def build_message() -> bytes:
    """
    Return the payload to hide:
      - If FILE_PATH is set, read the file in binary mode and pack it
        with the filename in the header.
      - Otherwise, use MESSAGE_TEXT as text (original mode).
    """
    if FILE_PATH:
        if not os.path.isfile(FILE_PATH):
            print(f"[ERROR] File not found: {FILE_PATH!r}", file=sys.stderr)
            sys.exit(1)
        print(f"[FILE] Reading {FILE_PATH!r} in binary mode...")
        return pack_file(FILE_PATH)
    else:
        return MESSAGE_TEXT.encode("utf-8")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    message = build_message()

    print("=" * 60)
    print("CLIENT — ENCODING")
    print("=" * 60)
    print(f"Server:      {SERVER_HOST}")
    print(f"Carrier:     {len(CARRIER)} bytes (fixed)")
    print(f"  HEX:   {CARRIER.hex(' ')}")
    print(f"  ASCII: {''.join(chr(b) if 32 <= b <= 126 else '.' for b in CARRIER)}")
    print(f"Capacity:    {capacity(CARRIER)} bytes/fragment")
    print(f"Payload:     {payload_summary(message)}")
    print(f"Size:        {len(message)} bytes")
    print(f"ICMP ID:     0x{ICMP_ID:04X}")

    # ── Fragmentation + encoding ──────────────────────────────
    try:
        payloads = encode_message(message, CARRIER)
    except ValueError as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    total = len(payloads)
    print(f"Fragments:   {total}")
    print()

    # ── Send ──────────────────────────────────────────────────
    with create_socket() as s:
        s.bind(("0.0.0.0", 0))

        for seq, payload in enumerate(payloads):
            packet = create_icmp(payload, seq)
            s.sendto(packet, (SERVER_HOST, 0))
            data = decode(payload)

            pct = (seq + 1) / total * 100
            print(f"  [{seq + 1:>6}/{total}  {pct:5.1f}%]"
                  f"  → {SERVER_HOST}"
                  f"  |  {len(packet)} B/packet"
                  f"  |  stego={data['seq']}/{data['total']}"
                  f"  |  frag={data['message']!r}")

    print()
    print(f"[OK] {total} fragment(s) sent  —  {len(message)} bytes total")
    print("=" * 60)
