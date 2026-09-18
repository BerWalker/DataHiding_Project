import os
import socket
import sys

from icmp         import ICMP_ECHO_REPLY, create_socket, parse_icmp
from stego        import decode, reassemble
from file_payload import unpack_payload, payload_summary

# ============================================================
# CONFIGURATION
# ============================================================

HOST       = "0.0.0.0"
TIMEOUT    = int(os.environ.get("TIMEOUT",    "30"))   # seconds without a new packet
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/output")    # directory to save files


# ============================================================
# HELPERS
# ============================================================

def save_file(output_dir: str, filename: str, data: bytes) -> str:
    """
    Save `data` to `output_dir/filename`.
    If the file already exists, append a numeric suffix to avoid overwriting.
    Return the full path where it was saved.
    """
    os.makedirs(output_dir, exist_ok=True)

    base, ext   = os.path.splitext(filename)
    dest        = os.path.join(output_dir, filename)
    counter     = 1

    while os.path.exists(dest):
        dest = os.path.join(output_dir, f"{base}_{counter}{ext}")
        counter += 1

    with open(dest, 'wb') as fh:
        fh.write(data)

    return dest


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    received    = {}    # seq → raw stego carrier bytes
    total_frags = None

    print("=" * 60)
    print("SERVER — WAITING FOR FRAGMENTS")
    print("=" * 60)
    print(f"Listening on  {HOST}  (timeout: {TIMEOUT}s without packets)")
    print(f"Output directory: {OUTPUT_DIR}")
    print()

    with create_socket() as s:
        s.bind((HOST, 0))
        s.settimeout(TIMEOUT)

        while True:
            try:
                raw, addr = s.recvfrom(65535)
            except socket.timeout:
                print("[TIMEOUT] No more packets — ending reception")
                break

            icmp = parse_icmp(raw)
            if icmp is None:
                continue

            # Only process Echo Replies (type 0)
            if icmp["type"] != ICMP_ECHO_REPLY:
                continue

            stego_payload = icmp["payload"]
            data          = decode(stego_payload)

            # Drop packets that do not contain a valid stego payload
            if data is None:
                continue

            frag_seq = data["seq"]

            # Drop duplicates
            if frag_seq in received:
                continue

            received[frag_seq] = stego_payload
            total_frags        = data["total"]

            pct = len(received) / total_frags * 100
            print(f"  [RECV  {len(received):>5}/{total_frags}  {pct:5.1f}%]"
                  f"  from={addr[0]}"
                  f"  |  icmp_id=0x{icmp['icmp_id']:04X}"
                  f"  |  stego={frag_seq + 1}/{total_frags}"
                  f"  |  frag={data['message'][:16]!r}"
                  f"{'...' if len(data['message']) > 16 else ''}")

            if len(received) == total_frags:
                print()
                print(f"[OK] All {total_frags} fragment(s) received — waiting for timeout...")

    # ── Reassembly ────────────────────────────────────────────
    print()
    print("-" * 60)
    print("REASSEMBLY")
    print("-" * 60)

    if not received:
        print("[ERROR] No fragments received")
        sys.exit(1)

    recovered = reassemble(list(received.values()))

    if recovered is None:
        print("[ERROR] Reassembly failed — fragments corrupted or missing")
        sys.exit(1)

    print(f"[OK] {len(recovered)} bytes reassembled")
    print(f"     Payload: {payload_summary(recovered)}")
    print()

    # ── Detection: file or text? ──────────────────────────────
    filename, file_data = unpack_payload(recovered)

    if filename is not None:
        # ── File mode ─────────────────────────────────────────
        dest = save_file(OUTPUT_DIR, filename, file_data)
        size_kb = len(file_data) / 1024
        print(f"[FILE] {filename!r}  ({size_kb:.2f} KB) saved to:")
        print(f"       {dest}")
    else:
        # ── Text mode (backward compatible) ───────────────────
        try:
            text = file_data.decode("utf-8")
            print(f"[TEXT] {text!r}")
        except UnicodeDecodeError:
            print(f"[BINARY] {len(file_data)} bytes  —  {file_data!r}")

    print()
    print("=" * 60)
