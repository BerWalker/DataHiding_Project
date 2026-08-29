import os
import random

# ============================================================
# CONFIGURATION
# ============================================================

MAGIC_HEADER = 0xABCD
MAGIC_START = 0xD3A7

HEADER_BYTES = 20
START_BYTES = 8

MESSAGE = b"Hello, World!"

CARRIER = b"\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037 !\"#$%&'()*+,-./01234567" # None for random carrier 
CARRIER_SIZE = 80 # Only used if CARRIER is None


# ============================================================
# BITS
# ============================================================

def write_bits(carrier, pos, value, bits):
    for word in range(bits // 2):
        carrier[pos + word] = (carrier[pos + word] & 0b11111100) | (value & 0b11)
        value >>= 2

    return pos + bits // 2


def read_bits(carrier, pos, bits):
    value = 0

    for word in range(bits // 2):
        recovered_bits = carrier[pos + word] & 0b11
        value |= recovered_bits << (word * 2)

    return value, pos + bits // 2


def hide_bytes(carrier, pos, data):
    for byte in data:
        pos = write_bits(carrier, pos, byte, 8)

    return pos


def read_bytes(carrier, pos, amount):
    data = bytearray()

    for _ in range(amount):
        byte, pos = read_bits(carrier, pos, 8)
        data.append(byte)

    return bytes(data), pos


# ============================================================
# CAPACITY
# ============================================================

def capacity(carrier):
    """Returns how many bytes of message fit in the carrier."""
    available = len(carrier) - HEADER_BYTES - START_BYTES
    return max(0, available // 4)


# ============================================================
# ENCODING
# ============================================================

def encode(carrier, message, seq, total):
    buf = bytearray(carrier)

    # Header
    pos = write_bits(buf, 0, MAGIC_HEADER, 16)
    pos = write_bits(buf, pos, total, 8)
    pos = write_bits(buf, pos, seq, 8)
    write_bits(buf, pos, len(message), 8)

    # Choose where the marker will be
    max_start = len(buf) - START_BYTES - len(message) * 4
    start = random.randint(HEADER_BYTES, max_start)

    # Marker + message
    write_bits(buf, start, MAGIC_START, 16)
    hide_bytes(buf, start + START_BYTES, message)

    return bytes(buf)


# ============================================================
# DECODING
# ============================================================

def decode(carrier):
    if len(carrier) < HEADER_BYTES:
        return None

    # Read header
    magic, pos = read_bits(carrier, 0, 16)
    total, pos = read_bits(carrier, pos, 8)
    seq, pos = read_bits(carrier, pos, 8)
    size, pos = read_bits(carrier, pos, 8)

    # Validation
    if magic != MAGIC_HEADER:
        return None

    if total == 0 or seq >= total or size == 0:
        return None

    # Find the marker
    start = None

    for p in range(HEADER_BYTES, len(carrier) - START_BYTES + 1):
        marker, _ = read_bits(carrier, p, 16)

        if marker == MAGIC_START:
            start = p
            break

    if start is None:
        return None

    # Verify if message fits
    pos = start + START_BYTES

    if pos + size * 4 > len(carrier):
        return None

    message, _ = read_bytes(carrier, pos, size)

    return {
        "seq": seq,
        "total": total,
        "message": message
    }


# ============================================================
# FRAGMENTATION
# ============================================================

def encode_message(message, carrier):
    cap = capacity(carrier)

    fragments = [
        message[i:i + cap]
        for i in range(0, len(message), cap)
    ]

    total = len(fragments)

    return [
        encode(carrier, fragment, seq, total)
        for seq, fragment in enumerate(fragments)
    ]


# ============================================================
# REASSEMBLY
# ============================================================

def reassemble(payloads):
    fragments = {}
    total = None

    for payload in payloads:
        data = decode(payload)

        if data is None:
            return None

        if total is None:
            total = data["total"]
        elif data["total"] != total:
            return None

        fragments[data["seq"]] = data["message"]

    if total is None or len(fragments) != total:
        return None

    return b"".join(fragments[i] for i in range(total))


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    carrier = CARRIER or os.urandom(CARRIER_SIZE)

    print("=" * 60)
    print("STEGANOGRAPHY")
    print("=" * 60)

    print(f"Carrier:     {len(carrier)} bytes")
    print(f"Capacity:    {capacity(carrier)} bytes/fragment")
    print(f"Message:     {MESSAGE!r}")
    print(f"Size:        {len(MESSAGE)} bytes")

    # Original carrier
    print()
    print("Original carrier:")
    print(f"  HEX:   {carrier.hex(' ')}")
    print(f"  ASCII: {''.join(chr(b) if 32 <= b <= 126 else '.' for b in carrier)}")

    # Encoding
    payloads = encode_message(MESSAGE, carrier)

    print()
    print(f"Fragments: {len(payloads)}")

    for i, payload in enumerate(payloads):

        data = decode(payload)

        print()
        print("-" * 60)
        print(f"FRAGMENT {i}")
        print("-" * 60)

        if data is None:
            print("[ERROR] Invalid payload")
            continue

        print(f"Magic:       0x{MAGIC_HEADER:04X}")
        print(f"Total:       {data['total']}")
        print(f"Seq:         {data['seq']}")
        print(f"Size:        {len(data['message'])} bytes")
        print(f"Message:     {data['message']!r}")

        print()
        print("Payload:")
        print(f"  HEX:   {payload.hex(' ')}")

    # Reassembly out of order
    print()
    print("-" * 60)
    print("REASSEMBLY")
    print("-" * 60)

    recovered = reassemble(payloads[::-1])

    if recovered == MESSAGE:
        print("[OK] Message recovered correctly")
        print(f"     {recovered!r}")
    else:
        print("[ERROR] Different message")
        print(f"     Expected: {MESSAGE!r}")
        print(f"     Received: {recovered!r}")

    print("=" * 60)

