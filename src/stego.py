import random

# ============================================================
# CONFIGURATION
# ============================================================

MAGIC_HEADER = 0xABCD
MAGIC_START  = 0xD3A7

# Header layout (each bit-pair occupies 1 byte of the carrier):
#
#   Field         bits   carrier bytes
#   ──────────────────────────────────
#   MAGIC_HEADER   16        8
#   total          16        8   ← extended from 8 to support files
#   seq            16        8   ← extended from 8 to support files
#   size            8        4   ← unchanged (max 255 B; carrier cap is 3 B)
#   ──────────────────────────────────
#   Total                   28
#
HEADER_BYTES = 28
START_BYTES  = 8


# ============================================================
# BITS
# ============================================================

def write_bits(carrier, pos, value, bits):
    """Hide `value` (`bits` bits) in the 2 LSBs of each carrier byte."""
    for word in range(bits // 2):
        carrier[pos + word] = (carrier[pos + word] & 0b11111100) | (value & 0b11)
        value >>= 2
    return pos + bits // 2


def read_bits(carrier, pos, bits):
    """Recover `bits` bits from the 2 LSBs of each carrier byte."""
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
    """Payload bytes that fit in a single carrier fragment."""
    available = len(carrier) - HEADER_BYTES - START_BYTES
    return max(0, available // 4)


# ============================================================
# ENCODING
# ============================================================

def encode(carrier, message, seq, total):
    """
    Hide the `message` fragment inside a copy of `carrier`.

    Header (always at the start):
        MAGIC_HEADER  – 16 bits
        total         – 16 bits  (up to 65 535 fragments)
        seq           – 16 bits  (0-based index)
        size          –  8 bits  (bytes in this fragment)

    Marker + payload (random position after the header):
        MAGIC_START   – 16 bits
        <message bytes>
    """
    buf = bytearray(carrier)

    pos = write_bits(buf, 0,   MAGIC_HEADER,  16)
    pos = write_bits(buf, pos, total,          16)
    pos = write_bits(buf, pos, seq,            16)
    write_bits(buf,       pos, len(message),    8)

    max_start = len(buf) - START_BYTES - len(message) * 4
    start = random.randint(HEADER_BYTES, max_start)

    write_bits(buf, start, MAGIC_START, 16)
    hide_bytes(buf, start + START_BYTES, message)

    return bytes(buf)


# ============================================================
# DECODING
# ============================================================

def decode(carrier):
    """
    Extract a hidden fragment from `carrier`.

    Returns dict { "seq": int, "total": int, "message": bytes }
    or None if the carrier does not contain a valid stego payload.
    """
    if len(carrier) < HEADER_BYTES:
        return None

    magic, pos = read_bits(carrier, 0,   16)
    total, pos = read_bits(carrier, pos, 16)
    seq,   pos = read_bits(carrier, pos, 16)
    size,  pos = read_bits(carrier, pos,  8)

    if magic != MAGIC_HEADER:
        return None

    if total == 0 or seq >= total or size == 0:
        return None

    start = None
    for p in range(HEADER_BYTES, len(carrier) - START_BYTES + 1):
        marker, _ = read_bits(carrier, p, 16)
        if marker == MAGIC_START:
            start = p
            break

    if start is None:
        return None

    pos = start + START_BYTES
    if pos + size * 4 > len(carrier):
        return None

    message, _ = read_bytes(carrier, pos, size)

    return {"seq": seq, "total": total, "message": message}


# ============================================================
# FRAGMENTATION
# ============================================================

def encode_message(message, carrier):
    """
    Split `message` into fragments that fit in the carrier and encode them.
    Returns a list of payloads ready to send (one per fragment).
    """
    cap = capacity(carrier)
    if cap == 0:
        raise ValueError(
            f"Carrier too small ({len(carrier)} B) — "
            f"needs at least {HEADER_BYTES + START_BYTES + 4} bytes."
        )

    fragments = [message[i:i + cap] for i in range(0, len(message), cap)]
    total     = len(fragments)

    if total > 65535:
        raise ValueError(
            f"Message too large: requires {total} fragments (max 65535). "
            f"A {len(carrier)} B carrier supports up to "
            f"{cap * 65535 // 1024} KB."
        )

    return [encode(carrier, frag, seq, total) for seq, frag in enumerate(fragments)]


# ============================================================
# REASSEMBLY
# ============================================================

def reassemble(payloads):
    """
    Decode each payload and rebuild the original message in order.
    Returns bytes or None if any fragment is missing or corrupted.
    """
    fragments = {}
    total     = None

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
