"""
debug.py — Detailed inspection of the steganography protocol.

Usage:
    python debug.py
    python debug.py "another message"

The stego.py file remains without debug code.
"""

import sys
import os

import stego

from stego import (
    MAGIC_HEADER,
    MAGIC_START,
    HEADER_BYTES,
    START_BYTES,
    capacity,
    encode_message,
    encode,
    decode,
    read_bits,
    read_bytes,
)


# ============================================================
# VISUAL CONFIGURATION
# ============================================================

W = 90

RESET = "\033[0m"
BOLD = "\033[1m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
GRAY = "\033[90m"
WHITE = "\033[97m"


def color(text, code):
    return f"{code}{text}{RESET}"


def section(title):
    print()
    print(color("═" * W, CYAN))
    print(color(f"  {title}", BOLD + CYAN))
    print(color("═" * W, CYAN))


def subsection(title):
    print()
    print(color(f"--- {title} ---", BLUE))


def ok(text):
    print(f"  {color('✓', GREEN)} {text}")


def error(text):
    print(f"  {color('✗', RED)} {text}")


def warning(text):
    print(f"  {color('!', YELLOW)} {text}")


def info(text):
    print(f"     {text}")


# ============================================================
# FORMATTING
# ============================================================

def bits8(value):
    return f"{value:08b}"


def bits2(value):
    return f"{value:02b}"


def hex_bytes(data):
    return " ".join(f"{b:02X}" for b in data)


def safe_text(data):
    return "".join(
        chr(b) if 32 <= b <= 126 else "."
        for b in data
    )


# ============================================================
# PAYLOAD MAP
# ============================================================

def payload_map(payload, start, size):
    """
    Identifies the function of each carrier byte.

    H = Header
    M = Marker
    D = Data
    . = Unused
    """

    map_data = ["."] * len(payload)

    # Header
    for i in range(
        min(HEADER_BYTES, len(payload))
    ):
        map_data[i] = "H"

    # Marker
    if start is not None:
        for i in range(
            start,
            min(start + START_BYTES, len(payload))
        ):
            map_data[i] = "M"

        # Message
        msg_start = start + START_BYTES
        msg_end = msg_start + size * 4

        for i in range(
            msg_start,
            min(msg_end, len(payload))
        ):
            map_data[i] = "D"

    return map_data


def print_map(payload, start, size):
    map_data = payload_map(
        payload,
        start,
        size
    )

    cols = 16

    print()

    print("      ", end="")

    for i in range(cols):
        print(f"{i:02X} ", end="")

    print()

    print("     " + "─" * (cols * 3))

    for line in range(
        0,
        len(payload),
        cols
    ):
        print(f"  {line:02X} ", end="")

        for symbol in map_data[line:line + cols]:

            if symbol == "H":
                c = BLUE
            elif symbol == "M":
                c = GREEN
            elif symbol == "D":
                c = YELLOW
            else:
                c = GRAY

            print(
                color(symbol, c),
                end="  "
            )

        print()

    print()

    print(
        f"     {color('H', BLUE)} = Header"
    )

    print(
        f"     {color('M', GREEN)} = Marker"
    )

    print(
        f"     {color('D', YELLOW)} = Data"
    )

    print(
        f"     {color('.', GRAY)} = Unused"
    )


# ============================================================
# GENERAL INFORMATION
# ============================================================

def show_configuration(message, carrier):
    section("CONFIGURATION")

    info(
        f"MAGIC_HEADER : "
        f"0x{MAGIC_HEADER:04X}"
    )

    info(
        f"MAGIC_START : "
        f"0x{MAGIC_START:04X}"
    )

    info(
        f"HEADER_BYTES : "
        f"{HEADER_BYTES}"
    )

    info(
        f"START_BYTES : "
        f"{START_BYTES}"
    )

    info(
        f"Carrier      : "
        f"{len(carrier)} bytes"
    )

    info(
        f"Message      : "
        f"{len(message)} bytes"
    )

    info(
        f"Capacity     : "
        f"{capacity(carrier)} bytes/fragment"
    )

    print()

    print(
        f"Message: "
        f"{color(repr(message), MAGENTA)}"
    )

    print(
        f"Hex:     "
        f"{color(hex_bytes(message), CYAN)}"
    )


# ============================================================
# FRAGMENTATION
# ============================================================

def show_fragmentation(message, carrier):
    section("FRAGMENTATION")

    cap = capacity(carrier)

    if cap <= 0:
        raise ValueError(
            "Carrier has no capacity for message."
        )

    fragments = [
        message[i:i + cap]
        for i in range(
            0,
            len(message),
            cap
        )
    ]

    info(
        f"Capacity per fragment: "
        f"{cap} bytes"
    )

    info(
        f"Total message: "
        f"{len(message)} bytes"
    )

    info(
        f"Number of fragments: "
        f"{len(fragments)}"
    )

    print()

    for i, fragment in enumerate(fragments):

        print(
            f"  {color(f'[{i}]', CYAN)} "
            f"{len(fragment):3d} bytes  "
            f"{repr(fragment)}"
        )

        print(
            f"       HEX: "
            f"{hex_bytes(fragment)}"
        )

    return fragments


# ============================================================
# CHANGED BYTES
# ============================================================

def show_changed_bytes(original_carrier, payload):
    section("CHANGED BYTES")

    changed = []

    for i, (original, new) in enumerate(
        zip(original_carrier, payload)
    ):
        if original != new:
            changed.append(
                (i, original, new)
            )

    info(
        f"Original carrier : "
        f"{len(original_carrier)} bytes"
    )

    info(
        f"Payload          : "
        f"{len(payload)} bytes"
    )

    info(
        f"Changed bytes    : "
        f"{len(changed)}"
    )

    info(
        f"Intact bytes     : "
        f"{len(payload) - len(changed)}"
    )

    if not changed:
        warning("No bytes were changed.")
        return

    print()

    print(
        "  POS    ORIGINAL       PAYLOAD       XOR       "
        "LSB original   LSB new"
    )

    print(
        "  " + "─" * 78
    )

    for pos, original, new in changed:

        xor = original ^ new

        print(
            f"  {pos:04d}   "
            f"0x{original:02X} "
            f"{bits8(original)}   "
            f"0x{new:02X} "
            f"{bits8(new)}   "
            f"0x{xor:02X}   "
            f"{bits2(original & 0b11)}"
            f"            "
            f"{color(bits2(new & 0b11), YELLOW)}"
        )


# ============================================================
# COMPLETE PAYLOAD
# ============================================================

def show_payload(payload, original_carrier=None):
    section(
        f"COMPLETE PAYLOAD ({len(payload)} bytes)"
    )

    print()

    print(
        color(
            "HEX:",
            BOLD + CYAN
        )
    )

    print(
        hex_bytes(payload)
    )

    print()

    print(
        color(
            "TABLE:",
            BOLD + CYAN
        )
    )

    print()

    print(
        "  POS   HEX   BINARY      ASCII    LSB"
    )

    print(
        "  " + "─" * 43
    )

    for i, byte in enumerate(payload):

        ascii_char = (
            chr(byte)
            if 32 <= byte <= 126
            else "."
        )

        lsb = byte & 0b11

        changed = (
            original_carrier is not None
            and i < len(original_carrier)
            and original_carrier[i] != byte
        )

        if changed:
            c = YELLOW
        else:
            c = GRAY

        print(
            color(
                f"  {i:04d}  "
                f"{byte:02X}    "
                f"{byte:08b}      "
                f"{ascii_char!r}       "
                f"{lsb:02b}",
                c
            )
        )


# ============================================================
# HEADER
# ============================================================

def inspect_header(payload):
    section("HEADER")

    pos = 0

    magic, pos = read_bits(
        payload,
        pos,
        16
    )

    total, pos = read_bits(
        payload,
        pos,
        8
    )

    seq, pos = read_bits(
        payload,
        pos,
        8
    )

    size, pos = read_bits(
        payload,
        pos,
        8
    )

    print()

    info(
        f"Magic:   "
        f"0x{magic:04X}  "
        f"bits={bits8(magic >> 8)}"
        f"{bits8(magic & 0xFF)}"
    )

    info(
        f"Total:   {total}"
    )

    info(
        f"Seq:     {seq}"
    )

    info(
        f"Size: {size} bytes"
    )

    info(
        f"Next position: {pos}"
    )

    print()

    if magic == MAGIC_HEADER:
        ok(
            f"MAGIC_HEADER correct "
            f"(0x{MAGIC_HEADER:04X})"
        )
    else:
        error(
            f"Invalid MAGIC_HEADER. "
            f"Expected 0x{MAGIC_HEADER:04X}"
        )

    if total > 0:
        ok(f"Valid total: {total}")
    else:
        error("Invalid total")

    if seq < total:
        ok(f"Valid sequence: {seq}")
    else:
        error(
            f"Invalid sequence: "
            f"{seq} >= {total}"
        )

    if size > 0:
        ok(f"Valid size: {size}")
    else:
        error("Invalid size")

    return magic, total, seq, size


# ============================================================
# MARKER
# ============================================================

def inspect_marker(payload):
    section("START MARKER")

    start = None
    attempts = 0

    for p in range(
        HEADER_BYTES,
        len(payload) - START_BYTES + 1
    ):

        value, _ = read_bits(
            payload,
            p,
            16
        )

        attempts += 1

        if value == MAGIC_START:
            start = p
            break

    info(
        f"Search start: "
        f"{HEADER_BYTES}"
    )

    info(
        f"Positions checked: "
        f"{attempts}"
    )

    if start is None:

        error(
            "MAGIC_START not found."
        )

        return None

    ok(
        f"MAGIC_START found "
        f"at position {start}"
    )

    info(
        f"Value: "
        f"0x{MAGIC_START:04X}"
    )

    info(
        f"Carrier used: "
        f"{start} → "
        f"{start + START_BYTES - 1}"
    )

    info(
        f"Size: "
        f"{START_BYTES} bytes"
    )

    return start


# ============================================================
# MESSAGE
# ============================================================

def inspect_message(
    payload,
    start,
    size
):
    section("MESSAGE DATA")

    if start is None:
        error(
            "Cannot locate message."
        )
        return None

    msg_start = (
        start + START_BYTES
    )

    msg_end = (
        msg_start +
        size * 4 -
        1
    )

    info(
        f"Start in carrier: "
        f"{msg_start}"
    )

    info(
        f"End in carrier: "
        f"{msg_end}"
    )

    info(
        f"Carrier bytes used: "
        f"{size * 4}"
    )

    info(
        f"Actual message bytes: "
        f"{size}"
    )

    info(
        "Ratio: 1 message byte = "
        "4 carrier bytes"
    )

    if msg_end >= len(payload):
        error(
            "Message exceeds payload."
        )
        return None

    message, _ = read_bytes(
        payload,
        msg_start,
        size
    )

    print()

    info(
        f"Recovered message: "
        f"{repr(message)}"
    )

    info(
        f"HEX: "
        f"{hex_bytes(message)}"
    )

    info(
        f"ASCII: "
        f"{safe_text(message)}"
    )

    return message


# ============================================================
# LSBs
# ============================================================

def inspect_lsbs(
    payload,
    start,
    size
):
    section("CARRIER LSBs")

    map_data = payload_map(
        payload,
        start,
        size
    )

    print()

    print(
        "  POS    BYTE       BINARY       LSB    FUNCTION"
    )

    print(
        "  " + "─" * 58
    )

    for i, byte in enumerate(payload):

        function = map_data[i]

        if function == "H":
            c = BLUE
            name = "HEADER"
        elif function == "M":
            c = GREEN
            name = "MARKER"
        elif function == "D":
            c = YELLOW
            name = "DATA"
        else:
            c = GRAY
            name = "FREE"

        print(
            f"  {i:04d}   "
            f"0x{byte:02X}     "
            f"{byte:08b}      "
            f"{color(bits2(byte & 0b11), c)}    "
            f"{color(name, c)}"
        )


# ============================================================
# MESSAGE COMPARISON
# ============================================================

def compare_message(
    original,
    recovered
):
    section("FINAL COMPARISON")

    if recovered == original:

        ok("Message recovered correctly.")

        print()
        info(
            f"Original : {original!r}"
        )

        info(
            f"Received : {recovered!r}"
        )

        return True

    error(
        "Recovered message is different."
    )

    print()

    info(
        f"Original : {original!r}"
    )

    info(
        f"Received : {recovered!r}"
    )

    print()

    size = max(
        len(original),
        len(recovered or b"")
    )

    for i in range(size):

        a = (
            original[i]
            if i < len(original)
            else None
        )

        b = (
            recovered[i]
            if recovered is not None
            and i < len(recovered)
            else None
        )

        if a != b:

            print(
                f"  position {i}: "
                f"{color(str(a), RED)} → "
                f"{color(str(b), RED)}"
            )

    return False


# ============================================================
# INSPECT A PAYLOAD
# ============================================================

def inspect_payload(
    payload,
    original_carrier,
    index
):
    print()

    print(
        color(
            "╔" + "═" * (W - 2) + "╗",
            MAGENTA
        )
    )

    title = (
        f" PAYLOAD {index} "
        f"({len(payload)} bytes) "
    )

    print(
        color(
            "║" +
            title.center(W - 2) +
            "║",
            MAGENTA + BOLD
        )
    )

    print(
        color(
            "╚" + "═" * (W - 2) + "╝",
            MAGENTA
        )
    )

    # Header
    (
        magic,
        total,
        seq,
        size
    ) = inspect_header(payload)

    if magic != MAGIC_HEADER:
        error(
            "Invalid payload due to MAGIC_HEADER."
        )
        return None

    # Marker
    start = inspect_marker(
        payload
    )

    # Message
    message = inspect_message(
        payload,
        start,
        size
    )

    # Map
    section("CARRIER MAP")

    if start is not None:
        print_map(
            payload,
            start,
            size
        )

    # LSBs
    inspect_lsbs(
        payload,
        start,
        size
    )

    # Changed bytes
    show_changed_bytes(
        original_carrier,
        payload
    )

    # Payload
    show_payload(
        payload,
        original_carrier
    )

    # API result
    section("DECODING VIA STEGO.PY")

    result = decode(payload)

    if result is None:

        error(
            "stego.decode() returned None."
        )

        return None

    ok("Payload accepted by protocol.")

    info(
        f"seq     = {result['seq']}"
    )

    info(
        f"total   = {result['total']}"
    )

    info(
        f"message = {result['message']!r}"
    )

    return result


# ============================================================
# REASSEMBLY
# ============================================================

def test_reassembly(
    payloads,
    original_message
):
    section("REASSEMBLY OUT OF ORDER")

    indices = list(
        range(len(payloads))
    )

    indices.reverse()

    info(
        f"Original order: "
        f"{list(range(len(payloads)))}"
    )

    info(
        f"Tested order:  "
        f"{indices}"
    )

    print()

    fragments = {}
    total = None

    for index in indices:

        result = decode(
            payloads[index]
        )

        if result is None:

            error(
                f"Payload {index}: "
                f"decoding failure"
            )

            continue

        seq = result["seq"]

        if total is None:
            total = result["total"]

        fragments[seq] = result[
            "message"
        ]

        info(
            f"Payload {index} → "
            f"seq={seq} "
            f"({len(fragments)}/{total})"
        )

    print()

    if total is None:
        error("No valid fragments.")
        return None

    if len(fragments) != total:

        error(
            f"Incomplete reassembly: "
            f"{len(fragments)}/{total}"
        )

        return None

    recovered = b"".join(
        fragments[i]
        for i in range(total)
    )

    ok(
        "All fragments were found."
    )

    compare_message(
        original_message,
        recovered
    )

    return recovered


# ============================================================
# INDIVIDUAL ENCODING TEST
# ============================================================

def test_individual_encoding(
    carrier
):
    section("INDIVIDUAL ENCODING TEST")

    message = b"ABC"

    info(
        f"Test message: "
        f"{message!r}"
    )

    payload = encode(
        carrier,
        message,
        seq=0,
        total=1
    )

    ok(
        f"Payload created: "
        f"{len(payload)} bytes"
    )

    result = decode(
        payload
    )

    if result is None:

        error(
            "Failed to decode payload."
        )

        return

    if result["message"] == message:

        ok(
            "Individual encoding "
            "works correctly."
        )

    else:

        error(
            "Individual message "
            "was not recovered."
        )


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # Message
    # --------------------------------------------------------

    if len(sys.argv) > 1:
        message = sys.argv[1].encode()
    else:
        message = (
            b"Hello, World!"
        )

    # Uses the carrier defined in stego.py
    if stego.CARRIER is not None:
        carrier = stego.CARRIER
    else:
        carrier = os.urandom(
            stego.CARRIER_SIZE
        )

    print()
    print(
        color(
            "╔" + "═" * (W - 2) + "╗",
            CYAN
        )
    )

    print(
        color(
            "║" +
            " DEBUG OF STEGANOGRAPHY PROTOCOL ".center(W - 2) +
            "║",
            CYAN + BOLD
        )
    )

    print(
        color(
            "╚" + "═" * (W - 2) + "╝",
            CYAN
        )
    )

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    show_configuration(
        message,
        carrier
    )

    # --------------------------------------------------------
    # Basic test
    # --------------------------------------------------------

    test_individual_encoding(
        carrier
    )

    # --------------------------------------------------------
    # Fragmentation
    # --------------------------------------------------------

    show_fragmentation(
        message,
        carrier
    )

    # --------------------------------------------------------
    # Encoding
    # --------------------------------------------------------

    section("MESSAGE ENCODING")

    payloads = encode_message(
        message,
        carrier
    )

    ok(
        f"{len(payloads)} payload(s) generated"
    )

    # --------------------------------------------------------
    # Inspects each payload
    # --------------------------------------------------------

    for seq, payload in enumerate(
        payloads
    ):

        inspect_payload(
            payload,
            carrier,
            seq
        )

    # --------------------------------------------------------
    # Reassembly
    # --------------------------------------------------------

    test_reassembly(
        payloads,
        message
    )

    # --------------------------------------------------------
    # Final
    # --------------------------------------------------------

    print()

    print(
        color(
            "═" * W,
            GREEN
        )
    )

    print(
        color(
            "  DEBUG COMPLETED",
            GREEN + BOLD
        )
    )

    print(
        color(
            "═" * W,
            GREEN
        )
    )


if __name__ == "__main__":
    main()
