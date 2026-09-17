"""
file_payload.py — Pack/unpack files into the message payload.

File payload format:
    [MAGIC : 4 bytes] [name_len : 2 bytes BE] [filename : name_len bytes] [data : rest]

MAGIC = b'\\x1bFIL'  — unlikely in ordinary text; used as a signature.

If the payload does not start with MAGIC, it is treated as a plain-text
message (backward-compatible mode).
"""
import os
import struct

FILE_MAGIC = b'\x1bFIL'   # 4 bytes
_HEADER_FMT = '>4sH'       # magic(4) + name_len(2) → 6 fixed bytes


def pack_file(filepath: str) -> bytes:
    """
    Read `filepath` in binary mode and return the full payload:
        MAGIC + name_len + filename + file_data
    """
    filename = os.path.basename(filepath)
    encoded_name = filename.encode('utf-8')

    if len(encoded_name) > 65535:
        raise ValueError("Filename too long (max 65535 bytes).")

    with open(filepath, 'rb') as fh:
        file_data = fh.read()

    header = struct.pack(_HEADER_FMT, FILE_MAGIC, len(encoded_name))
    return header + encoded_name + file_data


def unpack_payload(message: bytes):
    """
    Try to unpack a file payload.

    Returns:
        (filename: str, data: bytes)  — if it is a file payload
        (None, message)               — if it is a plain-text message
    """
    min_header = struct.calcsize(_HEADER_FMT)

    if len(message) < min_header:
        return None, message

    magic, name_len = struct.unpack_from(_HEADER_FMT, message)

    if magic != FILE_MAGIC:
        return None, message   # plain text

    offset   = min_header
    name_end = offset + name_len

    if name_end > len(message):
        return None, message   # corrupted — treat as text

    filename  = message[offset:name_end].decode('utf-8', errors='replace')
    file_data = message[name_end:]

    return filename, file_data


def payload_summary(message: bytes) -> str:
    """Return a human-readable string describing the payload (for logs)."""
    filename, data = unpack_payload(message)
    if filename is not None:
        return f"<file: {filename!r}, {len(data)} bytes>"
    try:
        return f"<text: {message.decode('utf-8')!r}>"
    except UnicodeDecodeError:
        return f"<binary: {len(message)} bytes>"
