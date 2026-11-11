"""Synthetic fixture builders. No real mod content is used anywhere in the tests."""

from __future__ import annotations

import json
import struct
import zipfile
import zlib
from pathlib import Path

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def make_zip(path: Path, files: dict[str, bytes | str]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return path


def make_dbpf(resources: list[tuple[int, int, int, int, bytes]] | None = None) -> bytes:
    resources = resources if resources is not None else [(1, 2, 3, 4, b"payload")]
    count = len(resources)
    index_size = 4 + count * 32
    body = b"".join(r[4] for r in resources)
    data_start = 96
    index_pos = data_start + len(body)
    header = bytearray(96)
    header[:4] = b"DBPF"
    struct.pack_into("<II", header, 4, 2, 1)
    struct.pack_into("<I", header, 36, count)
    struct.pack_into("<I", header, 44, index_size)
    struct.pack_into("<I", header, 64, index_pos)
    index = bytearray(struct.pack("<I", 0))
    offset = data_start
    for rtype, group, hi, lo, payload in resources:
        index += struct.pack(
            "<IIIIIIIHH",
            rtype,
            group,
            hi,
            lo,
            offset,
            len(payload) | 0x80000000,
            len(payload),
            0,
            1,
        )
        offset += len(payload)
    return bytes(header) + body + bytes(index)


def png_chunk(ctype: bytes, body: bytes) -> bytes:
    crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
    return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)


def make_png(text: dict[str, str] | None = None, extra: list[bytes] | None = None) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    out = PNG_MAGIC + png_chunk(b"IHDR", ihdr)
    for k, v in (text or {}).items():
        out += png_chunk(b"tEXt", k.encode("latin-1") + b"\x00" + v.encode("latin-1"))
    for chunk in extra or []:
        out += chunk
    out += png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
    return out + png_chunk(b"IEND", b"")


def inzoi_manifest(**overrides: object) -> bytes:
    data: dict[str, object] = {
        "FriendlyName": "Sample",
        "ProjectName": "SampleMod",
        "Author": "Tester",
        "Version": "1.0.0",
        "Description": "A synthetic test manifest.",
        "Dependencies": [],
        "FileChecksums": [],
        "bEnable": True,
    }
    data.update(overrides)
    return b"\xef\xbb\xbf" + json.dumps(data).encode("utf-8")


def write_tree(root: Path, files: dict[str, bytes | str]) -> Path:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)
    return root
