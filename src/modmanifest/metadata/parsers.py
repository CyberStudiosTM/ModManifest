"""Bounded, read-only parsers for image metadata containers (PNG, JPEG, EXIF, XMP)."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_CHUNKS = 5000
MAX_TEXT = 256 * 1024


@dataclass(slots=True)
class ImageMeta:
    text: list[tuple[str, str]] = field(default_factory=list)  # PNG text (key, value)
    exif: dict[str, str] = field(default_factory=dict)
    xmp_blobs: list[bytes] = field(default_factory=list)
    c2pa_marker: bool = False


def _inflate(data: bytes) -> str:
    try:
        out = zlib.decompressobj().decompress(data, MAX_TEXT)
    except zlib.error:
        return ""
    return out.decode("utf-8", "replace")


def parse_png(data: bytes) -> ImageMeta:
    meta = ImageMeta()
    pos, n = 8, len(data)
    for _ in range(MAX_CHUNKS):
        if pos + 8 > n:
            break
        length, ctype = struct.unpack_from(">I4s", data, pos)
        body = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if ctype == b"caBX":
            meta.c2pa_marker = True
        elif ctype == b"tEXt" and b"\x00" in body:
            key, _, val = body.partition(b"\x00")
            meta.text.append((key.decode("latin-1"), val[:MAX_TEXT].decode("latin-1")))
        elif ctype == b"zTXt" and b"\x00" in body:
            key, _, rest = body.partition(b"\x00")
            meta.text.append((key.decode("latin-1"), _inflate(rest[1:])))
        elif ctype == b"iTXt" and b"\x00" in body:
            key, _, rest = body.partition(b"\x00")
            if len(rest) >= 2:
                compressed = rest[0] == 1
                parts = rest[2:].split(b"\x00", 2)
                if len(parts) == 3:
                    raw = parts[2]
                    text = (
                        _inflate(raw) if compressed else raw[:MAX_TEXT].decode("utf-8", "replace")
                    )
                    if key == b"XML:com.adobe.xmp":
                        meta.xmp_blobs.append(text.encode("utf-8"))
                    else:
                        meta.text.append((key.decode("latin-1"), text))
        elif ctype == b"IEND":
            break
    return meta


def parse_jpeg(data: bytes) -> ImageMeta:
    meta = ImageMeta()
    pos, n = 2, len(data)
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker in (0xDA, 0xD9):
            break
        (length,) = struct.unpack_from(">H", data, pos + 2)
        body = data[pos + 4 : pos + 2 + length]
        pos += 2 + length
        if length < 2:
            break
        if marker == 0xE1 and body.startswith(b"Exif\x00\x00"):
            meta.exif.update(parse_exif(body[6:]))
        elif marker == 0xE1 and body.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
            meta.xmp_blobs.append(body[29:][:MAX_TEXT])
        elif marker == 0xEB and body[:2] == b"JP" and b"c2pa" in body[:64]:
            meta.c2pa_marker = True
    return meta


_EXIF_TAGS = {0x0131: "Software", 0x010E: "ImageDescription"}


def parse_exif(tiff: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return out
    fmt = "<" if tiff[:2] == b"II" else ">"
    try:
        (ifd,) = struct.unpack_from(fmt + "I", tiff, 4)
        if ifd + 2 > len(tiff):
            return out
        (count,) = struct.unpack_from(fmt + "H", tiff, ifd)
        for i in range(min(count, 256)):
            off = ifd + 2 + i * 12
            if off + 12 > len(tiff):
                break
            tag, typ, cnt, val = struct.unpack_from(fmt + "HHII", tiff, off)
            if tag not in _EXIF_TAGS or typ != 2 or cnt > 4096:
                continue
            if cnt <= 4:
                raw = tiff[off + 8 : off + 8 + cnt]
            else:
                if val + cnt > len(tiff):
                    continue
                raw = tiff[val : val + cnt]
            out[_EXIF_TAGS[tag]] = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    except struct.error:
        return out
    return out


def parse_xmp(blob: bytes) -> dict[str, list[str]] | None:
    """Return {local property name: values} for properties of interest; None if unparseable."""
    start = blob.find(b"<")
    if start < 0:
        return None
    try:
        root = SafeET.fromstring(blob[start:], forbid_dtd=True)
    except (SafeET.ParseError, DefusedXmlException, ValueError):
        return None
    wanted = {"DigitalSourceType", "CreatorTool", "softwareAgent", "AISystemUsed"}
    found: dict[str, list[str]] = {}

    def local(name: str) -> str:
        return name.rsplit("}", 1)[-1]

    for el in root.iter():
        name = local(el.tag)
        if name in wanted:
            text = (el.text or "").strip()
            if text:
                found.setdefault(name, []).append(text)
            for k, v in el.attrib.items():
                if local(k) == "resource":
                    found.setdefault(name, []).append(v)
        for k, v in el.attrib.items():
            lk = local(k)
            if lk in wanted:
                found.setdefault(lk, []).append(v)
    return found
