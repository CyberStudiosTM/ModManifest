from __future__ import annotations

import json
import struct
from pathlib import Path

from modmanifest.inspector import run
from modmanifest.models import AI_NONE_FOUND, Report

from .helpers import make_png, make_zip, png_chunk, write_tree


def cats(report: Report) -> list[tuple[str, str]]:
    return [(a.code, a.category.value) for a in report.ai_findings]


def test_no_indicators_wording(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a/readme.txt": "A cozy rug set."})
    data = run("audit-ai", str(tmp_path / "a")).to_dict()
    assert data["ai_metadata"]["summary"] == AI_NONE_FOUND
    assert "absent" in data["ai_metadata"]["note"]
    assert "free" not in json.dumps(data).lower().replace("freeform", "")


def test_explicit_boolean_and_polarity(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a/mod_manifest.json": '{"AIGenerated": true}'})
    report = run("audit-ai", str(tmp_path / "a"))
    assert cats(report) == [("MM-AI-001", "explicit_declaration")]
    assert report.ai_findings[0].polarity == "affirmative"
    write_tree(tmp_path, {"b/mod_manifest.json": '{"ai_generated": false}'})
    neg = run("audit-ai", str(tmp_path / "b"))
    assert neg.ai_findings[0].polarity == "negative"


def test_tool_reference_vs_ambiguous(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a/mod_manifest.json": '{"Generator": "ComfyUI 1.2"}'})
    assert cats(run("audit-ai", str(tmp_path / "a"))) == [("MM-AI-003", "tool_reference")]
    write_tree(tmp_path, {"b/mod_manifest.json": '{"Generator": "Firefly"}'})
    assert cats(run("audit-ai", str(tmp_path / "b"))) == [("MM-AI-003", "ambiguous_indicator")]


def test_free_text_is_only_ambiguous(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a/mod_manifest.json": '{"Description": "textures are AI generated"}'})
    report = run("audit-ai", str(tmp_path / "a"))
    assert cats(report) == [("MM-AI-004", "ambiguous_indicator")]
    assert report.ai_findings[0].confidence == "low"


def test_png_generation_record_without_copying_text(tmp_path: Path) -> None:
    secret = "a secret prompt about cats"
    value = f"{secret}\nSteps: 20, Sampler: Euler a, CFG scale: 7"
    write_tree(tmp_path, {"a/pic.png": make_png({"parameters": value})})
    report = run("audit-ai", str(tmp_path / "a"))
    assert cats(report) == [("MM-AI-010", "explicit_declaration")]
    assert secret not in json.dumps(report.to_dict())


def test_png_workflow_and_tool_chunk(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "a/w.png": make_png({"prompt": '{"3": {"class_type": "KSampler"}}'}),
            "a/i.png": make_png({"invokeai_metadata": "{}"}),
        },
    )
    codes = {a.code for a in run("audit-ai", str(tmp_path / "a")).ai_findings}
    assert codes == {"MM-AI-011", "MM-AI-013"}


def test_png_software_chunk(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a/s.png": make_png({"Software": "Midjourney"})})
    assert cats(run("audit-ai", str(tmp_path / "a"))) == [("MM-AI-012", "tool_reference")]


def xmp_packet(body: str) -> bytes:
    return (
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
        'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
        'xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/" '
        'xmlns:xmp="http://ns.adobe.com/xap/1.0/">'
        f"<rdf:Description {body}/></rdf:RDF></x:xmpmeta>"
    ).encode()


def itxt_xmp(packet: bytes) -> bytes:
    body = b"XML:com.adobe.xmp\x00\x00\x00\x00\x00" + packet
    return png_chunk(b"iTXt", body)


def test_xmp_digital_source_type(tmp_path: Path) -> None:
    packet = xmp_packet(
        'Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/'
        'trainedAlgorithmicMedia"'
    )
    write_tree(tmp_path, {"a/x.png": make_png(extra=[itxt_xmp(packet)])})
    assert cats(run("audit-ai", str(tmp_path / "a"))) == [("MM-AI-020", "explicit_declaration")]


def test_xmp_plain_algorithmic_is_ambiguous(tmp_path: Path) -> None:
    packet = xmp_packet(
        'Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/'
        'algorithmicMedia"'
    )
    write_tree(tmp_path, {"a/x.png": make_png(extra=[itxt_xmp(packet)])})
    assert cats(run("audit-ai", str(tmp_path / "a"))) == [("MM-AI-020", "ambiguous_indicator")]


def test_xmp_dtd_is_rejected(tmp_path: Path) -> None:
    packet = b'<!DOCTYPE x [<!ENTITY a "b">]><x xmp:CreatorTool="&a;"/>'
    write_tree(tmp_path, {"a/x.png": make_png(extra=[itxt_xmp(packet)])})
    assert run("audit-ai", str(tmp_path / "a")).ai_findings == []


def test_exif_software_in_jpeg(tmp_path: Path) -> None:
    text = b"DALL-E 3\x00"
    tiff = b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", 1)
    tiff += struct.pack("<HHII", 0x0131, 2, len(text), 26) + struct.pack("<I", 0) + text
    seg = b"Exif\x00\x00" + tiff
    jpeg = b"\xff\xd8\xff\xe1" + struct.pack(">H", len(seg) + 2) + seg + b"\xff\xd9"
    write_tree(tmp_path, {"a/p.jpg": jpeg})
    assert cats(run("audit-ai", str(tmp_path / "a"))) == [("MM-AI-030", "tool_reference")]


def test_c2pa_sidecar_and_png_chunk_are_detection_only(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {"a/x.c2pa": b"x", "a/y.png": make_png(extra=[png_chunk(b"caBX", b"jumb c2pa")])},
    )
    report = run("audit-ai", str(tmp_path / "a"))
    assert {a.code for a in report.ai_findings} == {"MM-AI-040"}
    assert all(a.category.value == "ambiguous_indicator" for a in report.ai_findings)
    assert "not parsed" in report.ai_findings[0].explanation


def test_malformed_images_do_not_crash(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "a/bad.png": b"\x89PNG\r\n\x1a\n" + b"\xff" * 40,
            "a/bad.jpg": b"\xff\xd8\xff\xe1\xff\xff",
        },
    )
    assert run("audit-ai", str(tmp_path / "a")).scan_status == "complete"


def test_ai_findings_do_not_affect_integrity(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {"m/mod_manifest.json": '{"AIGenerated": true}'})
    report = run("inspect", str(z))
    assert report.ai_findings
    assert all(f.code.startswith("MM-") and "AI" not in f.code for f in report.findings)
