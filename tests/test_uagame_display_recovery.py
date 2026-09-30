from __future__ import annotations

import base64
import io
import json
import re
import subprocess
import unittest
import zipfile
import zlib
from pathlib import Path



APP_JS = Path(__file__).parents[1] / "tcpv_mitm_emitter" / "app.js"


def js_runtime() -> str:
    """Exercise the real view functions without starting a browser or server."""
    source = APP_JS.read_text()
    names = re.findall(r"^function (\w+)\(", source, re.M)
    # Include protocol helpers, not DOM render/bootstrap functions. The same
    # functions drive collapsed badges and expanded message details.
    core = {
        "extractPrintableRuns", "escapeRegexLiteral", "readSummaryValue", "parseFlexibleInt", "formatHexValue", "b64ToBytes",
        "bytesFromHexPrefix", "normalizeHex", "childHexByteText", "shortenText",
        "readBe16", "readBe32", "readLe32", "isDecodedFlowEvent", "getCurrentFlowMeta",
        "buildGcloudSummaryInsights", "chooseGcloudCommandDisplay", "findGcloudCommandMatches",
        "walkGcloudProtoNodes", "parseGcloudProtoNodes", "decodeGcloudLz4Block",
        "getGcloudBusinessProtoCached", "inspectUagameMrpcsResource", "uagameDisplayCrc32",
        "getUagameDisplayEnvelope", "shouldHydrateSummaryBadges",
    }
    selected = [name for name in names if name in core or "Uagame" in name or name.startswith("uagame") or re.match(r"(?:gcloud|analyzeGcloud|analyzeUagame|parseGcloud|readGcloud|isUagame|isGcloud|normalizeGcloud|getGcloud|detectGcloud)", name)]
    def extract(name: str) -> str:
        # Top-level function braces in this source close at column zero. This
        # avoids mistaking quoted regex/comment text for JavaScript braces.
        start = source.index(f"function {name}(")
        end = re.search(r"(?m)^}$", source[start:])
        assert end is not None, name
        return source[start:start + end.end()]
    # Resolve the transitive helper functions actually called by these entry
    # points, so the harness does not replace protocol behavior with stubs.
    pending = list(selected)
    extracted: dict[str, str] = {}
    while pending:
        name = pending.pop()
        if name in extracted:
            continue
        function = extract(name)
        extracted[name] = function
        pending.extend(candidate for candidate in names if candidate not in extracted
                       and re.search(r"\b" + candidate + r"\s*\(", function))
    functions = "\n".join(extracted.values())
    maps = []
    for name in (
        "GCLOUD_UAGAME_OPCODE_NAMES", "GCLOUD_CS_COMMAND_STEM_LABELS",
        "GCLOUD_CS_COMMAND_TOKEN_LABELS", "GCLOUD_COMMAND_FULL_LABELS",
        "GCLOUD_17500_NUMERIC_COMMANDS",
    ):
        start = source.index(f"const {name} = new Map([");
        maps.append(source[start:source.index("]);", start) + 3])
    start = source.index("const PRINTABLE_RUN_ANCHOR_PATTERNS = [")
    maps.append(source[start:source.index("];", start) + 2])
    return "\n".join([
        "const state = {events: [], flows: [], flowId: ''};",
        functions, *maps,
        "function getCurrentFlowMeta() { return null; }",
    ])


def varint(n: int) -> bytes:
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def field(n: int, value: bytes | int) -> bytes:
    if isinstance(value, int):
        return varint(n << 3) + varint(value)
    return varint((n << 3) | 2) + varint(len(value)) + value


def envelope(body: bytes, opcode: int = 0x08000001) -> bytes:
    return len(body).to_bytes(4, "big") + opcode.to_bytes(4, "big") + bytes(30) + b"\xab\xab" + body


def literal_lz4(data: bytes) -> bytes:
    out = bytearray([min(len(data), 15) << 4])
    extra = len(data) - 15
    if extra >= 0:
        while extra >= 255:
            out.append(255)
            extra -= 255
        out.append(extra)
    return bytes(out) + data


def event(data: bytes, *, direction: int = 1, port: int = 20001) -> dict:
    return {
        "dir": direction, "len": len(data), "pay": base64.b64encode(data).decode(),
        "pfx": data[:192].hex(),
        "summary": f"transport=tgcp65010 command=0x4013 target_port={port} crypto=decrypted",
        "analysis": {
            "schema": "tcpv.gcloud.analysis.v1", "analysis_authoritative": True,
            "generic_semantic_reparse": "skipped",
            "transport": {"command": "0x4013", "target_port": port, "decrypted": True},
            "packet": {"shape": {}, "fields": [], "children": []},
        },
    }


class UagameDisplayRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime = js_runtime()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("unzipmrpcs.data", b"synthetic safe resource" * 12)
        cls.zip = stream.getvalue()
        cls.tuple = b"".join([
            field(1, b"mrpcs-uam-ios-167.data"), field(2, 123),
            field(3, cls.zip), field(4, 456), field(5, zlib.crc32(cls.zip)),
        ])
        cls.body = field(4, field(25, cls.tuple))

    def run_js(self, events: list[dict], assertions: str) -> dict:
        script = self.runtime + "\nconst events=" + json.dumps(events) + ";\n" + assertions
        result = subprocess.run(["node"], input=script, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr[-1800:])
        return json.loads(result.stdout)

    def test_direct_and_compressed_resource_use_exact_body_and_crc(self) -> None:
        frames = [envelope(self.body), literal_lz4(envelope(self.body))]
        result = self.run_js([event(frame) for frame in frames], """
const results = events.map(ev => {
  const before = JSON.stringify({analysis:ev.analysis,pay:ev.pay,summary:ev.summary});
  const meta = parseGcloud65010Summary(ev.summary,ev);
  const preview = getGcloudPreviewBytes(ev);
  const proto = getGcloudBusinessProtoCached(ev,preview.bytes,preview.complete);
  const chips = buildGcloudSummaryInsights(ev).map(x=>x.text);
  return {resource:proto.uagameResource,carrier:meta.uagameEnvelope.carrier,
    opcode:meta.gcloudOpcode,body:proto.viewBytes.length,start:proto.start,
    name:gcloudUagameOpcodeInfo(meta).name,chips,
    unchanged:before===JSON.stringify({analysis:ev.analysis,pay:ev.pay,summary:ev.summary})};
}); console.log(JSON.stringify({results}));
""")
        for row in result["results"]:
            self.assertEqual(row["resource"]["name"], "mrpcs-uam-ios-167.data")
            self.assertTrue(row["resource"]["crcMatch"])
            self.assertEqual(row["resource"]["zipLength"], len(self.zip))
            self.assertEqual(row["body"], len(self.body))
            self.assertEqual(row["start"], 0)
            self.assertEqual(row["name"], "")  # inbound 08000001 != LoginReq
            self.assertIn("ZIP blob CRC32 ✓", row["chips"])
            self.assertTrue(row["unchanged"])
        self.assertEqual([row["carrier"] for row in result["results"]], ["direct", "lz4_raw"])

    def test_crc_mismatch_is_explicit_not_verified(self) -> None:
        bad = self.tuple[:-1] + bytes([self.tuple[-1] ^ 1])
        result = self.run_js([event(envelope(field(4, field(25, bad))))], """
const proto=getGcloudBusinessProtoCached(events[0],getGcloudPreviewBytes(events[0]).bytes,true);
console.log(JSON.stringify({resource:proto.uagameResource}));
""")
        self.assertFalse(result["resource"]["crcMatch"])

    def test_header_length_marker_port_cipher_and_truncation_controls(self) -> None:
        good = envelope(self.body)
        controls = [event(good[:-1]), event(good[:38]+b"\xab\xac"+good[40:]),
                    event(b"\x00\x00\x00\x00"+good[4:]), event(good, port=65010),
                    event(literal_lz4(good)[:-2])]
        cipher = event(good)
        cipher["summary"] = cipher["summary"].replace("decrypted", "encrypted")
        cipher["analysis"]["transport"]["decrypted"] = False
        controls.append(cipher)
        result = self.run_js(controls, "console.log(JSON.stringify({values:events.map(ev=>getUagameDisplayEnvelope(ev))}));")
        self.assertEqual(result["values"], [None] * len(controls))

    def test_prefix_exposes_opcode_but_never_resource_or_negative_full_scan(self) -> None:
        compact = event(envelope(self.body))
        compact["pay"] = ""
        result = self.run_js([compact], """
const ev=events[0], meta=parseGcloud65010Summary(ev.summary,ev),p=getGcloudPreviewBytes(ev);
const proto=getGcloudBusinessProtoCached(ev,p.bytes,p.complete);
console.log(JSON.stringify({opcode:meta.gcloudOpcode,complete:proto.sourceComplete,
  resource:proto.uagameResource,chips:buildGcloudSummaryInsights(ev).map(x=>x.text),hydrate:shouldHydrateSummaryBadges(ev)}));
""")
        self.assertEqual(result["opcode"], "0x08000001")
        self.assertFalse(result["complete"])
        self.assertIsNone(result["resource"])
        self.assertNotIn("01 0a report 无命中", result["chips"])
        self.assertIn("正文待加载", result["chips"])
        self.assertTrue(result["hydrate"])

    def test_structured_handoff_empty_body_unknown_opcode_and_direction(self) -> None:
        structured = event(b"\x08\x01")
        structured["summary"] = ""
        structured["analysis"]["packet"]["shape"] = {"gcloud_schema": "uagame_binary_v1", "gcloud_opcode": "0x08100003"}
        result = self.run_js([structured, event(envelope(b"",0x08f30001)), event(envelope(b"",0x08000001),direction=0)], """
const meta=events.map(ev=>parseGcloud65010Summary(ev.summary,ev));
const e=events[1], p=getGcloudPreviewBytes(e), proto=getGcloudBusinessProtoCached(e,p.bytes,p.complete);
console.log(JSON.stringify({structured:isUagameGcloudMeta(meta[0]),unknown:gcloudUagameOpcodeInfo(meta[1]).name,
  empty:gcloudEventPayloadStatusText(proto,meta[1]),request:gcloudUagameOpcodeInfo(meta[2]).name}));
""")
        self.assertTrue(result["structured"])
        self.assertEqual(result["unknown"], "")
        self.assertEqual(result["empty"], "空正文")
        self.assertEqual(result["request"], "CSAccountLoginReq")

    def test_duplicate_wrong_path_and_non_resource_controls(self) -> None:
        bodies = [field(4, field(25,self.tuple)+field(25,self.tuple)),
                  field(2, field(25,self.tuple)), field(4, field(20,self.tuple)), b"opaque binary"]
        result = self.run_js([event(envelope(body)) for body in bodies], """
console.log(JSON.stringify({values:events.map(ev=>{const p=getGcloudPreviewBytes(ev);return getGcloudBusinessProtoCached(ev,p.bytes,p.complete).uagameResource;})}));
""")
        self.assertEqual(result["values"], [None] * len(bodies))

    def test_inbound_hydration_is_bounded_and_scoped(self) -> None:
        compact = event(envelope(self.body)); compact["pay"] = ""
        other = dict(compact, summary=compact["summary"].replace("20001","65010"))
        other["analysis"] = {}
        oversized = dict(compact, len=1024*1024+1)
        result = self.run_js([compact,other,oversized], "console.log(JSON.stringify({values:events.map(ev=>shouldHydrateSummaryBadges(ev))}));")
        self.assertEqual(result["values"], [True,False,False])

    def test_already_extracted_uagame_body_is_never_stripped_again(self) -> None:
        body = bytearray(41)
        body[:4] = bytes.fromhex("00000001")
        body[4:6] = (41).to_bytes(2,"big")
        body[6:10] = bytes.fromhex("010a0011")
        body[38:40] = bytes.fromhex("abab")
        e = event(bytes(body),direction=0)
        e["analysis"]["generic_semantic_reparse"] = "uagame_body"
        e["analysis"]["packet"]["shape"] = {"gcloud_schema":"uagame_binary_v1", "gcloud_opcode":"0x08100003"}
        result = self.run_js([e], "console.log(JSON.stringify({envelope:getUagameDisplayEnvelope(events[0]),opcode:parseGcloud65010Summary(events[0].summary,events[0]).gcloudOpcode}));")
        self.assertIsNone(result["envelope"])
        self.assertEqual(result["opcode"],"0x08100003")

    def test_zip_signature_without_directory_is_not_a_resource_archive(self) -> None:
        fake = bytes.fromhex("504b0304") + bytes(18)
        resource = b"".join([field(1,b"mrpcs-uam-ios-167.data"),field(2,1),field(3,fake),field(4,2),field(5,zlib.crc32(fake))])
        result = self.run_js([event(envelope(field(4,field(25,resource))))], "const p=getGcloudPreviewBytes(events[0]);console.log(JSON.stringify({resource:getGcloudBusinessProtoCached(events[0],p.bytes,p.complete).uagameResource}));")
        self.assertIsNone(result["resource"])


if __name__ == "__main__":
    unittest.main()
