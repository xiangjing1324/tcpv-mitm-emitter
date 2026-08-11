from __future__ import annotations

import base64
import json
import subprocess
import unittest
from pathlib import Path

from tcpv_mitm_emitter.api import create_app
from tcpv_mitm_emitter.runtime import TcpvRuntime
from tcpv_mitm_emitter.store import TcpvEventStore

from test_archive_and_store import FakeRedis


ROOT = Path(__file__).parents[1]
APP_JS = ROOT / "tcpv_mitm_emitter" / "app.js"


def _method3_frame(key: bytes, *, command: int = 0x1001, suffix: bytes = b"TAIL") -> bytes:
    key = bytes(key)
    if not 1 <= len(key) <= 64:
        raise ValueError("test key must be 1..64 bytes")
    header_len = 24 + len(key) + len(suffix)
    raw = bytearray(header_len)
    raw[0:2] = b"\x33\x66"
    raw[6:8] = int(command).to_bytes(2, "big")
    raw[13:17] = header_len.to_bytes(4, "big")
    raw[17:21] = (0).to_bytes(4, "big")
    raw[21] = 3
    raw[22:24] = len(key).to_bytes(2, "big")
    raw[24 : 24 + len(key)] = key
    raw[24 + len(key) :] = suffix
    return bytes(raw)


def _extract_js_function(source: str, name: str) -> str:
    marker = f"function {name}("
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    quote = ""
    escaped = False
    index = brace
    while index < len(source):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in {'"', "'", "`"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
        index += 1
    raise AssertionError(f"unterminated JS function: {name}")


class GCloudDhHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key63 = bytes(range(1, 64))
        self.key64 = bytes(range(64))
        self.forwarded = _method3_frame(self.key63, suffix=b"AFTER")
        self.received = _method3_frame(self.key64, suffix=b"BEFORE")
        self.analysis = {
            "schema": "tcpv.gcloud.analysis.v1",
            "analysis_authoritative": True,
            "analysis_source": "producer_handoff",
            "transport": {
                "kind": "tgcp",
                "command": "0x1001",
                "direction": "outbound",
                "key_method": 3,
                "key_length": 63,
                "header_len": len(self.received),
                "frame_len": len(self.received),
                "rewrite_before_length": len(self.received),
                "rewrite_after_length": len(self.forwarded),
                "session_stage": "client_rewritten",
                "keys_ready": False,
                "fallback_reason": None,
                "handshake_failed_after_rewrite": False,
            },
            "packet": {"semantic_category": "transport.gcloud.handshake"},
        }

    def _stored_event(self) -> tuple[TcpvRuntime, dict]:
        store = TcpvEventStore(
            FakeRedis(),
            "gcloud-dh",
            ttl_seconds=0,
            stream_maxlen=0,
            api_max_limit=20,
        )
        runtime = TcpvRuntime()
        runtime.store = store
        runtime._append_store_event(
            store,
            {
                "account": "acct",
                "cid": "client->server:65010",
                "dir": 0,
                "payload": self.forwarded,
                "packet_len": len(self.forwarded),
                "full_payload": self.received,
                "full_packet_len": len(self.received),
                "before_payload": b"",
                "before_packet_len": 0,
                "raw_payload": self.forwarded,
                "raw_packet_len": len(self.forwarded),
                "proxy_username": "",
                "summary": "transport=tgcp65010 command=0x1001 direction=outbound",
                "analysis": self.analysis,
                "ts_ms": 1000,
                "msg_idx": 1,
                "chunk_idx": 0,
            },
        )
        event = store.get_event("acct", "1")
        assert event is not None
        return runtime, event

    def test_producer_store_and_api_preserve_native_63_byte_wire_evidence(self) -> None:
        runtime, event = self._stored_event()
        self.assertEqual(event["analysis"], self.analysis)
        self.assertEqual(event["analysis"]["transport"]["key_length"], 63)
        self.assertEqual(base64.b64decode(event["pay"]), self.forwarded)
        self.assertEqual(base64.b64decode(event["full_pay"]), self.received)

        app = create_app(runtime)
        endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", "") == "/event")
        api_event = endpoint(account="acct", id="1")
        self.assertEqual(api_event["analysis"]["transport"]["key_length"], 63)
        self.assertEqual(base64.b64decode(api_event["pay"]), self.forwarded)
        self.assertEqual(base64.b64decode(api_event["full_pay"]), self.received)

    def test_frontend_render_model_keeps_actual_63_byte_key_and_diagnostics(self) -> None:
        _runtime, event = self._stored_event()
        source = APP_JS.read_text(encoding="utf-8")
        names = [
            "gcloudAuthoritativeAnalysis",
            "gcloudProducerTransport",
            "parseGcloudHandshakeWire",
            "gcloudWireHandshakeEvidence",
            "gcloudProducerHandshakeDiagnostics",
            "gcloudHandshakeDiagnosticRows",
        ]
        functions = "\n".join(_extract_js_function(source, name) for name in names)
        script = f"""
function b64ToBytes(value) {{ return Array.from(Buffer.from(String(value || ''), 'base64')); }}
{functions}
const event = {json.dumps(event)};
const evidence = gcloudWireHandshakeEvidence(event);
const rows = gcloudHandshakeDiagnosticRows(event, evidence);
process.stdout.write(JSON.stringify({{evidence, rows}}));
"""
        completed = subprocess.run(
            ["node", "--eval", script],
            check=True,
            capture_output=True,
            text=True,
        )
        rendered = json.loads(completed.stdout)
        forwarded = next(item for item in rendered["evidence"] if item["source"] == "forwarded")
        received = next(item for item in rendered["evidence"] if item["source"] == "received")
        self.assertTrue(forwarded["valid"])
        self.assertEqual(forwarded["keyLength"], 63)
        self.assertEqual(forwarded["keyHex"], self.key63.hex())
        self.assertTrue(received["valid"])
        self.assertEqual(received["keyLength"], 64)
        self.assertEqual(received["keyHex"], self.key64.hex())

        row_text = "\n".join(f"{item['label']}: {item['value']}" for item in rendered["rows"])
        self.assertIn("key_len=63", row_text)
        self.assertIn(f"key={self.key63.hex()}", row_text)
        self.assertIn("session_stage=client_rewritten", row_text)
        self.assertIn("keys_ready=false", row_text)
        self.assertIn("handshake_failed_after_rewrite=false", row_text)
        self.assertIn(f"before_len={len(self.received)}", row_text)
        self.assertIn(f"after_len={len(self.forwarded)}", row_text)
        self.assertNotIn("invalid", row_text.lower())

    def test_method3_lengths_1_62_63_64_are_not_filtered_as_invalid(self) -> None:
        source = APP_JS.read_text(encoding="utf-8")
        function = _extract_js_function(source, "parseGcloudHandshakeWire")
        fixtures = {
            length: base64.b64encode(_method3_frame(bytes([0xA5]) * length)).decode("ascii")
            for length in (1, 62, 63, 64)
        }
        script = f"""
{function}
const fixtures = {json.dumps(fixtures)};
const result = Object.fromEntries(Object.entries(fixtures).map(([length, value]) => [
  length,
  parseGcloudHandshakeWire(Array.from(Buffer.from(value, 'base64'))),
]));
process.stdout.write(JSON.stringify(result));
"""
        completed = subprocess.run(
            ["node", "--eval", script],
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads(completed.stdout)
        for length in (1, 62, 63, 64):
            with self.subTest(length=length):
                self.assertTrue(result[str(length)]["valid"])
                self.assertEqual(result[str(length)]["keyLength"], length)
                self.assertEqual(len(result[str(length)]["keyHex"]), length * 2)

    def test_frontend_prefers_exact_command_field_and_removes_candidate_suffix(self) -> None:
        source = APP_JS.read_text(encoding="utf-8")
        functions = "\n".join(
            _extract_js_function(source, name)
            for name in ("chooseGcloudCommandDisplay", "gcloudReadableTypeName")
        )
        script = f"""
{functions}
process.stdout.write(JSON.stringify({{
  report: chooseGcloudCommandDisplay('CSReportIDCReq', 'CSReportIDCReqB'),
  auction: chooseGcloudCommandDisplay('CSAuctionAutoLoadGuidePriceReq', 'CSAuctionAutoLoadGuidePriceReqB'),
  fallback: chooseGcloudCommandDisplay('', 'CSMallGetRecycleGoodsReqB'),
  readable: gcloudReadableTypeName('UAGameActivityDetailCandidate'),
}}));
"""
        completed = subprocess.run(
            ["node", "--eval", script],
            check=True,
            capture_output=True,
            text=True,
        )
        rendered = json.loads(completed.stdout)
        self.assertEqual(rendered["report"], "CSReportIDCReq")
        self.assertEqual(rendered["auction"], "CSAuctionAutoLoadGuidePriceReq")
        self.assertEqual(rendered["fallback"], "CSMallGetRecycleGoodsReq")
        self.assertEqual(rendered["readable"], "UAGameActivityDetail")

    def test_frontend_promotes_producer_business_strings(self) -> None:
        source = APP_JS.read_text(encoding="utf-8")
        producer = _extract_js_function(source, "gcloudProducerPacket")
        readable_start = source.index("function gcloudReadableStringsForEvent(")
        readable_end = source.index("\nfunction gcloudPayloadChangeSummary(", readable_start)
        functions = f"{producer}\n{source[readable_start:readable_end]}"
        script = f"""
function shortenText(value, maxLen) {{ return String(value).slice(0, maxLen); }}
function isGcloudVisibleString(value) {{ return String(value).length >= 4; }}
function gcloudCollectProtoStrings() {{ return []; }}
function gcloudRawPathText() {{ return ''; }}
{functions}
const event = {{analysis: {{packet: {{
  text_summary: {{previews: [
    {{path: 'f2[0].f1[0].f7', value: '【内含福利】2077联动军需加赠20连！'}},
  ]}},
  fields: [
    {{path: 'f2[0].f1[3].f7', value_type: 'string', value: '卡莫纳福利计划'}},
  ],
}}}}}};
process.stdout.write(JSON.stringify(gcloudReadableStringsForEvent(event, null)));
"""
        completed = subprocess.run(
            ["node", "--eval", script],
            check=True,
            capture_output=True,
            text=True,
        )
        values = [item["text"] for item in json.loads(completed.stdout)]
        self.assertEqual(
            values,
            ["【内含福利】2077联动军需加赠20连！", "卡莫纳福利计划"],
        )

    def test_frontend_renders_known_uagame_opcode_as_readable_type(self) -> None:
        source = APP_JS.read_text(encoding="utf-8")
        map_start = source.index("const GCLOUD_UAGAME_OPCODE_NAMES = new Map(")
        map_end = source.index("]);", map_start) + 3
        functions = "\n".join(
            _extract_js_function(source, name)
            for name in (
                "isUagameGcloudMeta",
                "gcloudReadableTypeName",
                "gcloudUagameOpcodeInfo",
                "gcloudUagameOpcodeDisplay",
            )
        )
        script = f"""
function parseFlexibleInt(value) {{ return Number.parseInt(String(value), 16); }}
function formatHexValue(value, width) {{ return `0x${{Number(value).toString(16).padStart(width, '0')}}`; }}
{source[map_start:map_end]}
{functions}
const meta = {{
  gcloudSchema: 'uagame_binary_v1',
  gcloudProto: 'uagame_message',
  gcloudOpcode: '0x1d000011',
  gcloudInferredType: 'UAGameActivityBenefitCatalogCandidate',
}};
process.stdout.write(gcloudUagameOpcodeDisplay(meta));
"""
        completed = subprocess.run(
            ["node", "--eval", script],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.stdout,
            "运营活动/福利目录批量获取 · UAGameActivityBenefitCatalog [0x1d000011]",
        )


if __name__ == "__main__":
    unittest.main()
