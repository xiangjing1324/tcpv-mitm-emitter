from __future__ import annotations

import base64
import json
import subprocess
import unittest
from urllib.parse import quote

from test_uagame_display_recovery import js_runtime


def _typed_rpc(name: str, body: bytes = b"", *, marker: bytes = b"") -> bytes:
    command = name.encode("ascii")
    return marker + b"\x03" + bytes([len(command)]) + command + body


def _literal_lz4(data: bytes) -> bytes:
    out = bytearray([min(len(data), 15) << 4])
    extra = len(data) - 15
    if extra >= 0:
        while extra >= 255:
            out.append(255)
            extra -= 255
        out.append(extra)
    return bytes(out) + data


def _event(payload: bytes, *, before: bytes = b"", port: int = 17500) -> dict:
    label = quote("业务心跳保活")
    detail = quote("客户端保活请求；命令名和正文边界已验证。")
    return {
        "dir": 0,
        "len": len(payload),
        "pay": base64.b64encode(payload).decode(),
        "before_len": len(before),
        "before_pay": base64.b64encode(before).decode() if before else "",
        "summary": (
            f"transport=tgcp65010 command=0x4013 direction=outbound target_port={port} "
            "crypto=decrypted beforedump=gcloud_4013 gcloud_type=heart_beat "
            f"tgcp_rpc_name=heart_beat tgcp_rpc_label={label} tgcp_rpc_detail={detail} "
            "tgcp_rpc_basis=command_length_boundary tgcp_rpc_encoding=literal "
            "tgcp_rpc_body_offset=12 tgcp_rpc_body_length=3 tgcp_rpc_decoded_length=15"
        ),
        "analysis": {
            "schema": "tcpv.gcloud.analysis.v1",
            "analysis_authoritative": True,
            "transport": {"command": "0x4013", "target_port": port, "decrypted": True},
            "packet": {"shape": {}, "fields": [], "children": []},
        },
    }


class Pubgm17500GcloudAlignmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime = js_runtime()

    def run_js(self, events: list[dict], assertions: str) -> dict:
        script = self.runtime + "\nconst events=" + json.dumps(events) + ";\n" + assertions
        result = subprocess.run(["node"], input=script, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr[-3000:])
        return json.loads(result.stdout)

    def test_17500_uses_gcloud_panel_with_verified_chinese_rpc_fields(self) -> None:
        event = _event(_typed_rpc("heart_beat", b"\x01\x02\x03"))
        result = self.run_js([event], r"""
const ev = events[0]; const before = JSON.stringify(ev);
const info = analyzeGcloudEvent(ev, ev.summary);
const rows = pubgm17500RpcFieldRows(info.typedRpc);
console.log(JSON.stringify({
  kind: info.kind, title: info.title, labels: rows.map(row => row.label),
  command: rows.find(row => row.key === 'rpc.name').value,
  body: rows.find(row => row.key === 'rpc.body').value,
  unchanged: before === JSON.stringify(ev),
}));
""")
        self.assertEqual(result["kind"], "pubgm_rpc")
        self.assertIn("PUBGM 17500", result["title"])
        self.assertIn("业务心跳保活", result["title"])
        self.assertEqual(
            result["labels"],
            ["应用层标记", "命令名称长度", "命令名称", "承载编码", "业务正文长度", "业务正文"],
        )
        self.assertIn("heart_beat", result["command"])
        self.assertEqual(result["body"].replace(" ", ""), "010203")
        self.assertTrue(result["unchanged"])

    def test_literal_or_lz4_before_is_compared_with_normalized_current(self) -> None:
        decoded_before = _typed_rpc("heart_beat", b"\x01\x02\x03")
        before = b"z" + _literal_lz4(decoded_before)
        current = _typed_rpc("heart_beat", b"\x01\x02\x04")
        event = _event(current, before=before)
        result = self.run_js([event], r"""
const ev = events[0]; const info = analyzeGcloudEvent(ev, ev.summary);
const compare = pubgm17500RpcCompareRows(ev, info);
console.log(JSON.stringify({
  canCompare: compare.canCompare,
  states: Object.fromEntries(compare.rows.map(row => [row.key, row.status])),
  reason: compare.reason,
}));
""")
        self.assertTrue(result["canCompare"])
        self.assertEqual(result["states"]["rpc.name"], "same")
        self.assertEqual(result["states"]["rpc.body"], "changed")
        self.assertIn("17500 RPC", result["reason"])

    def test_adapter_does_not_claim_65010_or_invalid_rpc_bytes(self) -> None:
        valid = _typed_rpc("heart_beat", b"\x01")
        invalid = b"\x03\x05bad name"
        result = self.run_js([_event(valid, port=65010)], """
const info = analyzeGcloudEvent(events[0], events[0].summary);
console.log(JSON.stringify({kind: info.kind, invalid: parsePubgm17500TypedRpc(""" + json.dumps(list(invalid)) + ", {})}));")
        self.assertNotEqual(result["kind"], "pubgm_rpc")
        self.assertIsNone(result["invalid"])

    def test_collapsed_row_uses_chinese_rpc_name_without_loading_body(self) -> None:
        event = _event(_typed_rpc("heart_beat", b"\x01"))
        result = self.run_js([event], r"""
const current = pubgm17500CompactSummaryInfo(events[0].summary, events[0]);
const other = {...events[0], summary: events[0].summary.replace('target_port=17500', 'target_port=65010')};
console.log(JSON.stringify({current, other: pubgm17500CompactSummaryInfo(other.summary, other)}));
""")
        self.assertEqual(result["current"]["text"], "业务心跳保活 · heart_beat · 已解密")
        self.assertIn("命令名和正文边界已验证", result["current"]["title"])
        self.assertIsNone(result["other"])


if __name__ == "__main__":
    unittest.main()
