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

    def run_dom_js(self, events: list[dict], assertions: str) -> dict:
        dom = r"""
class Element {
  constructor(tag) {
    this.tag = tag; this.children = []; this.className = ''; this.textContent = '';
    this.dataset = {}; this.attributes = {}; this.listeners = {}; this.open = false;
    this.classList = {
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(' '); },
      contains: name => this.className.split(/\s+/).includes(name),
    };
  }
  appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
  addEventListener(name, callback) { (this.listeners[name] ||= []).push(callback); }
  async emit(name) { for (const callback of this.listeners[name] || []) await callback({target:this}); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  querySelectorAll(selector) {
    const matches = node => selector.startsWith('.') ? node.classList.contains(selector.slice(1)) : node.tag === selector;
    return this.children.flatMap(child => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
  }
}
const installed = [];
const document = {
  createElement: tag => new Element(tag),
  getElementById: id => installed.find(item => item.id === id) || null,
  head: {appendChild: item => installed.push(item)},
};
function nodes(root, cls) {
  if (!root) return [];
  return [...(root.classList.contains(cls) ? [root] : []), ...root.children.flatMap(child => nodes(child, cls))];
}
function text(root) { return root ? [root.textContent, ...root.children.map(text)].filter(Boolean).join('\n') : ''; }
"""
        script = self.runtime + "\n" + dom + "\nconst events=" + json.dumps(events) + ";\n" + assertions
        result = subprocess.run(["node"], input=script, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
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

    def test_structure_rows_split_complete_body_into_annotated_sixteen_byte_lines(self) -> None:
        body = bytes(index % 256 for index in range(257))
        event = _event(_typed_rpc("on_recv_client_data", body))
        result = self.run_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const rows = pubgm17500RpcStructureRows(info.typedRpc);
console.log(JSON.stringify({
  count: rows.length,
  maxWidth: Math.max(...rows.map(row => row.bytes.length)),
  bodyRows: rows.filter(row => row.kind === 'body').map(row => ({key:row.key,offset:row.offset,label:row.label,width:row.bytes.length,description:row.description})),
  names: rows.filter(row => row.kind === 'name').map(row => row.label),
}));
""")
        self.assertEqual(result["count"], 21)
        self.assertEqual(result["maxWidth"], 16)
        self.assertEqual(len(result["bodyRows"]), 17)
        self.assertEqual(result["bodyRows"][0]["label"], "业务正文 +0x0000")
        self.assertEqual(result["bodyRows"][-1]["label"], "业务正文 +0x0100")
        self.assertEqual(result["bodyRows"][-1]["width"], 1)
        self.assertTrue(all("字段含义待确认" in row["description"] for row in result["bodyRows"]))
        self.assertEqual(result["names"], ["命令名称", "命令名称（续 +0x10）"])

    def test_structure_compare_aligns_before_after_by_body_offset(self) -> None:
        before_body = bytes(index % 256 for index in range(255))
        after_body = before_body + b"\xaa\xbb"
        event = _event(_typed_rpc("on_recv_client_data", after_body), before=_typed_rpc("on_recv_client_data", before_body))
        result = self.run_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const before = parsePubgm17500TypedRpc([...Buffer.from(events[0].before_pay, 'base64')], info.meta);
const compare = pubgm17500RpcStructureCompare(before, info.typedRpc);
console.log(JSON.stringify({
  canCompare: compare.canCompare,
  lengths: [compare.beforeBodyLength, compare.afterBodyLength],
  rows: compare.rows.map(row => ({key:row.key,status:row.status,before:row.before && row.before.bytes.length,after:row.after && row.after.bytes.length})),
}));
""")
        self.assertTrue(result["canCompare"])
        self.assertEqual(result["lengths"], [255, 257])
        rows = {row["key"]: row for row in result["rows"]}
        self.assertEqual(rows["body:224"]["status"], "same")
        self.assertEqual(rows["body:240"]["status"], "changed")
        self.assertEqual(rows["body:256"]["status"], "added")

    def test_expanded_view_is_multiline_three_column_structure_not_one_long_field(self) -> None:
        before_body = bytes(index % 256 for index in range(255))
        after_body = before_body + b"\xaa\xbb"
        event = _event(_typed_rpc("on_recv_client_data", after_body), before=_typed_rpc("on_recv_client_data", before_body))
        result = self.run_dom_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const panel = pubgm17500RpcStructurePanel(events[0], info);
const rows = nodes(panel, 'pubgm-rpc-row');
const bodyRows = nodes(panel, 'pubgm-rpc-row-body');
const hexLines = nodes(panel, 'pubgm-rpc-hex-line');
const annotations = nodes(panel, 'pubgm-rpc-annotation');
const controls = panel.querySelectorAll('button');
console.log(JSON.stringify({
  mode: panel.dataset.mode,
  rows: rows.length,
  bodyRows: bodyRows.length,
  hexLines: hexLines.length,
  annotations: annotations.length,
  longFields: nodes(panel, 'gcloud-long-value').length,
  oldTable: nodes(panel, 'gcloud-compare-table').length,
  headings: nodes(panel, 'pubgm-rpc-head').map(text),
  allPressed: controls.find(button => button.textContent === '全部行').attributes['aria-pressed'],
  bodyLabels: annotations.map(text).filter(value => value.includes('业务正文')).slice(0, 3),
}));
""")
        self.assertEqual(result["mode"], "all")
        self.assertEqual(result["rows"], 21)
        self.assertEqual(result["bodyRows"], 17)
        self.assertEqual(result["hexLines"], 41)  # one added row has no before-side line
        self.assertEqual(result["annotations"], 21)
        self.assertEqual(result["longFields"], 0)
        self.assertEqual(result["oldTable"], 0)
        self.assertEqual(result["allPressed"], "true")
        self.assertIn("修改前明文", result["headings"][0])
        self.assertIn("结构 / 注释", result["headings"][0])
        self.assertIn("修改后明文", result["headings"][0])
        self.assertTrue(all("业务正文 +0x" in label for label in result["bodyLabels"]))


if __name__ == "__main__":
    unittest.main()
