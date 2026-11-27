from __future__ import annotations

import base64
import json
import subprocess
import unittest
import zlib
from urllib.parse import quote

from test_uagame_display_recovery import js_runtime


def _typed_rpc(name: str, body: bytes = b"", *, marker: bytes = b"") -> bytes:
    command = name.encode("ascii")
    return marker + b"\x03" + bytes([len(command)]) + command + body


def _rpc_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"\x03" + _varint(len(encoded)) + encoded


def _rpc_integer(value: int) -> bytes:
    if 0 <= value <= 246:
        return bytes([value + 9])
    zigzag = value * 2 if value >= 0 else (-value * 2) - 1
    return b"\x02" + _varint(zigzag)


def _rpc_table(pairs: list[tuple[str, bytes]]) -> bytes:
    return b"\x07" + b"".join(_rpc_string(key) + value for key, value in pairs) + b"\x08"


def _login_rpc(model: str, render_quality: int, user_agent: str, stable: str = "keep") -> bytes:
    numeric_flags = b"\x07" + _rpc_integer(1) + b"\x05" + _rpc_integer(2) + b"\x06\x08"
    body = (
        _rpc_string("1.39.13.16319")
        + _rpc_table(
            [
                ("CpuHardware", _rpc_string(model)),
                ("RenderQualityApply", _rpc_integer(render_quality)),
                ("UserAgent", _rpc_string(user_agent)),
                ("StableField", _rpc_string(stable)),
            ]
        )
        + _rpc_string("arg2")
        + _rpc_table([("app_version", _rpc_string("1.39.13.16319"))])
        + numeric_flags
    )
    return _typed_rpc("login", body)


def _literal_lz4(data: bytes) -> bytes:
    out = bytearray([min(len(data), 15) << 4])
    extra = len(data) - 15
    if extra >= 0:
        while extra >= 255:
            out.append(255)
            extra -= 255
        out.append(extra)
    return bytes(out) + data


def _ace_record(report_code: int, payload: bytes = b"") -> bytes:
    length = 10 + len(payload)
    return b"\x00\x00\x00\x01" + length.to_bytes(2, "big") + report_code.to_bytes(4, "big") + payload


def _ace_body(*records: bytes, prefix: bytes = b"\x02\xaa\x01\x03\xcd\x02") -> bytes:
    return prefix + b"".join(records)


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _rotate32(value: int, amount: int) -> int:
    amount &= 31
    return ((value << amount) | (value >> (32 - amount if amount else 32))) & 0xFFFFFFFF


def _tdreport_word_mask(data: bytes) -> bytes:
    out = bytearray(data)
    token = int.from_bytes(out[:4], "little")
    for index in range(1, len(out) // 4):
        offset = index * 4
        value = int.from_bytes(out[offset : offset + 4], "little")
        out[offset : offset + 4] = (value ^ _rotate32(token, index)).to_bytes(4, "little")
    return bytes(out)


def _tdreport_rpc(fields: list[tuple[str, str]], token: bytes = b"\x94\x74\x89\x9e") -> bytes:
    text = b"|".join(key.encode() + b"=" + value.encode() for key, value in fields) + b"|"
    content = token + text
    crc = b"RFC=%08x|" % (zlib.crc32(content) & 0xFFFFFFFF)
    trailer = crc + bytes(64 - len(crc))
    masked = _tdreport_word_mask(content + trailer)
    report = masked + bytes([0x5A]) * 256
    encoded = report.hex().upper().encode()
    body = b"\x03" + _varint(len(encoded)) + encoded + b"\x09\x0d"
    return _typed_rpc("report_sec_tdreport_req", body)


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
    this.dataset = {}; this.attributes = {}; this.listeners = {}; this.open = false; this.style = {};
    this.classList = {
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(' '); },
      contains: name => this.className.split(/\s+/).includes(name),
    };
  }
  get childNodes() { return this.children; }
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
  createTextNode: value => { const node = new Element('#text'); node.textContent = String(value); return node; },
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

    def test_login_typed_rpc_is_aligned_by_semantic_table_key(self) -> None:
        before = _login_rpc("iPad14,3", 3, "Mozilla/5.0 (iPad)")
        after = _login_rpc("iPhone18,2", 4, "Mozilla/5.0 (iPhone)")
        event = _event(after, before=before)
        result = self.run_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const previous = parsePubgm17500TypedRpc(b64ToBytes(events[0].before_pay), info.meta);
const compare = pubgm17500LoginCompare(previous, info.typedRpc);
console.log(JSON.stringify({
  title: compare.title,
  defaultMode: compare.defaultMode,
  rows: Object.fromEntries(compare.rows.map(row => [row.key, {
    label: row.label,
    status: row.status,
    before: row.before && row.before.value,
    after: row.after && row.after.value,
  }])),
}));
""")
        self.assertEqual(result["title"], "登录字段对照")
        self.assertEqual(result["defaultMode"], "all")
        self.assertEqual(result["rows"]["login.arg0"]["status"], "same")
        self.assertEqual(result["rows"]["login.arg1.CpuHardware"]["before"], "iPad14,3")
        self.assertEqual(result["rows"]["login.arg1.CpuHardware"]["after"], "iPhone18,2")
        self.assertEqual(result["rows"]["login.arg1.RenderQualityApply"]["status"], "changed")
        self.assertEqual(result["rows"]["login.arg1.UserAgent"]["status"], "changed")
        self.assertEqual(result["rows"]["login.arg1.StableField"]["status"], "same")
        self.assertEqual(result["rows"]["login.arg3.app_version"]["status"], "same")
        self.assertEqual(result["rows"]["login.arg4"]["status"], "same")
        self.assertIn("2 项 · 数字键 1–2", result["rows"]["login.arg4"]["after"])

    def test_login_keeps_unsafe_64_bit_integer_exact(self) -> None:
        exact_value = 1_345_785_623_905_087_498
        event = _event(_typed_rpc("login", _rpc_integer(exact_value)))
        result = self.run_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const rows = pubgm17500LoginFieldRows(info.typedRpc);
console.log(JSON.stringify({
  value: rows && rows[0] && rows[0].value,
  type: rows && rows[0] && rows[0].type,
}));
""")
        self.assertEqual(result["value"], str(exact_value))
        self.assertEqual(result["type"], "整数")

    def test_login_panel_uses_clear_field_table_instead_of_raw_byte_rows(self) -> None:
        before = _login_rpc("iPad14,3", 3, "Mozilla/5.0 (iPad)")
        after = _login_rpc("iPhone18,2", 4, "Mozilla/5.0 (iPhone)")
        event = _event(after, before=before)
        result = self.run_dom_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const panel = pubgm17500RpcStructurePanel(events[0], info);
console.log(JSON.stringify({
  mode: panel.dataset.mode,
  fieldTables: nodes(panel, 'gcloud-compare-table').length,
  rawTables: nodes(panel, 'pubgm-rpc-table').length,
  rows: nodes(panel, 'gcloud-compare-row').length,
  text: text(panel),
}));
""")
        self.assertEqual(result["mode"], "all")
        self.assertEqual(result["fieldTables"], 1)
        self.assertEqual(result["rawTables"], 0)
        self.assertGreaterEqual(result["rows"], 6)
        self.assertIn("登录字段对照", result["text"])
        self.assertIn("CpuHardware", result["text"])
        self.assertIn("iPad14,3", result["text"])
        self.assertIn("iPhone18,2", result["text"])

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

    def test_ace_layout_separates_outer_header_and_scans_multiple_nodes(self) -> None:
        first = _ace_record(0x0112232E, b"\x00\x00\x00\x0drole_id:sunday")
        second = _ace_record(0x010A0009, b"\x01\x02\x03\x04")
        body = _ace_body(first, second)
        event = _event(_typed_rpc("on_recv_client_data", body))
        result = self.run_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const layout = pubgm17500AceLayout(info.typedRpc);
console.log(JSON.stringify({
  headerLength: layout && layout.headerLength,
  headerHex: layout && layout.headerBytes.map(value => value.toString(16).padStart(2, '0')).join(' '),
  complete: layout && layout.complete,
  nodes: layout && layout.nodes.map(node => ({
    index: node.index,
    label: node.nodeLabel,
    start: node.recordStart,
    end: node.recordEnd,
    len: node.len,
    report: node.reportCode,
  })),
}));
""")
        self.assertEqual(result["headerLength"], 6)
        self.assertEqual(result["headerHex"], "02 aa 01 03 cd 02")
        self.assertTrue(result["complete"])
        self.assertEqual([node["label"] for node in result["nodes"]], ["child[0]", "child[1]"])
        self.assertEqual([node["report"] for node in result["nodes"]], [0x0112232E, 0x010A0009])
        self.assertEqual(result["nodes"][0]["start"], 6)
        self.assertEqual(result["nodes"][0]["end"], 6 + len(first))
        self.assertEqual(result["nodes"][1]["start"], 6 + len(first))

    def test_ace_layout_requires_closed_lengths_not_a_report_code_coincidence(self) -> None:
        valid = bytearray(_ace_record(0x0112232E, b"payload"))
        valid[4:6] = (len(valid) + 1).to_bytes(2, "big")
        accidental = b"header\x01\x12\x23\x2efooter"
        events = [
            _event(_typed_rpc("on_recv_client_data", _ace_body(bytes(valid)))),
            _event(_typed_rpc("on_recv_client_data", accidental)),
        ]
        result = self.run_js(events, r"""
console.log(JSON.stringify(events.map(event => {
  const info = analyzeGcloudEvent(event, event.summary);
  return pubgm17500AceLayout(info.typedRpc);
})));
""")
        self.assertEqual(result, [None, None])

    def test_ace_panel_renders_every_closed_node_with_existing_child_cards(self) -> None:
        first = _ace_record(0x0112232E, b"config2.dat")
        second = _ace_record(0x010A0009, b"\x01\x02\x03\x04")
        current = _typed_rpc("on_recv_client_data", _ace_body(first, second))
        event = _event(current)
        result = self.run_dom_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const rpc = info.typedRpc;
const layout = pubgm17500AceLayout(rpc);
const panel = pubgm17500AceChildPanel(null, rpc, null, layout);
console.log(JSON.stringify({
  cards: nodes(panel, 'child-pair-card').length,
  outer: nodes(panel, 'pubgm-ace-outer').length,
  text: text(panel),
}));
""")
        self.assertEqual(result["cards"], 2)
        self.assertEqual(result["outer"], 1)
        self.assertIn("child[0]", result["text"])
        self.assertIn("child[1]", result["text"])
        self.assertIn("0x0112232e", result["text"])
        self.assertIn("0x010a0009", result["text"])

    def test_tdreport_second_layer_decodes_word_mask_crc_and_fields(self) -> None:
        before = _tdreport_rpc([("Version", "1"), ("IsRoot", "0"), ("SysVer", "16.3.1")])
        after = _tdreport_rpc([("Version", "1"), ("IsRoot", "0"), ("SysVer", "27.0.1")])
        event = _event(after, before=before)
        event["summary"] += ",iphone17_17500_tdreport_rsa_md5_verified=1"
        result = self.run_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const before = parsePubgm17500TypedRpc(b64ToBytes(events[0].before_pay), info.meta);
const beforeLayer = pubgm17500TdreportLayer(before, events[0].summary);
const afterLayer = pubgm17500TdreportLayer(info.typedRpc, events[0].summary);
console.log(JSON.stringify({
  before: beforeLayer,
  after: afterLayer,
}));
""")
        self.assertTrue(result["before"]["valid"])
        self.assertTrue(result["after"]["valid"])
        self.assertTrue(result["after"]["maskRoundtrip"])
        self.assertTrue(result["after"]["crcMatch"])
        self.assertTrue(result["after"]["rsaMd5Verified"])
        self.assertEqual(result["after"]["signatureLength"], 256)
        self.assertEqual(
            {field["key"]: field["value"] for field in result["before"]["fields"]}["SysVer"],
            "16.3.1",
        )
        self.assertEqual(
            {field["key"]: field["value"] for field in result["after"]["fields"]}["SysVer"],
            "27.0.1",
        )

    def test_tdreport_panel_states_that_fields_are_not_ace_child_nodes(self) -> None:
        before = _tdreport_rpc([("Version", "1"), ("IsRoot", "0"), ("SysVer", "16.3.1")])
        after = _tdreport_rpc([("Version", "1"), ("IsRoot", "0"), ("SysVer", "27.0.1")])
        event = _event(after, before=before)
        result = self.run_dom_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const panel = pubgm17500RpcStructurePanel(events[0], info);
console.log(JSON.stringify({
  changed: nodes(panel, 'pubgm-tdreport-row-changed').length,
  text: text(panel),
}));
""")
        self.assertEqual(result["changed"], 1)
        self.assertIn("TDReport 二次解析", result["text"])
        self.assertIn("ACE 节点 0", result["text"])
        self.assertIn("SysVer", result["text"])
        self.assertIn("16.3.1", result["text"])
        self.assertIn("27.0.1", result["text"])

    def test_tdreport_panel_shows_multiline_hex_and_precise_tss_structure_verdict(self) -> None:
        report = _tdreport_rpc([("Version", "1"), ("IsRoot", "0"), ("SysVer", "27.0.1")])
        event = _event(report)
        result = self.run_dom_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
const layer = pubgm17500TdreportLayer(info.typedRpc, events[0].summary);
const panel = pubgm17500RpcStructurePanel(events[0], info);
console.log(JSON.stringify({
  inspection: nodes(panel, 'pubgm-tdreport-inspection').length,
  lines: nodes(panel, 'pubgm-tdreport-hex-line').length,
  maskedLength: layer.maskedLength,
  signatureOffset: `+0x${layer.maskedLength.toString(16).padStart(4, '0')}`,
  text: text(panel),
}));
""")
        self.assertEqual(result["inspection"], 1)
        self.assertGreater(result["lines"], 10)
        self.assertIn("属于安全上报，但不是普通 TSS child 记录封装", result["text"])
        self.assertIn("标准 TSS 记录头", result["text"])
        self.assertIn("不匹配", result["text"])
        self.assertIn("RSA/MD5 签名", result["text"])
        self.assertIn("+0x0000", result["text"])
        self.assertIn(result["signatureOffset"], result["text"])

    def test_ace_encrypted_node_renders_verified_second_layer_panel(self) -> None:
        envelope = bytearray.fromhex(
            "000000010055010a0037000000000000000000000108196d32fd0039"
            "f16c4aff1395d71ca64685e9c13a7a5d57b00452007523b70bc3e703"
            "55668025e56f3997e8f7742eb6177251c8d8c870dfb667c26fc75ac64c"
        )
        envelope[6:10] = bytes.fromhex("010a0009")
        event = _event(_typed_rpc("on_recv_client_data", _ace_body(bytes(envelope))))
        result = self.run_dom_js([event], r"""
const record = Array.from(new Uint8Array(Buffer.from(events[0].pay, 'base64')));
const info = analyzeGcloudEvent(events[0], events[0].summary);
const layout = pubgm17500AceLayout(info.typedRpc);
const child = childBytesFromParsed(info.typedRpc.body, layout.nodes[0]);
const nested = pubgm17500AceNestedPanel([], child, 'child[0]');
console.log(JSON.stringify({
  nested: nodes(nested, 'pubgm-ace-nested').length,
  cards: nodes(nested, 'child-pair-card').length,
  text: text(nested),
}));
""")
        self.assertEqual(result["nested"], 1)
        self.assertGreaterEqual(result["cards"], 1)
        self.assertIn("二次解密", result["text"])
        self.assertIn("CRC32 通过", result["text"])
        self.assertIn("0x010a005b", result["text"])

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

    def test_three_column_structure_has_narrow_width_overflow_guards(self) -> None:
        event = _event(
            _typed_rpc("on_recv_client_data", bytes(range(32))),
            before=_typed_rpc("on_recv_client_data", bytes(range(32))),
        )
        result = self.run_dom_js([event], r"""
const info = analyzeGcloudEvent(events[0], events[0].summary);
pubgm17500RpcStructurePanel(events[0], info);
const style = installed.find(item => item.id === 'tcpv-pubgm-17500-structure-style');
console.log(JSON.stringify({css: style ? style.textContent : ''}));
""")
        css = result["css"]
        self.assertIn("container-type:inline-size", css)
        self.assertIn(".pubgm-rpc-side{", css)
        self.assertIn("overflow:hidden", css)
        self.assertIn("@container (max-width:1500px)", css)
        self.assertIn(".pubgm-rpc-ascii{display:none}", css)


if __name__ == "__main__":
    unittest.main()
