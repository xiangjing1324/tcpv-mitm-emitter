from __future__ import annotations

import json
import subprocess
import unittest

import test_ace_node_focused_view as ace_view
from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS


class GcloudBytesViewTests(unittest.TestCase):
    """Exercise source selection and both actual clipboard implementations."""

    @classmethod
    def setUpClass(cls) -> None:
        ace_view.AceNodeFocusedViewTests.setUpClass()
        source = APP_JS.read_text(encoding="utf-8")
        # Restore the real GCloud field compositor, not a marker stand-in, so
        # these tests fail if compact mode drops useful fields or node contents.
        cls.runtime = ace_view.AceNodeFocusedViewTests.runtime + "\n" + "\n".join(
            _packet_function(source, name)
            for name in ("buildGcloudPacketPanel", "buildPacketBasicPanel")
        ) + r"""
function byteFixture() {
  return { summary: 'fixture decrypted', dir: 0,
    pay: gcloudBytesBase64([0, 17, 128, 255]), len: 4,
    before_pay: gcloudBytesBase64([1, 34, 129, 254]), before_len: 4,
    full_pay: gcloudBytesBase64([2, 51, 130, 253]), full_len: 4,
    raw_pay: gcloudBytesBase64([3, 68, 131, 252]), raw_len: 4 };
}
function plainHex(value) { return String(value).replace(/\s+/g, '').toLowerCase(); }
function one(root, cls) {
  const found = nodes(root, cls);
  assert(found.length === 1, 'expected exactly one ' + cls + ', got ' + found.length);
  return found[0];
}
"""

    def run_js(self, assertions: str) -> dict:
        script = self.runtime + "\n(async () => {\n" + assertions + "\n})().catch(error => { console.error(error); process.exitCode = 1; });"
        result = subprocess.run(["node"], input=script, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        return json.loads(result.stdout)

    def test_byte_sources_are_distinct_and_never_substitute_another_source(self) -> None:
        result = self.run_js(r"""
const ev = byteFixture(); const before = JSON.stringify(ev);
const sources = packetByteSources(ev, ev.summary);
assert(JSON.stringify(sources.map(source => source.key)) === JSON.stringify(['current', 'before', 'wireReceived', 'wireSent']), 'source mapping changed');
for (const [index, source] of sources.entries()) {
  assert(source.complete && source.status === 'complete' && source.actualLength === 4 && source.expectedLength === 4, source.key + ' completeness mismatch');
  assert(JSON.stringify(source.bytes) === JSON.stringify([[0,17,128,255], [1,34,129,254], [2,51,130,253], [3,68,131,252]][index]), source.key + ' source bytes changed');
  assert(plainHex(source.hex) === Buffer.from(source.bytes).toString('hex'), source.key + ' hex changed');
}
assert(JSON.stringify(ev) === before, 'display adapter mutated event');
assert(!sources[0].label.includes('解密') && !sources[3].label.includes('实际发送'), 'labels guessed decoding or sending without evidence');
assert(packetByteSources(ev, 'crypto=decrypted')[0].label.includes('解密'), 'explicit decoded evidence ignored');
assert(!packetByteSources(ev, '[OPAQUE] crypto=decrypted')[0].label.includes('解密'), 'opaque bytes were mislabeled as decrypted');
for (const summary of ['raw_pay_is_sent_wire=1', 'tcpview_after_source=raw_pay_sent_wire']) {
  assert(packetByteSources(ev, summary).find(source => source.key === 'wireSent').label.includes('实际发送'), 'explicit sent-wire evidence ignored');
}
const authoritative = { ...ev, analysis: { schema: 'tcpv.gcloud.analysis.v1', analysis_authoritative: true, transport: { decrypted: true } } };
assert(packetByteSources(authoritative, '')[0].label.includes('解密'), 'authoritative decoded evidence ignored');
const onlyWire = { full_pay: ev.full_pay, full_len: 4, len: 4 };
assert(JSON.stringify(packetByteSources(onlyWire, '').map(source => source.key)) === '["wireReceived"]', 'wire received data was relabeled as current/before');
assert(packetByteSources({}, '').length === 0, 'missing data fabricated a source');
console.log(JSON.stringify({sources: sources.length, unchanged: true}));
""")
        self.assertEqual(result, {"sources": 4, "unchanged": True})

    def test_payload_detail_and_cache_keep_current_declared_length(self) -> None:
        source = APP_JS.read_text(encoding="utf-8")
        functions = "\n".join(_packet_function(source, name) for name in (
            "buildPayloadCacheKey", "trimPayloadCache", "readPayloadCache", "writePayloadCache", "applyEventPayloadDetail"
        ))
        result = self.run_js(functions + r"""
const payloadCache = new Map(); let payloadCacheBytes = 0;
const PAYLOAD_CACHE_MAX_ENTRIES = 24; const PAYLOAD_CACHE_MAX_BYTES = 6 * 1024 * 1024;
const detail = { pay: gcloudBytesBase64([0,17,128,255]), len: 4 };
const ev = { pay: '', len: 99 };
assert(applyEventPayloadDetail(ev, detail) && ev.len === 4, 'payload detail retained stale current length');
assert(packetByteSources(ev, '')[0].complete, 'hydrated complete data was mislabeled truncated');
for (const len of [4, 9]) {
  writePayloadCache('fixture', 'event', { ...detail, len });
  const cached = readPayloadCache('fixture', 'event');
  assert(cached && cached.len === len, 'payload cache discarded declared current length');
  const restored = { pay: '', len: 99 };
  assert(applyEventPayloadDetail(restored, cached) && restored.len === len, 'cache hydration retained stale current length');
  const current = packetByteSources(restored, '')[0];
  assert(current.actualLength === 4 && current.expectedLength === len && current.complete === (len === 4), 'cache hydration changed completeness evidence');
}
console.log(JSON.stringify({lengthsPreserved: 2}));
""")
        self.assertEqual(result, {"lengthsPreserved": 2})

    def test_length_states_do_not_claim_missing_or_unproven_bytes_are_complete(self) -> None:
        result = self.run_js(r"""
for (const [expected, declared] of [['complete', 4], ['truncated', 9], ['mismatch', 2], ['unknown', undefined]]) {
  const ev = { pay: gcloudBytesBase64([0,17,128,255]) };
  if (declared !== undefined) ev.len = declared;
  const source = packetByteSources(ev, '')[0];
  assert(source.status === expected && source.actualLength === 4, expected + ' source state incorrect');
  assert(source.complete === (expected === 'complete'), expected + ' incorrectly marked complete');
  const panel = buildGcloudBytesPanel(ev, '');
  const button = one(panel, 'packet-byte-copy');
  assert(button.textContent === (source.complete ? '复制十六进制' : '复制已保存字节'), expected + ' misleading copy label');
  if (!source.complete) {
    const status = text(one(panel, 'packet-byte-status'));
    assert(status.includes('4') && !/^完整(?:[ ·，。]|$)/.test(status), expected + ' does not disclose saved-byte boundary');
    if (declared !== undefined) assert(status.includes(String(declared)), expected + ' omits declared length');
  }
}
const invalid = packetByteSources({ pay: '%%%not-base64%%%', len: 4 }, '')[0];
assert(invalid && invalid.status === 'invalid' && !invalid.complete && invalid.actualLength === 0, 'invalid encoded data fabricated valid bytes');
const invalidPanel = buildGcloudBytesPanel({ pay: '%%%not-base64%%%', len: 4, full_pay: gcloudBytesBase64([7,8]), full_len: 2 }, '');
assert(one(invalidPanel, 'packet-byte-source').value === 'current' && one(invalidPanel, 'packet-byte-copy').disabled, 'invalid current silently fell back to another stage');
assert(!one(invalidPanel, 'packet-byte-content').textContent, 'invalid current displayed another stage bytes');
const emptyPanel = buildGcloudBytesPanel({}, '');
assert(emptyPanel && one(emptyPanel, 'packet-byte-copy').disabled, 'no-data panel allows copying fabricated bytes');
const mixed = byteFixture(); mixed.before_len = 9; mixed.full_len = 2; delete mixed.raw_len;
const mixedPanel = buildGcloudBytesPanel(mixed, '');
for (const source of packetByteSources(mixed, '')) {
  const select = one(mixedPanel, 'packet-byte-source'); select.value = source.key; await select.emit('change');
  assert(one(mixedPanel, 'packet-byte-copy').textContent === (source.complete ? '复制十六进制' : '复制已保存字节'), source.key + ' stale completeness label after switching');
  if (!source.complete) assert(!/^完整(?:[ ·，。]|$)/.test(text(one(mixedPanel, 'packet-byte-status'))), source.key + ' stale complete status after switching');
}
console.log(JSON.stringify({states: 5, noData: true}));
""")
        self.assertEqual(result, {"states": 5, "noData": True})

    def test_one_fold_switches_and_copies_the_selected_exact_source(self) -> None:
        result = self.run_js(r"""
const ev = byteFixture(); ev.before_len = 9;
const panel = buildGcloudBytesPanel(ev, ev.summary);
assert(panel.tag === 'section' && panel.classList.contains('packet-byte-panel'), 'byte panel missing');
const select = one(panel, 'packet-byte-source'); const button = one(panel, 'packet-byte-copy');
const content = one(panel, 'packet-byte-content'); const fold = one(panel, 'packet-byte-fold');
assert(fold.tag === 'details' && !fold.open && content.tag === 'pre', 'bytes not in one collapsed content area');
assert(select.value === 'current' && select.children.length === 4, 'current is not the default source');
const copied = []; navigator.clipboard = { writeText: async value => { copied.push(value); } };
for (const source of packetByteSources(ev, ev.summary)) {
  select.value = source.key; await select.emit('change');
  assert(plainHex(content.textContent) === plainHex(source.hex), source.key + ' display retained stale bytes');
  await button.emit('click');
  assert(copied.at(-1) === source.hex, source.key + ' copied wrong bytes or display metadata');
  assert(/已复制|复制成功/.test(text(panel)), source.key + ' successful copy not confirmed');
  if (!source.complete) assert(text(panel).includes('仅已保存内容'), 'truncated copy was reported as complete data');
}
const beforeOnly = buildGcloudBytesPanel({ before_pay: ev.before_pay, before_len: 4 }, '');
assert(one(beforeOnly, 'packet-byte-source').value === 'before', 'missing current did not select first real source');
assert(nodes(panel, 'packet-byte-content').length === 1 && nodes(panel, 'packet-byte-fold').length === 1, 'switching duplicated byte views');
const largeBytes = Array.from({ length: 9000 }, (_, index) => index & 255);
const largeEvent = { pay: gcloudBytesBase64(largeBytes), len: largeBytes.length };
const largePanel = buildGcloudBytesPanel(largeEvent, '');
await one(largePanel, 'packet-byte-copy').emit('click');
assert(plainHex(copied.at(-1)) === Buffer.from(largeBytes).toString('hex'), 'copy silently capped a saved payload beyond 8KB');
assert(plainHex(one(largePanel, 'packet-byte-content').textContent) === plainHex(copied.at(-1)), 'large displayed bytes differ from copied bytes');
console.log(JSON.stringify({copied: copied.length, contentAreas: 1}));
""")
        self.assertEqual(result, {"copied": 5, "contentAreas": 1})

    def test_http_fallback_and_clipboard_rejection_copy_exact_text_and_remove_textarea(self) -> None:
        result = self.run_js(r"""
const copied = [];
document.execCommand = command => { assert(command === 'copy', 'unexpected browser command'); copied.push(document.selectedElement.value); return true; };
const expected = '00 80 ff 41';
delete navigator.clipboard; window.isSecureContext = false;
await copyPacketBytes(expected);
assert(copied.at(-1) === expected && !document.body.children.length, 'HTTP fallback copied wrong data or leaked textarea');
navigator.clipboard = { writeText: async () => { throw new Error('clipboard denied'); } }; window.isSecureContext = true;
await copyPacketBytes(expected + ' 42');
assert(copied.at(-1) === expected + ' 42' && !document.body.children.length, 'clipboard rejection did not use clean fallback');
console.log(JSON.stringify({fallbacks: copied.length, remainingTextareas: document.body.children.length}));
""")
        self.assertEqual(result, {"fallbacks": 2, "remainingTextareas": 0})

    def test_copy_failure_is_rejected_and_shown_without_false_success(self) -> None:
        result = self.run_js(r"""
navigator.clipboard = { writeText: async () => { throw new Error('clipboard denied'); } };
document.execCommand = () => false;
let rejected = false;
try { await copyPacketBytes('00 ff'); } catch (error) { rejected = true; }
assert(rejected && !document.body.children.length, 'copy falsely succeeded or leaked textarea');
const panel = buildGcloudBytesPanel(byteFixture(), '');
await one(panel, 'packet-byte-copy').emit('click');
assert(/复制失败|未能复制/.test(text(panel)), 'copy failure was not shown');
assert(!/已复制|复制成功/.test(text(panel)), 'copy failure was labeled success');
console.log(JSON.stringify({rejected, failureVisible: true}));
""")
        self.assertEqual(result, {"rejected": True, "failureVisible": True})

    def test_real_compact_gcloud_panels_preserve_fields_and_nodes_without_summary_cards(self) -> None:
        result = self.run_js(r"""
const label = 'retained-field-value'; const bytes = [8, 42, 18, label.length, ...Buffer.from(label)];
const parsed = parseGcloudProtoNodes(bytes, 0, bytes.length, 0, 240);
const proto = { nodes: parsed.nodes, flat: walkGcloudProtoNodes(parsed.nodes), viewBytes: bytes,
  sourceComplete: true, ok: parsed.ok, reason: '', commandName: 'CSAccountLoginReq', commandDisplay: 'CSAccountLoginReq' };
for (const kind of ['proto', 'ace', 'tss']) {
  const ev = fixture(kind, bytes, [], 'ace_ack'); ev.before_pay = ''; delete ev.before_len;
  ev.fixtureInfo.proto = proto; ev.fixtureInfo.protoBytes = bytes; ev.fixtureInfo.bytes = bytes;
  ev.fixtureInfo.nodeRows = []; ev.fixtureInfo.rows = []; ev.fixtureInfo.meta = {};
  const body = buildEventBody(ev, false);
  assert(nodes(body, 'gcloud-compare-row').length >= 2 && text(body).includes(label), kind + ' lost real fields');
  assert(nodes(body, 'gcloud-tree-details').length === 1, kind + ' lost raw field nodes');
  for (const cls of ['fixture-readable-summary', 'gcloud-kv-grid', 'gcloud-chip-list', 'gcloud-readable', 'gcloud-overview', 'dump-grid', 'ace-compare-status']) {
    assert(!nodes(body, cls).length, kind + ' retained duplicate ' + cls);
  }
  assert(nodes(body, 'packet-byte-panel').length === 1, kind + ' must have one byte picker');
  const nodeOnly = fixture(kind, bytes, [], 'ace_ack'); nodeOnly.before_pay = '';
  nodeOnly.fixtureInfo.nodeRows = [{ path: 'node[0]', value: 'retained-node-only-content' }];
  nodeOnly.fixtureInfo.rows = []; nodeOnly.fixtureInfo.meta = {};
  const nodeBody = buildEventBody(nodeOnly, false);
  assert(nodes(nodeBody, 'gcloud-node-row').length === 1 && text(nodeBody).includes('retained-node-only-content'), kind + ' dropped nodes without protobuf');
  const unparsed = fixture(kind, [0,255,17], [], 'ace_ack');
  unparsed.fixtureInfo.nodeRows = []; unparsed.fixtureInfo.rows = []; unparsed.fixtureInfo.meta = {};
  const unparsedBody = buildEventBody(unparsed, false);
  assert(nodes(unparsedBody, 'gcloud-note').some(note => text(note).includes('下方') && text(note).includes('原始字节')), kind + ' unparsed payload has no readable boundary note');
}
console.log(JSON.stringify({families: 3, retainedFields: true}));
""")
        self.assertEqual(result, {"families": 3, "retainedFields": True})


if __name__ == "__main__":
    unittest.main()
