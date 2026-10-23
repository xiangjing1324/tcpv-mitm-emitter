from __future__ import annotations

import json
import re
import subprocess
import unittest

from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS, js_runtime


class AceNodeFocusedViewTests(unittest.TestCase):
    """Run real DOM composition/cards/tree; inject only protocol and host edges."""

    @classmethod
    def setUpClass(cls) -> None:
        source = APP_JS.read_text(encoding="utf-8")
        names = re.findall(r"^function (\w+)\(", source, re.M)
        pending = ["buildEventBody", "buildGcloudAceCarrierDeepPanel"]
        extracted: dict[str, str] = {}
        while pending:
            name = pending.pop()
            if name in extracted:
                continue
            function = _packet_function(source, name)
            extracted[name] = function
            pending.extend(candidate for candidate in names if candidate not in extracted
                           and re.search(r"\b" + candidate + r"\s*\(", function))
        constants = []
        for name in ("XOR_COMMON_KEYS", "TSS_PARENT_TRAILER_MAGIC_HEX", "TSS_RECURSE_MAX_DEPTH", "TSS_RECURSE_MAX_NODES",
                     "TSS_RECURSE_MAX_CHILDREN", "TSS_RECURSE_MAX_HEX_BYTES", "TSS_RECURSE_MAX_STRING_LEN",
                     "TSS_RECURSE_KEY_SOURCE", "TSS_RECURSE_KEY_CONFIDENCE", "TIMESTAMP_SECONDS_MIN", "TIMESTAMP_SECONDS_MAX"):
            constants.append(re.search(rf"^const {name} = .+;.*$", source, re.M).group())
        for name, closing in (("XOR_TEXT_KEYWORDS", "\n];"), ("XOR_KEY_PRIORITY", "\n]);"),
                              ("KNOWN_0102000A_TIMESTAMP_LAYOUTS", "\n];")):
            start = source.index(f"const {name} = ")
            constants.append(source[start:source.index(closing, start) + len(closing)])
        start = source.index("const TSS_RECURSE_REPORT_NAMES = {")
        constants.append(source[start:source.index("\n};", start) + 3])
        baseline = subprocess.check_output(
            ["git", "show", "238c740:tcpv_mitm_emitter/app.js"], text=True, cwd=APP_JS.parent.parent
        )
        baseline_functions = "\n".join(
            _packet_function(baseline, name).replace(f"function {name}(", f"function baseline_{name}(", 1)
            for name in ("buildEventBody", "buildGcloudAceCarrierDeepPanel")
        )
        # Reuse the parser/display Node harness. No browser bootstrap or network
        # is executed. Card and recursive-tree renderers remain production code.
        cls.runtime = "\n".join([
            js_runtime(), *constants, *extracted.values(), baseline_functions,
            r"""
class Element {
  constructor(tag) {
    this.tag = tag; this.children = []; this.className = ''; this.textContent = '';
    this.innerHTML = ''; this.open = false; this.style = {}; this.dataset = {};
    this.classList = {
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(' '); },
      contains: name => this.className.split(/\s+/).includes(name),
    };
  }
  get childNodes() { return this.children; }
  appendChild(child) { this.children.push(child); return child; }
  insertBefore(child, target) {
    const index = this.children.indexOf(target);
    if (index < 0) this.children.push(child); else this.children.splice(index, 0, child);
    return child;
  }
  addEventListener() {}
  setAttribute(name, value) { this[name] = value; }
}
const document = {
  createElement: tag => new Element(tag),
  createTextNode: text => Object.assign(new Element('#text'), { textContent: text }),
  getElementById: () => null,
};
function marker(cls, text) {
  const el = new Element('section'); el.className = cls; el.textContent = text; return el;
}
function nodes(root, cls) {
  if (!root) return [];
  return [...(root.classList.contains(cls) ? [root] : []), ...root.children.flatMap(child => nodes(child, cls))];
}
function text(root) { return root ? [root.textContent, ...root.children.map(text)].filter(Boolean).join('\n') : ''; }
function snapshot(root) {
  if (!root) return null;
  return { tag: root.tag, cls: root.className, text: root.textContent, html: root.innerHTML,
    title: root.title || '', open: root.open, children: root.children.map(snapshot) };
}
function assert(condition, message) { if (!condition) throw new Error(message); }
function record(report, label = '') {
  const bytes = [0,0,0,1,0,0, (report >>> 24)&255, (report >>> 16)&255, (report >>> 8)&255, report&255,
    ...Array(10).fill(0), ...Buffer.from(label)];
  bytes[4] = bytes.length >>> 8; bytes[5] = bytes.length & 255; return bytes;
}
function container(children) {
  const bytes = record(0x010a001b);
  bytes.push(children.length);
  for (const child of children) bytes.push(child.length & 255, child.length >>> 8, 0, 0, ...child);
  bytes[4] = bytes.length >>> 8; bytes[5] = bytes.length & 255; return bytes;
}
const encryptedFixtures = new Map();
function decryptTssEncryptedEnvelope(bytes) { return encryptedFixtures.get(gcloudBytesBase64(bytes)) || null; }
function decryptDisplayableTssEnvelope(bytes) { return decryptTssEncryptedEnvelope(bytes); }
function fixture(kind = 'ace', payload = record(0x010a0057, 'keep-all-content'), before = payload, commandKind = 'ace_antidata') {
  const command = { kind: commandKind, commandName: 'CSAceSendAntiDataNtf',
    carrier: { payload, mode: 'binary_carrier', sourceKind: 'binary', profile: 'fixture-profile' } };
  return { dir: 0, len: payload.length, before_len: before.length, summary: 'fixture decoded',
    pay: gcloudBytesBase64(payload), before_pay: gcloudBytesBase64(before),
    full_pay: gcloudBytesBase64([0,1,2]), raw_pay: gcloudBytesBase64([0,1,3]),
    fixtureGcloud: true, fixtureInfo: { kind, [kind]: command }, fixtureBefore: before };
}
function analyzeGcloudEvent(ev) { return ev.fixtureInfo; }
function analyzeGcloudBeforeSecurityVariant(ev) {
  return ev.fixtureBefore.length ? { carrier: { payload: ev.fixtureBefore }, command: {} } : null;
}
function ensureChildCommonStyles() {}
function installGcloudCompareStyles() {}
function isOpaqueUndecryptedSummary() { return false; }
function isGcloud65010Summary(_summary, ev) { return ev.fixtureGcloud; }
function isWssJsonSummary() { return false; }
function packetUsesSpecializedView(ev, _summary, info) { return !ev.fixtureGcloud || ['ace', 'tss'].includes(info && info.kind); }
function buildEventReadableSummary() { return marker('fixture-readable-summary', 'duplicate readable summary'); }
function buildGcloudPacketPanel(ev) { return ev.fixtureGcloud ? marker('fixture-gcloud-panel', 'outer protocol cards and strings') : null; }
function buildPacketBasicPanel() { return marker('fixture-basic', 'ordinary bytes'); }
function buildEventAnalysisGrid() { return null; }
function buildTreeCompareRow() { return null; }
function isDecodedFlowEvent() { return true; }
function gcloudSummaryHasBackendRebuild() { return true; }
function gcloudSummaryHasSentWireChange() { return true; }
function currentFlowLooksLikePort8092() { return false; }
function eventModificationDiffText() { return { detail: 'backend sent proof' }; }
function buildEventTimestampStrip() { return null; }
function findTrailingChecksumCandidate() { return null; }
function mergeTimestampHighlightItems() { return []; }
function collectTimestampHighlightsForPayload() { return []; }
function collectChildTimestampHighlightsForPayload() { return []; }
function collectIdfvHighlightsForPayload() { return []; }
function collectHistoryOpenidHighlightsForPayload() { return []; }
function collectPacketSemanticInfoForPayload() { return null; }
function summarizeTimestampHighlights() { return ''; }
function mergeDumpAnnotationIndexes() { return new Map(); }
function buildPacketSemanticAnnotationIndex() { return new Map(); }
function buildTimestampAnnotationIndex() { return new Map(); }
function getBytesPerRow() { return 16; }
function formatHexDump() { return { header: 'raw bytes' }; }
function renderHexBodyHtml() { return 'raw byte content'; }
function attachDumpScrollPersistence() {}
function makeDumpScrollKey() { return ''; }
""",
        ])

    def run_js(self, assertions: str) -> dict:
        result = subprocess.run(["node"], input=self.runtime + "\n" + assertions,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-3500:])
        return json.loads(result.stdout)

    def test_compact_preserves_all_second_third_layer_cards_and_recursive_content(self) -> None:
        result = self.run_js(r"""
const plain = container([record(0x010a0057, 'first-child-content'), record(0x010a005f, 'second-child-content')]);
const outer = record(0x010a0008, 'outer-child-content');
encryptedFixtures.set(gcloudBytesBase64(outer), {
  supported: true, crcMatch: true, family: 2, familyName: 'family2_rc6', slot: 8,
  expectedCrc: 123, actualCrc: 123, cipherLength: 32, plain,
  innerRoot: { value: 0x010a001b, offset: 6 },
});
const ev = fixture('ace', outer);
const full = buildGcloudAceCarrierDeepPanel(ev, ev.summary);
const compact = buildGcloudAceCarrierDeepPanel(ev, ev.summary, { compact: true });
for (const cls of ['child-pair-card', 'tss-recursive-tree']) {
  assert(JSON.stringify(nodes(full, cls).map(snapshot)) === JSON.stringify(nodes(compact, cls).map(snapshot)), cls + ' changed');
}
assert(nodes(compact, 'child-pair-card').length === 3, 'second/third-layer cards missing');
assert(nodes(compact, 'child-preview-before').length === 3, 'before columns missing');
assert(nodes(compact, 'child-preview-after').length === 3, 'after columns missing');
const recursive = nodes(compact, 'tss-recursive-node');
assert(recursive.length === 4 && recursive[0].open && recursive.slice(1).every(node => !node.open), 'recursive expansion changed');
assert(text(compact).includes('first-child-content') && text(compact).includes('second-child-content'), 'child strings missing');
assert(nodes(full, 'ace-deep-lineage').length === 1 && nodes(full, 'ace-compare-status').length > 0, 'legacy control was not exercised');
assert(!nodes(compact, 'ace-deep-lineage').length && !nodes(compact, 'ace-compare-status').length, 'duplicate long explanations remain');
assert(!nodes(compact, 'tss-crypto-status').length, 'duplicate successful decode status remains');
console.log(JSON.stringify({cards: 3, recursive: recursive.length}));
""")
        self.assertEqual(result, {"cards": 3, "recursive": 4})

    def test_body_suppresses_duplicates_and_collapses_raw_bytes_only_for_real_ace_panel(self) -> None:
        result = self.run_js(r"""
for (const commandKind of ['ace_antidata', 'ace_light', 'ace_transfer']) {
  const ev = fixture('ace', undefined, undefined, commandKind);
  const body = buildEventBody(ev, false);
  assert(nodes(body, 'gcloud-ace-deep').length === 1, commandKind + ' missing deep panel');
  for (const cls of ['fixture-readable-summary', 'fixture-gcloud-panel', 'ace-deep-lineage', 'ace-compare-status']) {
    assert(!nodes(body, cls).length, commandKind + ' retained ' + cls);
  }
  const fold = nodes(body, 'gcloud-technical-details').find(node => nodes(node, 'dump-grid').length);
  assert(fold && !fold.open && text(fold).includes('原始字节 / 加密封包'), 'raw bytes must remain collapsed and available');
}
console.log(JSON.stringify({families: 3}));
""")
        self.assertEqual(result, {"families": 3})

    def test_missing_root_keeps_opaque_child_and_missing_deep_panel_falls_back(self) -> None:
        result = self.run_js(r"""
const opaque = buildEventBody(fixture('ace', [...Buffer.from('opaque-carrier-content')]), false);
assert(nodes(opaque, 'child-pair-card').length === 1 && text(opaque).includes('opaque-carrier-content'), 'opaque ACE content disappeared');
assert(!nodes(opaque, 'fixture-gcloud-panel').length, 'opaque carrier did not use compact view');
const empty = fixture('ace', [], []);
const fallback = buildEventBody(empty, false);
assert(nodes(fallback, 'fixture-readable-summary').length === 1, 'empty ACE lost readable fallback');
assert(nodes(fallback, 'fixture-gcloud-panel').length === 1, 'empty ACE lost outer fallback');
assert(!nodes(fallback, 'gcloud-security-deep-stack').length, 'empty carrier fabricated a deep panel');
const noDeep = buildEventBody(fixture('ace', undefined, undefined, 'ace_ack'), false);
assert(nodes(noDeep, 'fixture-readable-summary').length === 1 && nodes(noDeep, 'fixture-gcloud-panel').length === 1, 'ACE without supported deep kind lost fallback');
console.log(JSON.stringify({opaqueCards: 1, fallback: true}));
""")
        self.assertEqual(result, {"opaqueCards": 1, "fallback": True})

    def test_compact_keeps_unsupported_crypto_and_crc_failure_visible(self) -> None:
        result = self.run_js(r"""
for (const supported of [false, true]) {
  const outer = record(0x010a0008, 'failed-envelope');
  encryptedFixtures.set(gcloudBytesBase64(outer), { supported, crcMatch: false,
    familyName: 'family2_rc6', slot: 8, cipherLength: 32, expectedCrc: 1, actualCrc: 2,
    reason: 'fixture unsupported', plain: [],
  });
  const ev = fixture('ace', outer);
  const panel = buildGcloudAceCarrierDeepPanel(ev, ev.summary, { compact: true });
  assert(nodes(panel, 'tss-crypto-status-error').length === 1, 'crypto failure was hidden');
  assert(text(panel).includes(supported ? '失败' : '未解密'), 'failure detail was hidden');
}
console.log(JSON.stringify({failures: 2}));
""")
        self.assertEqual(result, {"failures": 2})

    def test_non_ace_gcloud_and_standalone_tersafe_match_previous_composition(self) -> None:
        result = self.run_js(r"""
const ordinary = fixture('business', undefined, undefined, 'ordinary');
const tss = fixture('tss');
const standalone = fixture('tss'); standalone.fixtureGcloud = false;
for (const ev of [ordinary, tss, standalone]) {
  assert(JSON.stringify(snapshot(buildEventBody(ev, false))) === JSON.stringify(snapshot(baseline_buildEventBody(ev, false))), 'non-ACE body changed');
}
assert(JSON.stringify(snapshot(buildGcloudAceCarrierDeepPanel(tss, tss.summary))) ===
  JSON.stringify(snapshot(baseline_buildGcloudAceCarrierDeepPanel(tss, tss.summary))), 'default TSS deep panel changed');
assert(nodes(buildEventBody(standalone, false), 'child-pair-card').length > 0, 'standalone TerSafe child control did not execute');
console.log(JSON.stringify({unchanged: 3}));
""")
        self.assertEqual(result, {"unchanged": 3})


if __name__ == "__main__":
    unittest.main()
