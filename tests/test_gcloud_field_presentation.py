from __future__ import annotations

import json
import subprocess
import unittest

import test_ace_node_focused_view as ace_view
from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS, field


class GcloudFieldPresentationTests(unittest.TestCase):
    """Display-only labels/grouping must not manufacture protocol semantics."""

    @classmethod
    def setUpClass(cls) -> None:
        ace_view.AceNodeFocusedViewTests.setUpClass()
        cls.source = APP_JS.read_text(encoding="utf-8")
        baseline = subprocess.check_output(
            ["git", "show", "b6167a0:tcpv_mitm_emitter/app.js"], cwd=APP_JS.parent.parent, text=True
        )
        cls.runtime = ace_view.AceNodeFocusedViewTests.runtime + "\n" + "\n".join(
            _packet_function(baseline, name).replace(f"function {name}(", f"function baseline_{name}(", 1)
            for name in ("gcloudCompareLeafRows", "buildPacketFieldTable")
        ) + r"""
function protoFixture(bytes, options = {}) {
  const parsed = parseGcloudProtoNodes(bytes, 0, bytes.length, 0, 240);
  return { nodes: parsed.nodes, flat: walkGcloudProtoNodes(parsed.nodes), viewBytes: bytes,
    sourceComplete: true, ok: parsed.ok, reason: parsed.reason || '',
    commandName: 'CSAccountLoginRes', commandDisplay: 'CSAccountLoginRes', ...options };
}
function allElements(root) { return root ? [root, ...root.children.flatMap(allElements)] : []; }
function tableSnapshot(root) {
  return { ...snapshot(root), attrs: root.attributes, data: root.dataset,
    children: root.children.map(tableSnapshot) };
}
"""
        cls.compare_styles = _packet_function(cls.source, "installGcloudCompareStyles").replace(
            "function installGcloudCompareStyles(", "function actualInstallGcloudCompareStyles(", 1
        )

    def run_js(self, assertions: str) -> dict:
        script = self.runtime + "\n(async () => {\n" + assertions + "\n})().catch(error => { console.error(error); process.exitCode = 1; });"
        result = subprocess.run(["node"], input=script, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        return json.loads(result.stdout)

    def test_unconfirmed_login_response_fields_keep_numbers_for_actual_wire_shapes(self) -> None:
        body = b"".join((field(2, 18446744073709551615), field(3, b"sample label 20 text!"),
                         field(7, 36), field(16, b"\xff\x00\xfe"), field(23, 1),
                         field(6, b"https://qlogo.cn/confirmed-avatar")))
        result = self.run_js("const bytes = " + json.dumps(list(field(2, body))) + r""";
for (const commandName of ['CSAccountLoginRes', 'CSAccountLoginResB']) {
  const proto = protoFixture(bytes, { commandName, commandDisplay: commandName });
  const rows = gcloudCompareLeafRows(proto);
  for (const number of [2,3,7,16,23]) {
    const row = rows.find(item => item.path.join('.') === '2.' + number);
    assert(row, 'missing actual-shaped field ' + number);
    assert(gcloudUnconfirmedLoginResponseField(row.path, proto) === number, 'response protection missing ' + number);
    assert(gcloudProtoFieldAlias(row.path, row.node, proto) === '', 'unproven response alias ' + number);
    assert(row.label === `字段 ${number}（含义未确认）`, 'unproven response meaning ' + number);
    assert(gcloudSemanticPathText(row.path, proto, -1, row.node) === `body > f${number}`, 'unconfirmed semantic path invented a name');
  }
  const avatar = rows.find(item => item.path.join('.') === '2.6');
  assert(avatar && avatar.label === '头像地址' && gcloudProtoFieldAlias(avatar.path, avatar.node, proto) === 'avatar_url', 'previously recognized field 6 changed');
}
console.log(JSON.stringify({commands: 2, protectedFields: 5}));
""")
        self.assertEqual(result, {"commands": 2, "protectedFields": 5})

    def test_inducing_text_wrong_types_and_truncation_cannot_name_protected_fields(self) -> None:
        result = self.run_js(r"""
const proto = { commandName: 'CSAccountLoginRes', commandDisplay: 'CSAccountLoginRes' };
const examples = ['12345678901234567890', 'IOS17.4', 'itopid', 'GenericGPUBrand', 'https://example.invalid/qlogo.cn/photo'];
for (const number of [2,3,7,16,23]) {
  for (const wire of [0,1,2,5]) {
    for (const value of examples) {
      const node = { field: number, wire, string: value, truncated: wire === 5 };
      const before = JSON.stringify(node);
      assert(gcloudProtoFieldAlias([2,number], node, proto) === '', 'text/type bypassed alias protection');
      assert(gcloudCompareFieldLabel([2,number], node, proto) === `字段 ${number}（含义未确认）`, 'text/type bypassed table protection');
      assert(JSON.stringify(node) === before, 'label helper changed parsed bytes/type');
    }
  }
}
console.log(JSON.stringify({protectedFields: 5, inducingValues: examples.length}));
""")
        self.assertEqual(result, {"protectedFields": 5, "inducingValues": 5})

    def test_display_only_response_hint_can_only_downgrade_and_never_override_structured_command(self) -> None:
        result = self.run_js(r"""
const node = { field: 2, wire: 2, string: 'IOS17.4' };
for (const commandDisplay of ['CSAccountLoginRes', 'CSAccountLoginResB']) {
  const proto = { commandName: '', commandDisplay };
  assert(gcloudUnconfirmedLoginResponseField([2,2], proto) === 2, 'display-only response failed conservative protection');
  assert(gcloudCompareFieldLabel([2,2], node, proto) === '字段 2（含义未确认）', 'rough response hint confirmed a name');
}
for (const commandName of ['CSAccountLoginReq', 'CSAccountLoginReqB', 'CSOtherRes', 'CSAccountLoginResExtra', 'PrefixCSAccountLoginRes']) {
  const proto = { commandName, commandDisplay: 'CSAccountLoginRes' };
  assert(gcloudUnconfirmedLoginResponseField([2,2], proto) === null, 'display overrode structured command ' + commandName);
}
const request = { commandName: 'CSAccountLoginReq', commandDisplay: 'CSAccountLoginReq' };
assert(gcloudCompareFieldLabel([2,2], node, request) === '系统 / 版本', 'request heuristics changed');
for (const path of [[2,6], [3,2], [2,2,3], [2], []]) {
  assert(gcloudUnconfirmedLoginResponseField(path, { commandName: 'CSAccountLoginRes' }) === null, 'protection leaked to unrelated path');
}
assert(gcloudUnconfirmedLoginResponseField([2,2], { commandName: 'CSAccountLoginRes', uagameBody: true }) === null, 'CS labels leaked into UAGame body');
console.log(JSON.stringify({displayOnlyProtected: 2, structuredCommandsUnchanged: 5}));
""")
        self.assertEqual(result, {"displayOnlyProtected": 2, "structuredCommandsUnchanged": 5})

    def test_ancestor_metadata_preserves_repeated_keys_values_order_and_fingerprints(self) -> None:
        body = field(5, field(1, 10) + field(2, 20)) + field(5, field(1, 11) + field(2, 22))
        header = list(field(1, field(7, b"CSAccountLoginRes")))
        result = self.run_js("const header = " + json.dumps(header) + ";\nconst bytes = " + json.dumps(list(field(2, body))) + r""";
const proto = protoFixture(bytes, { commandName: 'CSOtherRes', commandDisplay: 'CSOtherRes' });
const rows = gcloudCompareLeafRows(proto);
const baseline = baseline_gcloudCompareLeafRows(proto);
assert(rows.length === 4, 'nested leaves changed');
assert(JSON.stringify(rows.map(({ ancestors, valueByteLength, occurrence, repeated, ...row }) => row)) === JSON.stringify(baseline), 'metadata changed comparison data or order');
for (const [index, row] of rows.entries()) {
  assert(row.ancestors.length === 2, 'missing full ancestor chain');
  const branch = index < 2 ? 0 : 1;
  assert(row.ancestors[0].key === '2[0]' && row.ancestors[1].key === `2[0].5[${branch}]`, 'repeated groups merged by numeric path');
  assert(row.ancestors[1].pathText === `f2.f5[${branch}]` && row.ancestors[1].occurrence === branch, 'repeated group identity lost');
  assert(row.ancestors[0].depth === 1 && row.ancestors[1].depth === 2, 'ancestor depth is not structural');
  for (const ancestor of row.ancestors) {
    assert(['key','path','pathText','label','depth','field','occurrence'].every(key => Object.hasOwn(ancestor, key)), 'ancestor contract incomplete');
  }
}
assert(rows.every(row => row.ancestors[0].label === '字段 2'), 'unproven envelope received a semantic body name');
const envelopeBytes = header.concat(bytes);
const envelope = analyzeGcloudProtoCandidate(envelopeBytes, 0, true); envelope.viewBytes = envelopeBytes;
const envelopeGroups = gcloudCompareLeafRows(envelope).flatMap(row => row.ancestors).filter(group => group.depth === 1);
assert(envelopeGroups.some(group => group.label === '消息头') && envelopeGroups.some(group => group.label === '业务正文'), 'proven command envelope lost structural names');
for (const variant of [{ ...envelope, uagameBody: true }, { ...envelope, commandField: { path: [9,7], node: { string: envelope.commandName } } }]) {
  assert(gcloudCompareLeafRows(variant).flatMap(row => row.ancestors).filter(group => group.depth === 1).every(group => /^字段 [12]$/.test(group.label)), 'unproven envelope gained structural names');
}
console.log(JSON.stringify({leavesUnchanged: 4, repeatedGroups: 2}));
""")
        self.assertEqual(result, {"leavesUnchanged": 4, "repeatedGroups": 2})

    def test_generic_json_and_raw_packet_tables_keep_previous_dom_without_groups(self) -> None:
        before_json = list(json.dumps({"a": 1, "nested": {"b": True}}).encode())
        after_json = list(json.dumps({"a": 2, "nested": {"b": True}}).encode())
        inputs = [[before_json, after_json], [[0, 255, 128, 17], [0, 255, 128, 18]]]
        result = self.run_js("const inputs = " + json.dumps(inputs) + r""";
for (const [before, after] of inputs) {
  const compare = packetBasicCompare(before, after, true);
  assert(compare.rows.every(row => !(row.before || row.after).ancestors), 'generic fields unexpectedly gained protocol ancestors');
  const panel = buildPacketFieldTable(compare, {});
  const baseline = baseline_buildPacketFieldTable(compare, {});
  assert(!nodes(panel, 'gcloud-field-group').length, 'GCloud groups leaked into generic table');
  assert(JSON.stringify(tableSnapshot(panel)) === JSON.stringify(tableSnapshot(baseline)), 'non-GCloud table changed');
}
console.log(JSON.stringify({unchangedTables: 2}));
""")
        self.assertEqual(result, {"unchangedTables": 2})

    def test_real_dom_groups_repeated_messages_preserves_leaves_and_filters_empty_groups(self) -> None:
        before = field(2, field(5, field(1, 10) + field(2, 20)) + field(5, field(1, 11) + field(2, 22)))
        after = field(2, field(5, field(1, 10) + field(2, 21)) + field(5, field(1, 11) + field(2, 22)))
        result = self.run_js(self.compare_styles + "\nconst input = " + json.dumps([list(before), list(after)]) + r""";
const compare = gcloudCompareRows(...input.map(bytes => protoFixture(bytes)));
const original = JSON.stringify(compare); const ev = {};
const panel = buildPacketFieldTable(compare, ev);
const groups = nodes(panel, 'gcloud-field-group'); const leaves = nodes(panel, 'gcloud-compare-row');
assert(panel.classList.contains('gcloud-field-hierarchy') && groups.length === 3, 'repeated message grouping missing');
assert(JSON.stringify(groups.map(group => group.dataset.groupKey)) === '["2[0]","2[0].5[0]","2[0].5[1]"]', 'repeated groups merged');
assert(JSON.stringify(groups.map(group => group.dataset.hasChanges)) === '["true","true","false"]', 'empty group visibility metadata incorrect');
assert(JSON.stringify(leaves.map(row => row.dataset.fieldPath)) === JSON.stringify(compare.rows.map(row => row.key)), 'leaf ordering/keys changed');
for (const [index, leaf] of leaves.entries()) {
  const row = compare.rows[index], item = row.after || row.before, cell = leaf.children[0];
  assert(cell.classList.contains('gcloud-field-cell') && cell.dataset.fieldPath === item.pathText && cell.title === item.pathText, 'full path no longer inspectable');
  assert(cell.children[1].textContent === gcloudFieldDisplayType(row.before || row.after), 'leaf subline repeats a full field path');
  assert(cell.style.paddingLeft === `${12 + item.ancestors.length * 14}px`, 'leaf hierarchy indentation missing');
  assert(text(leaf.children[1]) === row.before.value && text(leaf.children[2]) === row.after.value, 'display grouping changed a field value');
}
assert(JSON.stringify(compare) === original, 'DOM rendering mutated comparison evidence');
actualInstallGcloudCompareStyles(); const css = document.head.children.at(-1).textContent;
assert(/\.gcloud-field-hierarchy\[data-mode=changes\] \.gcloud-compare-same/.test(css), 'unchanged leaves are not filtered');
assert(/\.gcloud-field-hierarchy\[data-mode=changes\] \.gcloud-field-group\[data-has-changes=false\]\s*\{\s*display:\s*none/.test(css), 'empty unchanged groups are not filtered');
assert(panel.dataset.mode === 'changes', 'changed table did not default to differences');
const buttons = panel.querySelectorAll('button');
await buttons.find(button => button.textContent === '全部字段').emit('click');
assert(panel.dataset.mode === 'all' && ev.__tcpvFieldCompareMode === 'all', 'all-fields control failed');
await buttons.find(button => button.textContent.startsWith('只看变化')).emit('click');
assert(panel.dataset.mode === 'changes' && ev.__tcpvFieldCompareMode === 'changes', 'changes control failed');
const lengthCompare = gcloudCompareRows(protoFixture([18,15,26,13,...Buffer.from('before value!')]), protoFixture([18,22,26,20,...Buffer.from('after value is large')]));
const lengthLeaf = nodes(buildPacketFieldTable(lengthCompare), 'gcloud-compare-row')[0];
assert(text(lengthLeaf.children[0].children[1]).includes('13 字节 →') && text(lengthLeaf.children[0].children[1]).includes('20 字节'), 'same-type length change lost before/after lengths');
assert(/第\s*1\s*项/.test(text(groups[1])) && /第\s*2\s*项/.test(text(groups[2])), 'repeated group ordinal missing');
const scalarCompare = gcloudCompareRows(null, protoFixture([18,4,40,10,40,11]));
const scalarLeaves = nodes(buildPacketFieldTable(scalarCompare), 'gcloud-compare-row');
assert(scalarLeaves.length === 2 && /第\s*1\s*项/.test(text(scalarLeaves[0].children[0])) && /第\s*2\s*项/.test(text(scalarLeaves[1].children[0])), 'repeated scalar field ordinal missing');
console.log(JSON.stringify({groups: 3, unchangedLeafOrder: leaves.length, lengthTransition: true}));
""")
        self.assertEqual(result, {"groups": 3, "unchangedLeafOrder": 4, "lengthTransition": True})

    def test_reentering_ancestor_run_does_not_merge_a_b_a_groups(self) -> None:
        body = field(2, field(5, field(1, 10) + field(2, 20)) + field(5, field(1, 11) + field(2, 22)))
        result = self.run_js("const bytes = " + json.dumps(list(body)) + r""";
const items = gcloudCompareLeafRows(protoFixture(bytes));
const order = [items[0], items[2], items[1]];
const compare = { canCompare: true, hasBefore: true, reason: 'A/B/A fixture', rows: order.map((item,index) => ({ ...item, before:item, after:item, status:index === 0 ? 'same' : 'changed' })) };
const entries = gcloudFieldHierarchyEntries(compare);
const groups = entries.filter(entry => entry.group).map(entry => entry.group);
assert(JSON.stringify(groups.map(group => group.key)) === '["2[0]","2[0].5[0]","2[0].5[1]","2[0].5[0]"]', 'A/B/A groups merged across intervening branch');
assert(JSON.stringify(groups.map(group => [group.count,group.changeCount,group.hasChanges])) === '[[3,2,true],[1,0,false],[1,1,true],[1,1,true]]', 'A/B/A run counts or empty-group flags wrong');
assert(entries.filter(entry => entry.row).every((entry,index) => entry.row === compare.rows[index]), 'hierarchy rebuilt or reordered comparison rows');
const panel = buildPacketFieldTable(compare);
assert(JSON.stringify(nodes(panel,'gcloud-field-group').map(group => group.dataset.groupKey)) === JSON.stringify(groups.map(group => group.key)), 'DOM lost reopened A group');
assert(JSON.stringify(nodes(panel,'gcloud-compare-row').map(row => row.dataset.fieldPath)) === JSON.stringify(order.map(item => item.key)), 'A/B/A leaf order changed');
console.log(JSON.stringify({groupRuns: 4, leaves: 3}));
""")
        self.assertEqual(result, {"groupRuns": 4, "leaves": 3})

    def test_current_only_and_cross_command_groups_stay_visible_without_fake_changes(self) -> None:
        body = field(2, field(5, field(1, 10) + field(2, 20)) + field(5, field(1, 11) + field(2, 22)))
        result = self.run_js("const bytes = " + json.dumps(list(body)) + r""";
const after = protoFixture(bytes);
for (const before of [null, protoFixture(bytes, {commandName:'CSOtherRes',commandDisplay:'CSOtherRes'})]) {
  const compare = gcloudCompareRows(before, after);
  assert(!compare.canCompare && compare.rows.every(row => row.status === 'current' && row.before === null), 'missing/mismatched command fabricated differences');
  const entries = gcloudFieldHierarchyEntries(compare);
  assert(entries.filter(entry => entry.group).every(entry => entry.group.hasChanges && entry.group.changeCount === 0), 'current-only groups will be hidden or mislabeled changed');
  const panel = buildPacketFieldTable(compare, {__tcpvFieldCompareMode:'changes'});
  assert(nodes(panel,'gcloud-field-group').every(group => group.dataset.hasChanges === 'true'), 'saved changes mode hides current-only groups');
  assert(nodes(panel,'gcloud-compare-current').length > 0 && !nodes(panel,'gcloud-compare-changed').length, 'current rows mislabeled modified');
}
console.log(JSON.stringify({currentOnlyCases: 2}));
""")
        self.assertEqual(result, {"currentOnlyCases": 2})

    def test_real_uint64_decimal_and_hex_remain_exact_above_javascript_safe_integer(self) -> None:
        fixtures = [[list(field(2, field(2, value))), str(value), hex(value)]
                    for value in (9007199254740993, 18446744073709551615)]
        result = self.run_js("const fixtures = " + json.dumps(fixtures) + r""";
for (const [bytes, decimal, hex] of fixtures) {
  const original = JSON.stringify(bytes); const proto = protoFixture(bytes);
  const current = gcloudCompareLeafRows(proto)[0], baseline = baseline_gcloudCompareLeafRows(proto)[0];
  assert(current.node.valueText === decimal && current.node.valueHexText === hex, 'source parser lost uint64 precision');
  assert(current.value === `${decimal} (${hex})`, 'display rounded exact uint64 hexadecimal value');
  assert(current.key === baseline.key && current.fingerprint === baseline.fingerprint, 'uint64 display fix changed field identity or captured bytes');
  assert(JSON.stringify(bytes) === original, 'uint64 presentation changed payload');
}
console.log(JSON.stringify({exactUint64Values: fixtures.length}));
""")
        self.assertEqual(result, {"exactUint64Values": 2})


if __name__ == "__main__":
    unittest.main()
