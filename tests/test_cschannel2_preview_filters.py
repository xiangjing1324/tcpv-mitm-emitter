from __future__ import annotations

import subprocess

from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS


def test_report_filter_uses_every_saved_node_and_ignores_unverified_data() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    functions = "\n".join(_packet_function(source, name) for name in (
        "normalizeCS2ReportFilter", "isCSChannel2Event", "cs2IsModificationRow",
        "cs2HasSavedPlaintext", "cs2ValidPlaintextPresentation", "cs2ValidCoordinateTree",
        "cs2PlaintextBytes", "cs2VerifiedApplicationBytes", "cs2ReportCode",
        "cs2CompactReportCounts", "cs2SavedPreviewMetadata", "cs2GetSavedPreview",
        "cs2EventMatchesReport",
    ))
    script = r"""
const assert = require('node:assert/strict');
const cs2SavedPreviewCache = new WeakMap();
const b64ToBytes = value => [...Buffer.from(value, 'base64')];
const bytesFromHexPrefix = (value, cap) => [...Buffer.from(value || '', 'hex')].slice(0, cap);
const cs2VerifiedNestedRecord = () => null;
""" + functions + r"""
const appSpace = 'application_plaintext';
const innerSpace = 'tersafe_inner_plaintext';
const node = (name, offset, end, options = {}) => ({
  name, offset, end, length: end - offset, coordinate_space: appSpace,
  status: 'observed', kind: 'field', children: [], ...options,
});
const makeLayer = (report, file, depth, kind, crc32 = '0x12345678') => {
  const b = Buffer.alloc(16 + file.length);
  b.writeUInt32BE(1, 0); b.writeUInt16BE(b.length, 4); b.writeUInt32BE(report, 6);
  b.write(file, 16);
  const shape = {coordinate_space: innerSpace};
  const root = node('inner', 0, b.length, {...shape, kind:'container', children:[
    node('header', 0, 16, shape), node('file', 16, b.length, {...shape, encoding:'ascii', value:file}),
  ]});
  return {kind, crc32, depth, root, length:b.length,
    report_code:'0x' + report.toString(16).padStart(8, '0'), plaintext_b64:b.toString('base64')};
};
const deepLayer = makeLayer(0x010a0022, 'mrp_example.data', 2, 'decrypted');
const saved = {
  summary:'protocol=cschannel2 status=decoded', full_pay:Buffer.alloc(64).toString('base64'), full_len:64,
  analysis:{
    schema:'tcpv.cschannel2.analysis.v1',
    crypto:{decrypt_status:'crc_validated'}, validation:{crc_match:true},
    display_mapping:{full_pay:'snappy_decompressed_plaintext'},
    plaintext_presentation:{
      schema:'tcpv.cschannel2.plaintext-presentation.v1', source:'native_crc_validated_full_plaintext',
      coordinate_space:appSpace, actual_length:64, exact_partition:true,
      root:node('root', 0, 64, {kind:'container', children:[
        node('node[0]', 0, 32, {value:'report=0x010a0035', kind:'container', children:[
          node('observed text', 0, 32, {encoding:'ascii', value:'config2.dat report=0x010a0099'}),
        ]}),
        node('node[1]', 32, 64, {value:'report=0x010a0036', tersafe_layers:{
          schema:'tcpv.tersafe.layers.v1', layers:[
            makeLayer(0x010a0057, 'config2.dat', 1, 'structural'),
            deepLayer,
            makeLayer(0x010a0066, 'mrp_rejected.data', 2, 'decrypted', ''),
          ],
        }}),
      ]}),
    },
  },
};
assert.equal(normalizeCS2ReportFilter('01 0A 00 36'), '0x010a0036');
assert.equal(normalizeCS2ReportFilter('010a0036'), '0x010a0036');
assert.equal(normalizeCS2ReportFilter('0x010a0036'), '0x010a0036');
assert.equal(normalizeCS2ReportFilter('0x010a'), null);
assert.equal(normalizeCS2ReportFilter(''), '');
const metadata = cs2SavedPreviewMetadata(saved);
assert.deepEqual([...metadata.outer.keys()], ['0x010a0035', '0x010a0036']);
assert.deepEqual([...metadata.inner.keys()], ['0x010a0057', '0x010a0022']);
assert.deepEqual(metadata.files, ['config2.dat', 'mrp_example.data']);
assert.equal(cs2EventMatchesReport(saved, '0x010a0036'), true);
assert.equal(cs2EventMatchesReport(saved, '0x010a0022'), true);
assert.equal(cs2EventMatchesReport(saved, '0x010a0099'), false);
assert.equal(cs2EventMatchesReport(saved, '0x010a0066'), false);
const pending = [];
const compact = {summary:'protocol=cschannel2 status=decoded'};
const wireOnly = {summary:'protocol=cschannel2 status=fragment_pending', full_pfx:'010a0022'};
assert.equal(cs2EventMatchesReport(compact, '0x010a0022', pending), false);
assert.equal(cs2EventMatchesReport(wireOnly, '0x010a0022', pending), false);
assert.deepEqual(pending, [compact]);
const wrongCrc = {...saved, analysis:{...saved.analysis, validation:{crc_match:false}}};
assert.equal(cs2SavedPreviewMetadata(wrongCrc), null);
assert.equal(cs2EventMatchesReport(wrongCrc, '0x010a0022', pending), false);
"""
    result = subprocess.run(["node"], input=script, text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
