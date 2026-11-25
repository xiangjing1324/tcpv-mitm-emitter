from __future__ import annotations

import subprocess

from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS


def test_constructor_badge_uses_verified_producer_metadata_and_summary_fallback() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    functions = "\n".join(_packet_function(source, name) for name in (
        "cs2ConstructorEvidence", "cs2ConstructorLabel",
    ))
    script = r"""
const assert = require('node:assert/strict');
const isCSChannel2Event = ev => ev?.analysis?.schema === 'tcpv.cschannel2.analysis.v1';
""" + functions + r"""
const structured = {
  summary:'protocol=cschannel2',
  analysis:{
    schema:'tcpv.cschannel2.analysis.v1',
    response_constructor:{
      role:'manual_injection', profile:'v_tl_vv_no_account', status:'injected',
      report_code:'0x010a0057',
      resource_name:'mrpcs_i_v_tl.data + mrpcs_i_vv.data',
      archive_crc32:'0x79f81d31 + 0x9a31f0c7',
      request_id:'request-123', frame_length:183,
    },
  },
};
const evidence = cs2ConstructorEvidence(structured);
assert.equal(cs2ConstructorLabel(evidence), '构造 v_tl+vv');
assert.equal(evidence.reportCode, '0x010a0057');
assert.equal(evidence.frameLength, 183);
assert.equal(evidence.resourceName, 'mrpcs_i_v_tl.data + mrpcs_i_vv.data');

const compact = {summary:'protocol=cschannel2 constructor_role=manual_injection constructor_profile=vv constructor_status=injected constructor_report=0x010a0035 constructor_resource=mrpcs_i_vv.data constructor_crc32=0x9a31f0c7 constructor_request=abc123'};
const compactEvidence = cs2ConstructorEvidence(compact);
assert.equal(cs2ConstructorLabel(compactEvidence), '构造 vv');
assert.equal(compactEvidence.resourceName, 'mrpcs_i_vv.data');
const compactPair = {summary:'protocol=cschannel2 constructor_role=manual_injection constructor_profile=v_tl_vv_no_account constructor_resource=mrpcs_i_v_tl.data+mrpcs_i_vv.data constructor_crc32=0x79f81d31+0x9a31f0c7'};
assert.equal(cs2ConstructorEvidence(compactPair).resourceName, 'mrpcs_i_v_tl.data + mrpcs_i_vv.data');
assert.equal(cs2ConstructorLabel({profile:'v_tl'}), '构造 v_tl');
assert.equal(cs2ConstructorEvidence({summary:'protocol=cschannel2'}), null);
"""
    result = subprocess.run(["node"], input=script, text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr


def test_preview_strip_renders_constructor_chip_and_clear_relay_threshold_text() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    strip = _packet_function(source, "buildCS2SummaryInsightStrip")
    relay = _packet_function(source, "appendCS2RelayStatus")
    assert "cs2-summary-constructor" in strip
    assert "cs2ConstructorEvidence" in strip
    assert "OK123 手动构造并注入 8091" in strip
    assert ".cs2-summary-constructor" in source
    assert "实际 ${relay.frameLength} B · 转发门槛：大于 120 B" in relay
    assert "${relay.frameLength} B（>120 B）" not in relay
