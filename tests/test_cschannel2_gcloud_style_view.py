from __future__ import annotations

import json
import subprocess

from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS


def test_cs2_reuses_the_exact_gcloud_child_compare_component() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    panel = _packet_function(source, "buildCSChannel2Panel")
    shared = _packet_function(source, "buildChildComparePanel")
    adapter = _packet_function(source, "cs2SharedComparablePayload")

    assert 'buildChildComparePanel("", "", "", {' in panel
    assert "beforeParsed: beforeComparable.parsed" in panel
    assert "afterParsed: afterComparable.parsed" in panel
    assert "appendCS2TersafeRecords(" not in panel
    assert "appendCS2PairedFieldTable(" not in panel
    assert "appendCS2GcloudStylePair(" not in panel
    assert "ensureCS2TersafeCompactStyles(" not in panel
    assert 'panel.classList.add("cs2-panel")' in panel
    assert "suppliedBeforeBytes" in shared
    assert "panelOptions.beforeParsed" in shared
    assert "panelOptions.afterParsed" in shared
    assert "cs2SharedDeepestVerifiedBytes(raw)" in adapter


def test_shared_child_compare_renders_every_parsed_node() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    shared = _packet_function(source, "buildChildComparePanel")
    program = f"""
class Element {{
  constructor(tag) {{
    this.tag = tag;
    this.children = [];
    this.className = '';
    this.textContent = '';
    this.dataset = {{}};
    this.classList = {{ add: (...names) => {{
      this.className = [this.className, ...names].filter(Boolean).join(' ');
    }} }};
  }}
  appendChild(child) {{ this.children.push(child); return child; }}
}}
const document = {{ createElement: tag => new Element(tag) }};
function isOpaqueUndecryptedSummary() {{ return false; }}
function b64ToBytes() {{ return []; }}
function parseTssChildRecords() {{ return {{ children: [] }}; }}
function makeRootComparableNode() {{ return null; }}
function parseChildActionDetails() {{ return new Map(); }}
function parseSummaryKeyValues() {{ return {{}}; }}
function parseSummaryChildTimestampHints() {{ return new Map(); }}
function parseChildSummaryCounts() {{ return {{}}; }}
function makeParentStructureStrip() {{ return null; }}
function makeChildCard(_before, after, _beforeBytes, _afterBytes, index) {{
  const card = new Element('card');
  card.dataset.index = String(index);
  card.dataset.resource = String(after[index]?.resource || '');
  return card;
}}
{shared}
const children = Array.from({{ length: 14 }}, (_unused, index) => ({{
  index,
  resource: index === 11 || index === 13 ? 'mrpcs_i_j.data' : '',
}}));
const panel = buildChildComparePanel('', '', '', {{
  afterBytes: [1],
  beforeParsed: {{ children: [] }},
  afterParsed: {{ children }},
  forceCurrentOnly: true,
}});
const grid = panel.children.find(child => child.className === 'child-compare-grid');
const indexes = grid.children.map(child => Number(child.dataset.index));
const resources = grid.children.filter(child => child.dataset.resource).map(child => child.dataset.resource);
console.log(JSON.stringify({{ count: grid.children.length, indexes, resources }}));
"""
    result = subprocess.run(["node"], input=program, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    rendered = json.loads(result.stdout)
    assert rendered["count"] == 14
    assert rendered["indexes"] == list(range(14))
    assert rendered["resources"] == ["mrpcs_i_j.data", "mrpcs_i_j.data"]


def test_cs2_verified_handshake_uses_secret_free_status_labels() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    panel = _packet_function(source, "buildCSChannel2Panel")
    handshake_panel = _packet_function(source, "buildCS2HandshakePanel")
    handshake_view = _packet_function(source, "cs2HandshakePresentationView")
    handshake_node = _packet_function(source, "cs2HandshakeNodeSection")
    handshake_meta = _packet_function(source, "appendCS2HandshakeNodeMeta")
    summary = _packet_function(source, "buildCS2SummaryInsightStrip")
    display = _packet_function(source, "cs2SummaryDisplaySource")

    assert 'handshakeVerification.status === "verified"' in panel
    assert '"握手已验证"' in panel
    assert '"C8 RSA 块精确匹配"' in panel
    assert '"C8 业务 CRC 验证"' in panel
    assert "S8 字段已观察" in panel
    assert 'ticket 保持不透明' in panel
    assert 'handshakeVerified ? " · 已验证" : ""' in summary
    assert 'label: handshakeVerified ? "握手已验证" : "线上帧"' in display
    assert "handshake_verify=c8_" in summary
    assert "handshake_verify=c8_" in display
    assert "buildCS2HandshakePanel" in panel
    assert "if (handshakePanel) return handshakePanel" in panel
    assert "makeCS2TersafeRecordCard" in handshake_panel
    assert "appendCS2CurrentPlaintext" in handshake_panel
    assert 'title:"node[0] 预览"' in handshake_node
    assert "cs2FieldRows" in handshake_node
    assert "redacted:true" in handshake_node
    assert '["消息", role === "request" ? "握手 1" : "握手 2"' in handshake_meta
    assert '["用途", role === "request" ? "客户端请求握手"' in handshake_meta
    assert "cs2HandshakeFieldRow" not in source
    assert "cs2HandshakeStructureCard" not in source
    assert 'presentation.schema !== "tcpv.cschannel2.presentation.v1"' in handshake_view
    assert 'presentation.exact_partition !== true' in handshake_view
    for forbidden in ("c8_hex", "s8_hex", "c8_value", "s8_value"):
        assert forbidden not in panel
        assert forbidden not in handshake_panel

