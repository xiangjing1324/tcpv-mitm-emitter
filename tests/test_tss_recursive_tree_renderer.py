from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path


APP_JS = Path(__file__).resolve().parents[1] / "tcpv_mitm_emitter" / "app.js"


def _extract_function(source: str, name: str) -> str:
    match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", source)
    assert match, f"missing function {name}"
    start = match.start()
    brace = source.find("{", match.end())
    assert brace >= 0

    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    i = brace
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
        elif block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        elif ch == "/" and nxt == "/":
            line_comment = True
            i += 1
        elif ch == "/" and nxt == "*":
            block_comment = True
            i += 1
        elif ch in {'"', "'", "`"}:
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
        i += 1
    raise AssertionError(f"unterminated function {name}")


def test_0057_recursive_child_renderer_executes_and_keeps_string_rows(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        raise AssertionError("node is required for the focused TCPView renderer test")

    source = APP_JS.read_text(encoding="utf-8")
    # These literals guard the integration point that previously used undefined
    # identifiers (`div` and `gcloud-ace-recursive-tree-wrap`) at runtime.
    assert 'const treeWrap = document.createElement("div");' in source
    assert 'treeWrap.className = "gcloud-ace-recursive-tree-wrap";' in source

    functions = "\n\n".join(
        _extract_function(source, name)
        for name in (
            "tssRecurseNodeDisplayName",
            "renderTssRecursiveTree",
            "renderTssRecursiveNode",
        )
    )
    tree = {
        "status": "verified",
        "root": {
            "status": "verified",
            "name": "nested-unwrap-envelope",
            "carrier": "010a0008-envelope",
            "stage": "decrypted",
            "actualLen": 50,
            "declaredLen": 50,
            "depth": 0,
            "sourceOffset": 0,
            "reportCode": 0x010A0008,
            "xor": {
                "familyName": "family2_rc6",
                "slot": 8,
                "slotLabel": "slot8",
                "keySource": "dfm template slot",
                "keyConfidence": "crc32-verified",
            },
            "crc": {"match": True, "expected": "0x7230c263", "actual": "0x7230c263"},
            "plainLen": 22,
            "plainHex": "00 00 00 01 00 16 01 0a 00 57",
            "hex": "00 00 00 01 00 32 01 0a 00 08",
            "strings": [],
            "children": [
                {
                    "status": "verified",
                    "name": "file-config-sync",
                    "carrier": "direct",
                    "stage": "decrypted",
                    "actualLen": 22,
                    "declaredLen": 22,
                    "depth": 1,
                    "sourceOffset": 0,
                    "reportCode": 0x010A0057,
                    "hex": "00 00 00 01 00 16 01 0a 00 57",
                    "stringStatus": "candidate",
                    "strings": [{"offset": 10, "text": "hello-0057", "truncated": False}],
                    "children": [],
                }
            ],
        },
    }
    program = f"""
class Element {{
  constructor(tag) {{ this.tag = tag; this.children = []; this.className = ''; this.textContent = ''; this.open = false; }}
  appendChild(child) {{ this.children.push(child); return child; }}
}}
const createdTags = [];
const document = {{ createElement(tag) {{ createdTags.push(tag); return new Element(tag); }} }};
function formatHexValue(value, width) {{ return '0x' + Number(value).toString(16).padStart(Number(width || 0), '0'); }}
function hexOffsetText(value) {{ return '0x' + Number(value).toString(16); }}
{functions}
function collectText(node, out) {{
  if (!node) return;
  if (node.textContent) out.push(node.textContent);
  for (const child of node.children || []) collectText(child, out);
}}
const container = new Element('root');
const tree = {json.dumps(tree, ensure_ascii=False)};
renderTssRecursiveTree(tree, container);
const text = [];
collectText(container, text);
const joined = text.join('\\n');
if (!joined.includes('file-config-sync')) throw new Error('missing 0057 child name');
if (!joined.includes('report=0x010a0057')) throw new Error('missing 0057 report code');
if (!joined.includes('CRC32 匹配')) throw new Error('missing verified CRC line');
if (!joined.includes('hello-0057')) throw new Error('candidate string row was not appended');
if (!createdTags.every((tag) => typeof tag === 'string')) throw new Error('createElement received a non-string tag');
if (!container.children[0] || container.children[0].className !== 'tss-recursive-tree') throw new Error('tree wrapper missing');
console.log(JSON.stringify({{ ok: true, nodes: createdTags.length }}));
"""
    harness = tmp_path / "renderer-smoke.js"
    harness.write_text(program, encoding="utf-8")
    result = subprocess.run([node, str(harness)], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ok"] is True


def test_standalone_gcloud_tss_record_reuses_recursive_tree_without_duplicate_panel(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    if not node:
        raise AssertionError("node is required for the focused TCPView renderer test")

    source = APP_JS.read_text(encoding="utf-8")
    assert '0x010a0056: "report-0056"' in source
    assert '0x010a0037: "report-0037"' in source
    build_event = _extract_function(source, "buildEventBody")
    assert "isGcloudEvent && !gcloudSecurityDeepPanel" in build_event
    assert "buildGcloudStandaloneTssRecursivePanel(ev, summaryText)" in build_event

    function_source = _extract_function(source, "buildGcloudStandaloneTssRecursivePanel")
    program = f"""
class Element {{
  constructor(tag) {{ this.tag = tag; this.children = []; this.className = ''; }}
  appendChild(child) {{ this.children.push(child); return child; }}
}}
const document = {{ createElement(tag) {{ return new Element(tag); }} }};
let styleCalls = 0;
let renderCalls = 0;
function ensureChildCommonStyles() {{ styleCalls += 1; }}
function analyzeGcloudEvent(ev) {{ return ev.info; }}
function readBe16(bytes, offset) {{ return (bytes[offset] << 8) | bytes[offset + 1]; }}
function readBe32(bytes, offset) {{
  return (((bytes[offset] * 0x1000000) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3]) >>> 0);
}}
function isLikelyTssReportCode(value) {{ return ((Number(value) >>> 16) & 0xffff) === 0x010a; }}
function buildTssRecursiveDecodeTree(bytes) {{
  return {{ status: 'verified', root: {{ reportCode: readBe32(bytes, 6) }} }};
}}
function renderTssRecursiveTree(tree, container) {{
  renderCalls += 1;
  const child = new Element('tree');
  child.reportCode = tree.root.reportCode;
  container.appendChild(child);
}}
{function_source}
const record = [0,0,0,1,0,21,1,10,0,86,0,0,0,0,0,0,0,0,0,0,1];
const panel = buildGcloudStandaloneTssRecursivePanel({{ info: {{ protoBytes: record, bytes: record }} }}, '');
if (!panel) throw new Error('standalone tree was not rendered');
if (!panel.className.includes('gcloud-standalone-tss-recursive')) throw new Error('standalone class missing');
if (renderCalls !== 1 || styleCalls !== 1) throw new Error('tree was duplicated');
if (!panel.children[0] || panel.children[0].reportCode !== 0x010a0056) throw new Error('0056 report missing');
const negative = buildGcloudStandaloneTssRecursivePanel({{ info: {{ protoBytes: [1,2,3,4,5,6,7,8,9,10] }} }}, '');
if (negative !== null) throw new Error('non-compact payload created a false tree');
console.log(JSON.stringify({{ ok: true, renderCalls }}));
"""
    harness = tmp_path / "standalone-tss-tree.js"
    harness.write_text(program, encoding="utf-8")
    result = subprocess.run([node, str(harness)], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"ok": True, "renderCalls": 1}


def test_0111_crc_plaintext_is_recognized_and_exposes_structured_fields(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        raise AssertionError("node is required for the focused TCPView metadata test")

    source = APP_JS.read_text(encoding="utf-8")
    functions = "\n\n".join(
        _extract_function(source, name)
        for name in (
            "isLikelyTssReportCode",
            "detectTssReport",
            "tssStructuredMetadataInsights",
        )
    )
    program = f"""
function readBe32(bytes, offset) {{
  if (!Array.isArray(bytes) || offset < 0 || offset + 3 >= bytes.length) return NaN;
  return (((bytes[offset] * 0x1000000) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3]) >>> 0);
}}
function formatHexValue(value, width) {{ return '0x' + Number(value).toString(16).padStart(Number(width || 0), '0'); }}
{functions}
const bytes = new Array(280).fill(0);
bytes.splice(0, 10, 0, 0, 0, 1, 1, 24, 1, 0x11, 0x23, 0x88);
bytes[0x11] = 1;
bytes[0x30] = 0x50;
bytes[0x31] = 0x73;
function put(offset, text) {{
  for (let i = 0; i < text.length; i += 1) bytes[offset + i] = text.charCodeAt(i);
}}
put(0x35, 'cs:00000000/00000000,ob:46/dc/c4/0/5;inc_id:11;obf_id:11');
put(0x95, '15802830196042628030');
put(0xaf, 'state:00201135,r:0/0/0/0/0/0/0,p:14216/15032,0');
const report = detectTssReport(bytes);
if (!report || report.value !== 0x01112388 || report.offset !== 6) throw new Error('0x0111 report was not recognized');
const items = tssStructuredMetadataInsights(bytes, report.value);
const byKind = Object.fromEntries(items.map((item) => [item.kind, item]));
if (!byKind.marker || byKind.marker.value !== '0x5073') throw new Error('5073 marker missing');
if (!byKind.requestFlag || byKind.requestFlag.value !== '0x01') throw new Error('request flag missing');
if (!byKind.cs || byKind.cs.value !== '00000000/00000000') throw new Error('CS field missing');
if (!byKind.ob || byKind.ob.value !== '46/dc/c4/0/5') throw new Error('OB field missing');
if (!byKind.incId || byKind.incId.value !== '11') throw new Error('inc_id missing');
if (!byKind.obfId || byKind.obfId.value !== '11') throw new Error('obf_id missing');
if (!byKind.account || byKind.account.value !== '15802830196042628030') throw new Error('AccountID missing');
if (!byKind.state || byKind.state.value !== '00201135') throw new Error('state missing');
if (!byKind.r || byKind.r.value !== '0/0/0/0/0/0/0') throw new Error('r missing');
if (!byKind.p || byKind.p.value !== '14216/15032,0') throw new Error('p missing');
console.log(JSON.stringify({{ ok: true, report: report.value, fields: items.length }}));
"""
    harness = tmp_path / "metadata-0111.js"
    harness.write_text(program, encoding="utf-8")
    result = subprocess.run([node, str(harness)], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    parsed = json.loads(result.stdout)
    assert parsed["ok"] is True
    assert parsed["report"] == 0x01112388
    assert parsed["fields"] >= 10


def test_structured_metadata_hides_only_duplicate_ascii_summary(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        raise AssertionError("node is required for the focused TCPView metadata test")

    source = APP_JS.read_text(encoding="utf-8")
    assert 'add("requestFlag", "请求标志", 0x11' in source
    assert 'offset.className = "child-hex-insight-offset";' in source
    functions = "\n\n".join(
        _extract_function(source, name)
        for name in (
            "tssStructuredMetadataInsights",
            "childOverlayRunDuplicatesStructuredMetadata",
        )
    )
    program = f"""
function formatHexValue(value, width) {{ return '0x' + Number(value).toString(16).padStart(Number(width || 0), '0'); }}
function normalizeVisibleText(value) {{ return String(value || '').replace(/\\s+/g, ' ').trim(); }}
{functions}
const bytes = new Array(280).fill(0);
bytes.splice(0, 10, 0, 0, 0, 1, 1, 24, 1, 0x11, 0x23, 0x88);
bytes[0x11] = 1;
bytes[0x30] = 0x50;
bytes[0x31] = 0x73;
function put(offset, text) {{
  for (let i = 0; i < text.length; i += 1) bytes[offset + i] = text.charCodeAt(i);
}}
put(0x35, 'cs:00000000/00000000,ob:46/dc/c4/0/5;inc_id:11;obf_id:11');
put(0x95, '15802830196042628030');
put(0xaf, 'state:00201135,r:0/0/0/0/0/0/0,p:14216/15032,0');
const items = tssStructuredMetadataInsights(bytes, 0x01112388);
const duplicateRuns = [
  {{text: 'cs:00000000/00000000,ob:46/dc/c4/0/5;inc_id:11;obf_id:11'}},
  {{text: '15802830196042628030'}},
  {{text: 'state:00201135,r:0/0/0/0/0/0/0,p:14216/15032,0'}},
];
if (!duplicateRuns.every((run) => childOverlayRunDuplicatesStructuredMetadata(run, items))) {{
  throw new Error('known structured ASCII was not suppressed');
}}
const usefulRuns = [
  {{text: 'model:iPad14,5;ver:16.10;inc_id:11;obf_id:11'}},
  {{text: 'config2.dat'}},
  {{text: 'unparsed-extra-text'}},
];
if (usefulRuns.some((run) => childOverlayRunDuplicatesStructuredMetadata(run, items))) {{
  throw new Error('useful unknown ASCII was suppressed');
}}
console.log(JSON.stringify({{ok: true, fields: items.length}}));
"""
    harness = tmp_path / "structured-metadata-dedupe.js"
    harness.write_text(program, encoding="utf-8")
    result = subprocess.run([node, str(harness)], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    parsed = json.loads(result.stdout)
    assert parsed["ok"] is True
    assert parsed["fields"] >= 10
