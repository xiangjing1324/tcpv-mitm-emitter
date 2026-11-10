from __future__ import annotations

import json
import subprocess
import unittest

from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS


class IdentityDigestHighlightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = APP_JS.read_text(encoding="utf-8")
        cls.runtime = r"""
class TestNode {
  constructor(tag) { this.tagName = tag; this.className = ''; this.textContent = ''; this.title = ''; this.children = []; }
  appendChild(child) { this.children.push(child); return child; }
}
const document = { createElement: tag => new TestNode(tag) };
function walk(node, predicate, out = []) {
  if (predicate(node)) out.push(node);
  for (const child of node.children || []) walk(child, predicate, out);
  return out;
}
function byClass(node, name) {
  return walk(node, item => String(item.className || '').split(/\s+/).includes(name));
}
function buildChildHexModel(_child, bytes) {
  const rows = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    rows.push({ offset, byteValues: bytes.slice(offset, offset + 16), changedIndexes: [], kind: '', note: '' });
  }
  return { rows, overlay: null, timestamps: [] };
}
function decryptDisplayableTssEnvelope() { return null; }
function detectTssReport(bytes) {
  return bytes[6] === 0x01 && bytes[7] === 0x02 && bytes[8] === 0x00 && bytes[9] === 0x0a
    ? { value: 0x0102000a, offset: 6 } : null;
}
function read0102000aLayout(bytes) { return { shift: 0, innerType: ((bytes[22] << 8) | bytes[23]) >>> 0 }; }
function xorByteValues(bytes, key) { return bytes.map(byte => (byte ^ key) & 0xff); }
function childUiTerm(value) { return value; }
function appendChildBodyLayoutPanel() {}
function childHexRowKindClass() { return ''; }
function childHexByteText(byte) { return Number(byte).toString(16).padStart(2, '0'); }
function hexOffsetText(offset) { return '+0x' + Number(offset).toString(16).padStart(2, '0'); }
function childTimestampDisplayFromNote() { return null; }
function normalizeVisibleText(value) { return String(value || ''); }
""" + _packet_function(source, "appendChildFullHexTable") + r"""
function fixture(identifier, digest, innerType = 0x8032) {
  const body = Array.from(identifier + ';' + digest, ch => ch.charCodeAt(0) ^ 0xb6);
  const bytes = Array(36).fill(0).concat(body, Array(12).fill(0));
  bytes[4] = (bytes.length >>> 8) & 0xff; bytes[5] = bytes.length & 0xff;
  bytes[6] = 0x01; bytes[7] = 0x02; bytes[8] = 0x00; bytes[9] = 0x0a;
  bytes[22] = (innerType >>> 8) & 0xff; bytes[23] = innerType & 0xff;
  const root = new TestNode('root');
  appendChildFullHexTable(root, {}, bytes);
  return root;
}
"""

    def run_js(self, expression: str) -> dict:
        result = subprocess.run(
            ["node"],
            input=self.runtime + "\nconsole.log(JSON.stringify(" + expression + "));\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        return json.loads(result.stdout)

    def test_exact_8032_shape_highlights_identifier_and_digest(self) -> None:
        identifier = "401558260549735717"
        digest = "07b3263b02eeabc360209b65183dab66"
        result = self.run_js(f"""(() => {{
          const root = fixture('{identifier}', '{digest}');
          const identityHex = byClass(root, 'child-hex-byte-cell-identity');
          const identityAscii = byClass(root, 'child-hex-ascii-cell-identity');
          const digestHex = byClass(root, 'child-hex-byte-cell-digest');
          const digestAscii = byClass(root, 'child-hex-ascii-cell-digest');
          return {{
            identityHex: identityHex.length,
            identityAscii: identityAscii.map(node => node.textContent).join(''),
            digestHex: digestHex.length,
            digestAscii: digestAscii.map(node => node.textContent).join(''),
            labels: byClass(root, 'child-hex-insight').map(node => node.children[0].textContent),
          }};
        }})()""")
        self.assertEqual(result["identityHex"], 18)
        self.assertEqual(result["identityAscii"], identifier)
        self.assertEqual(result["digestHex"], 32)
        self.assertEqual(result["digestAscii"], digest)
        self.assertEqual(result["labels"], ["18位标识", "32字符摘要"])

    def test_other_inner_type_and_wrong_length_are_not_highlighted(self) -> None:
        result = self.run_js("""(() => {
          const wrongType = fixture('401558260549735717', '07b3263b02eeabc360209b65183dab66', 0x8031);
          const wrongShape = fixture('40155826054973571', '07b3263b02eeabc360209b65183dab66');
          return {
            wrongType: byClass(wrongType, 'child-hex-byte-cell-identity').length,
            wrongShape: byClass(wrongShape, 'child-hex-byte-cell-identity').length,
          };
        })()""")
        self.assertEqual(result, {"wrongType": 0, "wrongShape": 0})


if __name__ == "__main__":
    unittest.main()
