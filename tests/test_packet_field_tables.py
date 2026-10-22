from __future__ import annotations

import base64
import json
import re
import subprocess
import unittest

from test_uagame_display_recovery import APP_JS, js_runtime


def _packet_function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    end = re.search(r"(?m)^}$", source[start:])
    if end is None:
        raise AssertionError(f"unterminated production function {name}")
    return source[start : start + end.end()]


class PacketFieldTableTests(unittest.TestCase):
    """Check generic display adapters; existing tests own protocol decoding."""

    @classmethod
    def setUpClass(cls) -> None:
        source = APP_JS.read_text(encoding="utf-8")
        cls.runtime = js_runtime() + "\n" + "\n".join(
            _packet_function(source, name)
            for name in (
                "packetFieldItem",
                "packetBasicFieldRows",
                "packetBasicCompare",
                "packetBeforePayloadForCompare",
                "packetCompareFieldRows",
            )
        ) + """
function fixtureRows(bytes) {
  const original = JSON.stringify(bytes);
  const rows = packetBasicFieldRows(bytes);
  if (JSON.stringify(bytes) !== original) throw new Error('display adapter mutated packet bytes');
  return rows;
}
function fixtureCompare(before, after, canCompare = true) {
  const left = before === null ? [] : fixtureRows(before);
  const right = fixtureRows(after);
  const original = JSON.stringify([left, right]);
  const result = packetCompareFieldRows(left, right, canCompare, 'fixture evidence boundary');
  if (JSON.stringify([left, right]) !== original) throw new Error('display comparison mutated rows');
  return result;
}
"""

    def evaluate(self, expression: str) -> dict | list:
        result = subprocess.run(
            ["node"],
            input=self.runtime + "\nconsole.log(JSON.stringify(" + expression + "));\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2400:])
        return json.loads(result.stdout)

    def rows(self, data: bytes) -> list:
        return self.evaluate(f"fixtureRows({json.dumps(list(data))})")

    def compare(self, before: bytes | None, after: bytes, *, can_compare: bool = True) -> dict:
        arguments = [list(before) if before is not None else None, list(after), can_compare]
        return self.evaluate(f"fixtureCompare(...{json.dumps(arguments)})")

    @staticmethod
    def by_key(rows: list) -> dict:
        return {row["key"]: row for row in rows}

    def test_unknown_bytes_preserve_the_entire_content_without_guessing_fields(self) -> None:
        data = b"\x00\xff\x81\x10\xfe\x02"
        rows = self.rows(data)
        by_key = self.by_key(rows)
        self.assertEqual(set(by_key), {"length", "content"})
        self.assertEqual(by_key["content"]["value"].replace(" ", "").lower(), data.hex())
        self.assertIn(str(len(data)), by_key["length"]["value"])
        self.assertEqual(len(rows), len(by_key), "display field keys must be unique")

    def test_readable_text_is_visible_and_original_bytes_remain_available(self) -> None:
        data = b"\x00hello world\xff"
        rows = self.rows(data)
        text_rows = [row for row in rows if row["key"].startswith("text[")]
        self.assertEqual(len(text_rows), 1)
        self.assertIn("hello world", text_rows[0]["value"])
        self.assertEqual(self.by_key(rows)["content"]["value"].replace(" ", "").lower(), data.hex())

    def test_same_length_different_text_and_content_are_changed_not_same(self) -> None:
        result = self.compare(b"\x00alpha text\xff", b"\x00bravo text\xff")
        by_key = self.by_key(result["rows"])
        self.assertTrue(result["canCompare"])
        self.assertEqual(by_key["length"]["status"], "same")
        self.assertEqual(by_key["content"]["status"], "changed")
        self.assertEqual(by_key["text[0]"]["status"], "changed")
        self.assertIn("alpha text", by_key["text[0]"]["before"]["value"])
        self.assertIn("bravo text", by_key["text[0]"]["after"]["value"])
        unchanged = self.compare(b"\x00same text\xff", b"\x00same text\xff")
        self.assertEqual({row["status"] for row in unchanged["rows"]}, {"same"})

    def test_length_change_keeps_one_stable_length_and_content_pair(self) -> None:
        result = self.compare(b"\x00\x81\xfe", b"\x00\x81\xfe\x02\xff")
        by_key = self.by_key(result["rows"])
        self.assertEqual(set(by_key), {"length", "content"})
        self.assertEqual(by_key["length"]["status"], "changed")
        self.assertEqual(by_key["content"]["status"], "changed")
        self.assertTrue(all(row["before"] and row["after"] for row in result["rows"]))

    def test_no_before_or_incomplete_evidence_shows_current_without_fake_additions(self) -> None:
        for before in (None, b"\x00old text\xff"):
            with self.subTest(before=before):
                result = self.compare(before, b"\x00current text\xff", can_compare=False)
                self.assertFalse(result["canCompare"])
                self.assertTrue(result["reason"])
                self.assertEqual({row["status"] for row in result["rows"]}, {"current"})
                self.assertTrue(all(row["before"] is None for row in result["rows"]))
                self.assertTrue(all(row["after"] is not None for row in result["rows"]))

    def test_json_paths_stay_aligned_after_longer_string_and_inserted_field(self) -> None:
        before = json.dumps({"os": "iOS", "count": 42, "nested": {"keep": "stable"}}).encode()
        after = json.dumps({"new": True, "os": "Harmony", "count": 42, "nested": {"keep": "stable"}}).encode()
        result = self.compare(before, after)
        fields = self.by_key(result["rows"])
        os_key = 'json:["os"]'
        count_key = 'json:["count"]'
        self.assertIn(os_key, fields)
        self.assertIn(count_key, fields)
        self.assertEqual(fields[os_key]["status"], "changed")
        self.assertEqual(fields[os_key]["before"]["value"], "iOS")
        self.assertEqual(fields[os_key]["after"]["value"], "Harmony")
        self.assertEqual(fields[count_key]["status"], "same")
        self.assertEqual(fields['json:["nested","keep"]']["status"], "same")
        self.assertEqual(fields['json:["new"]']["status"], "added")
        reverse = self.compare(after, before)
        self.assertEqual(self.by_key(reverse["rows"])['json:["new"]']["status"], "removed")

    def test_mixed_valid_invalid_json_uses_a_common_raw_display_boundary(self) -> None:
        for before, after in ((b'{"a":1}', b'{broken'), (b'{"a":9007199254740993}', b'{"a":1}')):
            result = self.evaluate(f"packetBasicCompare({list(before)}, {list(after)}, true)")
            self.assertFalse(any(row["key"].startswith("json:") for row in result["rows"]))
            self.assertTrue(any(row["key"] == "content" for row in result["rows"]))
            self.assertTrue(all(row["status"] in {"same", "changed"} for row in result["rows"]))

    def test_ordinary_capture_length_gate_applies_to_both_packet_directions(self) -> None:
        data = base64.b64encode(b"complete bytes").decode()
        for direction in (0, 1):
            event = {"dir": direction, "before_pay": data, "pay": data, "before_len": 100, "len": 14}
            self.assertEqual(self.evaluate("packetBeforePayloadForCompare(" + json.dumps(event) + ")"), "")
            event["before_len"] = 14
            self.assertEqual(self.evaluate("packetBeforePayloadForCompare(" + json.dumps(event) + ")"), data)
            event["len"] = 100
            self.assertEqual(self.evaluate("packetBeforePayloadForCompare(" + json.dumps(event) + ")"), "")
        source = APP_JS.read_text()
        self.assertIn("const canCompare = Boolean(packetBeforePayloadForCompare(ev))", source)

    def test_candidate_text_disappearing_is_not_a_confirmed_field_deletion(self) -> None:
        result = self.compare(b"readable text", b"\x00\xfe\xff\x01")
        texts = [row for row in result["rows"] if row["key"].startswith("text[")]
        self.assertTrue(texts)
        self.assertEqual({row["status"] for row in texts}, {"unmatched"})
        self.assertEqual(self.by_key(result["rows"])["content"]["status"], "changed")
    def test_specialized_tersafe_and_ace_renderers_match_the_original_baseline(self) -> None:
        import subprocess
        source = APP_JS.read_text()
        baseline = subprocess.check_output(["git", "show", "318789d:tcpv_mitm_emitter/app.js"], text=True)
        for name in ("makeChildCard", "buildChildComparePanel", "buildGcloudAceCarrierDeepPanel", "makeGcloudAceCompareStatus", "analyzeGcloudBeforeVariant", "appendGcloudReadableStrings"):
            self.assertEqual(_packet_function(source, name), _packet_function(baseline, name), name)
        security = _packet_function(source, "buildGcloudSecurityPacketPanel").replace("buildGcloudSecurityPacketPanel", "buildGcloudPacketPanel", 1)
        self.assertEqual(security, _packet_function(baseline, "buildGcloudPacketPanel"))
        self.assertIn('if (packetUsesSpecializedView(ev, summaryText, info)) return buildGcloudSecurityPacketPanel', source)
        self.assertIn('if (!modernView && isRequest && gcloudWireCompare)', source)
        self.assertIn('if (modernView) body.classList.add("packet-modern")', source)
        self.assertNotIn('function packetChildFieldRows(', source)
        self.assertNotIn('function packetChildComplete(', source)


if __name__ == "__main__":
    unittest.main()
