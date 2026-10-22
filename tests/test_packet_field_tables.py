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
                "packetChildComplete",
                "packetChildFieldRows",
                "packetCompareFieldRows",
            )
        ) + """
let fixtureChildFields = [];
function childHexStructure(child, bytes) {
  return {fields: fixtureChildFields, annotations: new Map(), valueStart: null};
}
function fixtureRows(bytes, childFields = null) {
  const original = JSON.stringify(bytes);
  fixtureChildFields = childFields || [];
  const rows = childFields === null ? packetBasicFieldRows(bytes)
    : packetChildFieldRows({reportCode: 0x010a0056}, bytes);
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

    def rows(self, data: bytes, fields: list | None = None) -> list:
        return self.evaluate(f"fixtureRows({json.dumps(list(data))},{json.dumps(fields)})")

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

    def test_tersafe_capture_length_gate_applies_to_both_packet_directions(self) -> None:
        data = base64.b64encode(b"complete bytes").decode()
        for direction in (0, 1):
            event = {"dir": direction, "before_pay": data, "pay": data, "before_len": 100, "len": 14}
            self.assertEqual(self.evaluate("packetBeforePayloadForCompare(" + json.dumps(event) + ")"), "")
            event["before_len"] = 14
            self.assertEqual(self.evaluate("packetBeforePayloadForCompare(" + json.dumps(event) + ")"), data)
            event["len"] = 100
            self.assertEqual(self.evaluate("packetBeforePayloadForCompare(" + json.dumps(event) + ")"), "")
        source = APP_JS.read_text()
        self.assertIn("buildChildComparePanel(comparableBeforePay, decodedPay", source)
        self.assertIn("const responseBeforePay = comparableBeforePay", source)

    def test_candidate_text_disappearing_is_not_a_confirmed_field_deletion(self) -> None:
        result = self.compare(b"readable text", b"\x00\xfe\xff\x01")
        texts = [row for row in result["rows"] if row["key"].startswith("text[")]
        self.assertTrue(texts)
        self.assertEqual({row["status"] for row in texts}, {"unmatched"})
        self.assertEqual(self.by_key(result["rows"])["content"]["status"], "changed")

    def test_child_record_declared_length_rejects_incomplete_frame(self) -> None:
        partial = [0,0,0,1,0,24,1,10,0,17,0,0,0,0]
        complete = [0,0,0,1,0,14,1,10,0,17,0,0,0,0]
        self.assertFalse(self.evaluate(f"packetChildComplete({{}}, {partial})"))
        self.assertTrue(self.evaluate(f"packetChildComplete({{}}, {complete})"))

    def test_child_structured_ranges_keep_all_uncovered_binary_bytes(self) -> None:
        data = b"\x00\x01\xfe\x80\x02\xff\x81"
        fields = [
            {"offset": 0, "length": 2, "note": "observed header", "kind": "report"},
            {"offset": 4, "length": 1, "note": "observed flag", "kind": "flags"},
        ]
        rows = self.rows(data, fields)
        by_key = self.by_key(rows)
        self.assertIn("report[0]", by_key)
        self.assertIn("flags[0]", by_key)
        self.assertIn("opaque", by_key)
        self.assertEqual(by_key["report[0]"]["value"].replace(" ", ""), "0001")
        self.assertEqual(by_key["opaque"]["value"].replace(" ", "").lower(), "fe80ff81")
        self.assertEqual(len(rows), len(by_key))

    def test_child_text_is_shown_once_and_does_not_consume_unknown_tail(self) -> None:
        data = b"\x00\x01hello world\x00\xfe\xff"
        fields = [{"offset": 0, "length": 2, "note": "observed header", "kind": "report"}]
        rows = self.rows(data, fields)
        text_rows = [row for row in rows if row["key"].startswith("text[")]
        self.assertEqual(len(text_rows), 1)
        self.assertIn("hello world", text_rows[0]["value"])
        self.assertEqual(self.by_key(rows)["opaque"]["value"].replace(" ", "").lower(), "00feff")
        covered_text = [{"offset": 2, "length": 11, "note": "observed text", "kind": "tlvValue"}]
        already_shown = self.rows(data, fields + covered_text)
        self.assertFalse(any(row["key"].startswith("text[") for row in already_shown))
        self.assertEqual(sum("hello world" in row["value"] for row in already_shown), 1)


if __name__ == "__main__":
    unittest.main()
