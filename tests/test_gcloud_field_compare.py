from __future__ import annotations

import base64
import json
import re
import subprocess
import unittest

from test_uagame_display_recovery import APP_JS, field, js_runtime, varint


class GcloudFieldCompareTests(unittest.TestCase):
    """Exercise the real display parser/comparison without packet/store writes."""

    @classmethod
    def setUpClass(cls) -> None:
        source = APP_JS.read_text(encoding="utf-8")
        globals_source = []
        for name in ("GCLOUD_BASE64_ANALYSIS_CACHE_MAX", "GCLOUD_BASE64_ANALYSIS_CACHE"):
            declaration = re.search(rf"^const {name} = .+;$", source, re.MULTILINE)
            if declaration is None:
                raise AssertionError(f"missing production global {name}")
            globals_source.append(declaration.group(0))
        cls.runtime = "\n".join(globals_source) + "\n" + js_runtime() + """
function fixtureProto(bytes, options = {}) {
  const parsed = parseGcloudProtoNodes(bytes, 0, bytes.length, 0, 240);
  return {
    nodes: parsed.nodes,
    flat: walkGcloudProtoNodes(parsed.nodes),
    viewBytes: bytes,
    sourceComplete: true,
    ok: parsed.ok,
    reason: parsed.reason || '',
    commandName: 'CSAccountLoginReq',
    commandDisplay: 'CSAccountLoginReq',
    ...options,
  };
}
function fixtureResult(before, after, beforeOptions = {}, afterOptions = {}) {
  const left = before === null ? null : fixtureProto(before, beforeOptions);
  const right = fixtureProto(after, afterOptions);
  const sourceBefore = JSON.stringify(left);
  const sourceAfter = JSON.stringify(right);
  const result = gcloudCompareRows(left, right);
  if (JSON.stringify(left) !== sourceBefore || JSON.stringify(right) !== sourceAfter) {
    throw new Error('display comparison mutated the parsed source');
  }
  return result;
}
"""

    def compare(
        self,
        before: bytes | None,
        after: bytes,
        *,
        before_options: dict | None = None,
        after_options: dict | None = None,
    ) -> dict:
        arguments = [
            list(before) if before is not None else None,
            list(after),
            before_options or {},
            after_options or {},
        ]
        result = subprocess.run(
            ["node"],
            input=self.runtime
            + "\nconsole.log(JSON.stringify(fixtureResult(..."
            + json.dumps(arguments)
            + ")));\n",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2400:])
        return json.loads(result.stdout)

    def row(self, result: dict, field_number: int, occurrence: int = 0) -> dict:
        rows = [
            row
            for row in result["rows"]
            if int((row.get("after") or row.get("before"))["node"]["field"])
            == field_number
        ]
        self.assertGreater(len(rows), occurrence, f"missing field {field_number}: {result}")
        return rows[occurrence]

    def assert_current_only(self, result: dict) -> None:
        self.assertFalse(result["canCompare"])
        self.assertTrue(result["reason"])
        self.assertTrue(result["rows"])
        self.assertEqual({row["status"] for row in result["rows"]}, {"current"})
        self.assertTrue(all(row.get("before") is None for row in result["rows"]))
        self.assertTrue(all(row.get("after") is not None for row in result["rows"]))

    def test_variable_length_string_does_not_shift_following_numeric_fields(self) -> None:
        before = field(20, b"iOS") + field(21, 42) + field(22, b"stable value")
        after = field(20, b"Harmony") + field(21, 42) + field(22, b"stable value")
        result = self.compare(before, after)
        self.assertTrue(result["hasBefore"])
        self.assertTrue(result["canCompare"])
        self.assertEqual(len(result["rows"]), 3)
        changed = self.row(result, 20)
        self.assertEqual(changed["status"], "changed")
        self.assertIn("iOS", str(changed["before"]["value"]))
        self.assertIn("Harmony", str(changed["after"]["value"]))
        self.assertEqual(self.row(result, 21)["status"], "same")
        self.assertEqual(self.row(result, 22)["status"], "same")

    def test_added_and_removed_fields_leave_unchanged_field_aligned(self) -> None:
        before = field(20, b"removed value") + field(21, 123)
        after = field(19, b"new value") + field(21, 123)
        result = self.compare(before, after)
        self.assertTrue(result["canCompare"])
        self.assertEqual(len(result["rows"]), 3)
        added = self.row(result, 19)
        removed = self.row(result, 20)
        self.assertEqual(added["status"], "added")
        self.assertIsNone(added["before"])
        self.assertEqual(removed["status"], "removed")
        self.assertIsNone(removed["after"])
        self.assertEqual(self.row(result, 21)["status"], "same")

    def test_same_field_changing_wire_type_is_one_changed_row(self) -> None:
        result = self.compare(field(20, 1234), field(20, b"1234"))
        self.assertTrue(result["canCompare"])
        self.assertEqual(len(result["rows"]), 1)
        row = result["rows"][0]
        self.assertEqual(row["status"], "changed")
        self.assertEqual(row["before"]["node"]["wire"], 0)
        self.assertEqual(row["after"]["node"]["wire"], 2)
        self.assertNotEqual(row["before"]["type"], row["after"]["type"])

    def test_every_repeated_ancestor_and_leaf_has_a_unique_stable_key(self) -> None:
        first = field(20, field(1, b"first text") + field(1, b"second text"))
        second = field(20, field(1, b"third text") + field(1, b"fourth text"))
        before = first + second
        after = (
            field(20, field(1, b"first extended text") + field(1, b"second text"))
            + second
        )
        result = self.compare(before, after)
        self.assertTrue(result["canCompare"])
        self.assertEqual(len(result["rows"]), 4, "containers must not repeat their leaf values")
        self.assertEqual(len({row["key"] for row in result["rows"]}), 4)
        self.assertTrue(all(row["path"] for row in result["rows"]))
        self.assertTrue(all(row["label"] for row in result["rows"]))
        self.assertEqual([row["status"] for row in result["rows"]].count("changed"), 1)
        self.assertEqual([row["status"] for row in result["rows"]].count("same"), 3)
        self.assertTrue(all(row["before"]["key"] == row["after"]["key"] for row in result["rows"]))

    def test_missing_before_is_current_not_fabricated_added_fields(self) -> None:
        result = self.compare(None, field(20, b"Harmony"))
        self.assertFalse(result["hasBefore"])
        self.assert_current_only(result)

    def test_incomplete_before_is_not_a_trustworthy_comparison(self) -> None:
        result = self.compare(
            field(20, b"iOS"),
            field(20, b"Harmony"),
            before_options={"sourceComplete": False},
        )
        self.assert_current_only(result)

    def test_failed_before_parse_is_not_a_trustworthy_comparison(self) -> None:
        result = self.compare(field(20, b"iOS")[:-1], field(20, b"Harmony"))
        self.assert_current_only(result)

    def test_incomplete_or_failed_after_parse_is_current_only(self) -> None:
        for options in ({"sourceComplete": False}, {"ok": False}):
            with self.subTest(options=options):
                result = self.compare(field(20, b"iOS"), field(20, b"Harmony"), after_options=options)
                self.assert_current_only(result)

    def test_different_commands_are_never_compared_as_one_packet(self) -> None:
        result = self.compare(
            field(20, b"iOS"),
            field(20, b"Harmony"),
            after_options={"commandName": "CSAceSendAntiDataNtf", "commandDisplay": "CSAceSendAntiDataNtf"},
        )
        self.assert_current_only(result)

    def test_missing_command_requires_both_sides_to_be_uagame_bodies(self) -> None:
        no_command = {"commandName": "", "commandDisplay": ""}
        result = self.compare(field(20, 42), field(20, 42), before_options=no_command, after_options=no_command)
        self.assert_current_only(result)
        body = {**no_command, "uagameBody": True}
        result = self.compare(field(20, 42), field(20, 42), before_options=body, after_options=body)
        self.assertTrue(result["canCompare"])
        self.assertEqual(result["rows"][0]["status"], "same")
        result = self.compare(field(20, 42), field(20, 42), before_options=body, after_options=no_command)
        self.assert_current_only(result)

    def test_zero_length_field_is_not_lost_as_an_empty_container(self) -> None:
        result = self.compare(field(20, b""), field(20, b""))
        self.assertTrue(result["canCompare"])
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["status"], "same")
        self.assertEqual(result["rows"][0]["after"]["node"]["len"], 0)

    def test_equal_numeric_value_with_different_encoding_is_still_a_byte_change(self) -> None:
        canonical = varint(20 << 3) + b"\x01"
        noncanonical = varint(20 << 3) + b"\x81\x00"
        result = self.compare(canonical, noncanonical)
        self.assertTrue(result["canCompare"])
        self.assertEqual(len(result["rows"]), 1)
        row = result["rows"][0]
        self.assertEqual(row["before"]["node"]["valueText"], "1")
        self.assertEqual(row["after"]["node"]["valueText"], "1")
        self.assertEqual(row["status"], "changed")

    def test_long_string_changes_beyond_preview_are_not_silently_equal(self) -> None:
        prefix = b"same printable prefix " * 20
        result = self.compare(field(20, prefix + b"before"), field(20, prefix + b"after!"))
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["status"], "changed")

    def test_invalid_nested_tail_is_compared_as_one_opaque_value(self) -> None:
        result = self.compare(field(20, b"\x08\x01\x00"), field(20, b"\x08\x01\xff"))
        self.assertTrue(result["canCompare"])
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["status"], "changed")
        self.assertEqual(result["rows"][0]["before"]["node"]["field"], 20)

    def test_complete_and_partial_nested_values_share_the_opaque_boundary(self) -> None:
        result = self.compare(field(20, b"\x08\x01\x00"), field(20, b"\x08\x01"))
        self.assertTrue(result["canCompare"])
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["status"], "changed")
        self.assertIsNotNone(result["rows"][0]["before"])
        self.assertIsNotNone(result["rows"][0]["after"])

    def test_declared_before_length_is_preserved_through_event_analysis(self) -> None:
        header = field(1, field(7, b"CSAccountLoginReq") + field(8, b"account"))
        current = header + field(2, field(20, b"current body"))
        event = {
            "dir": 0, "len": len(current), "before_len": len(current),
            "pay": base64.b64encode(current).decode(),
            "before_pay": base64.b64encode(header).decode(),
            "summary": "transport=tgcp65010 command=0x4013 crypto=decrypted target_port=65010",
        }
        script = self.runtime + "\nconst ev = " + json.dumps(event) + ";\n" + """
const left = analyzeGcloudBeforeVariant(ev, ev.summary);
const right = analyzeGcloudEvent(ev, ev.summary);
console.log(JSON.stringify({complete: left.proto.sourceComplete, result: gcloudCompareRows(left.proto, right.proto)}));
"""
        result = subprocess.run(["node"], input=script, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-2400:])
        observed = json.loads(result.stdout)
        self.assertFalse(observed["complete"])
        self.assert_current_only(observed["result"])

    def test_field_order_and_numeric_offsets_are_not_field_identity(self) -> None:
        before = field(20, 7) + field(21, 42) + field(22, 1234)
        after = field(22, 1234) + field(20, 7) + field(21, 42)
        result = self.compare(before, after)
        self.assertTrue(result["canCompare"])
        self.assertEqual(len(result["rows"]), 3)
        self.assertEqual({row["status"] for row in result["rows"]}, {"same"})


if __name__ == "__main__":
    unittest.main()
