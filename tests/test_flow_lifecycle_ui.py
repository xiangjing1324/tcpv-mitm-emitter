"""Exercise served lifecycle functions without a browser or service startup."""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import unittest


APP_JS = Path(__file__).resolve().parents[1] / "tcpv_mitm_emitter" / "app.js"


class FlowLifecycleUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = APP_JS.read_text()
        functions = []
        for name in ("getFlowPacketActivity", "isFlowOpen", "getFlowTimeInfo", "flowLifecycleStateText"):
            start = source.index(f"function {name}(")
            end = re.search(r"(?m)^}$", source[start:])
            assert end is not None
            functions.append(source[start:start + end.end()])
        constant = re.search(r"(?m)^const FLOW_ACTIVITY_FRESH_MS = .*;$", source)
        assert constant is not None
        cls.runtime = constant.group(0) + "\n" + "\n".join(functions)

    def evaluate(self, item: dict, now: int = 1_000_000) -> dict:
        script = self.runtime + "\nconst t = getFlowTimeInfo(" + json.dumps(item) + "," + str(now) + ");"
        script += "\nconsole.log(JSON.stringify({...t, stateText:flowLifecycleStateText(t)}));"
        result = subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True, timeout=5)
        return json.loads(result.stdout)

    def test_idle_open_socket_stays_blue_and_duration_keeps_running(self) -> None:
        row = {"tcp_start_ts": 1000, "tcp_end_ts": 0, "is_open": True, "status": "open", "status_source": "tcp_start", "last_packet_ts": 800_000}
        first = self.evaluate(row)
        later = self.evaluate(row, 1_300_000)
        self.assertTrue(first["open"])
        self.assertTrue(later["open"])
        self.assertEqual(later["durationMs"] - first["durationMs"], 300_000)
        self.assertEqual(first["statusSource"], "tcp_start")

    def test_end_with_late_fresh_packet_never_reopens(self) -> None:
        row = {"tcp_start_ts": 1000, "tcp_end_ts": 990_000, "is_open": True, "status": "open", "last_packet_ts": 999_999, "duration_ms": 989_000}
        result = self.evaluate(row)
        self.assertFalse(result["open"])
        self.assertEqual(result["recordedEndTs"], 990_000)
        self.assertEqual(result["durationMs"], 989_000)
        self.assertEqual(result["statusSource"], "tcp_end")

    def test_closed_boolean_with_fresh_packet_stays_closed(self) -> None:
        result = self.evaluate({"is_open": False, "last_packet_ts": 999_999})
        self.assertFalse(result["open"])

    def test_start_without_packets_is_open(self) -> None:
        result = self.evaluate({"tcp_start_ts": 1000})
        self.assertTrue(result["open"])
        self.assertEqual(result["durationMs"], 999_000)

    def test_status_only_open_does_not_expire(self) -> None:
        result = self.evaluate({"status": " OPEN ", "last_packet_ts": 1000})
        self.assertTrue(result["open"])

    def test_legacy_unknown_can_only_infer_activity(self) -> None:
        fresh = self.evaluate({"last_packet_ts": 999_999})
        idle = self.evaluate({"last_packet_ts": 1000})
        self.assertTrue(fresh["open"])
        self.assertIn("推测", fresh["stateText"])
        self.assertFalse(idle["open"])
        self.assertEqual(idle["statusSource"], "legacy_activity_inferred")

    def test_closed_duration_is_not_extended_by_later_packets_or_clock(self) -> None:
        row = {"tcp_start_ts": 1000, "tcp_end_ts": 2000, "last_packet_ts": 999_999, "is_open": False}
        first = self.evaluate(row)
        later = self.evaluate(row, 1_300_000)
        self.assertEqual(first["durationMs"], 1000)
        self.assertEqual(later["durationMs"], 1000)
        self.assertEqual(later["displayEndTs"], 2000)

    def test_ended_timestamp_wins_over_contradictory_open_status(self) -> None:
        self.assertFalse(self.evaluate({"ended_ts": 2000, "status": "open", "last_packet_ts": 999_999})["open"])


if __name__ == "__main__":
    unittest.main()
