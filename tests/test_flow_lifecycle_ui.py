"""Exercise served lifecycle functions without a browser or service startup."""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import unittest


APP_JS = Path(__file__).resolve().parents[1] / "tcpv_mitm_emitter" / "app.js"


class PacketVisibilityUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = APP_JS.read_text()
        start = source.index("const TCPV_EXACT_FILTERED_COMMAND_BASES")
        end = source.index("function findEventNodeById(")
        event_filter = source[start:end]
        cls.runtime = """
function escapeRegexLiteral(text) {
  return String(text || "").replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");
}
function readSummaryValue(summaryText, key) {
  const raw = String(summaryText || "");
  const safeKey = escapeRegexLiteral(key);
  const match = raw.match(new RegExp(`(?:^|\\\\s)${safeKey}=([^\\\\s]+)`));
  return match ? match[1] : "";
}
function parseFlexibleInt(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  const parsed = raw.toLowerCase().startsWith("0x")
    ? Number.parseInt(raw.slice(2), 16)
    : Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : null;
}
const state = {filters: {dir: "all", minLen: "", maxLen: "", csobOnly: false, aceMode: "all"}};
function eventHasCsob() { return false; }
function normalizeAceFilterMode() { return "all"; }
function currentFlowLooksLikeGcloud65010() { return true; }
function gcloudEventClass() { return ""; }
""" + event_filter

    @classmethod
    def evaluate_visibility(cls, summary: str, *, direction: int = 0) -> bool:
        script = cls.runtime + "\nconst ev = " + json.dumps({"dir": direction, "len": 87, "summary": summary}) + ";"
        script += "\nconsole.log(JSON.stringify(eventMatchesFilters(ev)));"
        result = subprocess.run(
            ["node", "-e", script], check=True, capture_output=True, text=True, timeout=5,
        )
        return json.loads(result.stdout)

    def test_only_exact_operator_business_rules_are_automatic(self) -> None:
        source = APP_JS.read_text()
        for retired_symbol in (
            "hideBusiness", "hiddenBusinessCount", "eventIsConfirmedBusinessHidden",
            "installBusinessDisplayControl", "按当前规则展示隐藏",
        ):
            with self.subTest(retired_symbol=retired_symbol):
                self.assertNotIn(retired_symbol, source)
        event_filter = source[source.index("function eventMatchesFilters("):
                              source.index("function findEventNodeById(")]
        self.assertIn('state.filters.dir || "all"', event_filter)
        self.assertIn("eventIsTcpViewExactFilteredCommand", event_filter)

    def test_backend_business_label_does_not_hide_a_loaded_row(self) -> None:
        summary = "gcloud_observation_hidden=1 gcloud_observation_command=CSQuestGetAcceptedQuestsRes"
        self.assertTrue(self.evaluate_visibility(summary))

    def test_exact_request_response_commands_and_join_notification_are_filtered(self) -> None:
        bases = (
            "CSDepositQueryShowRoom",
            "CSPlayerInfoGetAppearance",
            "CSMPGetAllStarWeapon",
            "CSSeasonGetRecordList",
            "CSSeasonGetRecord",
            "CSSeasonGetMatchScoreData",
        )
        prefix = "command=0x4013 crypto=decrypted gcloud_observation_command_names_verified=1"
        for base in bases:
            for suffix in ("Req", "Res", "ReqB", "ResB"):
                with self.subTest(command=base + suffix):
                    self.assertFalse(self.evaluate_visibility(
                        f"{prefix} gcloud_observation_command={base}{suffix}"
                    ))
        self.assertFalse(self.evaluate_visibility(
            f"{prefix} gcloud_observation_command=CSPlayerJoinMatchNtf"
        ))

    def test_near_names_and_unverified_commands_remain_visible(self) -> None:
        verified = "command=0x4013 crypto=decrypted gcloud_observation_command_names_verified=1"
        controls = (
            f"{verified} gcloud_observation_command=CSSeasonGetInfoReq",
            f"{verified} gcloud_observation_command=CSPlayerJoinMatchReq",
            f"{verified} gcloud_observation_command=CSDepositQueryShowRoomNtf",
            f"{verified} gcloud_observation_command=CSSeasonGetRecordListAck",
            f"{verified} gcloud_observation_command=CSSeasonGetRecordListExtraReq",
            "command=0x4013 crypto=decrypted gcloud_observation_command=CSSeasonGetRecordListReq",
            "command=0x4012 crypto=decrypted gcloud_observation_command_names_verified=1 gcloud_observation_command=CSSeasonGetRecordListReq",
            "command=0x4013 crypto=encrypted gcloud_observation_command_names_verified=1 gcloud_observation_command=CSSeasonGetRecordListReq",
        )
        for summary in controls:
            with self.subTest(summary=summary):
                self.assertTrue(self.evaluate_visibility(summary))

    def test_manual_direction_filter_still_applies(self) -> None:
        summary = "command=0x4013 crypto=decrypted gcloud_observation_command_names_verified=1 gcloud_observation_command=CSQuestGetAcceptedQuestsRes"
        source = self.runtime + "\nstate.filters.dir = 'resp';"
        source += "\nconsole.log(JSON.stringify(eventMatchesFilters(" + json.dumps({"dir": 0, "len": 87, "summary": summary}) + ")));"
        result = subprocess.run(["node", "-e", source], check=True, capture_output=True, text=True, timeout=5)
        self.assertFalse(json.loads(result.stdout))


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
