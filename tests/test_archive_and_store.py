from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from tcpv_mitm_emitter.analyzer import TersafeAnalyzer
from tcpv_mitm_emitter.archive import parse_txt_capture, read_flow_archive_bytes, write_flow_archive
from tcpv_mitm_emitter.runtime import TcpvRuntime
from tcpv_mitm_emitter.store import TcpvEventStore
from tcpv_mitm_emitter.semantic import analysis_from_event, analyze_payload, correlate_events
from tcpv_mitm_emitter.shape_summary import render_markdown, summarize_events, summarize_input


def _metadata_record(report_code: int, payload: bytes = b"") -> bytes:
    record = bytearray(b"\x00\x00\x00\x01\x00\x00")
    record.extend(int(report_code).to_bytes(4, "big"))
    record.extend(b"\x00" * 10)
    record.extend(payload)
    record[4:6] = len(record).to_bytes(2, "big")
    return bytes(record)


def _typed_record(
    inner_type: int,
    *,
    length: int = 68,
    selector0: int = 0x200E0002,
    selector1: int = 0x34560001,
    inner_field: int = 0,
    body: bytes = b"",
) -> bytes:
    record = bytearray(max(36, int(length)))
    record[0:4] = b"\x00\x00\x00\x01"
    record[4:6] = len(record).to_bytes(2, "big")
    record[6:10] = (0x0102000A).to_bytes(4, "big")
    record[20:22] = max(0, len(record) - 20).to_bytes(2, "big")
    record[22:24] = int(inner_type).to_bytes(2, "big")
    record[24:28] = int(selector0).to_bytes(4, "big")
    record[28:32] = int(selector1).to_bytes(4, "big")
    record[32:36] = int(inner_field).to_bytes(4, "big")
    record[36 : min(len(record), 36 + len(body))] = body[: max(0, len(record) - 36)]
    return bytes(record)


class FakePipeline:
    def __init__(self, redis):
        self.redis = redis
        self.calls = []

    def __getattr__(self, name):
        def wrapper(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return self

        return wrapper

    def execute(self):
        out = []
        for name, args, kwargs in self.calls:
            out.append(getattr(self.redis, name)(*args, **kwargs))
        self.calls.clear()
        return out


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.hashes = {}
        self.sets = {}
        self.streams = {}

    def pipeline(self):
        return FakePipeline(self)

    def incr(self, key):
        value = int(self.values.get(key, 0)) + 1
        self.values[key] = value
        return value

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = int(value)
        return True

    def xadd(self, key, fields, maxlen=None, approximate=True):
        stream = self.streams.setdefault(key, [])
        entry_id = str(len(stream) + 1)
        stream.append((entry_id, dict(fields)))
        if maxlen is not None and int(maxlen) > 0 and len(stream) > int(maxlen):
            del stream[: len(stream) - int(maxlen)]
        return entry_id

    def xrange(self, key, min="-", max="+", count=None):
        stream = list(self.streams.get(key, []))
        if min and str(min).startswith("("):
            after = int(str(min)[1:])
            stream = [(entry_id, fields) for entry_id, fields in stream if int(entry_id) > after]
        if count is not None:
            stream = stream[: int(count)]
        return stream

    def xrevrange(self, key, max="+", min="-", count=None):
        rows = list(reversed(self.streams.get(key, [])))
        if count is not None:
            rows = rows[: int(count)]
        return rows

    def sadd(self, key, value):
        self.sets.setdefault(key, set()).add(value)
        return 1

    def smembers(self, key):
        return set(self.sets.get(key, set()))

    def srem(self, key, value):
        self.sets.setdefault(key, set()).discard(value)
        return 1

    def hsetnx(self, key, field, value):
        target = self.hashes.setdefault(key, {})
        if field not in target:
            target[field] = str(value)
            return 1
        return 0

    def hset(self, key, mapping=None, **kwargs):
        target = self.hashes.setdefault(key, {})
        for field, value in (mapping or {}).items():
            target[field] = str(value)
        return len(mapping or {})

    def hincrby(self, key, field, amount):
        target = self.hashes.setdefault(key, {})
        target[field] = str(int(target.get(field, 0)) + int(amount))
        return int(target[field])

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def expire(self, key, seconds):
        return True

    def execute_command(self, command, *keys):
        if command == "UNLINK":
            return self.delete(*keys)
        raise RuntimeError(command)

    def delete(self, *keys):
        deleted = 0
        for key in keys:
            deleted += int(self.values.pop(key, None) is not None)
            deleted += int(self.hashes.pop(key, None) is not None)
            deleted += int(self.streams.pop(key, None) is not None)
            deleted += int(self.sets.pop(key, None) is not None)
        return deleted

    def scan(self, cursor=0, match=None, count=500):
        return 0, []


class ArchiveAndStoreTests(unittest.TestCase):
    def test_child_semantics_have_broad_categories_instead_of_family_unknown(self):
        opaque_metadata = _metadata_record(0x01122342, b"\x01\x02\x03\x04")
        metadata_analysis = analyze_payload(opaque_metadata, direction=0)["packet"]
        self.assertEqual(metadata_analysis["semantic_category"], "metadata.context")
        self.assertEqual(metadata_analysis["semantic_tier"], "approximate")
        self.assertNotEqual(metadata_analysis["semantic_label_zh"], "未解析记录")

        opaque_typed = _typed_record(0x1004, length=68)
        typed_analysis = analyze_payload(opaque_typed, direction=0)["packet"]
        self.assertEqual(typed_analysis["semantic_category"], "telemetry.binary_probe")
        self.assertEqual(typed_analysis["semantic_tier"], "approximate")

    def test_typed_leaf_time_and_xor_ui_shapes_are_classified(self):
        current = bytearray(_typed_record(0x100A, length=68))
        current[0x40:0x44] = (1781534846).to_bytes(4, "big")
        current_analysis = analyze_payload(bytes(current), direction=0)["packet"]
        self.assertEqual(current_analysis["semantic_category"], "telemetry.time.current")
        self.assertEqual(current_analysis["semantic_tier"], "confirmed")

        ui_text = b"UIWindow / UITransitionView / UIDropShadowView / UIView"
        ui_body = bytes(byte ^ 0xB6 for byte in ui_text)
        ui = _typed_record(0x100B, length=117, inner_field=0x53E3FFE1, body=ui_body)
        ui_analysis = analyze_payload(ui, direction=0)["packet"]
        self.assertEqual(ui_analysis["semantic_category"], "environment.ui_hierarchy")
        self.assertEqual(ui_analysis["semantic_tier"], "observed")

    def test_unresolved_provided_packet_does_not_mask_local_child_analysis(self):
        record = _metadata_record(0x0112237A, b"model:iPhone12,5;ver:26.50\x00")
        provided = {
            "schema": "tersafe.semantic.v1",
            "action": "observe_only",
            "packet": {"report_code": "0x00000000", "semantic_role": "unresolved_payload"},
        }
        analysis = analyze_payload(record, direction=0, provided=provided)
        self.assertEqual(analysis["action"], "observe_only")
        self.assertEqual(analysis["packet"]["report_code"], "0x0112237a")
        self.assertEqual(analysis["packet"]["semantic_category"], "metadata.device_profile")

        outer = b"encrypted-outer-frame"
        event = {
            "dir": 0,
            "pay": base64.b64encode(outer).decode("ascii"),
            "before_pay": base64.b64encode(record).decode("ascii"),
            "analysis": provided,
        }
        upgraded = analysis_from_event(event)
        self.assertEqual(upgraded["packet"]["report_code"], "0x0112237a")
        self.assertEqual(upgraded["packet"]["semantic_label_zh"], "设备型号/系统版本画像")

    def test_deep_report_uses_structured_analysis_when_display_is_outer_frame(self):
        decoded = _metadata_record(0x0112237A, b"model:iPhone12,5;ver:26.50\x00")
        analysis = analyze_payload(decoded, direction=0)
        summary = summarize_events(
            {"account": "outer-frame"},
            [{"ts": 1000, "dir": 0, "seq": 1, "display": "3366000b000c1001", "analysis": analysis}],
            input_name="outer-frame",
        )
        self.assertEqual(summary["deep"]["semantic_categories"], {"metadata.device_profile": 1})
        self.assertEqual(summary["deep"]["unknown_reports"], [])
        report = summary["deep"]["reports"][0]
        self.assertEqual(report["report_code"], "0x0112237a")
        self.assertEqual(report["semantic_labels_zh"], {"设备型号/系统版本画像": 1})

    def test_semantic_analysis_persists_in_redis_and_archive(self):
        record = _metadata_record(
            0x01122388,
            b"cs:11111111/22222222,ob:58/d4/ffffffff/0/79/1781534846/1781534856/1781534848/1/0/1;"
            b"\x00state:00b00017,r:0/9/275/284/206/7/7,p:988/988,1\x00",
        )
        analysis = analyze_payload(record, direction=0)
        self.assertEqual(analysis["schema"], "tersafe.semantic.v1")
        self.assertEqual(analysis["packet"]["report_family"], "0x011223xx")
        self.assertEqual(analysis["packet"]["dynamic_subtype"], 0x88)
        self.assertEqual(analysis["packet"]["semantic_role"], "csob_state_snapshot")
        accepted = analysis["packet"]["timestamps"]["accepted"]
        self.assertEqual([item["field"] for item in accepted], ["ob:T1", "ob:T2", "ob:T3"])

        store = TcpvEventStore(FakeRedis(), "semantic", ttl_seconds=0, stream_maxlen=0, api_max_limit=10)
        store.append_event("acct", "cid", 0, record, ts_ms=1000, analysis=analysis)
        event = store.get_event("acct", "1")
        self.assertEqual(event["analysis"]["packet"]["dynamic_subtype"], 0x88)

        flow = {"account": "acct", "first_ts": 1000, "last_ts": 1000}
        archive_event = {
            "ts": 1000,
            "dir": 0,
            "seq": 1,
            "raw": record.hex(),
            "full": record.hex(),
            "display": record.hex(),
            "analysis": analysis,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "semantic.tcpvflow.jsonl.gz"
            write_flow_archive(path, flow, [archive_event])
            _loaded_flow, loaded_events = read_flow_archive_bytes(path.read_bytes(), path.name)
        self.assertEqual(loaded_events[0]["analysis"]["schema"], "tersafe.semantic.v1")

    def test_ascii_dd3b_be32_candidate_is_rejected(self):
        record = bytearray(_metadata_record(0x01122342, b"x" * 80))
        record[0x44:0x48] = b"dd3b"
        analysis = analyze_payload(bytes(record), direction=0)
        rejected = analysis["packet"]["timestamps"]["rejected"]
        hit = next(item for item in rejected if item["offset"] == 0x44)
        self.assertEqual(hit["confidence"], "rejected")
        self.assertIn("ASCII", hit["reason"])
        summary = summarize_events(
            {"account": "timestamp-reject"},
            [{"ts": 1000, "dir": 0, "seq": 1, "display": bytes(record).hex(), "analysis": analysis}],
            input_name="timestamp-reject",
        )
        self.assertGreaterEqual(summary["deep"]["timestamps"]["rejected"], 1)
        self.assertIn("candidate falls inside ASCII/hash/string slot", summary["deep"]["timestamps"]["rejected_reasons"])
        self.assertIn("Timestamp Evidence Boundary", render_markdown(summary))

    def test_latest_200f_timestamp_shapes_use_compact_child_shift_and_chinese_semantics(self):
        event_seconds = 1_784_361_841

        current_full = bytearray(
            _typed_record(
                0x100A,
                length=68,
                selector0=0x200F0002,
                inner_field=1,
            )
        )
        current_full[0x40:0x44] = (event_seconds - 28).to_bytes(4, "big")
        current_compact = bytes(current_full[3:] + b"\x00\x00\x00")
        current = analyze_payload(current_compact, direction=0)
        self.assertEqual(current["packet"]["semantic_label_zh"], "当前采样时间")
        current_timestamp = next(
            item for item in current["packet"]["timestamps"]["accepted"] if item["field"] == "dfm-current-200f"
        )
        self.assertEqual(current_timestamp["offset"], 0x40 - 3)
        self.assertEqual(current_timestamp["value"], event_seconds - 28)

        session_full = bytearray(
            _typed_record(
                0x1001,
                length=80,
                selector0=0x200F0002,
                inner_field=event_seconds - 28,
            )
        )
        session_compact = bytes(session_full[3:] + b"\x00\x00\x00")
        session = analyze_payload(session_compact, direction=0)
        self.assertEqual(session["packet"]["semantic_label_zh"], "会话/缓存基准时间")
        session_timestamp = next(
            item for item in session["packet"]["timestamps"]["accepted"] if item["field"] == "dfm-session-200f"
        )
        self.assertEqual(session_timestamp["offset"], 0x20 - 3)
        self.assertEqual(session_timestamp["value"], event_seconds - 28)

    def test_be32_candidate_crossing_schema_field_boundary_is_rejected(self):
        record = _metadata_record(0x01122342, b"x" * 40 + b"state:1234\x00")
        analysis = analyze_payload(record, direction=0)
        rejected = analysis["packet"]["timestamps"]["rejected"]
        hit = next(item for item in rejected if item["offset"] == 0x40)
        self.assertEqual(hit["confidence"], "rejected")
        self.assertIn("crosses", hit["reason"])

    def test_deep_report_keeps_dynamic_subtypes_and_flags_response_burst(self):
        request = _metadata_record(
            0x01122388,
            b"cs:11111111/22222222,ob:58/d4/ffffffff/0/79/1781534846/1781534856/1781534848/1/0/1;"
            b"\x00state:00b00017,r:0/0/0,p:1/1,0\x00",
        )
        response = _metadata_record(0x010A0024, b"\x00" * 8)
        events = [
            {
                "ts": 1000,
                "dir": 0,
                "seq": 1,
                "display": request.hex(),
                "analysis": {
                    **analyze_payload(request, direction=0),
                    "actions": [
                        {"action": "candidate", "reason": "ok", "shape_match": "semantic_compatible"},
                        {"action": "passthrough", "reason": "opaque_or_non_csob_target_owned"},
                    ],
                    "consistency": 1.0,
                },
            },
            *[
                {"ts": 1100 + index * 100, "dir": 1, "seq": index + 2, "display": response.hex(), "analysis": {}}
                for index in range(4)
            ],
        ]
        summary = summarize_events({"account": "acct"}, events, input_name="test")
        deep = summary["deep"]
        self.assertEqual(deep["dynamic_011223_subtypes"], {"0x88": 1})
        self.assertEqual(deep["response_bursts"]["max_per_request_2s"]["0x010a0024"], 4)
        self.assertEqual(deep["traffic"]["response_request_ratio"], 4.0)
        self.assertEqual(deep["mirror"]["exact_shape_hit_rate"], 1.0)
        self.assertEqual(deep["mirror"]["shape_match_rate"], 1.0)
        self.assertEqual(deep["mirror"]["shape_match_kinds"], {"semantic_compatible": 1})
        self.assertEqual(deep["mirror"]["opaque_passthrough_rate"], 1.0)
        dynamic_report = next(item for item in deep["reports"] if item["report_code"] == "0x01122388")
        self.assertEqual(dynamic_report["payload_roles"], {"csob_state_snapshot (high)": 1})
        self.assertEqual(deep["timestamps"]["accepted"], 3)
        markdown = render_markdown(summary)
        self.assertIn("低字节只表示动态 subtype", markdown)
        self.assertIn("目前不能证明含义", markdown)

    def test_dynamic_subtype_payload_role_is_not_fixed_by_suffix(self):
        csob = _metadata_record(
            0x01122388,
            b"cs:11111111/22222222,ob:58/d4/ffffffff/0/79/1781534846/1781534856/1781534848/1/0/1;"
            b"\x00state:00b00017,r:0/0/0,p:1/1,0\x00",
        )
        config = _metadata_record(0x01122388, b"config2.dat;model:iPad14,5;ver:16.40\x00")
        events = [
            {"ts": 1000, "dir": 0, "seq": 1, "display": csob.hex(), "analysis": analyze_payload(csob, direction=0)},
            {"ts": 1100, "dir": 0, "seq": 2, "display": config.hex(), "analysis": analyze_payload(config, direction=0)},
        ]
        summary = summarize_events({"account": "mixed-subtype"}, events, input_name="mixed-subtype")
        dynamic_report = next(item for item in summary["deep"]["reports"] if item["report_code"] == "0x01122388")
        self.assertEqual(dynamic_report["payload_roles"]["csob_state_snapshot (high)"], 1)
        self.assertEqual(dynamic_report["payload_roles"]["configuration_file_observation (observed)"], 1)

    def test_historical_reportcode_matrix_keeps_provenance_without_inventing_direction(self):
        matrix = [
            {
                "report_code": "0x01122388",
                "observations": 12,
                "meaning": "legacy fixed suffix label",
                "role_distribution_unique": {"state_snapshot": 7, "device_profile": 5},
                "confidence": "观察",
                "evidence": "history",
            },
            {
                "report_code": "0x010a0011",
                "observations": 3,
                "meaning": "legacy whitelist claim",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reportcode_matrix.json"
            path.write_text(json.dumps(matrix), encoding="utf-8")
            summary = summarize_input(path)
        self.assertEqual(summary["input_kind"], "historical_reportcode_matrix")
        self.assertEqual(summary["deep"]["traffic"]["direction_unknown"], 15)
        dynamic = next(item for item in summary["deep"]["reports"] if item["report_code"] == "0x01122388")
        self.assertEqual(dynamic["family"], "0x011223xx")
        self.assertEqual(dynamic["counts"]["request"], 0)
        pairing = next(item for item in summary["deep"]["reports"] if item["report_code"] == "0x010a0011")
        self.assertEqual(pairing["meaning"], "配对/保护上下文（观察）")

    def test_response_correlation_and_65010_connection_timeline(self):
        request = _metadata_record(0x01122321, b"state:00300015,r:0/0/0,p:1/1,0\x00")
        response = _metadata_record(0x010A0044, b"\x00" * 8)
        events = [
            {
                "id": "1",
                "cid": "client->server:65010",
                "ts": 1000,
                "dir": 0,
                "seq": 1,
                "display": request.hex(),
                "analysis": analyze_payload(request, direction=0),
            },
            {
                "id": "2",
                "cid": "client->server:65010",
                "ts": 1200,
                "dir": 1,
                "seq": 2,
                "display": response.hex(),
                "analysis": analyze_payload(response, direction=1),
            },
        ]
        correlate_events(events)
        correlation = events[1]["analysis"]["response_correlation"]
        self.assertEqual(correlation["request_seq"], 1)
        self.assertEqual(correlation["delta_ms"], 200)
        self.assertEqual(correlation["burst_index"], 1)

        summary = summarize_events(
            {"account": "acct", "last_cid": "client->server:65010", "status": "open", "first_ts": 900, "last_ts": 1200},
            events,
            input_name="65010-test",
        )
        connection = summary["deep"]["connection_65010"]
        self.assertTrue(connection["observed"])
        self.assertEqual(connection["status"], "open")

    def test_parse_txt_capture_without_tersafe_root_keeps_raw(self):
        data = (
            "请求原包 2026-05-01 19:13:33.361\n"
            "010000002a070000000062ec6b9400000a92000000000000000000000000000000000000000069f48adc\n"
            "响应 2026-05-01 19:13:33.613\n"
            "0100000032080000000162ec6b9400000a92dd8af46917fc030000ed1818ccfa0313f413e259449ad9bed222d4d855bf7049\n"
        ).encode()
        flow, events = parse_txt_capture(data, "62ec6b94_8092_202605011913.txt", analyzer=TersafeAnalyzer(root=""))
        self.assertEqual(flow["listen_tag"], "port8092")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["dir"], 0)
        self.assertEqual(events[1]["dir"], 1)
        self.assertEqual(events[0]["raw"], events[0]["display"])
        self.assertEqual(events[0]["decode_status"], "unconfigured")

    def test_archive_roundtrip(self):
        flow = {"account": "import:test", "first_ts": 1, "last_ts": 2}
        events = [{"ts": 1, "dir": 0, "seq": 1, "raw": "0102", "full": "0102", "display": "0102"}]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.tcpvflow.jsonl.gz"
            write_flow_archive(path, flow, events)
            loaded_flow, loaded_events = read_flow_archive_bytes(path.read_bytes(), path.name)
        self.assertEqual(loaded_flow["account"], flow["account"])
        self.assertEqual(loaded_events[0]["display"], "0102")

    def test_store_stream_maxlen_zero_does_not_trim(self):
        store = TcpvEventStore(FakeRedis(), "test", ttl_seconds=0, stream_maxlen=0, api_max_limit=10)
        for idx in range(3):
            store.append_event("acct", "cid", 0, bytes([idx + 1]), ts_ms=1000 + idx)
        events, last_id, has_more = store.get_events("acct", limit=10)
        accounts = store.list_accounts()
        self.assertEqual(len(events), 3)
        self.assertEqual(last_id, "3")
        self.assertFalse(has_more)
        self.assertFalse(accounts[0]["trimmed_possible"])
        self.assertEqual(accounts[0]["last_seq"], 3)

    def test_runtime_backfills_old_analysis_even_for_compact_event_lists(self):
        record = _metadata_record(0x0112237A, b"state:00300015,r:0/0/0,p:1/1,0\x00")
        store = TcpvEventStore(FakeRedis(), "test", ttl_seconds=0, stream_maxlen=0, api_max_limit=10)
        store.append_event("acct", "cid", 0, record, ts_ms=1000)
        runtime = TcpvRuntime()
        runtime.store = store

        events, _last_id, _has_more = runtime.get_events(
            account="acct",
            after_id=None,
            limit=10,
            include_payload=False,
        )

        self.assertEqual(events[0]["pay"], "")
        self.assertEqual(events[0]["analysis"]["schema"], "tersafe.semantic.v1")
        self.assertEqual(events[0]["analysis"]["packet"]["dynamic_subtype"], 0x7A)

    def test_store_decodes_raw_after_payload(self):
        store = TcpvEventStore(FakeRedis(), "test", ttl_seconds=0, stream_maxlen=0, api_max_limit=10)
        store.append_event(
            "acct",
            "cid",
            0,
            b"decoded-after",
            full_payload=b"encrypted-before",
            before_payload=b"decoded-before",
            raw_payload=b"encrypted-after",
            ts_ms=1000,
        )
        event = store.get_event("acct", "1")
        self.assertEqual(event["full_len"], len(b"encrypted-before"))
        self.assertEqual(event["before_len"], len(b"decoded-before"))
        self.assertEqual(event["raw_len"], len(b"encrypted-after"))
        self.assertEqual(event["raw_pfx"], b"encrypted-after".hex())
        self.assertEqual(event["raw_pay"], base64.b64encode(b"encrypted-after").decode("ascii"))


if __name__ == "__main__":
    unittest.main()
