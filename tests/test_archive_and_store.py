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
from tcpv_mitm_emitter.semantic import analyze_payload, correlate_events
from tcpv_mitm_emitter.shape_summary import render_markdown, summarize_events, summarize_input


def _metadata_record(report_code: int, payload: bytes = b"") -> bytes:
    record = bytearray(b"\x00\x00\x00\x01\x00\x00")
    record.extend(int(report_code).to_bytes(4, "big"))
    record.extend(b"\x00" * 10)
    record.extend(payload)
    record[4:6] = len(record).to_bytes(2, "big")
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

    def test_be32_candidate_crossing_schema_field_boundary_is_rejected(self):
        record = _metadata_record(0x01122342, b"x" * 40 + b"state:1234\x00")
        analysis = analyze_payload(record, direction=0)
        rejected = analysis["packet"]["timestamps"]["rejected"]
        hit = next(item for item in rejected if item["offset"] == 0x40)
        self.assertEqual(hit["confidence"], "rejected")
        self.assertIn("crosses", hit["reason"])

    def test_deep_report_keeps_dynamic_subtypes_and_flags_response_burst(self):
        request = _metadata_record(0x01122388, b"state:00b00017,r:0/0/0,p:1/1,0\x00")
        response = _metadata_record(0x010A0024, b"\x00" * 8)
        events = [
            {
                "ts": 1000,
                "dir": 0,
                "seq": 1,
                "display": request.hex(),
                "analysis": {
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
        markdown = render_markdown(summary)
        self.assertIn("低字节只表示动态 subtype", markdown)
        self.assertIn("目前不能证明含义", markdown)

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
