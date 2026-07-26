from __future__ import annotations

import base64
import json
import struct
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


def _pubgm_0112235b_record(*, state: tuple[int, int, int] = (9, 9, 2)) -> bytes:
    record = bytearray(b"\x00" * 0x010D)
    record[:4] = b"\x00\x00\x00\x01"
    record[4:6] = len(record).to_bytes(2, "big")
    record[6:10] = (0x0112235B).to_bytes(4, "big")
    record[10:14] = (0x0CC8).to_bytes(4, "big")
    record[0x35:0x73] = b"model:iPad14,5;ver:16.10;role_id:sunday;inc_id:313;obf_id:313\x00"
    record[0x73:0x7B] = bytes.fromhex("0000000200000021")
    record[0x7B:0x9B] = b"EBACB0CDFE552BBA7666E7940D25180A"
    record[0x9B:0xA0] = bytes.fromhex("000000000b")
    record[0xA0:0xAA] = b"1106467070"
    record[0xAA:0xAF] = bytes.fromhex("000000000b")
    for offset, value in zip((0xFE, 0x106, 0x10C), state):
        record[offset] = value
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

    def exists(self, key):
        return int(key in self.values or key in self.hashes or key in self.sets or key in self.streams)

    def set(self, key, value):
        self.values[key] = int(value)
        return True

    def xadd(self, key, fields, id="*", maxlen=None, approximate=True):
        stream = self.streams.setdefault(key, [])
        entry_id = str(id) if str(id or "*") != "*" else str(len(stream) + 1)
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
    def test_pubgm_0112235b_exposes_only_closed_tail_state_semantics(self):
        alternate = analyze_payload(_pubgm_0112235b_record(), direction=0)
        baseline = analyze_payload(_pubgm_0112235b_record(state=(1, 1, 1)), direction=0)

        self.assertEqual(alternate["semantic_revision"], 8)
        packet = alternate["packet"]
        self.assertEqual(packet["semantic_category"], "metadata.device_profile_state")
        self.assertEqual(packet["semantic_label_zh"], "设备/账号绑定画像 + 尾部状态三联（只观察）")
        fields = {item["name"]: item for item in packet["fields"]}
        self.assertEqual(fields["identity_bundle_layout"]["value"], "kv62+opaque_hex32+account10")
        self.assertEqual(fields["tail_state_triplet"]["value"], "09/09/02")
        self.assertEqual(fields["tail_state_triplet"]["non_contiguous_offsets"], ["0xfe", "0x106", "0x10c"])
        self.assertEqual(fields["tail_state_class"]["value"], "variant_09_09_02")
        self.assertEqual(fields["tail_state_mutability"]["value"], "unproven_observe_only")
        self.assertIn("outer-270f-confounded", fields["tail_state_class"]["source"])
        baseline_fields = {item["name"]: item for item in baseline["packet"]["fields"]}
        self.assertEqual(baseline_fields["tail_state_triplet"]["value"], "01/01/01")
        self.assertEqual(baseline_fields["tail_state_class"]["value"], "variant_01_01_01")
        self.assertEqual(baseline_fields["tail_state_mutability"]["value"], "unproven_observe_only")

    def test_tcpview_frontend_renders_local_synthesis_badge(self):
        app_js = (Path(__file__).parents[1] / "tcpv_mitm_emitter" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function compactSynthesisInsight(summaryText)", app_js)
        self.assertIn('"SYNTH"', app_js)
        self.assertIn('`child_synth=${synthCount}`', app_js)
        self.assertIn('"local_semantic_synthesis"', app_js)
        self.assertIn("compactSynthesisInsight(summaryText)", app_js)

    def test_tcpview_frontend_labels_opaque_outer_packets_as_raw(self):
        app_js = (Path(__file__).parents[1] / "tcpv_mitm_emitter" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function compactOpaqueInsight(summaryText)", app_js)
        self.assertIn('"OPAQUE"', app_js)
        self.assertIn('"未解密外层"', app_js)
        self.assertIn('"value保持"', app_js)
        self.assertIn("修改前原始封包 [before/raw]", app_js)
        self.assertIn("修改后原始封包 [after/raw]", app_js)
        self.assertIn("tree-compare-single", app_js)
        self.assertIn("封包概览（未解密）", app_js)
        self.assertIn("只能按原始封包观察，未知 value 已保持", app_js)

    def test_tcpview_frontend_keeps_decoded_hex_dump_quiet(self):
        root = Path(__file__).parents[1]
        app_js = (root / "tcpv_mitm_emitter" / "app.js").read_text(encoding="utf-8")
        web_py = (root / "tcpv_mitm_emitter" / "web.py").read_text(encoding="utf-8")
        self.assertIn('return " ";', app_js)
        self.assertIn("function shouldRenderAsciiUnderRow(row)", app_js)
        self.assertIn("hex-ascii-under-spacer", app_js)
        self.assertIn("dump-grid-current-only", app_js)
        self.assertIn("tree-compare-single", app_js)
        self.assertIn("asciiRows: false", app_js)
        self.assertIn("showStringAnnotations", app_js)
        self.assertNotIn("ASCII row", app_js)
        self.assertNotIn("hex-ascii-under-label", app_js)
        self.assertIn("border-left: 2px solid", web_py)

    def test_tcpview_frontend_surfaces_ace_before_after_state(self):
        app_js = (Path(__file__).parents[1] / "tcpv_mitm_emitter" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function makeGcloudAceCompareStatus", app_js)
        self.assertIn("function gcloudAceCsobMarkerRewritePreview", app_js)
        self.assertIn("未发送证据", app_js)
        self.assertNotIn("本地模拟 before/after", app_js)
        self.assertIn("payload_modified=1 / wire_rebuilt=1 / raw_pay=raw_after_4013", app_js)
        self.assertIn("后端确认 rebuild/send", app_js)
        self.assertIn("raw_pay=重建后转发包", app_js)
        self.assertIn("raw_pay sent/rebuilt 4013", app_js)
        self.assertIn("raw_pay_is_sent_wire=1", app_js)
        self.assertIn("tcpview_after_source=raw_pay_sent_wire", app_js)
        self.assertIn("after 来自后端 sent wire", app_js)
        self.assertIn("收到的原始4013 [raw before/full_pay]", app_js)
        self.assertIn("修改后重建4013 [raw after/sent]", app_js)
        self.assertIn("修改后解密 [after/rebuilt]", app_js)
        self.assertIn("forceSideBySideSame: compareRoot", app_js)
        self.assertIn("forceSideBySideSame: hasBefore", app_js)
        self.assertIn("backend rebuilt", app_js)

    def test_tcpview_frontend_has_gcloud_65010_proto_view(self):
        app_js = (Path(__file__).parents[1] / "tcpv_mitm_emitter" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function isGcloud65010Summary", app_js)
        self.assertIn("function analyzeGcloudBusinessProto", app_js)
        self.assertIn("function buildGcloudPacketPanel", app_js)
        self.assertIn("TGCP 9001 控制帧", app_js)
        self.assertIn("payload_len=0 的控制旁路帧", app_js)
        self.assertIn("proto fragment", app_js)
        self.assertIn("protobuf tree", app_js)
        self.assertIn("raw field paths", app_js)
        self.assertIn("function buildGcloudProtoTree", app_js)
        self.assertIn("summary-insight-gcloud", app_js)
        self.assertIn("isGcloudEvent ? null : buildEventAnalysisGrid", app_js)
        self.assertIn("!isGcloudEvent && isRequest", app_js)

    def test_tcpview_frontend_uses_static_lightfeature_layout(self):
        app_js = (Path(__file__).parents[1] / "tcpv_mitm_emitter" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function gcloudAnalyzeAceFixed64", app_js)
        self.assertIn("bodyLength = layer1.length >= 6 ? readBe16(layer1, 4)", app_js)
        self.assertIn("staticXorKey >= 0x10", app_js)
        self.assertIn("staticXorKey <= 0xaf", app_js)
        self.assertIn("(wireMarker ^ 0xb6b6) & 0xffff", app_js)
        self.assertIn("common_protocol_id", app_js)
        self.assertIn("schema_or_version", app_js)
        self.assertIn("optional_u32", app_js)
        self.assertIn("fixed64/state_vector", app_js)
        self.assertNotIn("sample=${sampleCounter}", app_js)
        self.assertNotIn("rolling_token?", app_js)

    def test_tcpview_frontend_decodes_gateway_kick_player_notice(self):
        app_js = (Path(__file__).parents[1] / "tcpv_mitm_emitter" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function analyzeGcloudGatewayKickCommand", app_js)
        self.assertIn('"2.1": "kick_code"', app_js)
        self.assertIn('"2.2": "notice"', app_js)
        self.assertIn("protoBytes.slice(Number(noticeNode.valueStart), Number(noticeNode.valueEnd))", app_js)
        self.assertIn("gcloudBytesToUtf8(noticeBytes)", app_js)
        self.assertIn("账号冻结 / 网关强制下线", app_js)
        self.assertIn("kick_code 仅按本包 varint 原值展示", app_js)
        self.assertIn("不把任何数值硬编码成官方处罚枚举", app_js)
        self.assertIn("冻结期限、解封时间和风险提示均从当前 notice 动态提取", app_js)
        self.assertIn("body.field1=varint", app_js)
        self.assertIn("body.field2=utf8", app_js)
        self.assertIn("不足以证明具体由哪条 ACE/TerSafe 上报触发", app_js)
        self.assertIn("服务器提示", app_js)
        self.assertIn("解封时间", app_js)

    def test_fff3_body_is_tick_plus_six_byte_probe_entries(self):
        tick = 0x0426
        entries = [
            (0x18C0, 0x03000000),
            (0x0651, 0xC1000000),
            (0x079A, 0x40000000),
            (0x08BC, 0x81C00021),
            (0x2000, 0x22),
            (0x2001, 0x03),
            (0x2002, 0x03),
            (0x2003, 0x11),
            (0x2004, 0x22),
            (0x2005, 0x22),
            (0x2006, 0x22),
            (0x2007, 0x22),
            (0x2008, 0x11),
            (0x200A, 0x22),
            (0x200B, 0x22),
            (0x200C, 0x22),
            (0x200F, 0x01),
            (0x2010, 0x22),
            (0x2011, 0x03),
            (0x2012, 0x11),
            (0x2013, 0x22),
            (0x2015, 0x11),
            (0x2018, 0x01),
            (0x201A, 0x22),
            (0x201B, 0x22),
            (0x201C, 0x22),
            (0x201E, 0x22),
            (0x2025, 0x01),
            (0x2027, 0x01),
            (0x2029, 0x01),
            (0x202F, 0x22),
            (0x2030, 0x01),
            (0x2031, 0x22),
            (0x8100, 0x22),
            (0x8102, 0x01),
            (0x8103, 0x01),
            (0x8000, 0x23),
        ]
        body = tick.to_bytes(4, "big") + b"".join(
            probe_id.to_bytes(2, "big") + value.to_bytes(4, "big")
            for probe_id, value in entries
        )
        record = _typed_record(
            0xFFF3,
            length=36 + len(body),
            selector0=0,
            selector1=(tick << 16) | 1,
            inner_field=0x00030003,
            body=body,
        )
        packet = analyze_payload(record, direction=0)["packet"]
        self.assertEqual(len(record), 262)
        self.assertEqual(packet["semantic_category"], "telemetry.probe_scheduler")
        self.assertEqual(packet["semantic_tier"], "observed")
        layout = packet["body_layout"]
        self.assertEqual(layout["kind"], "periodic_probe_table")
        self.assertEqual(layout["layout_algebra"], "4 + 37×6 = 226")
        self.assertEqual(layout["tick"], 0x0426)
        self.assertTrue(layout["selector_tick_match"])
        self.assertEqual(layout["inner_pair"], {"left": 3, "right": 3})
        by_id = {item["probe_id"]: item for item in layout["entries"]}
        self.assertEqual(by_id["0x2007"]["value"]["be32"], 34)
        self.assertEqual(by_id["0x2007"]["value_kind"], "per_round_candidate")
        self.assertAlmostEqual(by_id["0x2007"]["global_round_ratio_candidate"], 34 / 35, places=3)
        self.assertEqual(by_id["0x2008"]["value"]["be32"], 17)
        self.assertEqual(by_id["0x2008"]["value_kind"], "half_round_candidate")
        self.assertEqual(by_id["0x8000"]["value_kind"], "global_round")
        self.assertEqual(by_id["0x0651"]["value"]["float_be"], -8.0)
        self.assertEqual(layout["probe_id_registry"], "sparse_enum_not_sequence")
        self.assertEqual(layout["historical_reference"]["sample_count"], 415)

    def test_2001_and_2011_bodies_render_as_word_layouts_not_xor_text(self):
        words_2001 = [0x00000001, 0x00000005, 0x00004000, 0x00000000]
        body_2001 = b"".join(value.to_bytes(4, "big") for value in words_2001)
        record_2001 = _typed_record(
            0x2001,
            length=52,
            selector0=0x23800002,
            selector1=0x34560001,
            inner_field=2,
            body=body_2001,
        )
        packet_2001 = analyze_payload(record_2001, direction=0)["packet"]
        self.assertEqual(packet_2001["semantic_category"], "telemetry.binary_probe.words")
        self.assertEqual(packet_2001["body_layout"]["kind"], "fixed_word_block")
        self.assertEqual(packet_2001["body_layout"]["layout_algebra"], "4×u32 = 16")
        self.assertEqual([word["value"]["be32"] for word in packet_2001["body_layout"]["words"]], words_2001)

        words_2011 = [0x223D8000, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF]
        body_2011 = b"".join(value.to_bytes(4, "big") for value in words_2011)
        record_2011 = _typed_record(
            0x2011,
            length=68,
            selector0=0x23800002,
            selector1=0x34560001,
            inner_field=1,
            body=body_2011,
        )
        packet_2011 = analyze_payload(record_2011, direction=0)["packet"]
        self.assertEqual(packet_2011["semantic_category"], "telemetry.binary_probe.bitmap")
        self.assertEqual(packet_2011["body_layout"]["kind"], "bitmap_word_block")
        self.assertEqual(packet_2011["body_layout"]["layout_algebra"], "8×u32 = 32")
        self.assertEqual(sum(bool(word["all_one"]) for word in packet_2011["body_layout"]["words"]), 5)

    def test_child_semantics_have_broad_categories_instead_of_family_unknown(self):
        opaque_metadata = _metadata_record(0x01122342, b"\x01\x02\x03\x04")
        metadata_analysis = analyze_payload(opaque_metadata, direction=0)["packet"]
        self.assertEqual(metadata_analysis["semantic_category"], "metadata.context")
        self.assertEqual(metadata_analysis["semantic_tier"], "approximate")
        self.assertNotEqual(metadata_analysis["semantic_label_zh"], "未解析记录")

        opaque_typed = _typed_record(0x1004, length=68)
        typed_analysis = analyze_payload(opaque_typed, direction=0)["packet"]
        self.assertEqual(typed_analysis["semantic_category"], "environment.capability_state")
        self.assertEqual(typed_analysis["semantic_tier"], "approximate")
        self.assertEqual(typed_analysis["body_layout"]["kind"], "generic_typed_probe_body")
        self.assertIn("field_boundaries", typed_analysis["body_layout"])

        unknown_short = bytearray(32)
        unknown_short[6:10] = bytes.fromhex("12345678")
        short_analysis = analyze_payload(bytes(unknown_short), direction=0)["packet"]
        self.assertEqual(short_analysis["semantic_category"], "control.opaque_candidate")
        self.assertEqual(short_analysis["semantic_tier"], "approximate")
        self.assertIn("高概率候选", short_analysis["semantic_label_zh"])

    def test_live_pubgm_typed_shapes_get_distinct_high_probability_candidates(self):
        scalar = _typed_record(
            0x0070,
            length=36,
            selector0=0x23800002,
            selector1=0x34560001,
            inner_field=0x3FB33333,
        )
        scalar_analysis = analyze_payload(scalar, direction=0)["packet"]
        self.assertEqual(scalar_analysis["semantic_role"], "runtime_scalar_threshold_candidate")
        self.assertEqual(scalar_analysis["semantic_category"], "environment.runtime_scalar")
        self.assertEqual(
            scalar_analysis["body_layout"]["inner_field_views"]["float_be"],
            struct.unpack(">f", bytes.fromhex("3fb33333"))[0],
        )

        memory_words = [0, 0x0266C000, 0, 0x0D67C000, 0, 0]
        memory = _typed_record(
            0x00A5,
            length=60,
            selector0=0x23800002,
            selector1=0x34560001,
            inner_field=2,
            body=b"".join(value.to_bytes(4, "big") for value in memory_words),
        )
        memory_analysis = analyze_payload(memory, direction=0)["packet"]
        self.assertEqual(memory_analysis["semantic_role"], "memory_region_size_profile_candidate")
        self.assertEqual(memory_analysis["semantic_category"], "environment.memory_layout")
        self.assertEqual(memory_analysis["body_layout"]["traits"]["page_aligned_words"], 2)

        digest_text = b"0123456789ABCDEF0123456789ABCDEF"
        digest = _typed_record(
            0x01C3,
            length=36 + len(digest_text),
            selector0=0x23800002,
            selector1=0x34560001,
            inner_field=0x10,
            body=bytes(value ^ 0xB6 for value in digest_text),
        )
        digest_analysis = analyze_payload(digest, direction=0)["packet"]
        self.assertEqual(digest_analysis["semantic_role"], "integrity_digest_or_hash_list_candidate")
        self.assertEqual(digest_analysis["semantic_category"], "environment.integrity_digest")
        self.assertEqual(digest_analysis["body_layout"]["traits"]["xor_b6_hex_run_count"], 1)
        self.assertIn("shape_gated_value_writer_only", digest_analysis["body_layout"]["semantic_candidate"]["mutation_scope"])

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

    def test_partial_csob_state_with_device_profile_is_labeled_as_csob_candidate(self):
        record = _metadata_record(
            0x01122388,
            b"cs:b1aee09a/890ae32f;model:iPad13,6;ver:16.40;inc_id:95;obf_id:95\x00"
            b"state:00b00017,r:0/2/330/332/210/2/2,p:12317/12317,13\x00",
        )

        analysis = analyze_payload(record, direction=0)

        self.assertEqual(analysis["packet"]["semantic_role"], "csob_state_candidate_missing_ob")
        self.assertEqual(analysis["packet"]["semantic_category"], "metadata.state.csob_candidate")
        self.assertEqual(analysis["packet"]["semantic_label_zh"], "CSOB 状态候选（缺少 ob） + 设备画像")
        self.assertIn("missing_ob", analysis["packet"]["semantic_role_evidence"])

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
        self.assertEqual(pairing["meaning"], "服务器确认型子请求（保活/握手候选）")

    def test_010a0011_child_correlates_exact_010a0010_response_by_leaf_id(self):
        request = bytes.fromhex(
            "00000001001d010a001100000ab2000000000000f42db1fe0468695f31"
        )
        response = bytes.fromhex(
            "000000010016010a001000000ab20000000000000324"
        )
        events = [
            {
                "id": "11",
                "cid": "client->server:65010",
                "ts": 1000,
                "dir": 0,
                "seq": 11,
                "display": request.hex(),
                "analysis": analyze_payload(request, direction=0),
            },
            {
                "id": "12",
                "cid": "client->server:65010",
                "ts": 1125,
                "dir": 1,
                "seq": 12,
                "display": response.hex(),
                "analysis": analyze_payload(response, direction=1),
            },
        ]

        correlate_events(events)

        request_packet = events[0]["analysis"]["packet"]
        response_packet = events[1]["analysis"]["packet"]
        correlation = events[1]["analysis"]["response_correlation"]
        self.assertEqual(request_packet["semantic_role"], "server_acknowledged_child_request")
        request_fields = {item["name"]: item for item in request_packet["fields"]}
        self.assertEqual(request_fields["delivery_requirement"]["value"], "required_no_drop")
        self.assertIn("leaf_id_locked", request_fields["mutation_scope"]["value"])
        self.assertEqual(response_packet["semantic_role"], "010a0011_ack_response")
        self.assertEqual(correlation["status"], "exact_010a0011_leaf_ack")
        self.assertEqual(correlation["request_report_code"], "0x010a0011")
        self.assertEqual(correlation["response_report_code"], "0x010a0010")
        self.assertEqual(correlation["leaf_id"], "0x00000ab2")
        self.assertEqual(correlation["delta_ms"], 125)
        self.assertEqual(correlation["confidence"], "confirmed")
        ack_status = next(field for field in response_packet["fields"] if field["name"] == "ack_status")
        self.assertEqual(ack_status["value"], "0324")

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

    def test_runtime_can_omit_analysis_for_lightweight_event_lists(self):
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
            include_analysis=False,
        )

        self.assertEqual(events[0]["pay"], "")
        self.assertEqual(events[0]["analysis"], {})

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
