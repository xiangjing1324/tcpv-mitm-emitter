from __future__ import annotations

import base64
import json
import subprocess
import unittest
from unittest import mock

import test_ace_node_focused_view as ace_view
from test_archive_and_store import FakeRedis
from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS

from tcpv_mitm_emitter.runtime import TcpvRuntime
from tcpv_mitm_emitter.semantic import analysis_from_event, analysis_needs_upgrade
from tcpv_mitm_emitter.store import TcpvEventStore


def _tss_record(report: int, payload: bytes = b"") -> bytes:
    record = bytearray(b"\x00\x00\x00\x01\x00\x00")
    record.extend(int(report).to_bytes(4, "big"))
    record.extend(payload)
    record[4:6] = len(record).to_bytes(2, "big")
    return bytes(record)


def _typed_leaf_record() -> bytes:
    record = bytearray(_tss_record(0x0102000A, b"\x00" * 42))
    record[20:22] = (32).to_bytes(2, "big")
    record[22:24] = (0x8029).to_bytes(2, "big")
    record[24:28] = (0x20100002).to_bytes(4, "big")
    record[28:32] = (0x34560001).to_bytes(4, "big")
    record[32:36] = (0x000001CB).to_bytes(4, "big")
    return bytes(record)


def _c2_item(
    body: bytes,
    *,
    identity: bytes = b"",
    business_type: int = 1001,
    business_subtype: int = 0,
) -> bytes:
    if len(identity) > 255:
        raise ValueError("identity is too long")
    return b"".join(
        (
            b"\x03\x04",
            bytes((len(identity),)),
            identity,
            int(business_type).to_bytes(2, "big"),
            int(business_subtype).to_bytes(2, "big"),
            b"\x00" * 12,
            len(body).to_bytes(4, "big"),
            body,
        )
    )


def _c2_type4(*bodies: bytes) -> bytes:
    if len(bodies) > 255:
        raise ValueError("too many nodes")
    encoded = bytearray((4, len(bodies)))
    for body in bodies:
        item = _c2_item(body)
        encoded.extend(len(item).to_bytes(2, "big"))
        encoded.extend(item)
    return bytes(encoded)


def _analysis(*, modified: bool = False, wire_mutated: bool = False) -> dict:
    return {
        "schema": "tcpv.cschannel2.analysis.v1",
        "analysis_authoritative": True,
        "analysis_source": "producer_handoff",
        "mutation": {"modified": modified, "wire_mutated": wire_mutated},
        "transport": {
            "host": "cschannel2.anticheatexpert.com",
            "port": 443,
            "direction": "client_to_server",
            "frame_type": 7,
            "subtype_or_algorithm": 3,
            "algorithm_id": 3,
            "sequence": 41,
            "sequence_gap": 0,
            "frame_length": 23,
            "payload_length": 5,
        },
        "session": {
            "recovery_status": "ready",
            "tested_candidates": 76864,
            "match_count": 1,
            "elapsed_ms": 2538,
        },
        "validation": {
            "parse_status": "ok",
            "display_status": "decoded",
            "crc_match": True,
            "expected_crc32_hex": "11223344",
            "actual_crc32_hex": "11223344",
        },
        "compression": {
            "status": "ok",
            "declared_plain_length": 7,
            "compressed_length": 5,
            "decoded_length": 7,
        },
        "display_mapping": {
            "raw_pay": "complete_wire_frame",
            "before_pay": "encrypted_payload",
            "pay": "crc_validated_decrypted_wrapper",
            "full_pay": "snappy_decompressed_plaintext",
        },
    }


class Cschannel2StoreTests(unittest.TestCase):
    def _store(self) -> TcpvEventStore:
        return TcpvEventStore(
            FakeRedis(), "cschannel2-test", ttl_seconds=0, stream_maxlen=0, api_max_limit=20
        )

    def test_four_decode_layers_are_not_treated_as_mutation(self) -> None:
        store = self._store()
        analysis = _analysis()
        store.append_event(
            "acct",
            "client->cschannel2.anticheatexpert.com:443",
            0,
            b"decrypted-envelope",
            full_payload=b"snappy-plaintext",
            before_payload=b"ciphertext-payload",
            raw_payload=b"complete-wire-frame",
            # Conflicting legacy tokens must not override authoritative flags.
            summary="transport=cschannel2 payload_modified=1 wire_changed=1",
            analysis=analysis,
            ts_ms=1000,
        )

        event = store.get_event("acct", "1")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertFalse(event["modified"])
        self.assertEqual(event["modification_evidence"], [])
        self.assertEqual(event["analysis"], analysis)
        self.assertEqual(base64.b64decode(event["raw_pay"]), b"complete-wire-frame")
        self.assertEqual(base64.b64decode(event["before_pay"]), b"ciphertext-payload")
        self.assertEqual(base64.b64decode(event["pay"]), b"decrypted-envelope")
        self.assertEqual(base64.b64decode(event["full_pay"]), b"snappy-plaintext")

        compact, _last_id, _has_more = store.get_events(
            "acct", include_payload=False, include_analysis=False
        )
        self.assertFalse(compact[0]["modified"])
        self.assertEqual(compact[0]["modification_evidence"], [])

    def test_either_authoritative_mutation_flag_is_positive_evidence(self) -> None:
        for modified, wire_mutated in ((True, False), (False, True)):
            with self.subTest(modified=modified, wire_mutated=wire_mutated):
                store = self._store()
                store.append_event(
                    "acct",
                    "cid",
                    0,
                    b"envelope",
                    full_payload=b"plain",
                    before_payload=b"cipher",
                    raw_payload=b"frame",
                    analysis=_analysis(modified=modified, wire_mutated=wire_mutated),
                    ts_ms=1000,
                )
                event = store.get_event("acct", "1")
                assert event is not None
                self.assertTrue(event["modified"])
                self.assertEqual(event["modification_evidence"], ["analysis"])

    def test_runtime_and_semantic_layer_keep_authoritative_analysis_verbatim(self) -> None:
        store = self._store()
        runtime = TcpvRuntime()
        runtime.store = store
        analysis = _analysis()
        item = {
            "account": "acct",
            "cid": "cid",
            "dir": 1,
            "payload": b"envelope",
            "packet_len": 8,
            "full_payload": b"plain",
            "full_packet_len": 5,
            "before_payload": b"cipher",
            "before_packet_len": 6,
            "raw_payload": b"frame",
            "raw_packet_len": 5,
            "summary": "transport=cschannel2",
            "analysis": analysis,
            "proxy_username": "",
            "ts_ms": 1000,
            "msg_idx": 1,
            "chunk_idx": 0,
        }
        with mock.patch("tcpv_mitm_emitter.runtime.analyze_payload") as analyze:
            runtime._append_store_event(store, item)
        analyze.assert_not_called()
        self.assertEqual(runtime.get_stats()["producer_analysis_count"], 1)
        self.assertEqual(runtime.get_stats()["semantic_skipped_payload_count"], 4)
        self.assertFalse(analysis_needs_upgrade(analysis))

        event = store.get_event("acct", "1")
        assert event is not None
        with mock.patch("tcpv_mitm_emitter.semantic.analyze_payload") as analyze_semantic:
            rebuilt = analysis_from_event(event)
        analyze_semantic.assert_not_called()
        self.assertIs(rebuilt, event["analysis"])

    def test_runtime_emit_keeps_raw_only_authoritative_frame(self) -> None:
        store = self._store()
        runtime = TcpvRuntime()
        runtime.store = store
        runtime.enabled = True
        analysis = _analysis()
        analysis["validation"] = {
            "parse_status": "raw_only",
            "display_status": "raw_only",
            "crc_match": False,
        }
        analysis["compression"] = {"status": "not_attempted"}
        runtime.emit_packet(
            account="acct",
            packet_data=b"",
            from_client=False,
            cid="server->client",
            summary="transport=cschannel2 display_status=raw_only",
            raw_packet_data=b"complete-wire-frame",
            raw_packet_len=len(b"complete-wire-frame"),
            analysis=analysis,
            ts_ms=1000,
        )
        item = runtime._queue.get_nowait()
        self.assertEqual(item["payload"], b"")
        self.assertEqual(item["raw_payload"], b"complete-wire-frame")
        runtime._append_store_event(store, item)
        event = store.get_event("acct", "1")
        assert event is not None
        self.assertEqual(event["pay"], "")
        self.assertEqual(base64.b64decode(event["raw_pay"]), b"complete-wire-frame")
        self.assertEqual(event["analysis"]["validation"]["display_status"], "raw_only")

        untrusted = TcpvRuntime()
        untrusted.store = self._store()
        untrusted.enabled = True
        untrusted.emit_packet(
            account="acct",
            packet_data=b"",
            from_client=False,
            raw_packet_data=b"frame",
            analysis={**analysis, "analysis_authoritative": False},
        )
        self.assertTrue(untrusted._queue.empty(), "untrusted empty pay bypassed the existing guard")


class Cschannel2BrowserViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ace_view.AceNodeFocusedViewTests.setUpClass()
        source = APP_JS.read_text(encoding="utf-8")
        cls.runtime = (
            ace_view.AceNodeFocusedViewTests.runtime
            + "\nconst ANALYSIS_XOR_SCAN_MAX_BYTES = 768;\n"
            + "\nconst payloadCache = new Map(); let payloadCacheBytes = 0;"
            + "\nconst PAYLOAD_CACHE_MAX_ENTRIES = 24; const PAYLOAD_CACHE_MAX_BYTES = 6 * 1024 * 1024;\n"
            + "\n".join(
                _packet_function(source, name)
                for name in (
                    "eventModificationDiffText", "eventModificationEvidence", "buildPayloadCacheKey",
                    "trimPayloadCache", "readPayloadCache", "writePayloadCache", "applyEventPayloadDetail",
                )
            )
        )

    def run_js(self, assertions: str) -> dict:
        result = subprocess.run(
            ["node"],
            input=self.runtime + "\n" + assertions,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        return json.loads(result.stdout)

    def test_exact_authority_gate_and_four_distinct_sources(self) -> None:
        result = self.run_js(
            r"""
const analysis = """ + json.dumps(_analysis()) + r""";
const values = {
  raw_pay: [1,2,3,4], before_pay: [17,18,19], pay: [33,34,35,36,37], full_pay: [49,50,51,52,53,54],
};
const ev = { dir: 0, analysis, summary: 'transport=cschannel2 crc_match=1', cid: 'cschannel2.anticheatexpert.com:443' };
for (const [key, bytes] of Object.entries(values)) ev[key] = gcloudBytesBase64(bytes);
Object.assign(ev, { raw_len: 4, before_len: 3, len: 5, full_len: 6 });
const original = JSON.stringify(ev);
const sources = cschannel2LayerSources(ev);
assert(JSON.stringify(sources.map(item => item.key)) === JSON.stringify(['raw_pay','before_pay','pay','full_pay']), 'stage order changed');
assert(JSON.stringify(sources.map(item => item.bytes)) === JSON.stringify(Object.values(values)), 'stage bytes crossed fields');
assert(sources.every(item => item.status === 'complete' && item.complete), 'complete stage marked incomplete');
assert(sources[2].label.includes('CRC 通过') && sources[3].label.includes('Snappy 解压'), 'verified success labels missing');
assert(JSON.stringify(ev) === original, 'view adapter mutated event');
assert(cschannel2AuthoritativeAnalysis(ev) === analysis, 'exact authoritative analysis rejected');
for (const candidate of [
  {...ev, analysis: {...analysis, analysis_authoritative: false}},
  {...ev, analysis: {...analysis, schema: 'tcpv.cschannel2.analysis.v2'}},
  {...ev, analysis: null},
]) assert(cschannel2AuthoritativeAnalysis(candidate) === null, 'untrusted/wrong schema accepted');
console.log(JSON.stringify({sources: sources.length, exact: true}));
"""
        )
        self.assertEqual(result, {"sources": 4, "exact": True})

    def test_handshake_mapping_never_uses_type7_crypto_labels(self) -> None:
        result = self.run_js(
            r"""
const base = """ + json.dumps(_analysis()) + r""";
for (const [frameType, dir, frameLength] of [[1, 0, 416], [2, 1, 306]]) {
  const frame = [frameType, 3, 1, 0]; const payload = [9,8,7];
  const analysis = {...base,
    transport: {...base.transport, frame_type: frameType, frame_length: frameLength,
      direction: dir === 0 ? 'client_to_server' : 'server_to_client'},
    validation: {parse_status:'handshake_ok', display_status:'handshake', crc_match:null},
    compression: {status:'not_applicable'},
    display_mapping: {pay:'complete_handshake_frame', full_pay:'unavailable',
      before_pay:'handshake_payload', raw_pay:'complete_handshake_frame'}};
  const ev = {dir, analysis, pay:gcloudBytesBase64(frame), len:frame.length,
    full_pay:'', full_len:0, before_pay:gcloudBytesBase64(payload), before_len:payload.length,
    raw_pay:gcloudBytesBase64(frame), raw_len:frame.length};
  const sources = cschannel2LayerSources(ev);
  const labels = Object.fromEntries(sources.map(source => [source.key, source.label]));
  assert(labels.pay === '完整握手帧' && labels.raw_pay === '完整握手帧', 'handshake frame mapping ignored');
  assert(labels.before_pay === '握手负载' && labels.full_pay === '不可用', 'handshake payload/unavailable mapping ignored');
  assert(!labels.pay.includes('解密') && !labels.before_pay.includes('密文'), 'handshake mislabeled as type7 crypto');
}
console.log(JSON.stringify({handshakes: 2, honest: true}));
"""
        )
        self.assertEqual(result, {"handshakes": 2, "honest": True})

    def test_raw_fallback_mapping_does_not_claim_decryption(self) -> None:
        result = self.run_js(
            r"""
const base = """ + json.dumps(_analysis()) + r""";
const analysis = {...base,
  validation:{parse_status:'type7_ok', display_status:'crc_failed_raw_fallback', crc_match:false,
    expected_crc32_hex:'11223344', actual_crc32_hex:'55667788'},
  compression:{status:'not_attempted'},
  display_mapping:{pay:'raw_fallback', full_pay:'unavailable', before_pay:'encrypted_payload', raw_pay:'complete_wire_frame'}};
const ev = {dir:0, analysis, pay:gcloudBytesBase64([1,2,3]), len:3,
  full_pay:'', full_len:0, before_pay:gcloudBytesBase64([4,5]), before_len:2,
  raw_pay:gcloudBytesBase64([0,0,0,7,1,2,3]), raw_len:7};
const sources = cschannel2LayerSources(ev);
const labels = Object.fromEntries(sources.map(source => [source.key, source.label]));
assert(labels.pay === '未解密原始回退' && !labels.pay.includes('封套'), 'raw fallback mislabeled as decrypted wrapper');
assert(labels.before_pay === '密文负载' && labels.raw_pay === '完整线上帧', 'type7 raw evidence roles changed');
assert(labels.full_pay === '不可用' && !labels.full_pay.includes('明文'), 'missing plaintext was invented');
const parsedAnalysis = {...base,
  transport:{...base.transport, frame_type:99, algorithm_id:null},
  validation:{parse_status:'unsupported_type', display_status:'raw_only', crc_match:null},
  compression:{status:'not_attempted'},
  display_mapping:{pay:'raw_fallback', full_pay:'unavailable', before_pay:'wire_payload', raw_pay:'complete_wire_frame'}};
const parsed = cschannel2LayerSources({...ev, analysis:parsedAnalysis});
const parsedLabels = Object.fromEntries(parsed.map(source => [source.key, source.label]));
assert(parsedLabels.pay === '未解密原始回退' && parsedLabels.before_pay === '线上负载（未解密）', 'ordinary raw-only roles ignored');
assert(!parsedLabels.before_pay.includes('密文负载'), 'unknown raw-only payload invented encryption');
console.log(JSON.stringify({rawFallback: 2, honest: true}));
"""
        )
        self.assertEqual(result, {"rawFallback": 2, "honest": True})

    def test_truncated_stream_preview_uses_preview_roles_and_lengths(self) -> None:
        result = self.run_js(
            r"""
const base = """ + json.dumps(_analysis()) + r""";
const preview = [1,2,3,4];
const analysis = {...base,
  transport:{...base.transport, frame_type:-1, frame_length:40, payload_length:40},
  validation:{parse_status:'stream_error', display_status:'truncated_preview', crc_match:null,
    display_truncated:true, preview_length:preview.length},
  compression:{status:'not_attempted'},
  display_mapping:{pay:'raw_fallback', full_pay:'unavailable',
    before_pay:'observed_tcp_chunk_preview', raw_pay:'observed_tcp_chunk_preview'}};
const ev = {dir:1, analysis, pay:gcloudBytesBase64(preview), len:40,
  full_pay:'', full_len:0, before_pay:gcloudBytesBase64(preview), before_len:40,
  raw_pay:gcloudBytesBase64(preview), raw_len:40};
const sources = cschannel2LayerSources(ev);
const byKey = Object.fromEntries(sources.map(source => [source.key, source]));
for (const key of ['pay','before_pay','raw_pay']) assert(byKey[key].status === 'truncated', key + ' preview completeness overstated');
assert(byKey.before_pay.label.includes('TCP 分片观测预览') && byKey.raw_pay.label.includes('TCP 分片观测预览'), 'preview mapping ignored');
assert(byKey.pay.label.includes('未解密原始回退') && !byKey.pay.label.includes('解密压缩封套'), 'truncated raw pay mislabeled decrypted');
assert(!byKey.raw_pay.label.includes('完整线上帧') && byKey.full_pay.label === '不可用', 'truncated preview mislabeled complete/plaintext');
const observerAnalysis = {...analysis,
  transport:{...analysis.transport, frame_type:null},
  validation:{...analysis.validation, parse_status:'observer_unavailable', display_status:'raw_only_preview'},
  display_mapping:{pay:'raw_fallback', full_pay:'unavailable', before_pay:'raw_fallback', raw_pay:'observed_tcp_chunk_preview'}};
const observer = cschannel2LayerSources({...ev, analysis:observerAnalysis});
const observerLabels = Object.fromEntries(observer.map(source => [source.key, source.label]));
assert(observerLabels.pay.includes('未解密原始回退') && observerLabels.before_pay.includes('未解密原始回退'), 'observer fallback mislabeled parsed/decrypted');
assert(observerLabels.raw_pay.includes('TCP 分片观测预览') && observerLabels.full_pay === '不可用', 'observer preview mapping ignored');
console.log(JSON.stringify({truncated: 3, previewLength: preview.length, observer: true}));
"""
        )
        self.assertEqual(result, {"truncated": 3, "previewLength": 4, "observer": True})

    def test_request_and_response_use_compact_view_and_collapsed_four_layer_evidence(self) -> None:
        result = self.run_js(
            r"""
const analysis = """ + json.dumps(_analysis()) + r""";
const bytes = value => gcloudBytesBase64(value);
for (const dir of [0, 1]) {
  const ev = { dir, analysis, cid: 'cschannel2.anticheatexpert.com:443', summary: 'transport=cschannel2 parse=ok crc=match',
    raw_pay: bytes([1,2,3,4]), raw_len: 4, before_pay: bytes([5,6,7]), before_len: 3,
    pay: bytes([8,9,10,11,12]), len: 5, full_pay: bytes([13,14,15,16,17,18]), full_len: 6 };
  const body = buildEventBody(ev, false, 'fixture-event');
  assert(nodes(body, 'cschannel2-view').length === 1, 'dedicated view missing');
  assert(nodes(body, 'cschannel2-layer').length === 4, 'four layers not rendered');
  assert(nodes(body, 'cschannel2-evidence').length === 1 && !nodes(body, 'cschannel2-evidence')[0].open, 'evidence must default collapsed');
  assert(nodes(body, 'cschannel2-layer').every(layer => !layer.open), 'individual evidence layers must default collapsed');
  for (const cls of ['dump-grid', 'child-pair-card', 'fixture-gcloud-panel', 'fixture-readable-summary', 'cschannel2-status']) {
    assert(nodes(body, cls).length === 0, 'legacy view leaked: ' + cls);
  }
  const bodyText = text(body);
  for (const expected of ['完整线上帧','密文负载','CRC 通过的解密压缩封套','Snappy 解压明文',
      '密钥就绪','CRC ✓','Snappy ✓','加密 / 校验 / 解压证据','transport=cschannel2 parse=ok crc=match']) {
    assert(bodyText.includes(expected), 'status/summary missing: ' + expected);
  }
  for (const hidden of ['Analysis（权威分析）','Display mapping（字段映射）','tested=76864','expected=11223344']) {
    assert(!bodyText.includes(hidden), 'low-value diagnostics leaked into compact view: ' + hidden);
  }
  assert(bodyText.includes(dir === 0 ? '请求' : '响应'), 'direction label missing');
}
console.log(JSON.stringify({directions: 2, layers: 4}));
"""
        )
        self.assertEqual(result, {"directions": 2, "layers": 4})

    def test_type4_parser_uses_be32_body_length_and_exact_node_boundaries(self) -> None:
        first = _typed_leaf_record()
        second = _tss_record(0x01122389, b"second-node")
        type4 = _c2_type4(first, second)
        identity_item = _c2_item(first, identity=b"identity-20-bytes!!!!"[:20])
        result = self.run_js(
            r"""
const type4 = """ + json.dumps(list(type4)) + r""";
const parsed = parseCschannel2PlaintextNodes(type4);
assert(parsed.ok && parsed.exactConsumption && parsed.carrierType === 4, 'type4 carrier rejected');
assert(parsed.declaredCount === 2 && parsed.nodes.length === 2, 'type4 node count changed');
assert(parsed.nodes.every(node => node.complete && node.analyzerEligible), 'eligible records not verified');
assert(parsed.nodes[0].bodyLength === """ + str(len(first)) + r""" && parsed.nodes[1].bodyLength === """ + str(len(second)) + r""", 'canonical BE32 body length ignored');
assert(parsed.nodes[0].itemOffset === 4 && parsed.nodes[1].itemOffset === 4 + parsed.nodes[0].itemLength + 2, 'item offsets crossed length prefixes');
const identityItem = """ + json.dumps(list(identity_item)) + r""";
const direct = parseCschannel2PlaintextNodes(identityItem);
assert(direct.ok && direct.nodes.length === 1, 'type3 direct item rejected');
assert(direct.nodes[0].identityLength === 20 && direct.nodes[0].headerLength === 43, 'identity-dependent header was hard-coded to 23');
assert(direct.nodes[0].bodyOffset === 43 && direct.nodes[0].bodyLength === """ + str(len(first)) + r""", 'dynamic body boundary wrong');
console.log(JSON.stringify({nodes: parsed.nodes.length, identityHeader: direct.nodes[0].headerLength}));
"""
        )
        self.assertEqual(result, {"nodes": 2, "identityHeader": 43})

    def test_verified_type4_nodes_reuse_legacy_preview_highlight_and_full_hex(self) -> None:
        first = _typed_leaf_record()
        second = _tss_record(0x01122389, b"printable-node")
        plaintext = _c2_type4(first, second)
        analysis = _analysis()
        analysis["compression"].update(
            declared_plain_length=len(plaintext), decoded_length=len(plaintext)
        )
        result = self.run_js(
            r"""
const analysis = """ + json.dumps(analysis) + r""";
const plain = """ + json.dumps(list(plaintext)) + r""";
const ev = {dir:0, analysis, summary:'transport=cschannel2',
  raw_pay:gcloudBytesBase64([7,3,4]), raw_len:3,
  before_pay:gcloudBytesBase64([9,8]), before_len:2,
  pay:gcloudBytesBase64([5,2,0]), len:3,
  full_pay:gcloudBytesBase64(plain), full_len:plain.length};
const body = buildEventBody(ev, false, 'type4-fixture');
assert(nodes(body, 'cschannel2-node-panel').length === 2, 'carrier nodes not rendered one by one');
assert(nodes(body, 'child-pair-card').length === 2, 'legacy cards not reused for roots');
assert(nodes(body, 'child-preview-row-single').length === 2, 'current-only preview is not single-column');
assert(nodes(body, 'child-hex-table').length === 2, 'complete legacy hex table missing');
assert(nodes(body, 'child-hex-row-report').length >= 2, 'report highlight rows missing');
assert(nodes(body, 'child-hex-byte-cell').length === """ + str(len(first) + len(second)) + r""", 'complete record bytes were not rendered');
assert(!nodes(body, 'child-preview-before').length && !nodes(body, 'child-preview-after').length, 'crypto stages became before/after mutation');
const bodyText = text(body);
for (const expected of ['业务节点 2','node[0] 预览','node[1] 预览','0x0102000a','0x01122389','当前结构']) {
  assert(bodyText.includes(expected), 'legacy node preview detail missing: ' + expected);
}
assert(!bodyText.includes('修改前') && !bodyText.includes('修改后'), 'read-only stages mislabeled as mutation');
console.log(JSON.stringify({panels:nodes(body,'cschannel2-node-panel').length, cards:nodes(body,'child-pair-card').length}));
"""
        )
        self.assertEqual(result, {"panels": 2, "cards": 2})

    def test_encrypted_record_reuses_legacy_child_cards_after_verified_inner_crc(self) -> None:
        outer = _tss_record(0x010A0008, b"encrypted-envelope-fixture")
        plaintext = _c2_type4(outer)
        analysis = _analysis()
        analysis["compression"].update(
            declared_plain_length=len(plaintext), decoded_length=len(plaintext)
        )
        result = self.run_js(
            r"""
const analysis = """ + json.dumps(analysis) + r""";
const outer = """ + json.dumps(list(outer)) + r""";
const inner = container([
  record(0x010a0057, 'first-inner-child'),
  record(0x010a005f, 'second-inner-child'),
]);
encryptedFixtures.set(gcloudBytesBase64(outer), {
  supported:true, crcMatch:true, family:2, familyName:'family2_rc6', slot:8,
  expectedCrc:1, actualCrc:1, cipherLength:16, plain:inner,
  innerRoot:{value:0x010a001b, offset:6},
});
const plain = """ + json.dumps(list(plaintext)) + r""";
const ev = {dir:0, analysis, summary:'', raw_pay:gcloudBytesBase64([1]), raw_len:1,
  before_pay:gcloudBytesBase64([2]), before_len:1, pay:gcloudBytesBase64([3]), len:1,
  full_pay:gcloudBytesBase64(plain), full_len:plain.length};
const body = buildEventBody(ev, false, 'inner-fixture');
assert(nodes(body, 'cschannel2-node-panel').length === 1, 'outer node panel missing');
assert(nodes(body, 'cschannel2-inner-panel').length === 1, 'verified decrypted child panel missing');
assert(nodes(body, 'child-pair-card').length === 3, 'outer root plus every inner child must render');
assert(nodes(body, 'child-hex-table').length === 3, 'inner child lost complete hex preview');
const bodyText = text(body);
for (const expected of ['node[0] 解密后 child','CRC32 通过','child[0]','child[1]','first-inner-child','second-inner-child']) {
  assert(bodyText.includes(expected), 'inner legacy preview missing: ' + expected);
}
console.log(JSON.stringify({outer:1, innerCards:2, totalCards:nodes(body,'child-pair-card').length}));
"""
        )
        self.assertEqual(result, {"outer": 1, "innerCards": 2, "totalCards": 3})

    def test_all_type4_nodes_render_and_unsupported_records_remain_opaque(self) -> None:
        supported = [_tss_record(0x010A0011, bytes((index,))) for index in range(10)]
        unsupported_family = _tss_record(0x01110002, b"opaque-family")
        unsupported_business_item = _c2_item(
            b"not-a-tss-record", business_type=1002, business_subtype=11
        )
        encoded = bytearray((4, 12))
        for body in [*supported, unsupported_family]:
            item = _c2_item(body)
            encoded.extend(len(item).to_bytes(2, "big"))
            encoded.extend(item)
        encoded.extend(len(unsupported_business_item).to_bytes(2, "big"))
        encoded.extend(unsupported_business_item)
        analysis = _analysis()
        analysis["compression"].update(
            declared_plain_length=len(encoded), decoded_length=len(encoded)
        )
        result = self.run_js(
            r"""
const analysis = """ + json.dumps(analysis) + r""";
const plain = """ + json.dumps(list(encoded)) + r""";
const ev = {dir:0, analysis, summary:'', raw_pay:gcloudBytesBase64([1]), raw_len:1,
  before_pay:gcloudBytesBase64([2]), before_len:1, pay:gcloudBytesBase64([3]), len:1,
  full_pay:gcloudBytesBase64(plain), full_len:plain.length};
const parsed = parseCschannel2PlaintextNodes(plain);
assert(parsed.ok && parsed.nodes.length === 12, 'outer verified item list rejected');
assert(parsed.nodes[10].recordStatus === 'unsupported_report_family' && !parsed.nodes[10].analyzerEligible, 'unsupported family was forced through old detector');
assert(parsed.nodes[11].recordStatus === 'unsupported_business' && !parsed.nodes[11].analyzerEligible, 'unsupported business was forced through old detector');
const body = buildEventBody(ev, false, 'many-nodes');
assert(nodes(body, 'cschannel2-node-panel').length === 12, 'type4 nodes were capped at legacy child limit');
assert(nodes(body, 'child-pair-card').length === 12, 'opaque nodes did not preserve individual previews');
assert(text(body).includes('record / opaque 2'), 'carrier title overclaimed every node as TerSafe');
assert(nodes(body, 'child-compare-note').length === 0, 'all top-level nodes were not rendered');
assert(nodes(body, 'cschannel2-node-panel').filter(panel => panel.dataset.recordStatus === 'unsupported_report_family').length === 1, 'unsupported family status missing');
assert(nodes(body, 'cschannel2-node-panel').filter(panel => panel.dataset.recordStatus === 'unsupported_business').length === 1, 'unsupported business status missing');
const unsupportedBusinessPanel = nodes(body, 'cschannel2-node-panel').find(panel => panel.dataset.recordStatus === 'unsupported_business');
assert(unsupportedBusinessPanel && !text(unsupportedBusinessPanel).includes('0x00000000'), 'opaque business fabricated report 0');
console.log(JSON.stringify({nodes:nodes(body,'cschannel2-node-panel').length, opaque:2}));
"""
        )
        self.assertEqual(result, {"nodes": 12, "opaque": 2})

    def test_oversized_node_list_keeps_every_node_but_defers_full_hex_dom(self) -> None:
        plaintext = _c2_type4(
            *[_tss_record(0x010A0011, bytes((index,))) for index in range(65)]
        )
        analysis = _analysis()
        analysis["compression"].update(
            declared_plain_length=len(plaintext), decoded_length=len(plaintext)
        )
        result = self.run_js(
            r"""
const analysis = """ + json.dumps(analysis) + r""";
const plain = """ + json.dumps(list(plaintext)) + r""";
const ev = {dir:0, analysis, summary:'', raw_pay:gcloudBytesBase64([1]), raw_len:1,
  before_pay:gcloudBytesBase64([2]), before_len:1, pay:gcloudBytesBase64([3]), len:1,
  full_pay:gcloudBytesBase64(plain), full_len:plain.length};
const body = buildEventBody(ev, false, 'deferred');
const deferred = nodes(body, 'cschannel2-node-deferred');
assert(deferred.length === 65, 'large carrier did not preserve every node summary');
assert(!nodes(body, 'cschannel2-node-panel').length && !nodes(body, 'child-pair-card').length, 'large carrier eagerly built full hex DOM');
assert(text(body).includes('node[64]'), 'last node summary disappeared');
deferred[0].open = true;
for (const callback of deferred[0].listeners.toggle || []) callback({target:deferred[0]});
assert(nodes(body, 'cschannel2-node-panel').length === 1 && nodes(body, 'child-pair-card').length === 1, 'expanded node did not build complete preview');
assert(nodes(body, 'child-hex-table').length === 1, 'expanded node lost full hex table');
console.log(JSON.stringify({summaries:deferred.length, rendered:nodes(body,'child-pair-card').length}));
"""
        )
        self.assertEqual(result, {"summaries": 65, "rendered": 1})

    def test_malformed_type4_and_type10_fail_closed_without_fake_nodes(self) -> None:
        good = _c2_type4(_tss_record(0x010A0011, b"ok"))
        malformed = bytearray(good)
        malformed[2:4] = (len(good) + 20).to_bytes(2, "big")
        type10 = bytes.fromhex(
            "0a0000000b3237303333333632353600000100000000094e00000000"
        )
        analysis = _analysis()
        result = self.run_js(
            r"""
const base = """ + json.dumps(analysis) + r""";
for (const [name, plain] of [['malformed', """ + json.dumps(list(malformed)) + r"""], ['type10', """ + json.dumps(list(type10)) + r"""]]) {
  const analysis = {...base, compression:{...base.compression, declared_plain_length:plain.length, decoded_length:plain.length}};
  const ev = {dir:1, analysis, summary:'', raw_pay:gcloudBytesBase64([1]), raw_len:1,
    before_pay:gcloudBytesBase64([2]), before_len:1, pay:gcloudBytesBase64([3]), len:1,
    full_pay:gcloudBytesBase64(plain), full_len:plain.length};
  const parsed = parseCschannel2PlaintextNodes(plain);
  assert(!parsed.ok && parsed.nodes.length === 0, name + ' fabricated parsed nodes');
  const body = buildEventBody(ev, false, name);
  assert(!nodes(body, 'cschannel2-node-panel').length && !nodes(body, 'child-pair-card').length, name + ' fabricated semantic cards');
  assert(nodes(body, 'cschannel2-parse-note').length === 1, name + ' fail-closed note missing');
  assert(nodes(body, 'cschannel2-layer').length === 4, name + ' lost raw evidence');
}
console.log(JSON.stringify({negativeControls:2, fakeNodes:0}));
"""
        )
        self.assertEqual(result, {"negativeControls": 2, "fakeNodes": 0})

    def test_crc_snappy_or_full_length_failure_never_enters_node_parser(self) -> None:
        plaintext = _c2_type4(_tss_record(0x010A0011, b"trusted-only"))
        base = _analysis()
        base["compression"].update(
            declared_plain_length=len(plaintext), decoded_length=len(plaintext)
        )
        result = self.run_js(
            r"""
const base = """ + json.dumps(base) + r""";
const plain = """ + json.dumps(list(plaintext)) + r""";
const variants = [
  {...base, validation:{...base.validation, crc_match:false}},
  {...base, compression:{...base.compression, status:'failed'}},
  {...base, validation:{...base.validation, display_status:'raw_only'}},
  {...base, transport:{...base.transport, frame_type:1}},
  {...base, compression:{...base.compression, decoded_length:plain.length + 1}},
];
for (const analysis of variants) {
  const ev = {dir:0, analysis, summary:'', raw_pay:gcloudBytesBase64([1]), raw_len:1,
    before_pay:gcloudBytesBase64([2]), before_len:1, pay:gcloudBytesBase64([3]), len:1,
    full_pay:gcloudBytesBase64(plain), full_len:plain.length};
  const body = buildEventBody(ev, false, 'gate');
  assert(!nodes(body, 'child-pair-card').length, 'failed verification entered node parser');
}
const truncated = {dir:0, analysis:base, summary:'', raw_pay:gcloudBytesBase64([1]), raw_len:1,
  before_pay:gcloudBytesBase64([2]), before_len:1, pay:gcloudBytesBase64([3]), len:1,
  full_pay:gcloudBytesBase64(plain.slice(0,-1)), full_len:plain.length};
assert(!nodes(buildEventBody(truncated,false,'truncated'), 'child-pair-card').length, 'truncated full_pay entered node parser');
console.log(JSON.stringify({gates:6, fakeNodes:0}));
"""
        )
        self.assertEqual(result, {"gates": 6, "fakeNodes": 0})

    def test_crc_compression_and_mutation_statuses_do_not_overclaim(self) -> None:
        result = self.run_js(
            r"""
const base = """ + json.dumps(_analysis()) + r""";
const ev = { dir: 1, summary: 'payload_modified=1 wire_changed=1',
  raw_pay: gcloudBytesBase64([1]), raw_len: 1, before_pay: gcloudBytesBase64([2]), before_len: 1,
  pay: gcloudBytesBase64([3]), len: 1, full_pay: gcloudBytesBase64([4]), full_len: 1,
  analysis: {...base, validation: {...base.validation, crc_match: false}, compression: {...base.compression, status: 'failed'},
    display_mapping: {}, mutation: {modified: false, wire_mutated: false}} };
const sources = cschannel2LayerSources(ev);
assert(!sources[2].label.includes('CRC 通过'), 'failed CRC labeled passed');
assert(!sources[3].label.includes('Snappy 解压明文'), 'failed Snappy labeled decoded');
assert(!sources[3].label.includes('明文'), 'failed Snappy still claimed plaintext');
const conflicting = cschannel2LayerSources({...ev, analysis: {...ev.analysis,
  compression: {...ev.analysis.compression, status: 'snappy_ok'}}});
assert(!conflicting[3].label.includes('Snappy 解压明文'), 'CRC failure plus snappy_ok overclaimed plaintext');
const unsupported = cschannel2LayerSources({...ev, full_pay:'', full_len:0, analysis: {...base,
  validation:{...base.validation, display_status:'snappy_unsupported', crc_match:true},
  compression:{...base.compression, status:'unsupported'}, display_mapping:{}}});
assert(unsupported[1].label === '密文负载', 'type7 encrypted payload fallback disappeared');
assert(unsupported[2].label.includes('CRC 通过'), 'valid wrapper disappeared when Snappy was unsupported');
assert(!unsupported[3].label.includes('明文') && unsupported[3].label.includes('未完成'), 'unsupported Snappy invented plaintext');
const rawStatusConflict = cschannel2LayerSources({...ev, analysis: {...base,
  validation:{...base.validation, display_status:'raw_only', crc_match:true},
  compression:{...base.compression, status:'snappy_ok'}}});
assert(!rawStatusConflict[2].label.includes('CRC 通过') && !rawStatusConflict[3].label.includes('明文'), 'raw-only validation was overridden by success roles');
const unchanged = eventModificationEvidence(ev, ev.summary);
assert(unchanged && unchanged.state === 'unchanged' && !unchanged.modified, 'cross-stage bytes or summary tokens became mutation');
assert(!eventModificationDiffText(ev).short, 'cross-stage diff text was generated');
for (const [flags, expected] of [[{modified:true,wire_mutated:false},'mutation.modified=true'], [{modified:false,wire_mutated:true},'mutation.wire_mutated=true']]) {
  const evidence = eventModificationEvidence({...ev, analysis: {...ev.analysis, mutation: flags}}, ev.summary);
  assert(evidence && evidence.state === 'modified' && evidence.reasons.some(reason => reason.includes(expected)), expected + ' ignored');
}
assert(eventModificationEvidence({...ev, analysis: {...ev.analysis, mutation: {modified:false}}}, ev.summary) === null, 'missing mutation flag guessed unchanged');
console.log(JSON.stringify({unchanged: true, positives: 2, truthfulFailures: true}));
"""
        )
        self.assertEqual(
            result, {"unchanged": True, "positives": 2, "truthfulFailures": True}
        )

    def test_payload_cache_and_hydration_keep_raw_only_authoritative_events(self) -> None:
        result = self.run_js(
            r"""
const analysis = """ + json.dumps(_analysis()) + r""";
const detail = { pay: '', len: 0, full_pay: '', full_len: 0, before_pay: '', before_len: 0,
  raw_pay: gcloudBytesBase64([7,8,9]), raw_len: 3, summary: 'parse_status=raw_only',
  cid: 'cschannel2.anticheatexpert.com:443', analysis };
writePayloadCache('flow', 'event', detail);
const cached = readPayloadCache('flow', 'event');
assert(cached && cached.raw_pay === detail.raw_pay && cached.raw_len === 3, 'raw-only stage was not cached');
assert(cached.analysis === analysis, 'authoritative analysis identity changed in cache');
const ev = { pay: 'stale', len: 99 };
assert(applyEventPayloadDetail(ev, cached), 'raw-only authoritative detail was rejected');
assert(ev.pay === '' && ev.raw_pay === detail.raw_pay && ev.raw_len === 3, 'raw-only hydration crossed stages');
assert(ev.analysis === analysis && ev.summary === detail.summary, 'analysis/summary not hydrated verbatim');
console.log(JSON.stringify({cached: true, rawOnly: true}));
"""
        )
        self.assertEqual(result, {"cached": True, "rawOnly": True})


if __name__ == "__main__":
    unittest.main()
