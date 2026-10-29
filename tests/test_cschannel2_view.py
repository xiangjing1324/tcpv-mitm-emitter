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

    def test_request_and_response_show_status_summary_and_only_the_new_view(self) -> None:
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
  for (const cls of ['dump-grid', 'child-pair-card', 'fixture-gcloud-panel', 'fixture-readable-summary']) {
    assert(nodes(body, cls).length === 0, 'legacy view leaked: ' + cls);
  }
  const bodyText = text(body);
  for (const expected of ['完整线上帧','密文负载','CRC 通过的解密压缩封套','Snappy 解压明文',
      'ready','sequence_gap=0','11223344','transport=cschannel2 parse=ok crc=match']) {
    assert(bodyText.includes(expected), 'status/summary missing: ' + expected);
  }
  assert(bodyText.includes(dir === 0 ? '请求' : '响应'), 'direction label missing');
}
console.log(JSON.stringify({directions: 2, layers: 4}));
"""
        )
        self.assertEqual(result, {"directions": 2, "layers": 4})

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
