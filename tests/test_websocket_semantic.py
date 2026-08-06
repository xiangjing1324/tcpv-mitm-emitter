from __future__ import annotations

import base64
import io
import json
import unittest
import zipfile
import zlib

from tcpv_mitm_emitter.websocket_semantic import (
    analyze_websocket_payload,
    format_websocket_summary,
)


def _feature_message() -> tuple[bytes, bytes, bytes]:
    entry = b"\x00\x01MRPCS-rule-table\x00" * 32
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("unzipmrpcs.data", entry)
    blob = buffer.getvalue()
    payload = json.dumps(
        {
            "method": "ACELightFeature",
            "featureName": "mrpcs_i_l.data",
            "featureData": base64.b64encode(blob).decode("ascii"),
            "dataCRC": zlib.crc32(blob) & 0xFFFFFFFF,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return payload, blob, entry


class WebSocketSemanticTests(unittest.TestCase):
    def test_ace_light_feature_decodes_base64_zip_and_both_crc_scopes(self) -> None:
        payload, blob, entry = _feature_message()
        analysis = analyze_websocket_payload(
            payload,
            from_client=False,
            url="https://lobby.rm.qq.com/wsgate?authorization=must-not-be-stored",
        )

        self.assertEqual(analysis["schema"], "tcpv.wss_json.analysis.v1")
        self.assertTrue(analysis["analysis_authoritative"])
        self.assertEqual(analysis["transport"]["host"], "lobby.rm.qq.com")
        self.assertEqual(analysis["transport"]["path"], "/wsgate")
        self.assertFalse(analysis["transport"]["query_stored"])
        self.assertNotIn("authorization", json.dumps(analysis))
        self.assertEqual(analysis["json"]["method"], "ACELightFeature")

        resource = analysis["feature_resource"]
        self.assertEqual(resource["feature_name"], "mrpcs_i_l.data")
        self.assertEqual(resource["blob_len"], len(blob))
        self.assertTrue(resource["base64_valid"])
        self.assertTrue(resource["crc_match"])
        self.assertEqual(resource["crc_scope"], "decoded featureData ZIP/blob bytes")
        self.assertIn("not a proven causal link", resource["relationship_boundary"])

        archive = resource["archive"]
        self.assertTrue(archive["valid"])
        self.assertEqual(archive["entry_count"], 1)
        zip_entry = archive["entries"][0]
        self.assertEqual(zip_entry["name"], "unzipmrpcs.data")
        self.assertEqual(zip_entry["actual_size"], len(entry))
        self.assertTrue(zip_entry["crc_match"])

        summary = format_websocket_summary(analysis)
        self.assertIn("transport=wss_json", summary)
        self.assertIn("method=ACELightFeature", summary)
        self.assertIn("feature_name=mrpcs_i_l.data", summary)
        self.assertIn("feature_crc_ok=1", summary)
        self.assertIn("zip_entries=1", summary)
        self.assertIn("cross_flow_relation=unproven", summary)

    def test_uppercase_method_pong_is_recognized(self) -> None:
        analysis = analyze_websocket_payload(
            b'{"Method":"Pong"}',
            from_client=False,
            url="https://lobby.rm.qq.com/wsgate",
        )
        self.assertEqual(analysis["json"]["method_key"], "Method")
        self.assertEqual(analysis["json"]["method"], "Pong")
        self.assertEqual(analysis["packet"]["semantic_category"], "transport.websocket.heartbeat")

    def test_invalid_feature_base64_stays_observed_without_guessing(self) -> None:
        analysis = analyze_websocket_payload(
            json.dumps(
                {
                    "method": "ACELightFeature",
                    "featureName": "mrpcs_i_l.data",
                    "featureData": "not base64!",
                    "dataCRC": 1,
                }
            ).encode(),
            from_client=False,
        )
        resource = analysis["feature_resource"]
        self.assertFalse(resource["base64_valid"])
        self.assertIn("strict Base64", resource["reason"])
        self.assertNotIn("archive", resource)


if __name__ == "__main__":
    unittest.main()
