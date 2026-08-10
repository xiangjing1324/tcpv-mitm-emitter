from __future__ import annotations

import base64
import os
import unittest
from unittest import mock

from tcpv_mitm_emitter.agent_api import (
    filter_flows,
    parse_direction,
    parse_time_value,
    resolve_flow,
    shape_event,
)
from tcpv_mitm_emitter.api import create_app
from tcpv_mitm_emitter.runtime import TcpvRuntime
from tcpv_mitm_emitter.store import TcpvEventStore

from test_archive_and_store import FakeRedis


class AgentApiTests(unittest.TestCase):
    def _runtime(self) -> TcpvRuntime:
        store = TcpvEventStore(FakeRedis(), "agent-test", ttl_seconds=0, stream_maxlen=0, api_max_limit=100)
        store.append_event(
            "flow-old",
            "10.0.0.1:50000->1.2.3.4:65010",
            0,
            b"old",
            ts_ms=1_000,
            summary="transport=tgcp65010 command=0x1001",
        )
        store.append_event(
            "flow-live",
            "10.0.0.1:50001->1.2.3.4:65010",
            0,
            b"request-one",
            ts_ms=2_000,
            summary="transport=tgcp65010 command=0x4013 role=login",
            analysis={"schema": "tcpv.gcloud.analysis.v1", "analysis_authoritative": True},
        )
        store.append_event(
            "flow-live",
            "10.0.0.1:50001->1.2.3.4:65010",
            1,
            b"response-two",
            ts_ms=3_000,
            summary="transport=tgcp65010 command=0x4013 role=heartbeat",
        )
        runtime = TcpvRuntime()
        runtime.store = store
        runtime.instance_id = "agent-test"
        return runtime

    def test_time_direction_and_flow_resolution_are_machine_friendly(self) -> None:
        self.assertEqual(parse_time_value("5m", now_ms=1_000_000, relative=True), 700_000)
        self.assertEqual(parse_time_value("1700000000"), 1_700_000_000_000)
        self.assertEqual(parse_direction("request"), 0)
        self.assertEqual(parse_direction("response"), 1)
        self.assertIsNone(parse_direction("all"))

        flows = filter_flows(
            [
                {"account": "old", "last_ts": 10, "last_cid": "a:1->b:2"},
                {"account": "latest", "last_ts": 20, "last_cid": "a:3->b:4"},
            ],
            query="",
            limit=10,
        )
        self.assertEqual(resolve_flow(flows, "latest")["account"], "latest")
        self.assertEqual(resolve_flow(flows, "old")["account"], "old")

    def test_store_query_is_bounded_filtered_and_newest_first(self) -> None:
        runtime = self._runtime()
        events, cursor, has_more, scanned = runtime.query_events(
            "flow-live",
            limit=1,
            scan_limit=10,
            direction=1,
            summary_contains="heartbeat",
            include_payload=True,
        )
        self.assertEqual([event["ts"] for event in events], [3_000])
        self.assertEqual(base64.b64decode(events[0]["pay"]), b"response-two")
        self.assertEqual(cursor, "2")
        self.assertTrue(has_more)
        self.assertEqual(scanned, 1)

        older, next_cursor, _has_more, _scanned = runtime.query_events(
            "flow-live",
            before_id=cursor,
            limit=10,
            scan_limit=10,
            include_payload=False,
        )
        self.assertEqual([event["ts"] for event in older], [2_000])
        self.assertEqual(next_cursor, "1")

    def test_payload_view_is_capped_structured_and_hashable(self) -> None:
        shaped = shape_event(
            {
                "id": "1",
                "dir": 0,
                "len": 6,
                "pfx": "616263646566",
                "full_pfx": "616263646566",
                "pay": base64.b64encode(b"abcdef").decode("ascii"),
                "full_pay": "",
                "before_pay": "",
                "raw_pay": "",
                "analysis": {"secret": "not returned in payload mode"},
            },
            view="payload",
            payload_bytes=3,
            payload_encoding="hex",
        )
        self.assertEqual(shaped["payloads"]["display"]["data"], b"abc".hex())
        self.assertTrue(shaped["payloads"]["display"]["truncated"])
        self.assertNotIn("analysis", shaped)
        self.assertNotIn("pfx", shaped)
        self.assertNotIn("full_pfx", shaped)
        self.assertEqual(shaped["direction"], "request")

        full = shape_event(
            {
                "id": "1",
                "dir": 0,
                "len": 6,
                "pfx": "616263646566",
                "pay": base64.b64encode(b"abcdef").decode("ascii"),
            },
            view="full",
            payload_bytes=3,
            payload_encoding="hex",
        )
        self.assertEqual(full["pfx"], "616263646566")

    def test_fastapi_exposes_one_call_query_and_capability_discovery(self) -> None:
        runtime = self._runtime()
        with mock.patch.dict(os.environ, {"TCPV_AGENT_TOKEN": "unit-token"}, clear=False):
            app = create_app(runtime)
        routes = {getattr(route, "path", ""): route.endpoint for route in app.routes}
        self.assertIn("/api/agent/v1/capabilities", routes)
        self.assertIn("/api/agent/v1/flows", routes)
        self.assertIn("/api/agent/v1/query", routes)
        self.assertIn("/api/agent/v1/event", routes)

        capabilities = routes["/api/agent/v1/capabilities"]()
        self.assertTrue(capabilities["read_only"])
        self.assertTrue(capabilities["authentication"]["agent_bearer_token_configured"])

        result = routes["/api/agent/v1/query"](
            flow="latest",
            flow_q="",
            q="heartbeat",
            summary="",
            cid="",
            status="",
            source_port="",
            since="",
            until="",
            direction="response",
            min_len=None,
            max_len=None,
            cursor=None,
            limit=10,
            scan_limit=100,
            view="payload",
            payload_bytes=64,
            payload_encoding="hex",
        )
        self.assertEqual(result["flow"]["account"], "flow-live")
        self.assertEqual(result["event_count"], 1)
        self.assertEqual(result["events"][0]["payloads"]["display"]["data"], b"response-two".hex())
        self.assertEqual(result["cursor"]["order"], "newest_first")


if __name__ == "__main__":
    unittest.main()
