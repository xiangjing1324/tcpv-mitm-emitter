from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tcpv_mitm_emitter.analyzer import TersafeAnalyzer
from tcpv_mitm_emitter.archive import parse_txt_capture, read_flow_archive_bytes, write_flow_archive
from tcpv_mitm_emitter.store import TcpvEventStore


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


if __name__ == "__main__":
    unittest.main()
