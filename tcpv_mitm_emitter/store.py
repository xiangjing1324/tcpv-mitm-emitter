from __future__ import annotations

import base64
import time
from typing import Any

import redis


class TcpvEventStore:
    """Redis Stream storage for TCP analysis events."""

    def __init__(
        self,
        redis_client: redis.Redis,
        instance_id: str,
        ttl_seconds: int = 6 * 60 * 60,
        stream_maxlen: int = 5000,
        prefix_len: int = 12,
    ) -> None:
        self.r = redis_client
        self.instance_id = instance_id
        self.ttl_seconds = int(ttl_seconds)
        self.stream_maxlen = int(stream_maxlen)
        self.prefix_len = int(prefix_len)

        self.accounts_key = self._key("accounts")

    def _key(self, suffix: str) -> str:
        return f"tcpv:{self.instance_id}:{suffix}"

    def stream_key(self, account: str) -> str:
        return self._key(f"events:{account}")

    def meta_key(self, account: str) -> str:
        return self._key(f"meta:{account}")

    def seq_key(self, account: str) -> str:
        return self._key(f"seq:{account}")

    def append_event(
        self,
        account: str,
        cid: str,
        direction: int,
        payload: bytes,
        ts_ms: int | None = None,
        msg_idx: int | None = None,
        chunk_idx: int | None = None,
    ) -> str:
        if not account:
            raise ValueError("account must not be empty")

        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")

        payload_bytes = bytes(payload)
        now_ms = int(ts_ms or int(time.time() * 1000))
        seq = int(self.r.incr(self.seq_key(account)))

        stream_key = self.stream_key(account)
        meta_key = self.meta_key(account)

        fields = {
            "ts": str(now_ms),
            "cid": cid,
            "dir": str(int(direction)),
            "len": str(len(payload_bytes)),
            "pfx": payload_bytes[: self.prefix_len].hex(),
            "pay": base64.b64encode(payload_bytes).decode("ascii"),
            "seq": str(seq),
        }
        if msg_idx is not None:
            fields["midx"] = str(int(msg_idx))
        if chunk_idx is not None:
            fields["cidx"] = str(int(chunk_idx))

        pipe = self.r.pipeline()
        pipe.xadd(stream_key, fields, maxlen=self.stream_maxlen, approximate=True)
        pipe.sadd(self.accounts_key, account)
        pipe.hsetnx(meta_key, "first_ts", str(now_ms))
        meta_mapping = {
            "last_ts": str(now_ms),
            "status": "open",
            "ended_ts": "0",
        }
        if cid:
            meta_mapping["last_cid"] = cid
        pipe.hset(meta_key, mapping=meta_mapping)
        pipe.hincrby(meta_key, "total_count", 1)
        pipe.hincrby(meta_key, "total_bytes", len(payload_bytes))

        pipe.expire(stream_key, self.ttl_seconds)
        pipe.expire(meta_key, self.ttl_seconds)
        pipe.expire(self.accounts_key, self.ttl_seconds)
        pipe.expire(self.seq_key(account), self.ttl_seconds)

        result = pipe.execute()
        stream_id = result[0]
        if isinstance(stream_id, (bytes, bytearray)):
            return stream_id.decode("utf-8", errors="replace")
        return str(stream_id)

    def mark_flow_start(
        self,
        account: str,
        cid: str = "",
        ts_ms: int | None = None,
    ) -> None:
        account = str(account or "").strip()
        if not account:
            return

        now_ms = int(ts_ms or int(time.time() * 1000))
        meta_key = self.meta_key(account)

        pipe = self.r.pipeline()
        pipe.sadd(self.accounts_key, account)
        pipe.hsetnx(meta_key, "first_ts", str(now_ms))
        meta_mapping = {
            "last_ts": str(now_ms),
            "status": "open",
            "ended_ts": "0",
        }
        if cid:
            meta_mapping["last_cid"] = cid
        pipe.hset(meta_key, mapping=meta_mapping)
        pipe.expire(meta_key, self.ttl_seconds)
        pipe.expire(self.accounts_key, self.ttl_seconds)
        pipe.expire(self.seq_key(account), self.ttl_seconds)
        pipe.execute()

    def mark_flow_end(
        self,
        account: str,
        cid: str = "",
        ts_ms: int | None = None,
    ) -> None:
        account = str(account or "").strip()
        if not account:
            return

        now_ms = int(ts_ms or int(time.time() * 1000))
        meta_key = self.meta_key(account)

        pipe = self.r.pipeline()
        pipe.sadd(self.accounts_key, account)
        pipe.hsetnx(meta_key, "first_ts", str(now_ms))
        meta_mapping = {
            "last_ts": str(now_ms),
            "status": "closed",
            "ended_ts": str(now_ms),
        }
        if cid:
            meta_mapping["last_cid"] = cid
        pipe.hset(meta_key, mapping=meta_mapping)
        pipe.expire(meta_key, self.ttl_seconds)
        pipe.expire(self.accounts_key, self.ttl_seconds)
        pipe.expire(self.seq_key(account), self.ttl_seconds)
        pipe.execute()

    def list_accounts(self) -> list[dict[str, Any]]:
        raw_accounts = self.r.smembers(self.accounts_key)
        accounts = [self._to_str(item) for item in raw_accounts]

        if not accounts:
            return []

        pipe = self.r.pipeline()
        for account in accounts:
            pipe.hgetall(self.meta_key(account))
        raw_metas = pipe.execute()

        items: list[dict[str, Any]] = []
        empty_accounts: list[str] = []
        for account, raw_meta in zip(accounts, raw_metas):
            if not raw_meta:
                empty_accounts.append(account)
                continue
            meta = {self._to_str(k): self._to_str(v) for k, v in raw_meta.items()}
            first_ts = self._to_int(meta.get("first_ts"), 0)
            last_ts = self._to_int(meta.get("last_ts"), 0)
            ended_ts = self._to_int(meta.get("ended_ts"), 0)
            total_count = self._to_int(meta.get("total_count"), 0)
            total_bytes = self._to_int(meta.get("total_bytes"), 0)

            # Ignore and prune flows that only called start/end but never emitted packet payload.
            if total_count <= 0 and total_bytes <= 0:
                empty_accounts.append(account)
                continue

            status = str(meta.get("status", "")).strip().lower()
            if status not in {"open", "closed"}:
                status = "closed" if ended_ts > 0 else "open"
            if total_bytes <= 0 and total_count > 0:
                # Backward compatibility for old meta rows without total_bytes.
                total_bytes = total_count
            if first_ts <= 0:
                first_ts = last_ts
            if status == "closed":
                end_ref_ts = ended_ts if ended_ts > 0 else last_ts
                duration_ms = max(end_ref_ts - first_ts, 0)
            else:
                duration_ms = max(last_ts - first_ts, 0)
            items.append(
                {
                    "account": account,
                    "first_ts": first_ts,
                    "last_ts": last_ts,
                    "ended_ts": ended_ts,
                    "status": status,
                    "is_open": status == "open",
                    "duration_ms": duration_ms,
                    "total": total_bytes,
                    "total_bytes": total_bytes,
                    "total_count": total_count,
                    "last_cid": meta.get("last_cid", ""),
                }
            )

        if empty_accounts:
            clean = self.r.pipeline()
            for account in empty_accounts:
                clean.delete(self.stream_key(account))
                clean.delete(self.meta_key(account))
                clean.delete(self.seq_key(account))
                clean.srem(self.accounts_key, account)
            clean.execute()

        # Keep flow order stable by first-seen time (old -> new).
        items.sort(key=lambda x: (x.get("first_ts", 0), x.get("last_ts", 0), x.get("account", "")))
        return items

    def get_events(
        self,
        account: str,
        after_id: str | None = None,
        limit: int = 200,
    ) -> tuple[list[dict[str, Any]], str | None, bool]:
        stream_key = self.stream_key(account)
        batch = max(1, min(int(limit), 1000))
        min_id = f"({after_id}" if after_id else "-"

        rows = self.r.xrange(stream_key, min=min_id, max="+", count=batch + 1)
        has_more = len(rows) > batch
        if has_more:
            rows = rows[:batch]

        events = [self._decode_row(entry_id, fields) for entry_id, fields in rows]
        last_id = events[-1]["id"] if events else after_id
        return events, last_id, has_more

    def get_connections(self, account: str, recent: int = 2000) -> list[dict[str, Any]]:
        stream_key = self.stream_key(account)
        count = max(1, min(int(recent), 10000))
        rows = self.r.xrevrange(stream_key, max="+", min="-", count=count)

        stats: dict[str, dict[str, Any]] = {}
        for _entry_id, fields in rows:
            decoded = {self._to_str(k): self._to_str(v) for k, v in fields.items()}
            cid = decoded.get("cid", "")
            if not cid:
                continue
            ts = self._to_int(decoded.get("ts"), 0)
            if cid not in stats:
                stats[cid] = {"cid": cid, "count": 0, "last_ts": ts}
            stats[cid]["count"] += 1
            if ts > stats[cid]["last_ts"]:
                stats[cid]["last_ts"] = ts

        items = list(stats.values())
        items.sort(key=lambda x: x["last_ts"], reverse=True)
        return items

    def cleanup_instance(self) -> None:
        cursor = 0
        pattern = self._key("*")
        while True:
            cursor, keys = self.r.scan(cursor=cursor, match=pattern, count=500)
            if keys:
                self.r.delete(*keys)
            if cursor == 0:
                break

    def cleanup_account(self, account: str) -> None:
        if not account:
            return
        pipe = self.r.pipeline()
        pipe.delete(self.stream_key(account))
        pipe.delete(self.meta_key(account))
        pipe.delete(self.seq_key(account))
        pipe.srem(self.accounts_key, account)
        pipe.execute()

    def _decode_row(self, entry_id: bytes | str, fields: dict[Any, Any]) -> dict[str, Any]:
        decoded = {self._to_str(k): self._to_str(v) for k, v in fields.items()}
        return {
            "id": self._to_str(entry_id),
            "ts": self._to_int(decoded.get("ts"), 0),
            "cid": decoded.get("cid", ""),
            "dir": self._to_int(decoded.get("dir"), 0),
            "len": self._to_int(decoded.get("len"), 0),
            "pfx": decoded.get("pfx", ""),
            "pay": decoded.get("pay", ""),
            "seq": self._to_int(decoded.get("seq"), 0),
            "msg_idx": self._to_int(decoded.get("midx"), -1),
            "chunk_idx": self._to_int(decoded.get("cidx"), -1),
        }

    @staticmethod
    def _to_str(value: Any) -> str:
        if isinstance(value, (bytes, bytearray)):
            return value.decode("utf-8", errors="replace")
        return str(value)

    @staticmethod
    def _to_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
