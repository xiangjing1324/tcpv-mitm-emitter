from __future__ import annotations

import base64
import time
from typing import Any

import redis

from .config import env_int


class TcpvEventStore:
    """Redis Stream storage for TCP analysis events."""

    def __init__(
        self,
        redis_client: redis.Redis,
        instance_id: str,
        ttl_seconds: int | None = None,
        stream_maxlen: int | None = None,
        prefix_len: int | None = None,
        api_max_limit: int | None = None,
    ) -> None:
        self.r = redis_client
        self.instance_id = instance_id
        self.ttl_seconds = int(ttl_seconds if ttl_seconds is not None else env_int("TCPV_TTL_SECONDS", 24 * 60 * 60, min_value=0))
        self.stream_maxlen = int(stream_maxlen if stream_maxlen is not None else env_int("TCPV_STREAM_MAXLEN", 50_000, min_value=0))
        self.prefix_len = int(prefix_len if prefix_len is not None else env_int("TCPV_PREFIX_LEN", 128, min_value=16, max_value=2048))
        self.api_max_limit = int(api_max_limit if api_max_limit is not None else env_int("TCPV_API_MAX_LIMIT", 20_000, min_value=100, max_value=100_000))
        self._prefer_unlink = True

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
        packet_len: int | None = None,
        full_payload: bytes | bytearray | None = None,
        full_packet_len: int | None = None,
        before_payload: bytes | bytearray | None = None,
        before_packet_len: int | None = None,
        proxy_username: str = "",
        summary: str = "",
        label: str = "",
        raw_payload: bytes | bytearray | None = None,
        raw_packet_len: int | None = None,
        decode_status: str = "",
        source: str = "",
        imported_seq: int | None = None,
    ) -> str:
        if not account:
            raise ValueError("account must not be empty")

        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")

        payload_bytes = bytes(payload)
        try:
            real_packet_len = int(packet_len) if packet_len is not None else len(payload_bytes)
        except (TypeError, ValueError):
            real_packet_len = len(payload_bytes)
        if real_packet_len <= 0:
            real_packet_len = len(payload_bytes)
        full_payload_bytes = bytes(full_payload or b"")
        try:
            real_full_packet_len = int(full_packet_len) if full_packet_len is not None else len(full_payload_bytes)
        except (TypeError, ValueError):
            real_full_packet_len = len(full_payload_bytes)
        if real_full_packet_len <= 0:
            real_full_packet_len = len(full_payload_bytes)
        before_payload_bytes = bytes(before_payload or b"")
        try:
            real_before_packet_len = int(before_packet_len) if before_packet_len is not None else len(before_payload_bytes)
        except (TypeError, ValueError):
            real_before_packet_len = len(before_payload_bytes)
        if real_before_packet_len <= 0:
            real_before_packet_len = len(before_payload_bytes)
        raw_payload_bytes = bytes(raw_payload or b"")
        try:
            real_raw_packet_len = int(raw_packet_len) if raw_packet_len is not None else len(raw_payload_bytes)
        except (TypeError, ValueError):
            real_raw_packet_len = len(raw_payload_bytes)
        if real_raw_packet_len <= 0:
            real_raw_packet_len = len(raw_payload_bytes)
        now_ms = int(ts_ms or int(time.time() * 1000))
        if imported_seq is not None:
            seq = max(1, int(imported_seq))
            current_seq = self._to_int(self.r.get(self.seq_key(account)), 0)
            if seq > current_seq:
                self.r.set(self.seq_key(account), seq)
        else:
            seq = int(self.r.incr(self.seq_key(account)))

        stream_key = self.stream_key(account)
        meta_key = self.meta_key(account)

        fields = {
            "ts": str(now_ms),
            "cid": cid,
            "kp": str(proxy_username or ""),
            "sm": str(summary or ""),
            "dir": str(int(direction)),
            "len": str(real_packet_len),
            "pfx": payload_bytes[: self.prefix_len].hex(),
            "pay": base64.b64encode(payload_bytes).decode("ascii"),
            "seq": str(seq),
        }
        if label:
            fields["lbl"] = str(label)
        if decode_status:
            fields["dstat"] = str(decode_status)
        if source:
            fields["src"] = str(source)
        if msg_idx is not None:
            fields["midx"] = str(int(msg_idx))
        if chunk_idx is not None:
            fields["cidx"] = str(int(chunk_idx))
        if full_payload_bytes:
            fields["fpay"] = base64.b64encode(full_payload_bytes).decode("ascii")
            fields["fpfx"] = full_payload_bytes[: self.prefix_len].hex()
            fields["flen"] = str(real_full_packet_len)
        if before_payload_bytes:
            fields["bpay"] = base64.b64encode(before_payload_bytes).decode("ascii")
            fields["bpfx"] = before_payload_bytes[: self.prefix_len].hex()
            fields["blen"] = str(real_before_packet_len)
        if raw_payload_bytes:
            fields["rpay"] = base64.b64encode(raw_payload_bytes).decode("ascii")
            fields["rpfx"] = raw_payload_bytes[: self.prefix_len].hex()
            fields["rlen"] = str(real_raw_packet_len)

        pipe = self.r.pipeline()
        if self.stream_maxlen > 0:
            pipe.xadd(stream_key, fields, maxlen=self.stream_maxlen, approximate=True)
        else:
            pipe.xadd(stream_key, fields)
        pipe.sadd(self.accounts_key, account)
        pipe.hsetnx(meta_key, "first_ts", str(now_ms))
        pipe.hsetnx(meta_key, "first_seq", str(seq))
        meta_mapping = {
            "last_ts": str(now_ms),
            "last_seq": str(seq),
            "status": "open",
            "ended_ts": "0",
        }
        if self.stream_maxlen > 0 and seq > self.stream_maxlen:
            meta_mapping["trimmed_possible"] = "1"
        if cid:
            meta_mapping["last_cid"] = cid
        if proxy_username:
            meta_mapping["proxy_username"] = str(proxy_username)
        pipe.hset(meta_key, mapping=meta_mapping)
        pipe.hincrby(meta_key, "total_count", 1)
        pipe.hincrby(meta_key, "total_bytes", real_packet_len)

        if self.ttl_seconds > 0:
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
        proxy_username: str = "",
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
        if proxy_username:
            meta_mapping["proxy_username"] = str(proxy_username)
        pipe.hset(meta_key, mapping=meta_mapping)
        if self.ttl_seconds > 0:
            pipe.expire(meta_key, self.ttl_seconds)
            pipe.expire(self.accounts_key, self.ttl_seconds)
            pipe.expire(self.seq_key(account), self.ttl_seconds)
        pipe.execute()

    def mark_flow_end(
        self,
        account: str,
        cid: str = "",
        proxy_username: str = "",
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
        if proxy_username:
            meta_mapping["proxy_username"] = str(proxy_username)
        pipe.hset(meta_key, mapping=meta_mapping)
        if self.ttl_seconds > 0:
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
            first_seq = self._to_int(meta.get("first_seq"), 0)
            last_seq = self._to_int(meta.get("last_seq"), 0)
            trimmed_possible = self._to_int(meta.get("trimmed_possible"), 0) > 0

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
                    "proxy_username": meta.get("proxy_username", ""),
                    "first_seq": first_seq,
                    "last_seq": last_seq,
                    "trimmed_possible": trimmed_possible,
                    "source": meta.get("source", ""),
                    "source_file": meta.get("source_file", ""),
                    "listen_tag": meta.get("listen_tag", ""),
                    "source_port": meta.get("source_port", ""),
                }
            )

        if empty_accounts:
            keys_to_remove: list[str] = []
            clean = self.r.pipeline()
            for account in empty_accounts:
                keys_to_remove.append(self.stream_key(account))
                keys_to_remove.append(self.meta_key(account))
                keys_to_remove.append(self.seq_key(account))
                clean.srem(self.accounts_key, account)
            clean.execute()
            self._delete_keys(keys_to_remove)

        # Keep flow order stable by first-seen time (old -> new).
        items.sort(key=lambda x: (x.get("first_ts", 0), x.get("last_ts", 0), x.get("account", "")))
        return items

    def get_events(
        self,
        account: str,
        after_id: str | None = None,
        limit: int = 200,
        include_payload: bool = True,
    ) -> tuple[list[dict[str, Any]], str | None, bool]:
        stream_key = self.stream_key(account)
        batch = max(1, min(int(limit), self.api_max_limit))
        min_id = f"({after_id}" if after_id else "-"

        rows = self.r.xrange(stream_key, min=min_id, max="+", count=batch + 1)
        has_more = len(rows) > batch
        if has_more:
            rows = rows[:batch]

        events = [self._decode_row(entry_id, fields, include_payload=include_payload) for entry_id, fields in rows]
        last_id = events[-1]["id"] if events else after_id
        return events, last_id, has_more

    def iter_events(self, account: str, *, include_payload: bool = True, batch_size: int = 5000) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        after_id: str | None = None
        while True:
            rows, after_id, has_more = self.get_events(
                account=account,
                after_id=after_id,
                limit=batch_size,
                include_payload=include_payload,
            )
            events.extend(rows)
            if not has_more or not rows:
                break
        return events

    def get_event(self, account: str, event_id: str) -> dict[str, Any] | None:
        stream_key = self.stream_key(account)
        target_id = str(event_id or "").strip()
        if not target_id:
            return None

        rows = self.r.xrange(stream_key, min=target_id, max=target_id, count=1)
        if not rows:
            return None

        entry_id, fields = rows[0]
        if self._to_str(entry_id) != target_id:
            return None
        return self._decode_row(entry_id, fields, include_payload=True)

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
                self._delete_keys([self._to_str(k) for k in keys])
            if cursor == 0:
                break

    def cleanup_account(self, account: str) -> None:
        if not account:
            return
        keys_to_remove = [
            self.stream_key(account),
            self.meta_key(account),
            self.seq_key(account),
        ]
        self._delete_keys(keys_to_remove)
        self.r.srem(self.accounts_key, account)

    def import_flow(self, flow_meta: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
        account = str(flow_meta.get("account") or "").strip()
        if not account:
            raise ValueError("flow account must not be empty")
        self.cleanup_account(account)

        first_ts = self._to_int(flow_meta.get("first_ts"), 0)
        last_ts = self._to_int(flow_meta.get("last_ts"), first_ts)
        cid = str(flow_meta.get("last_cid") or flow_meta.get("cid") or "")
        proxy_username = str(flow_meta.get("proxy_username") or "")

        self.mark_flow_start(account=account, cid=cid, proxy_username=proxy_username, ts_ms=first_ts or None)
        imported_count = 0
        total_bytes = 0
        for index, event in enumerate(events, start=1):
            display_payload = _hex_to_bytes(event.get("display")) or _hex_to_bytes(event.get("raw")) or _hex_to_bytes(event.get("full"))
            if not display_payload:
                continue
            raw_payload = _hex_to_bytes(event.get("raw"))
            full_payload = _hex_to_bytes(event.get("full")) or raw_payload or display_payload
            before_payload = _hex_to_bytes(event.get("before"))
            event_cid = str(event.get("cid") or cid)
            seq = self._to_int(event.get("seq"), index)
            self.append_event(
                account=account,
                cid=event_cid,
                direction=self._to_int(event.get("dir"), 0),
                payload=display_payload,
                packet_len=len(display_payload),
                full_payload=full_payload,
                full_packet_len=len(full_payload),
                before_payload=before_payload,
                before_packet_len=len(before_payload),
                raw_payload=raw_payload or full_payload,
                raw_packet_len=len(raw_payload or full_payload),
                proxy_username=proxy_username,
                summary=str(event.get("summary") or ""),
                label=str(event.get("label") or ""),
                decode_status=str(event.get("decode_status") or ""),
                source=str(event.get("source") or flow_meta.get("source") or "import"),
                ts_ms=self._to_int(event.get("ts"), first_ts or int(time.time() * 1000)),
                msg_idx=self._to_int(event.get("msg_idx"), -1),
                chunk_idx=self._to_int(event.get("chunk_idx"), -1),
                imported_seq=seq,
            )
            imported_count += 1
            total_bytes += len(display_payload)

        self.mark_flow_end(account=account, cid=cid, proxy_username=proxy_username, ts_ms=last_ts or None)
        meta_key = self.meta_key(account)
        meta_mapping = {
            "source": str(flow_meta.get("source") or "import"),
            "source_file": str(flow_meta.get("source_file") or flow_meta.get("imported_from") or ""),
            "listen_tag": str(flow_meta.get("listen_tag") or ""),
            "source_port": str(flow_meta.get("source_port") or ""),
        }
        self.r.hset(meta_key, mapping=meta_mapping)
        if self.ttl_seconds > 0:
            self.r.expire(meta_key, self.ttl_seconds)
        return {"account": account, "events": imported_count, "total_bytes": total_bytes}

    def _delete_keys(self, keys: list[str]) -> int:
        key_list = [str(k) for k in keys if str(k)]
        if not key_list:
            return 0

        if self._prefer_unlink:
            try:
                result = self.r.execute_command("UNLINK", *key_list)
                return int(result or 0)
            except redis.ResponseError:
                self._prefer_unlink = False

        result = self.r.delete(*key_list)
        return int(result or 0)

    def _decode_row(
        self,
        entry_id: bytes | str,
        fields: dict[Any, Any],
        include_payload: bool = True,
    ) -> dict[str, Any]:
        decoded = {self._to_str(k): self._to_str(v) for k, v in fields.items()}
        return {
            "id": self._to_str(entry_id),
            "ts": self._to_int(decoded.get("ts"), 0),
            "cid": decoded.get("cid", ""),
            "proxy_username": decoded.get("kp", ""),
            "summary": decoded.get("sm", ""),
            "dir": self._to_int(decoded.get("dir"), 0),
            "len": self._to_int(decoded.get("len"), 0),
            "pfx": decoded.get("pfx", ""),
            "pay": decoded.get("pay", "") if include_payload else "",
            "full_len": self._to_int(decoded.get("flen"), 0),
            "full_pfx": decoded.get("fpfx", ""),
            "full_pay": decoded.get("fpay", "") if include_payload else "",
            "before_len": self._to_int(decoded.get("blen"), 0),
            "before_pfx": decoded.get("bpfx", ""),
            "before_pay": decoded.get("bpay", "") if include_payload else "",
            "raw_len": self._to_int(decoded.get("rlen"), 0),
            "raw_pfx": decoded.get("rpfx", ""),
            "raw_pay": decoded.get("rpay", "") if include_payload else "",
            "label": decoded.get("lbl", ""),
            "decode_status": decoded.get("dstat", ""),
            "source": decoded.get("src", ""),
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


def _hex_to_bytes(value: Any) -> bytes:
    text = str(value or "").strip()
    if not text:
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""
