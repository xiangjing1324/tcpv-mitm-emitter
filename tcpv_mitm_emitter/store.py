from __future__ import annotations

import base64
import json
import time
from typing import Any

import redis

from .config import env_int


_MODIFIED_SUMMARY_SIGNALS = (
    "[修改后:",
    "payload_modified=1",
    "wire_rebuilt=1",
    "wire_header_modified=1",
    "wire_changed=1",
    "raw_pay_is_sent_wire=1",
    "tcpview_after_source=raw_pay_sent_wire",
    "backend_rewrite_verified=1",
)


def _byte_diff_metrics(before: bytes, after: bytes) -> tuple[int, int]:
    """Return total changed bytes and the first changed absolute offset."""

    common_len = min(len(before), len(after))
    first_offset = -1
    changed = 0
    for offset in range(common_len):
        if before[offset] == after[offset]:
            continue
        changed += 1
        if first_offset < 0:
            first_offset = offset
    if len(before) != len(after):
        changed += abs(len(after) - len(before))
        if first_offset < 0:
            first_offset = common_len
    return changed, first_offset


def _event_modification_state(
    *,
    payload: bytes,
    full_payload: bytes,
    before_payload: bytes,
    raw_payload: bytes,
    summary: str,
    analysis: dict[str, Any] | None,
) -> tuple[str, str, int, int, int, int]:
    """Classify a compact row without requiring the browser to fetch payloads."""

    mutation = analysis.get("mutation") if isinstance(analysis, dict) else None
    action = str(mutation.get("action") or "").strip().casefold() if isinstance(mutation, dict) else ""
    dropped = bool(mutation.get("dropped")) if isinstance(mutation, dict) else False
    summary_folded = str(summary or "").casefold()
    if dropped or action in {"drop", "block", "blocked", "delete", "deleted"} or any(
        token in summary_folded
        for token in ("packet_dropped=1", "packet_blocked=1", "action=drop", "action=block")
    ):
        return "blocked", "backend_drop", 0, -1, len(before_payload or full_payload), 0

    comparisons = []
    if before_payload:
        comparisons.append(("payload", before_payload, payload))
    for basis, before, after in comparisons:
        changed, first_offset = _byte_diff_metrics(before, after)
        if changed > 0:
            return "modified", basis, changed, first_offset, len(before), len(after)

    declared_modified = isinstance(mutation, dict) and mutation.get("modified") is True
    summary_modified = any(signal.casefold() in summary_folded for signal in _MODIFIED_SUMMARY_SIGNALS)
    if declared_modified or summary_modified:
        if full_payload and raw_payload:
            changed, first_offset = _byte_diff_metrics(full_payload, raw_payload)
            return "modified", "wire", changed, first_offset, len(full_payload), len(raw_payload)
        return "modified", "backend", 0, -1, len(before_payload or full_payload), len(payload or raw_payload)

    if comparisons:
        basis, before, after = comparisons[0]
        return "original", basis, 0, -1, len(before), len(after)
    return "original", "no_diff_artifact", 0, -1, len(payload), len(payload)


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
        self.ttl_seconds = int(ttl_seconds if ttl_seconds is not None else env_int("TCPV_TTL_SECONDS", 0, min_value=0))
        self.stream_maxlen = int(stream_maxlen if stream_maxlen is not None else env_int("TCPV_STREAM_MAXLEN", 0, min_value=0))
        self.prefix_len = int(prefix_len if prefix_len is not None else env_int("TCPV_PREFIX_LEN", 128, min_value=16, max_value=2048))
        self.api_max_limit = int(api_max_limit if api_max_limit is not None else env_int("TCPV_API_MAX_LIMIT", 20_000, min_value=100, max_value=100_000))
        self._prefer_unlink = True

        self.accounts_key = self._key("accounts")
        self.runtime_key = self._key("runtime")

    def _key(self, suffix: str) -> str:
        return f"tcpv:{self.instance_id}:{suffix}"

    def stream_key(self, account: str) -> str:
        return self._key(f"events:{account}")

    def compact_stream_key(self, account: str) -> str:
        return self._key(f"events_compact:{account}")

    def meta_key(self, account: str) -> str:
        return self._key(f"meta:{account}")

    def seq_key(self, account: str) -> str:
        return self._key(f"seq:{account}")

    def runtime_owner_pid(self) -> int:
        meta = {
            self._to_str(key): self._to_str(value)
            for key, value in self.r.hgetall(self.runtime_key).items()
        }
        return self._to_int(meta.get("owner_pid"), 0)

    def register_runtime_owner(self, owner_pid: int, started_ts_ms: int) -> None:
        self.r.hset(
            self.runtime_key,
            mapping={
                "owner_pid": str(int(owner_pid)),
                "started_ts": str(int(started_ts_ms)),
            },
        )

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
        analysis: dict[str, Any] | None = None,
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
        modification_state = _event_modification_state(
            payload=payload_bytes,
            full_payload=full_payload_bytes,
            before_payload=before_payload_bytes,
            raw_payload=raw_payload_bytes,
            summary=summary,
            analysis=analysis,
        )
        fields.update(
            {
                "modstate": modification_state[0],
                "modbasis": modification_state[1],
                "moddiff": str(modification_state[2]),
                "modoff": str(modification_state[3]),
                "modblen": str(modification_state[4]),
                "modalen": str(modification_state[5]),
            }
        )
        if label:
            fields["lbl"] = str(label)
        if decode_status:
            fields["dstat"] = str(decode_status)
        if source:
            fields["src"] = str(source)
        if isinstance(analysis, dict) and analysis:
            fields["ana"] = json.dumps(analysis, ensure_ascii=False, separators=(",", ":"))
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
        pipe.hsetnx(meta_key, "first_packet_ts", str(now_ms))
        pipe.hsetnx(meta_key, "first_seq", str(seq))
        # Lifecycle state is monotonic.  A packet can be written after tcp_end
        # because packet analysis happens on the background writer queue; use
        # HSETNX so that such a late write can never reopen a closed flow.
        pipe.hsetnx(meta_key, "status", "open")
        pipe.hsetnx(meta_key, "ended_ts", "0")
        pipe.hsetnx(meta_key, "status_source", "packet_fallback")
        meta_mapping = {
            "last_ts": str(now_ms),
            "last_packet_ts": str(now_ms),
            "last_seq": str(seq),
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
            event_id = stream_id.decode("utf-8", errors="replace")
        else:
            event_id = str(stream_id)
        self._append_compact_event(account, event_id, fields)
        return event_id

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
        pipe.hsetnx(meta_key, "tcp_start_ts", str(now_ms))
        pipe.hsetnx(meta_key, "status", "open")
        pipe.hsetnx(meta_key, "ended_ts", "0")
        pipe.hsetnx(meta_key, "status_source", "tcp_start")
        meta_mapping = {
            "last_ts": str(now_ms),
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
        duration_ms: int | None = None,
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
            "tcp_end_ts": str(now_ms),
            "status_source": "tcp_end",
        }
        if cid:
            meta_mapping["last_cid"] = cid
        if proxy_username:
            meta_mapping["proxy_username"] = str(proxy_username)
        if duration_ms is not None:
            meta_mapping["tcp_duration_ms"] = str(max(0, int(duration_ms)))
        pipe.hset(meta_key, mapping=meta_mapping)
        if self.ttl_seconds > 0:
            # Refresh every per-flow key from the authoritative tcp_end so
            # they expire as one retention unit instead of leaving a partial
            # stream or orphaned metadata behind.
            pipe.expire(self.stream_key(account), self.ttl_seconds)
            pipe.expire(self.compact_stream_key(account), self.ttl_seconds)
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
            pipe.xlen(self.stream_key(account))
        raw_rows = pipe.execute()

        items: list[dict[str, Any]] = []
        for index, account in enumerate(accounts):
            raw_meta = raw_rows[index * 2]
            stream_count = self._to_int(raw_rows[index * 2 + 1], 0)
            if not raw_meta:
                # Read paths must never delete Redis state. A writer may be
                # recreating metadata after an operator-requested cache clear.
                continue
            meta = {self._to_str(k): self._to_str(v) for k, v in raw_meta.items()}
            stored_first_ts = self._to_int(meta.get("first_ts"), 0)
            stored_last_ts = self._to_int(meta.get("last_ts"), 0)
            tcp_start_ts = self._to_int(meta.get("tcp_start_ts"), 0)
            tcp_end_ts = self._to_int(meta.get("tcp_end_ts"), 0)
            tcp_duration_ms = self._to_int(meta.get("tcp_duration_ms"), -1)
            first_packet_ts = self._to_int(meta.get("first_packet_ts"), 0)
            last_packet_ts = self._to_int(meta.get("last_packet_ts"), 0)
            first_ts = tcp_start_ts or stored_first_ts or first_packet_ts
            ended_ts = tcp_end_ts or self._to_int(meta.get("ended_ts"), 0)
            last_ts = max(stored_last_ts, last_packet_ts, ended_ts)
            total_count = self._to_int(meta.get("total_count"), 0)
            total_bytes = self._to_int(meta.get("total_bytes"), 0)
            first_seq = self._to_int(meta.get("first_seq"), 0)
            last_seq = self._to_int(meta.get("last_seq"), 0)
            trimmed_possible = self._to_int(meta.get("trimmed_possible"), 0) > 0

            # The full Redis stream is authoritative for rows currently
            # available. Do not clean a flow from a read path when metadata
            # and XLEN disagree: on a busy live flow, destructive repair turns
            # a transient observation into permanent data loss.
            if total_count <= 0 and stream_count > 0:
                total_count = stream_count
            stored_total_count = total_count
            incomplete_possible = total_count != stream_count
            total_count = stream_count

            status = str(meta.get("status", "")).strip().lower()
            if tcp_end_ts > 0:
                status = "closed"
            if status not in {"open", "closed"}:
                status = "closed" if ended_ts > 0 else "open"
            if total_bytes <= 0 and total_count > 0:
                # Backward compatibility for old meta rows without total_bytes.
                total_bytes = total_count
            if first_ts <= 0:
                first_ts = last_ts
            if status == "closed":
                end_ref_ts = ended_ts if ended_ts > 0 else last_ts
                duration_ms = (
                    tcp_duration_ms
                    if tcp_duration_ms >= 0
                    else max(end_ref_ts - first_ts, 0)
                )
            else:
                duration_ms = max(last_ts - first_ts, 0)
            items.append(
                {
                    "account": account,
                    "first_ts": first_ts,
                    "last_ts": last_ts,
                    "ended_ts": ended_ts,
                    "tcp_start_ts": tcp_start_ts,
                    "tcp_end_ts": tcp_end_ts,
                    "tcp_duration_ms": tcp_duration_ms if tcp_duration_ms >= 0 else None,
                    "first_packet_ts": first_packet_ts,
                    "last_packet_ts": last_packet_ts,
                    "status": status,
                    "status_source": meta.get("status_source", ""),
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
                    "incomplete_possible": incomplete_possible,
                    "stored_total_count": stored_total_count,
                    "stream_count": stream_count,
                    "source": meta.get("source", ""),
                    "source_file": meta.get("source_file", ""),
                    "listen_tag": meta.get("listen_tag", ""),
                    "source_port": meta.get("source_port", ""),
                }
            )

        # Keep flow order stable by first-seen time (old -> new).
        items.sort(key=lambda x: (x.get("first_ts", 0), x.get("last_ts", 0), x.get("account", "")))
        return items

    def get_events(
        self,
        account: str,
        after_id: str | None = None,
        limit: int = 200,
        include_payload: bool = True,
        include_analysis: bool = True,
    ) -> tuple[list[dict[str, Any]], str | None, bool]:
        stream_key = self.stream_key(account)
        # HGETALL and XLEN must be one Redis transaction. Reading them in two
        # separate round trips races the async writer: total_count=N followed
        # by XLEN=N+1 was previously misclassified as corruption and caused
        # the live flow to be deleted and recreated from the next packet.
        state = self.r.pipeline()
        state.hgetall(self.meta_key(account))
        state.xlen(stream_key)
        raw_meta, raw_full_count = state.execute()
        meta = {
            self._to_str(key): self._to_str(value)
            for key, value in raw_meta.items()
        }
        full_count = self._to_int(raw_full_count, 0)
        expected_count = self._to_int(
            meta.get("total_count"),
            full_count,
        )
        if not meta or full_count <= 0:
            return [], after_id, False
        # A mismatch can describe legacy trimming or a partially restored
        # capture, but a GET request must remain read-only. Return the rows
        # that exist and preserve every Redis key for later analysis.
        del expected_count
        if not include_payload and not include_analysis:
            compact_key = self.compact_stream_key(account)
            compact_count = self._to_int(self.r.xlen(compact_key), 0)
            if compact_count == full_count:
                stream_key = compact_key
        batch = max(1, min(int(limit), self.api_max_limit))
        min_id = f"({after_id}" if after_id else "-"

        rows = self.r.xrange(stream_key, min=min_id, max="+", count=batch + 1)
        has_more = len(rows) > batch
        if has_more:
            rows = rows[:batch]

        events = [
            self._decode_row(
                entry_id,
                fields,
                include_payload=include_payload,
                include_analysis=include_analysis,
            )
            for entry_id, fields in rows
        ]
        last_id = events[-1]["id"] if events else after_id
        return events, last_id, has_more

    def iter_events(
        self,
        account: str,
        *,
        include_payload: bool = True,
        include_analysis: bool = True,
        batch_size: int = 5000,
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        after_id: str | None = None
        while True:
            rows, after_id, has_more = self.get_events(
                account=account,
                after_id=after_id,
                limit=batch_size,
                include_payload=include_payload,
                include_analysis=include_analysis,
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
        return self._decode_row(entry_id, fields, include_payload=True, include_analysis=True)

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

    def cleanup_instance(self) -> int:
        cursor = 0
        pattern = self._key("*")
        deleted = 0
        while True:
            cursor, keys = self.r.scan(cursor=cursor, match=pattern, count=500)
            if keys:
                deleted += self._delete_keys([self._to_str(k) for k in keys])
            if cursor == 0:
                break
        return deleted

    def cleanup_all_instances(self) -> int:
        """Remove every TCPView instance while preserving non-TCPView Redis data."""

        cursor = 0
        deleted = 0
        while True:
            cursor, keys = self.r.scan(cursor=cursor, match="tcpv:*", count=500)
            if keys:
                deleted += self._delete_keys([self._to_str(key) for key in keys])
            if cursor == 0:
                break
        return deleted

    def cleanup_account(self, account: str) -> None:
        if not account:
            return
        keys_to_remove = [
            self.stream_key(account),
            self.compact_stream_key(account),
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
                analysis=event.get("analysis") if isinstance(event.get("analysis"), dict) else None,
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
            pipe = self.r.pipeline()
            pipe.expire(self.stream_key(account), self.ttl_seconds)
            pipe.expire(self.compact_stream_key(account), self.ttl_seconds)
            pipe.expire(meta_key, self.ttl_seconds)
            pipe.expire(self.seq_key(account), self.ttl_seconds)
            pipe.expire(self.accounts_key, self.ttl_seconds)
            pipe.execute()
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
        include_analysis: bool = True,
    ) -> dict[str, Any]:
        decoded = {self._to_str(k): self._to_str(v) for k, v in fields.items()}
        analysis: dict[str, Any] = {}
        if include_analysis and decoded.get("ana"):
            try:
                value = json.loads(decoded["ana"])
                if isinstance(value, dict):
                    analysis = value
            except (TypeError, ValueError, json.JSONDecodeError):
                analysis = {}
        return {
            "id": self._to_str(entry_id),
            "ts": self._to_int(decoded.get("ts"), 0),
            "cid": decoded.get("cid", ""),
            "proxy_username": decoded.get("kp", ""),
            "summary": decoded.get("sm", ""),
            "modification_state": decoded.get("modstate", ""),
            "modification_basis": decoded.get("modbasis", ""),
            "modification_diff_count": self._to_int(decoded.get("moddiff"), 0),
            "modification_first_offset": self._to_int(decoded.get("modoff"), -1),
            "modification_before_len": self._to_int(decoded.get("modblen"), 0),
            "modification_after_len": self._to_int(decoded.get("modalen"), 0),
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
            "analysis": analysis,
        }

    def _append_compact_event(self, account: str, event_id: str, fields: dict[str, str]) -> None:
        compact_key = self.compact_stream_key(account)
        compact_fields = {
            key: value
            for key, value in fields.items()
            if key not in {"pay", "fpay", "bpay", "rpay", "ana"}
        }
        try:
            pipe = self.r.pipeline()
            if self.stream_maxlen > 0:
                pipe.xadd(compact_key, compact_fields, id=event_id, maxlen=self.stream_maxlen, approximate=True)
            else:
                pipe.xadd(compact_key, compact_fields, id=event_id)
            if self.ttl_seconds > 0:
                # Re-align all flow-key TTLs after the compact row is written.
                # This makes the final packet timestamp the common retention
                # deadline even when packet analysis completed asynchronously.
                pipe.expire(self.stream_key(account), self.ttl_seconds)
                pipe.expire(compact_key, self.ttl_seconds)
                pipe.expire(self.meta_key(account), self.ttl_seconds)
                pipe.expire(self.seq_key(account), self.ttl_seconds)
                pipe.expire(self.accounts_key, self.ttl_seconds)
            pipe.execute()
        except redis.ResponseError:
            # Compact rows are an acceleration path only; the full stream is authoritative.
            pass

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
