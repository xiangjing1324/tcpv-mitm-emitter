from __future__ import annotations

import logging
import base64
import json
import os
import queue
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

import redis

from .analyzer import TersafeAnalyzer
from .archive import export_event_from_api, make_archive_path, parse_import_bytes, write_flow_archive
from .config import archive_dir, env_int, overflow_dir, runtime_config
from .store import TcpvEventStore
from .semantic import analysis_from_event, analysis_needs_upgrade, analyze_payload, correlate_events

logger = logging.getLogger(__name__)


def _normalize_instance_id(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    safe = "".join(ch if ch.isalnum() or ch in "._:-" else "_" for ch in raw)
    return safe[:128]


def _cleanup_previous_on_start_enabled(value: bool | None) -> bool:
    """Clear the previous recording window unless preservation is explicit."""

    if value is not None:
        return bool(value)
    raw = str(os.getenv("TCPV_CLEAR_PREVIOUS_ON_START", "1") or "1").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _producer_analysis_is_authoritative(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("analysis_authoritative") is True
        and str(value.get("schema") or "").startswith("tcpv.")
    )


class TcpvRuntime:
    """Runtime manager for TCP packet event service and async Redis writer."""

    def __init__(self) -> None:
        self.enabled = False
        self.instance_id = ""
        self.store: TcpvEventStore | None = None

        self._queue_maxsize = env_int("TCPV_QUEUE_MAXSIZE", 100_000, min_value=1)
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=self._queue_maxsize)
        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None

        self._server_thread: threading.Thread | None = None
        self._uvicorn_server: Any = None

        self._lock = threading.Lock()
        self._drop_lock = threading.Lock()
        self._dropped_count = 0
        self._emit_count = 0
        self._write_count = 0
        self._write_error_count = 0
        self._sync_write_count = 0
        self._spooled_count = 0
        self._last_write_error = ""
        self._last_spool_path = ""
        self._producer_analysis_count = 0
        self._semantic_parse_count = 0
        self._semantic_skipped_payload_count = 0
        self._drop_before_ts_ms: dict[str, int] = {}
        self._analyzer = TersafeAnalyzer()
        self._cleanup_instance_on_stop = True

    def start(
        self,
        bind_host: str = "0.0.0.0",
        bind_port: int = 18091,
        redis_host: str = "127.0.0.1",
        redis_port: int = 6379,
        redis_db: int = 0,
        instance_id: str = "",
        cleanup_on_stop: bool | None = None,
        cleanup_previous_on_start: bool | None = None,
    ) -> bool:
        with self._lock:
            if self.enabled:
                return True
            self._drain_queue()

            try:
                redis_client = redis.Redis(host=redis_host, port=redis_port, db=redis_db)
                redis_client.ping()

                requested_instance_id = _normalize_instance_id(instance_id)
                self.instance_id = requested_instance_id or uuid.uuid4().hex
                self._cleanup_instance_on_stop = bool(cleanup_on_stop) if cleanup_on_stop is not None else not bool(requested_instance_id)
                self.store = TcpvEventStore(redis_client=redis_client, instance_id=self.instance_id)
                runtime_started_ts_ms = int(time.time() * 1000)
                previous_owner_pid = self.store.runtime_owner_pid()
                cleared_runtime_keys = 0
                if (
                    previous_owner_pid != os.getpid()
                    and _cleanup_previous_on_start_enabled(cleanup_previous_on_start)
                ):
                    # An ordinary mitmweb restart defines a new observation
                    # window.  Explicit opt-out is reserved for recovery or
                    # forensic preservation.
                    cleared_runtime_keys = self.store.cleanup_instance()
                self.store.register_runtime_owner(os.getpid(), runtime_started_ts_ms)
                if cleared_runtime_keys:
                    logger.info(
                        "cleared %s tcpv redis key(s) from the previous runtime",
                        cleared_runtime_keys,
                    )
                self._stop_event.clear()
                self._drop_before_ts_ms = {}

                self._worker_thread = threading.Thread(target=self._writer_loop, name="tcpv-writer", daemon=True)
                self._worker_thread.start()

                from .api import create_app

                app = create_app(self)
                self._server_thread = threading.Thread(
                    target=self._run_server,
                    args=(app, bind_host, int(bind_port)),
                    name="tcpv-api",
                    daemon=True,
                )
                self._server_thread.start()

                self.enabled = True
                logger.info(
                    "tcpv-mitm-emitter started at http://%s:%s (instance=%s)",
                    bind_host,
                    bind_port,
                    self.instance_id,
                )
                return True
            except Exception:
                logger.exception("failed to initialize tcpv runtime")
                self._stop_event.set()
                if self._worker_thread and self._worker_thread.is_alive():
                    self._worker_thread.join(timeout=1.0)
                if self.store is not None and self._cleanup_instance_on_stop:
                    try:
                        self.store.cleanup_instance()
                    except Exception:
                        logger.exception("failed to rollback tcpv redis keys")
                self.enabled = False
                self.instance_id = ""
                self.store = None
                self._uvicorn_server = None
                self._worker_thread = None
                self._server_thread = None
                self._drop_before_ts_ms = {}
                self._drain_queue()
                raise

    def stop(self) -> None:
        with self._lock:
            if not self.enabled and self.store is None:
                return

            self._stop_event.set()

            if self._worker_thread and self._worker_thread.is_alive():
                self._worker_thread.join(timeout=2.0)

            if self._uvicorn_server is not None:
                self._uvicorn_server.should_exit = True

            if self._server_thread and self._server_thread.is_alive():
                self._server_thread.join(timeout=3.0)

            if self.store is not None and self._cleanup_instance_on_stop:
                try:
                    self.store.cleanup_instance()
                except Exception:
                    logger.exception("failed to cleanup tcpv redis keys")

            self.enabled = False
            self.instance_id = ""
            self.store = None
            self._uvicorn_server = None
            self._worker_thread = None
            self._server_thread = None
            self._dropped_count = 0
            self._emit_count = 0
            self._write_count = 0
            self._write_error_count = 0
            self._sync_write_count = 0
            self._spooled_count = 0
            self._last_write_error = ""
            self._last_spool_path = ""
            self._producer_analysis_count = 0
            self._semantic_parse_count = 0
            self._semantic_skipped_payload_count = 0
            self._drop_before_ts_ms = {}
            self._cleanup_instance_on_stop = True
            self._drain_queue()

    def emit_packet(
        self,
        account: str,
        packet_data: Any,
        from_client: bool,
        cid: str = "",
        proxy_username: str = "",
        summary: str = "",
        msg_idx: int | None = None,
        chunk_idx: int | None = None,
        ts_ms: int | None = None,
        packet_len: int | None = None,
        full_packet_data: Any | None = None,
        full_packet_len: int | None = None,
        before_packet_data: Any | None = None,
        before_packet_len: int | None = None,
        raw_packet_data: Any | None = None,
        raw_packet_len: int | None = None,
        analysis: dict[str, Any] | None = None,
    ) -> None:
        if not self.enabled or self.store is None:
            return

        account = (account or "").strip()
        if not account:
            return

        payload = self._to_bytes(packet_data)
        if not payload:
            return

        try:
            real_packet_len = int(packet_len) if packet_len is not None else len(payload)
        except (TypeError, ValueError):
            real_packet_len = len(payload)
        if real_packet_len <= 0:
            real_packet_len = len(payload)

        full_payload = self._to_bytes(full_packet_data)
        try:
            real_full_packet_len = int(full_packet_len) if full_packet_len is not None else len(full_payload)
        except (TypeError, ValueError):
            real_full_packet_len = len(full_payload)
        if real_full_packet_len <= 0:
            real_full_packet_len = len(full_payload)
        before_payload = self._to_bytes(before_packet_data)
        try:
            real_before_packet_len = int(before_packet_len) if before_packet_len is not None else len(before_payload)
        except (TypeError, ValueError):
            real_before_packet_len = len(before_payload)
        if real_before_packet_len <= 0:
            real_before_packet_len = len(before_payload)
        raw_payload = self._to_bytes(raw_packet_data)
        try:
            real_raw_packet_len = int(raw_packet_len) if raw_packet_len is not None else len(raw_payload)
        except (TypeError, ValueError):
            real_raw_packet_len = len(raw_payload)
        if real_raw_packet_len <= 0:
            real_raw_packet_len = len(raw_payload)

        event = {
            "account": account,
            "cid": cid or "",
            "proxy_username": str(proxy_username or ""),
            "summary": str(summary or ""),
            "dir": 0 if from_client else 1,
            "payload": payload,
            "packet_len": real_packet_len,
            "full_payload": full_payload,
            "full_packet_len": real_full_packet_len,
            "before_payload": before_payload,
            "before_packet_len": real_before_packet_len,
            "raw_payload": raw_payload,
            "raw_packet_len": real_raw_packet_len,
            "ts_ms": int(ts_ms or (time.time() * 1000)),
            "msg_idx": msg_idx,
            "chunk_idx": chunk_idx,
            "analysis": dict(analysis) if isinstance(analysis, dict) else {},
        }

        try:
            self._queue.put_nowait(event)
            self._emit_count += 1
        except queue.Full:
            self._emit_count += 1
            if self._write_event_sync(event):
                self._sync_write_count += 1
                if self._sync_write_count % 1000 == 1:
                    logger.warning("tcpv queue full, wrote synchronously=%s", self._sync_write_count)
                return
            if self._spool_event(event, reason="queue_full"):
                self._spooled_count += 1
            else:
                self._dropped_count += 1
                if self._dropped_count % 1000 == 1:
                    logger.warning("tcpv queue full, dropped=%s", self._dropped_count)

    def emit_lobby_packet(
        self,
        flow: Any | None,
        packet_data: Any,
        from_client: bool,
        msg_idx: int | None = None,
        chunk_idx: int | None = None,
        account: str | None = None,
        cid: str | None = None,
        proxy_username: str | None = None,
        summary: str | None = None,
        ts_ms: int | None = None,
        packet_len: int | None = None,
        full_packet_data: Any | None = None,
        full_packet_len: int | None = None,
        before_packet_data: Any | None = None,
        before_packet_len: int | None = None,
        raw_packet_data: Any | None = None,
        raw_packet_len: int | None = None,
        analysis: dict[str, Any] | None = None,
    ) -> None:
        account_value = account
        if account_value is None and flow is not None:
            account_value = getattr(flow, "account_info", "")

        cid_value = cid
        if cid_value is None:
            if flow is not None:
                cid_value = self._build_cid(flow)
            else:
                cid_value = ""

        proxy_username_value = str(proxy_username or "").strip()
        if not proxy_username_value and flow is not None:
            proxy_username_value = str(getattr(flow, "proxy_username", "") or "").strip()
        summary_value = str(summary or "").strip()
        analysis_value = analysis
        if analysis_value is None and flow is not None:
            candidate = getattr(flow, "last_csob_semantic_analysis", None)
            if isinstance(candidate, dict):
                analysis_value = candidate

        self.emit_packet(
            account=account_value or "",
            packet_data=packet_data,
            from_client=from_client,
            cid=cid_value,
            proxy_username=proxy_username_value,
            summary=summary_value,
            msg_idx=msg_idx,
            chunk_idx=chunk_idx,
            ts_ms=ts_ms,
            packet_len=packet_len,
            full_packet_data=full_packet_data,
            full_packet_len=full_packet_len,
            before_packet_data=before_packet_data,
            before_packet_len=before_packet_len,
            raw_packet_data=raw_packet_data,
            raw_packet_len=raw_packet_len,
            analysis=analysis_value,
        )

    def tcp_start(
        self,
        flow: Any | None = None,
        account: str | None = None,
        cid: str | None = None,
        proxy_username: str | None = None,
        ts_ms: int | None = None,
    ) -> str:
        if not self.enabled or self.store is None:
            return ""

        account_value = str(account or "").strip()
        if not account_value and flow is not None:
            account_value = str(getattr(flow, "id", "") or "").strip()
        if not account_value and flow is not None:
            account_value = str(getattr(flow, "account_info", "") or "").strip()
        if not account_value:
            return ""

        cid_value = cid
        if cid_value is None:
            cid_value = self._build_cid(flow) if flow is not None else ""

        proxy_username_value = str(proxy_username or "").strip()
        if not proxy_username_value and flow is not None:
            proxy_username_value = str(getattr(flow, "proxy_username", "") or "").strip()

        now_ms = int(ts_ms or (time.time() * 1000))
        self.store.mark_flow_start(
            account=account_value,
            cid=cid_value or "",
            proxy_username=proxy_username_value,
            ts_ms=now_ms,
        )
        return account_value

    def tcp_end(
        self,
        flow: Any | None = None,
        account: str | None = None,
        cid: str | None = None,
        proxy_username: str | None = None,
        ts_ms: int | None = None,
        duration_ms: int | None = None,
    ) -> str:
        if not self.enabled or self.store is None:
            return ""

        account_value = str(account or "").strip()
        if not account_value and flow is not None:
            account_value = str(getattr(flow, "id", "") or "").strip()
        if not account_value and flow is not None:
            account_value = str(getattr(flow, "account_info", "") or "").strip()
        if not account_value:
            return ""

        cid_value = cid
        if cid_value is None:
            cid_value = self._build_cid(flow) if flow is not None else ""

        proxy_username_value = str(proxy_username or "").strip()
        if not proxy_username_value and flow is not None:
            proxy_username_value = str(getattr(flow, "proxy_username", "") or "").strip()

        now_ms = int(ts_ms or (time.time() * 1000))
        self.store.mark_flow_end(
            account=account_value,
            cid=cid_value or "",
            proxy_username=proxy_username_value,
            ts_ms=now_ms,
            duration_ms=duration_ms,
        )
        return account_value

    def get_accounts(self) -> list[dict[str, Any]]:
        store = self.store
        if store is None:
            return []
        return store.list_accounts()

    def get_events(
        self,
        account: str,
        after_id: str | None,
        limit: int,
        include_payload: bool = True,
        include_analysis: bool = True,
    ) -> tuple[list[dict[str, Any]], str | None, bool]:
        store = self.store
        if store is None:
            return [], after_id, False
        decode_payload = include_payload or include_analysis
        events, last_id, has_more = store.get_events(
            account=account,
            after_id=after_id,
            limit=limit,
            # Old rows without `ana` still need payload bytes when the caller
            # asks for analysis; compact list callers can skip both.
            include_payload=decode_payload,
            include_analysis=include_analysis,
        )
        if include_analysis:
            for event in events:
                if analysis_needs_upgrade(event.get("analysis")):
                    event["analysis"] = analysis_from_event(event)
            correlate_events(events)
        if not include_payload:
            for event in events:
                event["pay"] = ""
                event["full_pay"] = ""
                event["before_pay"] = ""
                event["raw_pay"] = ""
        return events, last_id, has_more

    def query_events(
        self,
        account: str,
        *,
        before_id: str | None = None,
        limit: int = 100,
        scan_limit: int = 5000,
        since_ts: int | None = None,
        until_ts: int | None = None,
        direction: int | None = None,
        min_len: int | None = None,
        max_len: int | None = None,
        summary_contains: str = "",
        cid_contains: str = "",
        query: str = "",
        include_payload: bool = False,
        include_analysis: bool = False,
    ) -> tuple[list[dict[str, Any]], str | None, bool, int]:
        store = self.store
        if store is None:
            return [], before_id, False, 0
        decode_payload = include_payload or include_analysis
        events, next_cursor, has_more, scanned = store.query_events(
            account=account,
            before_id=before_id,
            limit=limit,
            scan_limit=scan_limit,
            since_ts=since_ts,
            until_ts=until_ts,
            direction=direction,
            min_len=min_len,
            max_len=max_len,
            summary_contains=summary_contains,
            cid_contains=cid_contains,
            query=query,
            include_payload=decode_payload,
            include_analysis=include_analysis,
        )
        if include_analysis:
            for event in events:
                if analysis_needs_upgrade(event.get("analysis")):
                    event["analysis"] = analysis_from_event(event)
            correlate_events(events)
        if not include_payload:
            for event in events:
                event["pay"] = ""
                event["full_pay"] = ""
                event["before_pay"] = ""
                event["raw_pay"] = ""
        return events, next_cursor, has_more, scanned

    def export_flow(self, account: str) -> tuple[Path, dict[str, Any]]:
        account = str(account or "").strip()
        if not account:
            raise ValueError("account is required")
        store = self.store
        if store is None:
            raise RuntimeError("service not enabled")
        flow = next((item for item in store.list_accounts() if str(item.get("account") or "") == account), None)
        if flow is None:
            raise KeyError("flow not found")
        api_events = store.iter_events(account, include_payload=True)
        for event in api_events:
            if analysis_needs_upgrade(event.get("analysis")):
                event["analysis"] = analysis_from_event(event)
        correlate_events(api_events)
        events = [export_event_from_api(event) for event in api_events]
        if not events:
            raise KeyError("flow has no events")
        path = make_archive_path(flow)
        write_flow_archive(path, flow, events)
        return path, {"account": account, "events": len(events), "path": str(path)}

    def get_deep_report(self, account: str) -> tuple[dict[str, Any], str]:
        from .shape_summary import render_markdown, summarize_events

        account = str(account or "").strip()
        if not account:
            raise ValueError("account is required")
        store = self.store
        if store is None:
            raise RuntimeError("service not enabled")
        flow = next((item for item in store.list_accounts() if str(item.get("account") or "") == account), None)
        if flow is None:
            raise KeyError("flow not found")
        api_events = store.iter_events(account, include_payload=True)
        for event in api_events:
            if analysis_needs_upgrade(event.get("analysis")):
                event["analysis"] = analysis_from_event(event)
        correlate_events(api_events)
        events = [export_event_from_api(event) for event in api_events]
        if not events:
            raise KeyError("flow has no events")
        summary = summarize_events(flow, events, source="display", input_name=f"live:{account}")
        return summary, render_markdown(summary, top=40)

    def save_flow(self, account: str) -> dict[str, Any]:
        path, info = self.export_flow(account)
        info["saved"] = True
        info["filename"] = path.name
        return info

    def import_flow_bytes(self, data: bytes, filename: str) -> dict[str, Any]:
        store = self.store
        if store is None:
            raise RuntimeError("service not enabled")
        flow_meta, events = parse_import_bytes(data, filename, analyzer=self._analyzer)
        result = store.import_flow(flow_meta, events)
        result["source_file"] = filename
        result["account"] = flow_meta.get("account")
        return result

    def list_archives(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for path in sorted(archive_dir().glob(f"*{'.tcpvflow.jsonl.gz'}"), key=lambda p: p.stat().st_mtime, reverse=True):
            stat = path.stat()
            items.append(
                {
                    "name": path.name,
                    "path": str(path),
                    "size": stat.st_size,
                    "mtime": int(stat.st_mtime * 1000),
                }
            )
        return items

    def replay_archive(self, name: str) -> dict[str, Any]:
        safe_name = Path(str(name or "")).name
        if not safe_name:
            raise ValueError("archive name is required")
        path = archive_dir() / safe_name
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(safe_name)
        return self.import_flow_bytes(path.read_bytes(), path.name)

    def get_event(self, account: str, event_id: str) -> dict[str, Any] | None:
        store = self.store
        if store is None:
            return None
        event = store.get_event(account=account, event_id=event_id)
        if event is not None and analysis_needs_upgrade(event.get("analysis")):
            event["analysis"] = analysis_from_event(event)
        return event

    def get_connections(self, account: str, recent: int) -> list[dict[str, Any]]:
        store = self.store
        if store is None:
            return []
        return store.get_connections(account=account, recent=recent)

    def clear_account(self, account: str) -> None:
        account = (account or "").strip()
        if not account:
            return
        store = self.store
        if store is None:
            return

        cutoff_ms = int(time.time() * 1000)
        with self._drop_lock:
            self._drop_before_ts_ms[account] = cutoff_ms

        try:
            store.cleanup_account(account)
            logger.info("tcpv cleanup account=%s", account)
        except Exception:
            logger.exception("failed to cleanup tcpv account=%s", account)

    def _writer_loop(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            store = self.store
            if store is None:
                continue

            account = str(item.get("account", "")).strip()
            if account:
                with self._drop_lock:
                    drop_before = int(self._drop_before_ts_ms.get(account, 0) or 0)
                if drop_before and int(item.get("ts_ms", 0) or 0) <= drop_before:
                    continue

            try:
                self._append_store_event(store, item)
                self._write_count += 1
            except Exception:
                self._write_error_count += 1
                self._last_write_error = traceback.format_exc(limit=1).strip().splitlines()[-1]
                logger.exception("failed to append tcpv event")
                if self._spool_event(item, reason="write_error"):
                    self._spooled_count += 1

    def _run_server(self, app: Any, host: str, port: int) -> None:
        try:
            import uvicorn

            config = uvicorn.Config(app=app, host=host, port=port, access_log=False, log_level="warning")
            server = uvicorn.Server(config)
            self._uvicorn_server = server
            server.run()
        except Exception:
            logger.exception("tcpv api server crashed")

    def _drain_queue(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break

    def _append_store_event(self, store: TcpvEventStore, item: dict[str, Any]) -> None:
        direction = int(item.get("dir") or 0)
        before_payload = bytes(item.get("before_payload") or b"")
        analysis: dict[str, Any] | None = (
            item.get("analysis") if isinstance(item.get("analysis"), dict) else None
        )
        seen: set[bytes] = set()
        candidates: list[bytes] = []
        for candidate in (
            bytes(item.get("payload") or b""),
            before_payload,
            bytes(item.get("full_payload") or b""),
            bytes(item.get("raw_payload") or b""),
        ):
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        if _producer_analysis_is_authoritative(analysis):
            self._producer_analysis_count += 1
            self._semantic_skipped_payload_count += len(candidates)
        else:
            for candidate in candidates:
                analysis = analyze_payload(
                    candidate,
                    direction=direction,
                    before_payload=before_payload if candidate == bytes(item.get("payload") or b"") else b"",
                    provided=analysis,
                )
                self._semantic_parse_count += 1
        if analysis is None:
            analysis = analyze_payload(b"", direction=direction)
            self._semantic_parse_count += 1
        store.append_event(
            account=item["account"],
            cid=item["cid"],
            direction=item["dir"],
            payload=item["payload"],
            packet_len=item.get("packet_len"),
            full_payload=item.get("full_payload"),
            full_packet_len=item.get("full_packet_len"),
            before_payload=item.get("before_payload"),
            before_packet_len=item.get("before_packet_len"),
            raw_payload=item.get("raw_payload"),
            raw_packet_len=item.get("raw_packet_len"),
            proxy_username=item.get("proxy_username", ""),
            summary=item.get("summary", ""),
            analysis=analysis,
            ts_ms=item["ts_ms"],
            msg_idx=item.get("msg_idx"),
            chunk_idx=item.get("chunk_idx"),
        )

    def _write_event_sync(self, item: dict[str, Any]) -> bool:
        store = self.store
        if store is None:
            return False
        try:
            self._append_store_event(store, item)
            self._write_count += 1
            return True
        except Exception:
            self._write_error_count += 1
            self._last_write_error = traceback.format_exc(limit=1).strip().splitlines()[-1]
            logger.exception("failed to sync append tcpv event")
            return False

    def _spool_event(self, item: dict[str, Any], *, reason: str) -> bool:
        try:
            path = overflow_dir() / f"tcpv-overflow-{time.strftime('%Y%m%d')}.jsonl"
            row = {
                "reason": reason,
                "spooled_at": int(time.time() * 1000),
                "account": item.get("account", ""),
                "cid": item.get("cid", ""),
                "proxy_username": item.get("proxy_username", ""),
                "summary": item.get("summary", ""),
                "dir": item.get("dir", 0),
                "payload": _bytes_to_b64(item.get("payload")),
                "packet_len": item.get("packet_len", 0),
                "full_payload": _bytes_to_b64(item.get("full_payload")),
                "full_packet_len": item.get("full_packet_len", 0),
                "before_payload": _bytes_to_b64(item.get("before_payload")),
                "before_packet_len": item.get("before_packet_len", 0),
                "raw_payload": _bytes_to_b64(item.get("raw_payload")),
                "raw_packet_len": item.get("raw_packet_len", 0),
                "ts_ms": item.get("ts_ms", 0),
                "msg_idx": item.get("msg_idx"),
                "chunk_idx": item.get("chunk_idx"),
                "analysis": item.get("analysis") if isinstance(item.get("analysis"), dict) else {},
            }
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, separators=(",", ":")) + "\n")
            self._last_spool_path = str(path)
            return True
        except Exception:
            logger.exception("failed to spool tcpv overflow event")
            return False

    def get_stats(self) -> dict[str, Any]:
        cfg = runtime_config()
        return {
            "enabled": self.enabled,
            "instance_id": self.instance_id,
            "queue_size": int(self._queue.qsize()),
            "queue_maxsize": int(self._queue_maxsize),
            "emit_count": int(self._emit_count),
            "write_count": int(self._write_count),
            "sync_write_count": int(self._sync_write_count),
            "write_error_count": int(self._write_error_count),
            "dropped_count": int(self._dropped_count),
            "spooled_count": int(self._spooled_count),
            "producer_analysis_count": int(self._producer_analysis_count),
            "semantic_parse_count": int(self._semantic_parse_count),
            "semantic_skipped_payload_count": int(self._semantic_skipped_payload_count),
            "last_write_error": self._last_write_error,
            "last_spool_path": self._last_spool_path,
            "stream_maxlen": int(cfg["stream_maxlen"]),
            "ttl_seconds": int(cfg["ttl_seconds"]),
            "max_events_in_memory": int(cfg["max_events_in_memory"]),
        }

    def get_config(self) -> dict[str, Any]:
        return runtime_config()

    @staticmethod
    def _to_bytes(data: Any) -> bytes:
        if isinstance(data, bytes):
            return data
        if isinstance(data, bytearray):
            return bytes(data)
        if isinstance(data, list):
            try:
                return bytes(data)
            except (TypeError, ValueError):
                return b""
        return b""

    @staticmethod
    def _build_cid(flow: Any) -> str:
        client = getattr(getattr(flow, "client_conn", None), "address", None) or ("?", 0)
        server = getattr(getattr(flow, "server_conn", None), "address", None) or ("?", 0)
        c_host = client[0] if len(client) > 0 else "?"
        c_port = client[1] if len(client) > 1 else 0
        s_host = server[0] if len(server) > 0 else "?"
        s_port = server[1] if len(server) > 1 else 0
        return f"{c_host}:{c_port}->{s_host}:{s_port}"


TCPV_RUNTIME = TcpvRuntime()


def init_emitter(
    bind_host: str = "0.0.0.0",
    bind_port: int = 18091,
    redis_host: str = "127.0.0.1",
    redis_port: int = 6379,
    redis_db: int = 0,
    instance_id: str = "",
    cleanup_on_stop: bool | None = None,
    cleanup_previous_on_start: bool | None = None,
) -> bool:
    return TCPV_RUNTIME.start(
        bind_host=bind_host,
        bind_port=bind_port,
        redis_host=redis_host,
        redis_port=redis_port,
        redis_db=redis_db,
        instance_id=instance_id,
        cleanup_on_stop=cleanup_on_stop,
        cleanup_previous_on_start=cleanup_previous_on_start,
    )


def _bytes_to_b64(value: Any) -> str:
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, bytearray):
        return base64.b64encode(bytes(value)).decode("ascii")
    return ""


def shutdown_emitter() -> None:
    TCPV_RUNTIME.stop()


def emit_lobby_packet(
    flow: Any | None,
    packet_data: Any,
    from_client: bool,
    msg_idx: int | None = None,
    chunk_idx: int | None = None,
    account: str | None = None,
    cid: str | None = None,
    proxy_username: str | None = None,
    summary: str | None = None,
    ts_ms: int | None = None,
    packet_len: int | None = None,
    full_packet_data: Any | None = None,
    full_packet_len: int | None = None,
    before_packet_data: Any | None = None,
    before_packet_len: int | None = None,
    raw_packet_data: Any | None = None,
    raw_packet_len: int | None = None,
    analysis: dict[str, Any] | None = None,
) -> None:
    """Safe no-op when runtime is disabled.

    Compatibility:
    - old style: emit_lobby_packet(flow=flow, packet_data=..., from_client=...)
    - decoupled: emit_lobby_packet(flow=None, account="123", cid="a->b", ...)
    """
    TCPV_RUNTIME.emit_lobby_packet(
        flow=flow,
        packet_data=packet_data,
        from_client=from_client,
        msg_idx=msg_idx,
        chunk_idx=chunk_idx,
        account=account,
        cid=cid,
        proxy_username=proxy_username,
        summary=summary,
        ts_ms=ts_ms,
        packet_len=packet_len,
        full_packet_data=full_packet_data,
        full_packet_len=full_packet_len,
        before_packet_data=before_packet_data,
        before_packet_len=before_packet_len,
        raw_packet_data=raw_packet_data,
        raw_packet_len=raw_packet_len,
        analysis=analysis,
    )


def clear_lobby_account(account: str) -> None:
    """Safe no-op when runtime is disabled."""
    TCPV_RUNTIME.clear_account(account=account)


def tcp_start(
    flow: Any | None = None,
    account: str | None = None,
    cid: str | None = None,
    proxy_username: str | None = None,
    ts_ms: int | None = None,
) -> str:
    """Mark flow as started in external emitter."""
    return TCPV_RUNTIME.tcp_start(
        flow=flow,
        account=account,
        cid=cid,
        proxy_username=proxy_username,
        ts_ms=ts_ms,
    )


def tcp_end(
    flow: Any | None = None,
    account: str | None = None,
    cid: str | None = None,
    proxy_username: str | None = None,
    ts_ms: int | None = None,
    duration_ms: int | None = None,
) -> str:
    """Mark flow as ended in external emitter."""
    return TCPV_RUNTIME.tcp_end(
        flow=flow,
        account=account,
        cid=cid,
        proxy_username=proxy_username,
        ts_ms=ts_ms,
        duration_ms=duration_ms,
    )
