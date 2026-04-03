from __future__ import annotations

import logging
import queue
import threading
import time
import traceback
import uuid
from typing import Any

import redis

from .store import TcpvEventStore

logger = logging.getLogger(__name__)


class TcpvRuntime:
    """Runtime manager for TCP packet event service and async Redis writer."""

    def __init__(self) -> None:
        self.enabled = False
        self.instance_id = ""
        self.store: TcpvEventStore | None = None

        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=20000)
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
        self._last_write_error = ""
        self._drop_before_ts_ms: dict[str, int] = {}

    def start(
        self,
        bind_host: str = "0.0.0.0",
        bind_port: int = 18091,
        redis_host: str = "127.0.0.1",
        redis_port: int = 6379,
        redis_db: int = 0,
    ) -> bool:
        with self._lock:
            if self.enabled:
                return True
            self._drain_queue()

            try:
                redis_client = redis.Redis(host=redis_host, port=redis_port, db=redis_db)
                redis_client.ping()

                self.instance_id = uuid.uuid4().hex
                self.store = TcpvEventStore(redis_client=redis_client, instance_id=self.instance_id)
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
                if self.store is not None:
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

            if self.store is not None:
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
            self._last_write_error = ""
            self._drop_before_ts_ms = {}
            self._drain_queue()

    def emit_packet(
        self,
        account: str,
        packet_data: Any,
        from_client: bool,
        cid: str = "",
        proxy_username: str = "",
        msg_idx: int | None = None,
        chunk_idx: int | None = None,
        ts_ms: int | None = None,
        packet_len: int | None = None,
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

        event = {
            "account": account,
            "cid": cid or "",
            "proxy_username": str(proxy_username or ""),
            "dir": 0 if from_client else 1,
            "payload": payload,
            "packet_len": real_packet_len,
            "ts_ms": int(ts_ms or (time.time() * 1000)),
            "msg_idx": msg_idx,
            "chunk_idx": chunk_idx,
        }

        try:
            self._queue.put_nowait(event)
            self._emit_count += 1
        except queue.Full:
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
        ts_ms: int | None = None,
        packet_len: int | None = None,
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

        self.emit_packet(
            account=account_value or "",
            packet_data=packet_data,
            from_client=from_client,
            cid=cid_value,
            proxy_username=proxy_username_value,
            msg_idx=msg_idx,
            chunk_idx=chunk_idx,
            ts_ms=ts_ms,
            packet_len=packet_len,
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
    ) -> tuple[list[dict[str, Any]], str | None, bool]:
        store = self.store
        if store is None:
            return [], after_id, False
        return store.get_events(
            account=account,
            after_id=after_id,
            limit=limit,
            include_payload=include_payload,
        )

    def get_event(self, account: str, event_id: str) -> dict[str, Any] | None:
        store = self.store
        if store is None:
            return None
        return store.get_event(account=account, event_id=event_id)

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
                store.append_event(
                    account=item["account"],
                    cid=item["cid"],
                    direction=item["dir"],
                    payload=item["payload"],
                    packet_len=item.get("packet_len"),
                    proxy_username=item.get("proxy_username", ""),
                    ts_ms=item["ts_ms"],
                    msg_idx=item.get("msg_idx"),
                    chunk_idx=item.get("chunk_idx"),
                )
                self._write_count += 1
            except Exception:
                self._write_error_count += 1
                self._last_write_error = traceback.format_exc(limit=1).strip().splitlines()[-1]
                logger.exception("failed to append tcpv event")

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

    def get_stats(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "instance_id": self.instance_id,
            "queue_size": int(self._queue.qsize()),
            "emit_count": int(self._emit_count),
            "write_count": int(self._write_count),
            "write_error_count": int(self._write_error_count),
            "dropped_count": int(self._dropped_count),
            "last_write_error": self._last_write_error,
        }

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
) -> bool:
    return TCPV_RUNTIME.start(
        bind_host=bind_host,
        bind_port=bind_port,
        redis_host=redis_host,
        redis_port=redis_port,
        redis_db=redis_db,
    )


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
    ts_ms: int | None = None,
    packet_len: int | None = None,
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
        ts_ms=ts_ms,
        packet_len=packet_len,
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
) -> str:
    """Mark flow as ended in external emitter."""
    return TCPV_RUNTIME.tcp_end(
        flow=flow,
        account=account,
        cid=cid,
        proxy_username=proxy_username,
        ts_ms=ts_ms,
    )
