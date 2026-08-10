from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import re
import time
from typing import Any


AGENT_SCHEMA = "tcpv.agent.query.v1"
AGENT_API_PREFIX = "/api/agent/v1"
AGENT_MAX_FLOWS = 200
AGENT_MAX_EVENTS = 2000
AGENT_MAX_PAYLOAD_BYTES = 64 * 1024
_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)(ms|s|m|h|d)$", re.IGNORECASE)


def parse_time_value(value: str | int | None, *, now_ms: int | None = None, relative: bool = False) -> int | None:
    """Parse epoch seconds/ms, ISO-8601, ``now``, or a duration such as ``5m``."""

    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    if text.casefold() == "now":
        return now
    match = _DURATION_RE.fullmatch(text)
    if match:
        amount = float(match.group(1))
        unit = match.group(2).casefold()
        multiplier = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}[unit]
        duration_ms = int(amount * multiplier)
        return now - duration_ms if relative else duration_ms
    try:
        numeric = int(text, 10)
        return numeric * 1000 if abs(numeric) < 100_000_000_000 else numeric
    except ValueError:
        pass
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def parse_direction(value: str | int | None) -> int | None:
    text = str(value if value is not None else "").strip().casefold()
    if text in {"", "all", "any", "*"}:
        return None
    if text in {"0", "request", "req", "out", "outbound", "client"}:
        return 0
    if text in {"1", "response", "resp", "in", "inbound", "server"}:
        return 1
    raise ValueError("direction must be all/request/response")


def filter_flows(
    flows: list[dict[str, Any]],
    *,
    query: str = "",
    status: str = "",
    source_port: str = "",
    since_ts: int | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    needle = str(query or "").casefold()
    wanted_status = str(status or "").strip().casefold()
    wanted_port = str(source_port or "").strip().casefold()
    matches: list[dict[str, Any]] = []
    for item in flows:
        if wanted_status and wanted_status not in {"all", "any", "*"}:
            current_status = str(item.get("status") or ("open" if item.get("is_open") else "closed")).casefold()
            if current_status != wanted_status:
                continue
        if wanted_port and wanted_port not in {"all", "any", "*"}:
            port_text = str(item.get("source_port") or "").casefold()
            if port_text != wanted_port and wanted_port not in str(item.get("last_cid") or "").casefold():
                continue
        if since_ts is not None and int(item.get("last_ts") or 0) < int(since_ts):
            continue
        if needle:
            haystack = "\n".join(
                str(item.get(key) or "")
                for key in (
                    "account",
                    "last_cid",
                    "proxy_username",
                    "status",
                    "listen_tag",
                    "source_port",
                    "source",
                    "source_file",
                )
            ).casefold()
            if needle not in haystack:
                continue
        matches.append(dict(item))
    matches.sort(key=lambda row: (int(row.get("last_ts") or 0), int(row.get("last_seq") or 0)), reverse=True)
    return matches[: max(1, min(int(limit), AGENT_MAX_FLOWS))]


def resolve_flow(flows: list[dict[str, Any]], selector: str) -> dict[str, Any] | None:
    if not flows:
        return None
    value = str(selector or "latest").strip()
    if not value or value.casefold() == "latest":
        return flows[0]
    exact = next((item for item in flows if str(item.get("account") or "") == value), None)
    if exact is not None:
        return exact
    needle = value.casefold()
    partial = [
        item
        for item in flows
        if needle in str(item.get("account") or "").casefold()
        or needle in str(item.get("last_cid") or "").casefold()
        or needle in str(item.get("proxy_username") or "").casefold()
    ]
    return partial[0] if len(partial) == 1 else None


def _payload_view(encoded: str, *, declared_len: int, max_bytes: int, encoding: str) -> dict[str, Any] | None:
    if not encoded:
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        return {"encoding": encoding, "decode_error": True, "data": ""}
    cap = max(0, min(int(max_bytes), AGENT_MAX_PAYLOAD_BYTES))
    shown = raw[:cap]
    return {
        "encoding": encoding,
        "data": base64.b64encode(shown).decode("ascii") if encoding == "base64" else shown.hex(),
        "declared_bytes": max(int(declared_len or 0), len(raw)),
        "stored_bytes": len(raw),
        "returned_bytes": len(shown),
        "truncated": len(shown) < len(raw) or int(declared_len or 0) > len(raw),
        "sha256_stored": hashlib.sha256(raw).hexdigest(),
    }


def shape_event(
    event: dict[str, Any],
    *,
    view: str = "compact",
    payload_bytes: int = 256,
    payload_encoding: str = "hex",
) -> dict[str, Any]:
    mode = str(view or "compact").casefold()
    if mode not in {"compact", "analysis", "payload", "full"}:
        raise ValueError("view must be compact/analysis/payload/full")
    encoding = str(payload_encoding or "hex").casefold()
    if encoding not in {"hex", "base64"}:
        raise ValueError("payload_encoding must be hex/base64")

    item = dict(event)
    encoded_payloads = {
        "display": (str(item.pop("pay", "") or ""), int(item.get("len") or 0)),
        "received": (str(item.pop("full_pay", "") or ""), int(item.get("full_len") or 0)),
        "before": (str(item.pop("before_pay", "") or ""), int(item.get("before_len") or 0)),
        "forwarded": (str(item.pop("raw_pay", "") or ""), int(item.get("raw_len") or 0)),
    }
    if mode not in {"analysis", "full"}:
        item.pop("analysis", None)
    if mode in {"payload", "full"}:
        payloads = {
            name: payload
            for name, (encoded, declared) in encoded_payloads.items()
            if (payload := _payload_view(encoded, declared_len=declared, max_bytes=payload_bytes, encoding=encoding))
        }
        if payloads:
            item["payloads"] = payloads
    item["direction"] = "request" if int(item.get("dir") or 0) == 0 else "response"
    return item


def capabilities(*, instance_id: str, token_configured: bool) -> dict[str, Any]:
    return {
        "schema": "tcpv.agent.capabilities.v1",
        "service": "tcpv-mitm-emitter",
        "instance_id": instance_id,
        "read_only": True,
        "server_time_ms": int(time.time() * 1000),
        "authentication": {
            "agent_bearer_token_configured": bool(token_configured),
            "headers": ["Authorization: Bearer $TCPV_AGENT_TOKEN", "X-TCPV-Agent-Token: $TCPV_AGENT_TOKEN"],
        },
        "endpoints": {
            "capabilities": f"GET {AGENT_API_PREFIX}/capabilities",
            "flows": f"GET {AGENT_API_PREFIX}/flows?q=&status=&source_port=&since=&limit=",
            "query": (
                f"GET {AGENT_API_PREFIX}/query?flow=latest&since=5m&limit=100"
                "&view=analysis&direction=all&q="
            ),
            "event": f"GET {AGENT_API_PREFIX}/event?flow=<account>&id=<event_id>&view=full",
        },
        "views": ["compact", "analysis", "payload", "full"],
        "payload_encodings": ["hex", "base64"],
        "limits": {
            "flows": AGENT_MAX_FLOWS,
            "events": AGENT_MAX_EVENTS,
            "payload_bytes": AGENT_MAX_PAYLOAD_BYTES,
        },
        "time_syntax": ["30s", "5m", "2h", "1d", "epoch_seconds", "epoch_ms", "ISO-8601"],
    }


__all__ = [
    "AGENT_API_PREFIX",
    "AGENT_MAX_EVENTS",
    "AGENT_MAX_PAYLOAD_BYTES",
    "AGENT_SCHEMA",
    "capabilities",
    "filter_flows",
    "parse_direction",
    "parse_time_value",
    "resolve_flow",
    "shape_event",
]
