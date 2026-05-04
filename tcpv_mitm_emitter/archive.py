from __future__ import annotations

import base64
import gzip
import json
import re
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from .analyzer import TersafeAnalyzer
from .config import archive_dir

ARCHIVE_VERSION = 1
ARCHIVE_SUFFIX = ".tcpvflow.jsonl.gz"

_TXT_EVENT_RE = re.compile(
    r"^(请求原包未发送|请求原包|请求透传|请求|响应原包|响应)\s+"
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s*$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F\s]+$")


def safe_slug(value: str, default: str = "flow") -> str:
    text = str(value or "").strip()
    out = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in text)
    out = out.strip("._")
    return out[:120] or default


def make_archive_path(flow_meta: dict[str, Any], *, base_dir: Path | None = None) -> Path:
    base = base_dir or archive_dir()
    account = safe_slug(str(flow_meta.get("account") or "flow"))
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return base / f"{stamp}_{account}{ARCHIVE_SUFFIX}"


def write_flow_archive(path: Path, flow_meta: dict[str, Any], events: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = {
        "type": "flow",
        "version": ARCHIVE_VERSION,
        "created_at": int(time.time() * 1000),
        "flow": flow_meta,
    }
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write(json.dumps(header, ensure_ascii=False, separators=(",", ":")) + "\n")
        for event in events:
            row = {"type": "event", "version": ARCHIVE_VERSION, **event}
            fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    return path


def read_flow_archive_bytes(data: bytes, filename: str = "") -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw = bytes(data or b"")
    name = str(filename or "").lower()
    if name.endswith(".gz") or raw[:2] == b"\x1f\x8b":
        text = gzip.decompress(raw).decode("utf-8", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")

    flow_meta: dict[str, Any] | None = None
    events: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"archive json error line={line_no}: {exc}") from exc
        if item.get("type") == "flow":
            flow_meta = dict(item.get("flow") or {})
        elif item.get("type") == "event":
            event = dict(item)
            event.pop("type", None)
            event.pop("version", None)
            events.append(event)
    if flow_meta is None:
        raise ValueError("archive missing flow header")
    return flow_meta, events


def export_event_from_api(event: dict[str, Any]) -> dict[str, Any]:
    display = _b64_to_hex(event.get("pay"))
    full = _b64_to_hex(event.get("full_pay"))
    before = _b64_to_hex(event.get("before_pay"))
    raw = _b64_to_hex(event.get("raw_pay")) or full or display
    return {
        "ts": _to_int(event.get("ts"), 0),
        "dir": _to_int(event.get("dir"), 0),
        "seq": _to_int(event.get("seq"), 0),
        "cid": str(event.get("cid") or ""),
        "label": str(event.get("label") or ""),
        "raw": raw,
        "full": full or raw,
        "display": display or raw,
        "before": before,
        "summary": str(event.get("summary") or ""),
        "msg_idx": _to_int(event.get("msg_idx"), -1),
        "chunk_idx": _to_int(event.get("chunk_idx"), -1),
        "decode_status": str(event.get("decode_status") or ""),
        "source": str(event.get("source") or ""),
    }


def parse_import_bytes(data: bytes, filename: str, analyzer: TersafeAnalyzer | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    name = str(filename or "import").strip() or "import"
    lower = name.lower()
    if lower.endswith(".tcpvflow.jsonl") or lower.endswith(".tcpvflow.jsonl.gz"):
        return remap_imported_flow(*read_flow_archive_bytes(data, filename=name), filename=name)
    return parse_txt_capture(data, name, analyzer=analyzer)


def remap_imported_flow(
    flow_meta: dict[str, Any],
    events: list[dict[str, Any]],
    *,
    filename: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    original = str(flow_meta.get("account") or safe_slug(filename))
    account = f"import:{safe_slug(original)}:{uuid.uuid4().hex[:8]}"
    out_meta = dict(flow_meta)
    out_meta["account"] = account
    out_meta["imported_from"] = filename
    out_meta["original_account"] = original
    return out_meta, events


def parse_txt_capture(
    data: bytes,
    filename: str,
    *,
    analyzer: TersafeAnalyzer | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    text = bytes(data or b"").decode("utf-8", errors="replace")
    source_name = Path(filename or "import.txt").name
    stem = Path(source_name).stem
    account_hint = stem.split("_", 1)[0] if stem else "txt"
    imported_account = f"import:{safe_slug(stem or account_hint)}:{uuid.uuid4().hex[:8]}"
    listen_tag, source_port = _source_port_from_name(stem)
    cid = f"import:{source_name}"
    events: list[dict[str, Any]] = []
    lines = text.splitlines()
    index = 0
    seq = 0
    while index < len(lines):
        line = lines[index].strip()
        match = _TXT_EVENT_RE.match(line)
        if not match:
            index += 1
            continue
        label = match.group(1)
        ts_ms = _parse_ts_ms(match.group(2))
        index += 1
        hex_parts: list[str] = []
        while index < len(lines):
            candidate = lines[index].strip()
            if _TXT_EVENT_RE.match(candidate):
                break
            if candidate and _HEX_RE.match(candidate):
                hex_parts.append(candidate.replace(" ", ""))
            elif hex_parts:
                break
            index += 1
        raw_hex = "".join(hex_parts).lower()
        if not raw_hex or len(raw_hex) % 2:
            continue
        try:
            raw_bytes = bytes.fromhex(raw_hex)
        except ValueError:
            continue
        seq += 1
        analysis = analyzer.analyze(raw_bytes) if analyzer is not None else None
        if analysis is None:
            display_bytes = raw_bytes
            summary = f"import_label={safe_slug(label)} import_decode=skipped"
            decode_status = "skipped"
            before_hex = ""
        else:
            display_bytes = analysis.display_payload or raw_bytes
            summary = " ".join(part for part in (f"import_label={safe_slug(label)}", analysis.summary) if part)
            decode_status = analysis.decode_status
            before_hex = analysis.before_payload.hex()
        events.append(
            {
                "ts": ts_ms,
                "dir": 0 if label.startswith("请求") else 1,
                "seq": seq,
                "cid": cid,
                "label": label,
                "raw": raw_hex,
                "full": raw_hex,
                "display": display_bytes.hex(),
                "before": before_hex,
                "summary": summary,
                "msg_idx": -1,
                "chunk_idx": seq - 1,
                "decode_status": decode_status,
                "source": "txt",
                "listen_tag": listen_tag,
                "source_port": source_port,
            }
        )

    if not events:
        raise ValueError("txt import found no packet events")
    first_ts = int(events[0].get("ts") or 0)
    last_ts = int(events[-1].get("ts") or first_ts)
    flow_meta = {
        "account": imported_account,
        "original_account": account_hint,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "ended_ts": last_ts,
        "status": "closed",
        "last_cid": cid,
        "proxy_username": "",
        "source": "txt",
        "source_file": source_name,
        "listen_tag": listen_tag,
        "source_port": source_port,
    }
    return flow_meta, events


def _parse_ts_ms(text: str) -> int:
    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in text else "%Y-%m-%d %H:%M:%S"
    try:
        dt = datetime.strptime(text, fmt)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(time.time() * 1000)


def _source_port_from_name(stem: str) -> tuple[str, str]:
    match = re.search(r"(809\d)", stem or "")
    if not match:
        return "", ""
    port = match.group(1)
    return f"port{port}", port


def _b64_to_hex(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    try:
        return base64.b64decode(text).hex()
    except Exception:
        return ""


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
