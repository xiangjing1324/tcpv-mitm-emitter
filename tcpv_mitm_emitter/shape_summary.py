from __future__ import annotations

import argparse
import gzip
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


TAIL_BLOCKED_TYPES = {0x8027, 0x8029}
STRING_CANDIDATE_TYPES = {0x100B, 0x1105, 0x2000}
REGION_PATH_TYPES = {0xFFF2}
STRONG_TEXT_TOKEN_RE = re.compile(
    r"(?:\.dylib|\.framework|/usr/|/private/|com\.apple|SpringBoard|BackBoard|"
    r"Core[A-Za-z]*|UIWindow|UIView|HistoryOpenID|iDevIDFV|iTssSDKUUID|iAppMachUUID)",
    re.IGNORECASE,
)


def _read_flow_archive_bytes(data: bytes, filename: str = "") -> tuple[dict[str, Any], list[dict[str, Any]]]:
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


def _read_be16(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 2], "big")


def _read_be32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 4], "big")


def _read_le32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 4], "little")


def _fmt_hex(value: int | None, width: int = 0) -> str:
    if value is None:
        return "-"
    return f"0x{int(value):0{width}x}" if width > 0 else f"0x{int(value):x}"


def _compact_hex(data: bytes, max_bytes: int | None = None) -> str:
    raw = data if max_bytes is None else data[:max_bytes]
    text = raw.hex()
    if max_bytes is not None and len(data) > max_bytes:
        return f"{text}..."
    return text or "-"


def _is_likely_tss_report(value: int | None) -> bool:
    if value is None:
        return False
    family = (int(value) >> 16) & 0xFFFF
    return family in {0x010A, 0x0102, 0x0112}


def _detect_tss_report(data: bytes) -> dict[str, int] | None:
    for offset in (6, 0, 3):
        value = _read_be32(data, offset)
        if _is_likely_tss_report(value):
            return {"value": int(value), "offset": offset}
    return None


def _record_layout_base_shift(report: dict[str, int]) -> int | None:
    shift = int(report.get("offset", 0)) - 6
    if shift < -6 or shift > 8:
        return None
    return shift


def _read_0102000a_layout(record: bytes, report: dict[str, int]) -> dict[str, int] | None:
    shift = _record_layout_base_shift(report)
    if shift is None:
        return None
    len_offset = shift + 4
    inner_field_offset = shift + 0x20
    if len_offset < 0 or inner_field_offset + 4 > len(record):
        return None
    declared_len = _read_be16(record, len_offset)
    total_len = int(declared_len) if declared_len and declared_len > 0 else len(record) - shift
    body_start = shift + 0x24
    record_end = min(len(record), shift + total_len)
    if body_start < 0 or body_start > len(record):
        body_start = len(record)
    return {
        "shift": shift,
        "total_len": total_len,
        "report_code": _read_be32(record, shift + 0x06) or 0x0102000A,
        "leaf_id": _read_be32(record, shift + 0x0A) or 0,
        "inner_len": _read_be16(record, shift + 0x14) or 0,
        "inner_type": _read_be16(record, shift + 0x16) or 0,
        "selector0": _read_be32(record, shift + 0x18) or 0,
        "selector1": _read_be32(record, shift + 0x1C) or 0,
        "inner_field": _read_be32(record, shift + 0x20) or 0,
        "body_start": body_start,
        "body_len": max(0, record_end - body_start),
        "record_end": record_end,
    }


def _tail_info(record: bytes, layout: dict[str, int]) -> dict[str, Any]:
    body_len = int(layout.get("body_len") or 0)
    inner_type = int(layout.get("inner_type") or 0)
    tail_len = min(8, max(0, body_len)) if inner_type in TAIL_BLOCKED_TYPES else 0
    start = len(record) if tail_len <= 0 else max(int(layout.get("body_start") or 0), len(record) - tail_len)
    tail = record[start : start + tail_len]
    u32 = [
        int.from_bytes(tail[pos : pos + 4], "big")
        for pos in range(0, len(tail) - 3, 4)
    ]
    return {"tail_len": tail_len, "tail_start": start, "tail_hex": _compact_hex(tail), "tail_u32": u32}


def _shape_key(layout: dict[str, int], child_len: int) -> str:
    tail_len = min(8, int(layout.get("body_len") or 0)) if int(layout.get("inner_type") or 0) in TAIL_BLOCKED_TYPES else 0
    parts = [
        _fmt_hex(layout.get("report_code"), 8),
        _fmt_hex(layout.get("inner_type"), 4),
        _fmt_hex(layout.get("selector0"), 8),
        _fmt_hex(layout.get("selector1"), 8),
        _fmt_hex(layout.get("inner_field"), 8),
        f"len{int(child_len)}",
        f"body{int(layout.get('body_len') or 0)}",
        f"tail{tail_len}",
    ]
    return ":".join(parts)


def _printable_runs(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    start: int | None = None
    buf: list[int] = []
    for idx, byte in enumerate(data):
        if 32 <= byte < 127:
            if start is None:
                start = idx
            buf.append(byte)
            continue
        if start is not None and len(buf) >= min_len:
            out.append((start, bytes(buf).decode("ascii", errors="replace")))
        start = None
        buf = []
    if start is not None and len(buf) >= min_len:
        out.append((start, bytes(buf).decode("ascii", errors="replace")))
    return out


def _is_short_cycle(text: str, max_unit: int = 3) -> bool:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 6:
        return False
    for unit in range(1, max_unit + 1):
        if len(compact) < unit * 3 or len(compact) % unit:
            continue
        pattern = compact[:unit]
        if pattern and pattern * (len(compact) // unit) == compact:
            return True
    return False


def _longest_run_ratio(text: str) -> float:
    compact = re.sub(r"\s+", "", text)
    if not compact:
        return 0.0
    longest = 1
    current = 1
    prev = compact[0]
    for ch in compact[1:]:
        if ch == prev:
            current += 1
        else:
            current = 1
            prev = ch
        longest = max(longest, current)
    return longest / len(compact)


def _text_preview_kind(record: bytes, layout: dict[str, int], tail: dict[str, Any]) -> tuple[str, str]:
    body_start = int(layout.get("body_start") or 0)
    record_end = int(layout.get("record_end") or len(record))
    tail_start = int(tail.get("tail_start") or record_end)
    scan_end = min(record_end, tail_start)
    runs = _printable_runs(record[body_start:scan_end], 4)
    if not runs:
        return "opaque", ""
    _off, text = max(runs, key=lambda item: len(item[1]))
    compact = re.sub(r"\s+", "", text)
    unique = len(set(compact))
    has_separator = bool(re.search(r"[/.:_\- +]", text))
    has_alpha_digit = bool(re.search(r"[A-Za-z]", text) and re.search(r"\d", text))
    low_noise = (
        len(compact) >= 6
        and (
            unique < 4
            or _longest_run_ratio(text) > 0.60
            or _is_short_cycle(text)
            or (sum(1 for ch in compact if ch in "<=>$") / max(1, len(compact))) > 0.35
        )
    )
    if low_noise:
        return "xor_noise", text[:80]
    if STRONG_TEXT_TOKEN_RE.search(text):
        return "value", text[:120]
    if len(compact) >= 6 and unique >= 4 and (has_separator or has_alpha_digit):
        return "value", text[:120]
    if len(compact) >= 6 and unique >= 4:
        return "text_candidate", text[:120]
    return "opaque", text[:80]


def _policy_for_leaf(layout: dict[str, int], preview_kind: str) -> tuple[str, str, str, str]:
    inner_type = int(layout.get("inner_type") or 0)
    if inner_type in TAIL_BLOCKED_TYPES:
        return ("candidate", "blocked", "tail_policy_unknown_blocked; exact_writer_missing", "template_bucket_only / no_wire_drop")
    if inner_type in REGION_PATH_TYPES:
        return ("strong_candidate", "python_fallback", "region_path_profile_candidate; exact_leaf_writer_missing", "template_bucket_only / no_wire_drop")
    if inner_type in STRING_CANDIDATE_TYPES:
        return ("candidate", "python_fallback", "string_slot_candidate_same_length_only; exact_writer_missing", "template_bucket_only / no_wire_drop")
    if preview_kind in {"value", "text_candidate"}:
        return ("candidate", "observe_only", "fixed_layout_classifier_only; exact_writer_missing", "no_wire_drop")
    return ("blocked", "blocked", "opaque_body; exact_writer_missing", "template_bucket_only / no_wire_drop")


def _sibling_0112_context(children: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for child in children:
        report_code = child.get("report_code")
        if not isinstance(report_code, int) or ((report_code >> 16) & 0xFFFF) != 0x0112:
            continue
        runs = _printable_runs(child["record"], 4)
        text = " | ".join(run for _off, run in runs[:3])
        values.append(f"{_fmt_hex(report_code, 8)}:{text[:120] if text else _compact_hex(child['record'], 24)}")
    return values


def _parse_children_at(data: bytes, start_offset: int, max_children: int = 256) -> tuple[list[dict[str, Any]], int]:
    children: list[dict[str, Any]] = []
    offset = start_offset
    for index in range(max_children):
        if offset + 4 > len(data):
            break
        child_len = _read_le32(data, offset)
        endian = "le"
        if child_len is None or child_len <= 0 or offset + 4 + child_len > len(data):
            child_len = _read_be32(data, offset)
            endian = "be"
        if child_len is None or child_len <= 0 or offset + 4 + child_len > len(data):
            break
        record = data[offset + 4 : offset + 4 + child_len]
        report = _detect_tss_report(record)
        if not report:
            break
        report_code = int(report["value"])
        if not _is_likely_tss_report(report_code):
            break
        children.append(
            {
                "index": index,
                "offset": offset,
                "len": int(child_len),
                "length_endian": endian,
                "record": record,
                "report": report,
                "report_code": report_code,
            }
        )
        offset += 4 + int(child_len)
    return children, offset


def _parse_parent_children(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = _detect_tss_report(data)
    if not root or int(root["value"]) != 0x010A001B:
        return [], {}
    declared_count = _read_le32(data, 20)
    children: list[dict[str, Any]] = []
    end_offset = 24
    layout = "count-u32"
    if declared_count is not None and 0 <= declared_count <= 256:
        children, end_offset = _parse_children_at(data, 24, declared_count)
        if len(children) != declared_count:
            layout = "count-u32-partial"
    if not children:
        compact_count = data[20] if len(data) > 20 else 0
        if 0 < compact_count <= 256:
            compact_children, compact_end = _parse_children_at(data, 21, compact_count)
            if compact_children:
                children = compact_children
                end_offset = compact_end
                declared_count = compact_count
                layout = "compact-count-u8"
    if not children:
        children, end_offset = _parse_children_at(data, 16)
        layout = "legacy-no-count" if children else layout
    tail = data[end_offset:]
    return children, {
        "root": root,
        "declared_count": int(declared_count or 0),
        "parsed_count": len(children),
        "layout": layout,
        "tail_hex": _compact_hex(tail, 16),
        "tail_len": len(tail),
    }


def _event_hex(event: dict[str, Any], source: str) -> str:
    if source == "display":
        return str(event.get("display") or event.get("raw") or "")
    if source == "raw":
        return str(event.get("raw") or event.get("display") or "")
    if source == "full":
        return str(event.get("full") or event.get("raw") or event.get("display") or "")
    if source == "before":
        return str(event.get("before") or "")
    return str(event.get(source) or "")


def _report_family(report_code: int) -> tuple[str, int | None]:
    if int(report_code) & 0xFFFFFF00 == 0x01122300:
        return "0x011223xx", int(report_code) & 0xFF
    return _fmt_hex(report_code, 8), None


def _report_role(report_code: int, direction: int) -> tuple[str, str]:
    if report_code == 0x010A001B:
        return "父容器", "confirmed"
    if report_code & 0xFFFFFF00 == 0x01122300:
        return "动态 metadata event family；低字节仅为 subtype", "confirmed"
    if report_code == 0x0102000A:
        return "typed leaf shell；含义由完整 shape 判定", "confirmed"
    if report_code == 0x010A0011:
        return "配对/保护上下文（观察）", "observed"
    if report_code in {0x010A0010, 0x010A0024, 0x010A0027, 0x010A0044, 0x010A0057}:
        return ("响应反馈（按字段与前序请求解释）" if direction else "请求上下文"), "observed"
    return "目前不能证明含义", "unknown"


def _deep_report(events: list[dict[str, Any]], *, source: str) -> dict[str, Any]:
    reports: dict[str, dict[str, Any]] = {}
    subtype_counts: Counter[str] = Counter()
    phase_counts: Counter[str] = Counter()
    mirror_actions: Counter[str] = Counter()
    mirror_reasons: Counter[str] = Counter()
    consistency_values: list[float] = []
    source_ages: list[int] = []
    exact_shape_candidates = 0
    exact_shape_matches = 0
    opaque_nodes = 0
    opaque_passthrough = 0
    request_count = 0
    response_count = 0
    timeline: list[tuple[int, int, str]] = []

    def add_report(report_code: int, record: bytes, event: dict[str, Any], *, child_index: int | None) -> None:
        direction = int(event.get("dir") or 0)
        family, subtype = _report_family(report_code)
        role, confidence = _report_role(report_code, direction)
        key = _fmt_hex(report_code, 8)
        item = reports.setdefault(
            key,
            {
                "report_code": key,
                "family": family,
                "dynamic_subtype": subtype,
                "counts": {"request": 0, "response": 0},
                "roles": Counter(),
                "confidence": confidence,
                "shapes": Counter(),
                "fields": defaultdict(Counter),
                "correlations": Counter(),
                "samples": [],
                "meaning": role,
            },
        )
        item["counts"]["request" if direction == 0 else "response"] += 1
        item["roles"][role] += 1
        if subtype is not None:
            subtype_counts[f"0x{subtype:02x}"] += 1
        report = _detect_tss_report(record)
        if report_code == 0x0102000A and report:
            layout = _read_0102000a_layout(record, report)
            if layout:
                item["shapes"][_shape_key(layout, len(record))] += 1
        for field_name, regex in (
            ("cs", re.compile(rb"cs:([^,;\x00\r\n]+)")),
            ("ob", re.compile(rb"ob:([^;\x00\r\n]+)")),
            ("state", re.compile(rb"state:([^,;\x00\r\n]+)")),
            ("r", re.compile(rb",r:([^,;\x00\r\n]+)")),
            ("p", re.compile(rb",p:([^;\x00\r\n]+)")),
        ):
            match = regex.search(record)
            if match:
                item["fields"][field_name][match.group(1).decode("ascii", "replace")[:160]] += 1
        if report_code in {0x010A0010, 0x010A0024, 0x010A0027, 0x010A0044, 0x010A0057} and len(record) >= 0x16:
            for field_name, offset in (("field_a", 0x0A), ("field_b", 0x0E), ("field_c", 0x12)):
                item["fields"][field_name][_fmt_hex(_read_be32(record, offset), 8)] += 1
        if direction != 0:
            analysis = event.get("analysis") if isinstance(event.get("analysis"), dict) else {}
            correlation = analysis.get("response_correlation") if isinstance(analysis.get("response_correlation"), dict) else {}
            correlation_key = " <- ".join(
                value
                for value in (
                    str(correlation.get("request_report_code") or "unknown-request"),
                    str(correlation.get("status") or "unresolved"),
                )
                if value
            )
            item["correlations"][correlation_key] += 1
        if len(item["samples"]) < 5:
            item["samples"].append(
                {
                    "seq": event.get("seq"),
                    "ts": event.get("ts"),
                    "direction": "request" if direction == 0 else "response",
                    "child_index": child_index,
                    "record_len": len(record),
                    "summary": str(event.get("summary") or "")[:180],
                }
            )

    ordered = sorted(events, key=lambda event: (int(event.get("ts") or 0), int(event.get("seq") or 0)))
    for event in ordered:
        direction = int(event.get("dir") or 0)
        if direction == 0:
            request_count += 1
        else:
            response_count += 1
        payload = _hex_to_bytes(_event_hex(event, "display" if source == "display+before" else source))
        report = _detect_tss_report(payload)
        report_key = ""
        if report:
            report_code = int(report["value"])
            report_key = _fmt_hex(report_code, 8)
            add_report(report_code, payload, event, child_index=None)
            if report_code == 0x010A001B:
                children, _parent = _parse_parent_children(payload)
                for child in children:
                    add_report(int(child["report_code"]), child["record"], event, child_index=int(child["index"]))
        timeline.append((int(event.get("ts") or 0), direction, report_key))

        analysis = event.get("analysis") if isinstance(event.get("analysis"), dict) else {}
        phase_counts[str(analysis.get("state_phase") or "unknown")] += 1
        mirror_actions[str(analysis.get("action") or "none")] += 1
        mirror_reasons[str(analysis.get("reason") or "none")] += 1
        try:
            consistency_values.append(float(analysis["consistency"]))
        except (KeyError, TypeError, ValueError):
            pass
        try:
            source_ages.append(int(analysis["source_age_ms"]))
        except (KeyError, TypeError, ValueError):
            pass
        for action in analysis.get("actions") if isinstance(analysis.get("actions"), list) else []:
            if not isinstance(action, dict):
                continue
            reason = str(action.get("reason") or "")
            child_action = str(action.get("action") or "")
            if reason in {"exact_shape_mismatch", "ok"} or child_action == "candidate":
                exact_shape_candidates += 1
                if child_action == "candidate" and reason == "ok":
                    exact_shape_matches += 1
            if reason in {"opaque_or_non_csob_target_owned", "protected_or_unknown_target_owned"}:
                opaque_nodes += 1
                if child_action == "passthrough":
                    opaque_passthrough += 1

    bursts: Counter[str] = Counter()
    burst_max: Counter[str] = Counter()
    for index, (ts_ms, direction, _report_key) in enumerate(timeline):
        if direction != 0:
            continue
        local: Counter[str] = Counter()
        for response_ts, response_direction, response_report in timeline[index + 1 :]:
            if response_ts - ts_ms > 2000 or response_direction == 0:
                break
            if response_report:
                local[response_report] += 1
        for report_key, count in local.items():
            burst_max[report_key] = max(burst_max[report_key], count)
            if count > 3:
                bursts[report_key] += 1

    report_rows = []
    for key, item in sorted(
        reports.items(),
        key=lambda pair: (-(pair[1]["counts"]["request"] + pair[1]["counts"]["response"]), pair[0]),
    ):
        report_rows.append(
            {
                **{name: value for name, value in item.items() if name not in {"roles", "shapes", "fields", "correlations"}},
                "observations": int(item["counts"]["request"]) + int(item["counts"]["response"]),
                "roles": dict(item["roles"].most_common()),
                "shapes": dict(item["shapes"].most_common()),
                "fields": {name: dict(values.most_common(8)) for name, values in item["fields"].items()},
                "correlations": dict(item["correlations"].most_common(8)),
            }
        )
    unknown = [item["report_code"] for item in report_rows if item.get("confidence") == "unknown"]
    ratio = response_count / request_count if request_count else None
    return {
        "schema": "tersafe.semantic.v1",
        "reports": report_rows,
        "dynamic_011223_subtypes": dict(subtype_counts.most_common()),
        "traffic": {
            "requests": request_count,
            "responses": response_count,
            "response_request_ratio": ratio,
        },
        "response_bursts": {
            "max_per_request_2s": dict(burst_max.most_common()),
            "requests_over_3": dict(bursts.most_common()),
        },
        "mirror": {
            "state_phases": dict(phase_counts.most_common()),
            "actions": dict(mirror_actions.most_common()),
            "reasons": dict(mirror_reasons.most_common()),
            "average_consistency": (sum(consistency_values) / len(consistency_values)) if consistency_values else None,
            "max_source_age_ms": max(source_ages) if source_ages else None,
            "exact_shape_candidates": exact_shape_candidates,
            "exact_shape_matches": exact_shape_matches,
            "exact_shape_hit_rate": (
                exact_shape_matches / exact_shape_candidates if exact_shape_candidates else None
            ),
            "opaque_nodes": opaque_nodes,
            "opaque_passthrough": opaque_passthrough,
            "opaque_passthrough_rate": (opaque_passthrough / opaque_nodes if opaque_nodes else None),
        },
        "unknown_reports": unknown,
        "unknown_note": "未知项目前不能证明含义；保留原包与样例，不给出伪确定标签。",
    }


def _hex_to_bytes(text: str) -> bytes:
    compact = re.sub(r"[^0-9a-fA-F]", "", str(text or ""))
    if len(compact) % 2:
        compact = compact[:-1]
    return bytes.fromhex(compact) if compact else b""


@dataclass
class Bucket:
    shape_key: str
    report_code: int
    inner_type: int
    selector0: int
    selector1: int
    inner_field: int
    count: int = 0
    child_lens: Counter[int] = field(default_factory=Counter)
    body_lens: Counter[int] = field(default_factory=Counter)
    tail_lens: Counter[int] = field(default_factory=Counter)
    preview_kinds: Counter[str] = field(default_factory=Counter)
    pe_decisions: Counter[str] = field(default_factory=Counter)
    safety_classes: Counter[str] = field(default_factory=Counter)
    cleanup_hints: Counter[str] = field(default_factory=Counter)
    reasons: Counter[str] = field(default_factory=Counter)
    leaf_ids: Counter[str] = field(default_factory=Counter)
    tail_patterns: Counter[str] = field(default_factory=Counter)
    tail_u32: Counter[str] = field(default_factory=Counter)
    sibling_0112: Counter[str] = field(default_factory=Counter)
    samples: list[dict[str, Any]] = field(default_factory=list)

    def add(self, meta: dict[str, Any]) -> None:
        self.count += 1
        self.child_lens[int(meta["child_len"])] += 1
        self.body_lens[int(meta["body_len"])] += 1
        self.tail_lens[int(meta["tail_len"])] += 1
        self.preview_kinds[str(meta["preview_kind"])] += 1
        self.pe_decisions[str(meta["pe_decision"])] += 1
        self.safety_classes[str(meta["safety_class"])] += 1
        self.cleanup_hints[str(meta["cleanup_hint"])] += 1
        self.reasons[str(meta["reason"])] += 1
        self.leaf_ids[str(meta["leaf_id"])] += 1
        self.tail_patterns[str(meta["tail_hex"])] += 1
        self.tail_u32[str(meta["tail_u32"])] += 1
        for ctx in meta.get("sibling_0112") or []:
            self.sibling_0112[str(ctx)] += 1
        if len(self.samples) < 5:
            self.samples.append(meta["sample"])

    def as_dict(self) -> dict[str, Any]:
        return {
            "shape_key": self.shape_key,
            "count": self.count,
            "report_code": _fmt_hex(self.report_code, 8),
            "inner_type": _fmt_hex(self.inner_type, 4),
            "selector0": _fmt_hex(self.selector0, 8),
            "selector1": _fmt_hex(self.selector1, 8),
            "inner_field": _fmt_hex(self.inner_field, 8),
            "child_lens": dict(self.child_lens.most_common()),
            "body_lens": dict(self.body_lens.most_common()),
            "tail_lens": dict(self.tail_lens.most_common()),
            "preview_kinds": dict(self.preview_kinds.most_common()),
            "pe_decisions": dict(self.pe_decisions.most_common()),
            "safety_classes": dict(self.safety_classes.most_common()),
            "cleanup_hints": dict(self.cleanup_hints.most_common()),
            "reasons": dict(self.reasons.most_common()),
            "leaf_ids": dict(self.leaf_ids.most_common()),
            "tail_patterns": dict(self.tail_patterns.most_common()),
            "tail_u32": dict(self.tail_u32.most_common()),
            "sibling_0112": dict(self.sibling_0112.most_common(8)),
            "samples": self.samples,
        }


def summarize_archive(path: Path, *, source: str = "display") -> dict[str, Any]:
    flow, events = _read_flow_archive_bytes(path.read_bytes(), path.name)
    return summarize_events(flow, events, source=source, input_name=str(path))


def summarize_reportcode_matrix(path: Path) -> dict[str, Any]:
    matrix = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(matrix, list) or not all(isinstance(item, dict) for item in matrix):
        raise ValueError("reportcode matrix must be a JSON list")
    reports: list[dict[str, Any]] = []
    report_counts: Counter[str] = Counter()
    subtype_counts: Counter[str] = Counter()
    unknown: list[str] = []
    observation_total = 0
    for source_item in matrix:
        code_text = str(source_item.get("report_code") or "").strip().lower()
        try:
            report_code = int(code_text, 16)
        except ValueError:
            continue
        observations = int(source_item.get("observations") or 0)
        observation_total += observations
        key = _fmt_hex(report_code, 8)
        report_counts[key] += observations
        family, subtype = _report_family(report_code)
        role, role_confidence = _report_role(report_code, 0)
        observed_roles = source_item.get("role_distribution_unique")
        roles = {str(name): int(count or 0) for name, count in observed_roles.items()} if isinstance(observed_roles, dict) else {}
        if subtype is not None:
            subtype_counts[f"0x{subtype:02x}"] += observations
        if role_confidence == "unknown":
            unknown.append(key)
        reports.append(
            {
                "report_code": key,
                "family": family,
                "dynamic_subtype": subtype,
                "observations": observations,
                "counts": {"request": 0, "response": 0, "direction_unknown": observations},
                "roles": roles or {role: observations},
                "confidence": role_confidence,
                "source_confidence": str(source_item.get("confidence") or ""),
                "source_evidence": str(source_item.get("evidence") or ""),
                "shapes": {},
                "fields": {},
                "correlations": {},
                "samples": list(source_item.get("redacted_samples") or [])[:5],
                "meaning": role,
                "historical_observation": str(source_item.get("meaning") or ""),
            }
        )
    reports.sort(key=lambda item: (-int(item["observations"]), str(item["report_code"])))
    return {
        "input": str(path),
        "input_kind": "historical_reportcode_matrix",
        "source": "historical-matrix",
        "flow": {"account": "historical-baseline", "last_cid": "-"},
        "event_count": observation_total,
        "report_counts": dict(report_counts.most_common()),
        "inner_type_counts": {},
        "parent_roster": {"layout_counts": {}, "child_count_histogram": {}},
        "bucket_count": 0,
        "buckets": [],
        "deep": {
            "schema": "tersafe.semantic.v1",
            "reports": reports,
            "dynamic_011223_subtypes": dict(subtype_counts.most_common()),
            "traffic": {
                "requests": 0,
                "responses": 0,
                "direction_unknown": observation_total,
                "response_request_ratio": None,
            },
            "response_bursts": {"max_per_request_2s": {}, "requests_over_3": {}},
            "mirror": {
                "state_phases": {},
                "actions": {},
                "reasons": {},
                "average_consistency": None,
                "max_source_age_ms": None,
            },
            "connection_65010": {"observed": False, "status": "not_available_in_matrix"},
            "unknown_reports": unknown,
            "unknown_note": "历史矩阵没有方向/时序关联；未知项目前不能证明含义，不把旧标签升级为确定协议语义。",
        },
    }


def summarize_input(path: Path, *, source: str = "display") -> dict[str, Any]:
    if path.suffix.lower() == ".json":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            value = None
        if isinstance(value, list) and all(isinstance(item, dict) and "report_code" in item for item in value):
            return summarize_reportcode_matrix(path)
    return summarize_archive(path, source=source)


def summarize_events(
    flow: dict[str, Any],
    events: list[dict[str, Any]],
    *,
    source: str = "display",
    input_name: str = "live",
) -> dict[str, Any]:
    buckets: dict[str, Bucket] = {}
    parent_stats: Counter[str] = Counter()
    parent_child_counts: Counter[int] = Counter()
    report_counts: Counter[str] = Counter()
    inner_counts: Counter[str] = Counter()
    source_keys = ["display", "before"] if source == "display+before" else [source]

    for event in events:
        for source_key in source_keys:
            payload = _hex_to_bytes(_event_hex(event, source_key))
            if not payload:
                continue
            report = _detect_tss_report(payload)
            if not report:
                continue
            report_code = int(report["value"])
            report_counts[_fmt_hex(report_code, 8)] += 1
            if report_code == 0x010A001B:
                children, parent = _parse_parent_children(payload)
                if parent:
                    parent_stats[str(parent.get("layout") or "-")] += 1
                    parent_child_counts[int(parent.get("parsed_count") or 0)] += 1
                sibling_context = _sibling_0112_context(children)
                for child in children:
                    if child.get("report_code") != 0x0102000A:
                        continue
                    _add_leaf_bucket(
                        buckets,
                        child["record"],
                        child["report"],
                        child_len=int(child["len"]),
                        event=event,
                        source=source_key,
                        child_index=int(child["index"]),
                        parent_report=report_code,
                        parent_child_count=len(children),
                        sibling_0112=sibling_context,
                    )
            elif report_code == 0x0102000A:
                _add_leaf_bucket(
                    buckets,
                    payload,
                    report,
                    child_len=len(payload),
                    event=event,
                    source=source_key,
                    child_index=None,
                    parent_report=None,
                    parent_child_count=None,
                    sibling_0112=[],
                )

    for bucket in buckets.values():
        inner_counts[_fmt_hex(bucket.inner_type, 4)] += bucket.count

    bucket_list = sorted(buckets.values(), key=lambda item: (-item.count, item.shape_key))
    result = {
        "input": input_name,
        "source": source,
        "flow": flow,
        "event_count": len(events),
        "report_counts": dict(report_counts.most_common()),
        "inner_type_counts": dict(inner_counts.most_common()),
        "parent_roster": {
            "layout_counts": dict(parent_stats.most_common()),
            "child_count_histogram": dict(parent_child_counts.most_common()),
        },
        "bucket_count": len(bucket_list),
        "buckets": [bucket.as_dict() for bucket in bucket_list],
    }
    result["deep"] = _deep_report(events, source=source)
    source_port = str(flow.get("source_port") or "")
    cid = str(flow.get("last_cid") or flow.get("cid") or "")
    is_65010 = source_port == "65010" or ":65010" in cid
    result["deep"]["connection_65010"] = {
        "observed": is_65010,
        "status": str(flow.get("status") or "unknown") if is_65010 else "not_this_flow",
        "first_ts": flow.get("first_ts") if is_65010 else None,
        "last_ts": flow.get("last_ts") if is_65010 else None,
        "ended_ts": flow.get("ended_ts") if is_65010 else None,
        "event_count": len(events) if is_65010 else 0,
        "confidence": "transport-observed" if is_65010 else "unknown",
    }
    return result


def _add_leaf_bucket(
    buckets: dict[str, Bucket],
    record: bytes,
    report: dict[str, int],
    *,
    child_len: int,
    event: dict[str, Any],
    source: str,
    child_index: int | None,
    parent_report: int | None,
    parent_child_count: int | None,
    sibling_0112: list[str],
) -> None:
    layout = _read_0102000a_layout(record, report)
    if not layout:
        return
    tail = _tail_info(record, layout)
    preview_kind, preview_text = _text_preview_kind(record, layout, tail)
    safety_class, pe_decision, reason, cleanup_hint = _policy_for_leaf(layout, preview_kind)
    key = _shape_key(layout, child_len)
    if key not in buckets:
        buckets[key] = Bucket(
            shape_key=key,
            report_code=int(layout["report_code"]),
            inner_type=int(layout["inner_type"]),
            selector0=int(layout["selector0"]),
            selector1=int(layout["selector1"]),
            inner_field=int(layout["inner_field"]),
        )
    meta = {
        "child_len": child_len,
        "body_len": int(layout["body_len"]),
        "tail_len": int(tail["tail_len"]),
        "tail_hex": str(tail["tail_hex"]),
        "tail_u32": ",".join(_fmt_hex(value, 8) for value in tail["tail_u32"]) or "-",
        "preview_kind": preview_kind,
        "pe_decision": pe_decision,
        "safety_class": safety_class,
        "cleanup_hint": cleanup_hint,
        "reason": reason,
        "leaf_id": _fmt_hex(layout["leaf_id"], 8),
        "sibling_0112": sibling_0112,
        "sample": {
            "seq": event.get("seq"),
            "msg_idx": event.get("msg_idx"),
            "chunk_idx": event.get("chunk_idx"),
            "dir": event.get("dir"),
            "source": source,
            "event_summary": str(event.get("summary") or "")[:220],
            "child_index": child_index,
            "parent_report": _fmt_hex(parent_report, 8) if parent_report is not None else "-",
            "parent_child_count": parent_child_count,
            "child_len": child_len,
            "body_len": int(layout["body_len"]),
            "inner_type": _fmt_hex(layout["inner_type"], 4),
            "inner_field": _fmt_hex(layout["inner_field"], 8),
            "tail_hex": str(tail["tail_hex"]),
            "tail_u32": ",".join(_fmt_hex(value, 8) for value in tail["tail_u32"]) or "-",
            "preview_kind": preview_kind,
            "preview": preview_text,
            "pe_decision": pe_decision,
            "reason": reason,
        },
    }
    buckets[key].add(meta)


def _counter_text(value: dict[str, Any], limit: int = 4) -> str:
    if not value:
        return "-"
    items = list(value.items())[:limit]
    text = ", ".join(f"{key}={count}" for key, count in items)
    return f"{text}, ..." if len(value) > limit else text


def _dominant(mapping: dict[str, int]) -> str:
    if not mapping:
        return "-"
    return next(iter(mapping.keys()))


def _render_reportcode_matrix_markdown(summary: dict[str, Any]) -> str:
    deep = summary.get("deep") or {}
    reports = list(deep.get("reports") or [])
    lines = [
        "# TCPView Historical ReportCode Semantic Baseline",
        "",
        f"- input: `{summary.get('input')}`",
        f"- observations: `{summary.get('event_count', 0)}`",
        f"- reportCodes: `{len(reports)}`",
        "- evidence boundary: historical matrix contains aggregate child observations but no request/response direction or flow timing; those fields remain unknown.",
        "- interpretation policy: dynamic subtype and legacy labels are provenance, not fixed protocol semantics.",
        "",
        "## Every ReportCode",
        "",
        "| reportCode | observed | family/subtype | current safe interpretation | observed payload roles | source evidence | historical note |",
        "|---|---:|---|---|---|---|---|",
    ]
    for report in reports:
        subtype = report.get("dynamic_subtype")
        family = str(report.get("family") or "-")
        if subtype is not None:
            family += f" / subtype=0x{int(subtype):02x}"
        roles = _counter_text(report.get("roles") or {}, 6)
        evidence = " / ".join(
            value for value in (str(report.get("source_evidence") or ""), str(report.get("source_confidence") or "")) if value
        ) or "-"
        legacy_note = str(report.get("historical_observation") or "-").replace("|", "\\|")
        safe_meaning = str(report.get("meaning") or "目前不能证明含义").replace("|", "\\|")
        lines.append(
            f"| `{report.get('report_code')}` | {report.get('observations', 0)} | `{family}` | "
            f"{safe_meaning} | `{roles}` | `{evidence}` | {legacy_note} |"
        )
    lines.extend(
        [
            "",
            "## Dynamic 0x011223xx Subtypes",
            "",
            f"- subtype counts: `{_counter_text(deep.get('dynamic_011223_subtypes') or {}, 96)}`",
            "- low byte is only a dynamic subtype. Payload fields and full context decide the observed role.",
            "",
            "## Unresolved",
            "",
            f"- reportCodes: `{', '.join(deep.get('unknown_reports') or []) or '-'}`",
            f"- note: {deep.get('unknown_note') or '目前不能证明含义。'}",
            "",
        ]
    )
    return "\n".join(lines)


def render_markdown(summary: dict[str, Any], *, top: int = 20) -> str:
    if summary.get("input_kind") == "historical_reportcode_matrix":
        return _render_reportcode_matrix_markdown(summary)
    flow = summary.get("flow") or {}
    buckets = list(summary.get("buckets") or [])
    blocked = [b for b in buckets if "blocked" in (b.get("pe_decisions") or {})]
    tail_buckets = [b for b in buckets if b.get("inner_type") in {"0x8027", "0x8029"}]
    fff2 = [b for b in buckets if b.get("inner_type") == "0xfff2"]
    lines = [
        "# TCPView Shape Bucket Summary",
        "",
        f"- input: `{summary.get('input')}`",
        f"- source: `{summary.get('source')}`",
        f"- account: `{flow.get('account', '-')}`",
        f"- cid: `{flow.get('last_cid', '-')}`",
        f"- events: `{summary.get('event_count')}`",
        f"- shape_buckets: `{summary.get('bucket_count')}`",
        "- policy_note: cleanup only means template bucket / replay sample cleanup; no wire drop; no PE active mutation.",
        "",
        "## Report Counts",
        "",
        f"- reports: `{_counter_text(summary.get('report_counts') or {}, 12)}`",
        f"- inner_types: `{_counter_text(summary.get('inner_type_counts') or {}, 16)}`",
        f"- parent_roster_layouts: `{_counter_text((summary.get('parent_roster') or {}).get('layout_counts') or {}, 8)}`",
        f"- parent_child_count_histogram: `{_counter_text((summary.get('parent_roster') or {}).get('child_count_histogram') or {}, 12)}`",
        "",
        "## Top Buckets",
        "",
        "| count | inner_type | child_len | body_len | tail_len | pe_decision | preview | shape_key |",
        "|---:|---|---|---|---|---|---|---|",
    ]
    for bucket in buckets[:top]:
        lines.append(
            "| {count} | `{inner_type}` | `{child_lens}` | `{body_lens}` | `{tail_lens}` | `{pe}` | `{preview}` | `{shape}` |".format(
                count=bucket["count"],
                inner_type=bucket["inner_type"],
                child_lens=_counter_text(bucket.get("child_lens") or {}, 2),
                body_lens=_counter_text(bucket.get("body_lens") or {}, 2),
                tail_lens=_counter_text(bucket.get("tail_lens") or {}, 2),
                pe=_counter_text(bucket.get("pe_decisions") or {}, 3),
                preview=_counter_text(bucket.get("preview_kinds") or {}, 4),
                shape=bucket["shape_key"],
            )
        )
    lines.extend([
        "",
        "## Blocked Buckets",
        "",
        "| count | inner_type | tail | reason | cleanup_hint | samples |",
        "|---:|---|---|---|---|---|",
    ])
    for bucket in blocked[:top]:
        samples = ", ".join(
            f"seq={s.get('seq')}/msg={s.get('msg_idx')}/child={s.get('child_index')}"
            for s in bucket.get("samples", [])[:3]
        )
        lines.append(
            f"| {bucket['count']} | `{bucket['inner_type']}` | `{_counter_text(bucket.get('tail_patterns') or {}, 3)}` | "
            f"`{_counter_text(bucket.get('reasons') or {}, 2)}` | `{_counter_text(bucket.get('cleanup_hints') or {}, 2)}` | `{samples}` |"
        )
    lines.extend([
        "",
        "## 0x8027 / 0x8029 Tail Patterns",
        "",
        "| inner_type | count | tail_len | tail_hex | tail_u32 | shape_key |",
        "|---|---:|---|---|---|---|",
    ])
    for bucket in tail_buckets[:top]:
        lines.append(
            f"| `{bucket['inner_type']}` | {bucket['count']} | `{_counter_text(bucket.get('tail_lens') or {}, 2)}` | "
            f"`{_counter_text(bucket.get('tail_patterns') or {}, 4)}` | `{_counter_text(bucket.get('tail_u32') or {}, 4)}` | `{bucket['shape_key']}` |"
        )
    lines.extend([
        "",
        "## 0xFFF2 Region/Path Clusters",
        "",
        "| count | child_len | body_len | leaf_id/reserved | sibling_0112_context | shape_key |",
        "|---:|---|---|---|---|---|",
    ])
    for bucket in fff2[:top]:
        lines.append(
            f"| {bucket['count']} | `{_counter_text(bucket.get('child_lens') or {}, 3)}` | "
            f"`{_counter_text(bucket.get('body_lens') or {}, 3)}` | `{_counter_text(bucket.get('leaf_ids') or {}, 3)}` | "
            f"`{_counter_text(bucket.get('sibling_0112') or {}, 2)}` | `{bucket['shape_key']}` |"
        )
    lines.extend([
        "",
        "## Sample Children",
        "",
    ])
    for bucket in buckets[: min(top, 12)]:
        lines.append(f"### `{bucket['shape_key']}`")
        for sample in bucket.get("samples", [])[:5]:
            lines.append(
                "- seq={seq} msg={msg_idx} chunk={chunk_idx} child={child_index} parent={parent_report} "
                "len={child_len} body={body_len} inner={inner_type} tail={tail_hex} u32={tail_u32} "
                "pe={pe_decision} preview={preview_kind} reason={reason}".format(**sample)
            )
        lines.append("")
    deep = summary.get("deep") or {}
    traffic = deep.get("traffic") or {}
    mirror = deep.get("mirror") or {}
    bursts = deep.get("response_bursts") or {}
    connection_65010 = deep.get("connection_65010") or {}
    lines.extend(
        [
            "## Semantic Deep Report",
            "",
            "本节按方向、完整 shape、字段证据和前序请求解释 reportCode；动态后缀与偶然 hex 不作为固定语义。",
            "",
            f"- requests: `{traffic.get('requests', 0)}`",
            f"- responses: `{traffic.get('responses', 0)}`",
            f"- response/request ratio: `{traffic.get('response_request_ratio')}`",
            f"- state phases: `{_counter_text(mirror.get('state_phases') or {}, 8)}`",
            f"- mirror actions: `{_counter_text(mirror.get('actions') or {}, 8)}`",
            f"- average consistency: `{mirror.get('average_consistency')}`",
            f"- max source age ms: `{mirror.get('max_source_age_ms')}`",
            f"- exact shape hit rate: `{mirror.get('exact_shape_hit_rate')}` ({mirror.get('exact_shape_matches', 0)}/{mirror.get('exact_shape_candidates', 0)})",
            f"- opaque pass-through rate: `{mirror.get('opaque_passthrough_rate')}` ({mirror.get('opaque_passthrough', 0)}/{mirror.get('opaque_nodes', 0)})",
            f"- response burst max/request/2s: `{_counter_text(bursts.get('max_per_request_2s') or {}, 12)}`",
            f"- burst requests over 3: `{_counter_text(bursts.get('requests_over_3') or {}, 12)}`",
            f"- 65010 connection: `observed={connection_65010.get('observed', False)} status={connection_65010.get('status', 'unknown')} first={connection_65010.get('first_ts')} last={connection_65010.get('last_ts')}`",
            "",
            "### Every ReportCode",
            "",
            "| reportCode | family/subtype | observed | request | response | observed role | confidence | shapes | fields | preceding request |",
            "|---|---|---:|---:|---:|---|---|---|---|---|",
        ]
    )
    for report in deep.get("reports") or []:
        subtype = report.get("dynamic_subtype")
        family = str(report.get("family") or "-")
        if subtype is not None:
            family += f" / subtype=0x{int(subtype):02x}"
        counts = report.get("counts") or {}
        fields = report.get("fields") or {}
        field_text = "; ".join(
            f"{name}:{_counter_text(values, 2)}" for name, values in fields.items()
        ) or "-"
        lines.append(
            f"| `{report.get('report_code')}` | `{family}` | {report.get('observations', int(counts.get('request', 0)) + int(counts.get('response', 0)))} | "
            f"{counts.get('request', 0)} | {counts.get('response', 0)} | "
            f"{report.get('meaning', '目前不能证明含义')} | `{report.get('confidence', 'unknown')}` | "
            f"`{_counter_text(report.get('shapes') or {}, 2)}` | `{field_text}` | "
            f"`{_counter_text(report.get('correlations') or {}, 3)}` |"
        )
    lines.extend(
        [
            "",
            "### Dynamic 0x011223xx Subtypes",
            "",
            f"- subtype counts: `{_counter_text(deep.get('dynamic_011223_subtypes') or {}, 32)}`",
            "- 低字节只表示动态 subtype；具体含义必须由 payload 字段和上下文判定。",
            "",
            "### Unresolved",
            "",
            f"- reportCodes: `{', '.join(deep.get('unknown_reports') or []) or '-'}`",
            f"- note: {deep.get('unknown_note') or '目前不能证明含义。'}",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _write_outputs(summary: dict[str, Any], markdown: str | None, json_path: str | None, top: int) -> None:
    if markdown:
        Path(markdown).write_text(render_markdown(summary, top=top), encoding="utf-8")
    if json_path:
        Path(json_path).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a Tersafe semantic deep report and 0102000A shape buckets from a tcpvflow archive."
    )
    parser.add_argument(
        "archive",
        type=Path,
        help=".tcpvflow.jsonl(.gz) archive or historical reportcode_matrix.json",
    )
    parser.add_argument("--source", default="display", choices=["display", "raw", "full", "before", "display+before"])
    parser.add_argument("--markdown", help="Write Markdown summary to this path")
    parser.add_argument("--json", dest="json_path", help="Write JSON summary to this path")
    parser.add_argument("--top", type=int, default=20, help="Top bucket rows to include in Markdown")
    args = parser.parse_args(list(argv) if argv is not None else None)

    summary = summarize_input(args.archive, source=args.source)
    _write_outputs(summary, args.markdown, args.json_path, args.top)
    if not args.markdown and not args.json_path:
        print(render_markdown(summary, top=args.top))
    else:
        print(
            json.dumps(
                {
                    "archive": str(args.archive),
                    "source": args.source,
                    "events": summary["event_count"],
                    "shape_buckets": summary["bucket_count"],
                    "markdown": args.markdown or "",
                    "json": args.json_path or "",
                },
                ensure_ascii=False,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
