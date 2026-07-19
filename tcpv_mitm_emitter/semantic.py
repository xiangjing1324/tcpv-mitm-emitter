from __future__ import annotations

import base64
import copy
import re
from typing import Any

from .shape_summary import (
    _detect_tss_report,
    _fmt_hex,
    _payload_semantic_profile,
    _parse_parent_children,
    _parse_typed_body_structure,
    _read_0102000a_layout,
)


SCHEMA = "tersafe.semantic.v1"
SEMANTIC_REVISION = 4
_CS_RE = re.compile(rb"cs:([^,;\x00\r\n]+)")
_OB_RE = re.compile(rb"ob:([^;\x00\r\n]+)")
_STATE_RE = re.compile(rb"state:([^,;\x00\r\n]+)")
_R_RE = re.compile(rb",r:([^,;\x00\r\n]+)")
_P_RE = re.compile(rb",p:([^;\x00\r\n]+)")
_PRINTABLE_RE = re.compile(rb"[ -~]{4,}")

_KNOWN_TYPED_TIMESTAMPS = (
    (68, 0x100A, 0x200E0002, 0x34560001, 0x40, "dfm-current"),
    (80, 0x1001, 0x200E0002, 0x34560001, 0x20, "dfm-session"),
    (68, 0x100A, 0x200D0002, 0x34560001, 0x40, "dfm-current-200d"),
    (80, 0x1001, 0x200D0002, 0x34560001, 0x20, "dfm-session-200d"),
    (68, 0x100A, 0x200F0002, 0x34560001, 0x40, "dfm-current-200f"),
    (80, 0x1001, 0x200F0002, 0x34560001, 0x20, "dfm-session-200f"),
    (68, 0x810B, 0x21650002, 0x34560001, 0x40, "uagame-current"),
    (160, 0x8023, 0x21650002, 0x34560001, 0x58, "uagame-current-8023"),
    (80, 0x8102, 0x21650002, 0x34560001, 0x20, "uagame-session"),
)


def report_family(report_code: int | None) -> tuple[str, int | None]:
    value = int(report_code or 0)
    if value & 0xFFFFFF00 == 0x01122300:
        return "0x011223xx", value & 0xFF
    return _fmt_hex(value, 8), None


def report_role(report_code: int | None, *, direction: int) -> tuple[str, str]:
    value = int(report_code or 0)
    if value == 0x010A001B:
        return "parent_container", "confirmed"
    if value & 0xFFFFFF00 == 0x01122300:
        return "dynamic_metadata_event", "confirmed"
    if value == 0x0102000A:
        return "typed_leaf_shell", "confirmed"
    if value == 0x010A0011:
        return "pairing_or_protection_context_observed", "observed"
    if value in {0x010A0010, 0x010A0024, 0x010A0027, 0x010A0044, 0x010A0057}:
        return ("response_feedback" if int(direction) else "request_context"), "observed"
    return "unknown", "unknown"


def _field(record: bytes, regex: re.Pattern[bytes], name: str) -> dict[str, Any] | None:
    match = regex.search(record)
    if match is None:
        return None
    raw = match.group(1)
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return {
        "name": name,
        "value": value,
        "offset": match.start(1),
        "length": len(raw),
        "source": "schema:csob-ascii",
        "confidence": "high",
    }


def _printable_ranges(record: bytes) -> list[tuple[int, int]]:
    return [(match.start(), match.end()) for match in _PRINTABLE_RE.finditer(record)]


def _inside_range(offset: int, width: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= offset and offset + width <= end for start, end in ranges)


def _crosses_range_boundary(offset: int, width: int, ranges: list[tuple[int, int]]) -> bool:
    end_offset = offset + width
    return any(
        max(offset, start) < min(end_offset, end)
        and not (start <= offset and end_offset <= end)
        for start, end in ranges
    )


def _timestamps(record: bytes, layout: dict[str, int] | None) -> dict[str, list[dict[str, Any]]]:
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    accepted_offsets: set[int] = set()

    ob_match = _OB_RE.search(record)
    if ob_match is not None:
        parts = ob_match.group(1).split(b"/")
        cursor = ob_match.start(1)
        for index, part in enumerate(parts):
            if index in {5, 6, 7} and part.isdigit() and len(part) in {10, 13}:
                scale = 1000 if len(part) == 13 else 1
                seconds = int(part) / scale
                if 946684800 <= seconds <= 4102444800:
                    accepted.append(
                        {
                            "field": f"ob:T{index - 4}",
                            "offset": cursor,
                            "length": len(part),
                            "value": int(part),
                            "unit": "ms" if scale == 1000 else "s",
                            "source": "schema:ob-triplet",
                            "confidence": "high",
                        }
                    )
            cursor += len(part) + 1

    if layout:
        shape = (
            len(record),
            int(layout.get("inner_type") or 0),
            int(layout.get("selector0") or 0),
            int(layout.get("selector1") or 0),
        )
        for record_len, inner_type, selector0, selector1, schema_offset, label in _KNOWN_TYPED_TIMESTAMPS:
            offset = int(layout.get("shift") or 0) + schema_offset
            if shape != (record_len, inner_type, selector0, selector1) or offset < 0 or offset + 4 > len(record):
                continue
            value = int.from_bytes(record[offset : offset + 4], "big")
            if 946684800 <= value <= 4102444800:
                accepted_offsets.add(offset)
                accepted.append(
                    {
                        "field": label,
                        "offset": offset,
                        "length": 4,
                        "value": value,
                        "unit": "s",
                        "source": "schema:typed-leaf-shape",
                        "confidence": "high",
                    }
                )
        if (
            int(layout.get("inner_type") or 0) == 0x8418
            and int(layout.get("selector0") or 0) == 0x21650002
            and int(layout.get("selector1") or 0) == 0x34560001
        ):
            offset = len(record) - 0x14
            if offset >= 0 and offset + 4 <= len(record):
                value = int.from_bytes(record[offset : offset + 4], "big")
                if 946684800 <= value <= 4102444800:
                    accepted_offsets.add(offset)
                    accepted.append(
                        {
                            "field": "uagame-tail-8418",
                            "offset": offset,
                            "length": 4,
                            "value": value,
                            "unit": "s",
                            "source": "schema:typed-leaf-shape",
                            "confidence": "high",
                        }
                    )

    printable = _printable_ranges(record)
    schema_ranges = list(printable)
    for regex in (_CS_RE, _OB_RE, _STATE_RE, _R_RE, _P_RE):
        schema_ranges.extend(match.span(1) for match in regex.finditer(record))
    for offset in range(0, len(record) - 3, 4):
        if offset in accepted_offsets:
            continue
        value = int.from_bytes(record[offset : offset + 4], "big")
        if not 946684800 <= value <= 4102444800:
            continue
        if _crosses_range_boundary(offset, 4, schema_ranges):
            reason = "candidate crosses a schema/string field boundary"
        elif _inside_range(offset, 4, printable):
            reason = "candidate falls inside ASCII/hash/string slot"
        else:
            reason = "ordinary BE32 has no schema-proven timestamp role"
        rejected.append(
            {
                "field": "be32_candidate",
                "offset": offset,
                "length": 4,
                "value": value,
                "source": "generic-scan",
                "confidence": "rejected",
                "reason": reason,
            }
        )
    return {"accepted": accepted, "rejected": rejected}


def _record_analysis(record: bytes, *, direction: int, index: int | None = None) -> dict[str, Any]:
    report = _detect_tss_report(record)
    report_code = int(report["value"]) if report else 0
    family, subtype = report_family(report_code)
    role, role_confidence = report_role(report_code, direction=direction)
    semantic_profile = _payload_semantic_profile(report_code, record)
    semantic_role = str(semantic_profile.get("role") or "unresolved_payload")
    semantic_role_confidence = str(semantic_profile.get("confidence") or "unknown")
    semantic_role_evidence = tuple(semantic_profile.get("evidence") or ())
    layout = _read_0102000a_layout(record, report) if report and report_code == 0x0102000A else None
    body_layout = _parse_typed_body_structure(record, layout)
    fields = []
    for name, regex in (("cs", _CS_RE), ("ob", _OB_RE), ("state", _STATE_RE), ("r", _R_RE), ("p", _P_RE)):
        item = _field(record, regex, name)
        if item:
            fields.append(item)
    if report_code in {0x010A0010, 0x010A0024, 0x010A0027, 0x010A0044, 0x010A0057} and len(record) >= 0x16:
        for name, offset in (("field_a", 0x0A), ("field_b", 0x0E), ("field_c", 0x12)):
            fields.append(
                {
                    "name": name,
                    "value": _fmt_hex(int.from_bytes(record[offset : offset + 4], "big"), 8),
                    "offset": offset,
                    "length": 4,
                    "source": "observed:fixed-response-offset",
                    "confidence": "observed",
                }
            )
    shape = {
        "report_family": family,
        "inner_type": _fmt_hex(layout.get("inner_type"), 4) if layout else None,
        "selector0": _fmt_hex(layout.get("selector0"), 8) if layout else None,
        "selector1": _fmt_hex(layout.get("selector1"), 8) if layout else None,
        "inner_field": _fmt_hex(layout.get("inner_field"), 8) if layout else None,
        "record_len": len(record),
    }
    # Parent containers embed complete child records. Counting/scanning the
    # parent as one flat value duplicates every child timestamp and produces
    # misleading generic BE32 rejects. Child nodes remain authoritative.
    timestamp_analysis = (
        {"accepted": [], "rejected": []}
        if report_code == 0x010A001B
        else _timestamps(record, layout)
    )
    return {
        "index": index,
        "report_code": _fmt_hex(report_code, 8),
        "report_family": family,
        "dynamic_subtype": subtype,
        "role": role,
        "role_confidence": role_confidence,
        "semantic_role": semantic_role,
        "semantic_role_confidence": semantic_role_confidence,
        "semantic_role_evidence": list(semantic_role_evidence),
        "semantic_category": str(semantic_profile.get("category") or "unknown"),
        "semantic_label_zh": str(semantic_profile.get("label_zh") or "未解析记录"),
        "semantic_tier": str(semantic_profile.get("tier") or "unknown"),
        "semantic_exact_meaning": bool(semantic_profile.get("exact_meaning")),
        "leaf_id": _fmt_hex(int.from_bytes(record[10:14], "big"), 8) if len(record) >= 14 else None,
        "shape": shape,
        "body_layout": body_layout,
        "fields": fields,
        "timestamps": timestamp_analysis,
    }


def analyze_payload(
    payload: bytes,
    *,
    direction: int = 0,
    before_payload: bytes = b"",
    provided: dict[str, Any] | None = None,
) -> dict[str, Any]:
    raw = bytes(payload or b"")
    base = copy.deepcopy(provided) if isinstance(provided, dict) else {}
    base["schema"] = SCHEMA
    base["semantic_revision"] = SEMANTIC_REVISION
    packet = _record_analysis(raw, direction=direction)
    children, parent = _parse_parent_children(raw)
    packet["children"] = [
        _record_analysis(child["record"], direction=direction, index=int(child["index"]))
        for child in children
    ]
    if parent:
        packet["parent"] = {
            "layout": parent.get("layout"),
            "declared_count": parent.get("declared_count"),
            "parsed_count": parent.get("parsed_count"),
            "tail_len": parent.get("tail_len"),
        }
    provided_packet = base.get("packet") if isinstance(base.get("packet"), dict) else {}
    base["packet"] = _merge_packet_analysis(provided_packet, packet)
    base.setdefault("direction", "request" if int(direction) == 0 else "response")
    base.setdefault("state_phase", "unknown")
    base.setdefault("response_correlation", {"status": "unresolved", "reason": "requires flow timeline"})
    base.setdefault("source_compare", {})
    base.setdefault("actions", [])
    if before_payload:
        base.setdefault(
            "before",
            _record_analysis(bytes(before_payload), direction=direction),
        )
    return base


def _packet_quality(packet: dict[str, Any]) -> int:
    report_code = str(packet.get("report_code") or "").lower()
    score = 0
    if report_code and report_code not in {"0x00000000", "0x0", "-"}:
        score += 4
    role = str(packet.get("semantic_role") or "")
    if role and role not in {"unknown", "unresolved_payload"}:
        score += 3
    category = str(packet.get("semantic_category") or "")
    if category and category != "unknown":
        score += 2
    children = packet.get("children")
    if isinstance(children, list) and children:
        score += 4
    if isinstance(packet.get("fields"), list) and packet.get("fields"):
        score += 1
    return score


def _merge_packet_analysis(provided: dict[str, Any], computed: dict[str, Any]) -> dict[str, Any]:
    """Merge emitter-supplied semantics with the local decoded-record parser.

    Packet Engine may know the decrypted report while TCPView only receives an
    outer transport frame; the inverse also happens for old events.  Select
    the better packet as authoritative and fill missing children/shape fields
    from the other one instead of letting an unresolved stub mask useful data.
    """
    supplied = copy.deepcopy(provided) if isinstance(provided, dict) else {}
    local = copy.deepcopy(computed) if isinstance(computed, dict) else {}
    supplied_wins = _packet_quality(supplied) > _packet_quality(local)
    primary, secondary = (supplied, local) if supplied_wins else (local, supplied)
    merged = copy.deepcopy(secondary)
    merged.update(copy.deepcopy(primary))

    primary_shape = primary.get("shape") if isinstance(primary.get("shape"), dict) else {}
    secondary_shape = secondary.get("shape") if isinstance(secondary.get("shape"), dict) else {}
    merged_shape = copy.deepcopy(secondary_shape)
    merged_shape.update({key: value for key, value in primary_shape.items() if value not in {None, "", "-"}})
    if merged_shape:
        merged["shape"] = merged_shape

    primary_children = primary.get("children") if isinstance(primary.get("children"), list) else []
    secondary_children = secondary.get("children") if isinstance(secondary.get("children"), list) else []
    merged["children"] = copy.deepcopy(primary_children or secondary_children)
    return merged


def analysis_needs_upgrade(analysis: dict[str, Any] | None) -> bool:
    if not isinstance(analysis, dict):
        return True
    if analysis.get("schema") != SCHEMA:
        return True
    try:
        revision = int(analysis.get("semantic_revision") or 0)
    except (TypeError, ValueError):
        revision = 0
    packet = analysis.get("packet") if isinstance(analysis.get("packet"), dict) else {}
    return revision < SEMANTIC_REVISION or "semantic_category" not in packet


def analysis_from_event(event: dict[str, Any]) -> dict[str, Any]:
    def decode(name: str) -> bytes:
        value = str(event.get(name) or "")
        if not value:
            return b""
        try:
            return base64.b64decode(value)
        except Exception:
            return b""

    payload = decode("pay")
    before = decode("before_pay")
    provided = event.get("analysis") if isinstance(event.get("analysis"), dict) else None
    analysis = provided
    seen: set[bytes] = set()
    for candidate in (payload, before, decode("full_pay"), decode("raw_pay")):
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        analysis = analyze_payload(
            candidate,
            direction=int(event.get("dir") or 0),
            before_payload=before if candidate == payload else b"",
            provided=analysis,
        )
    if isinstance(analysis, dict):
        return analysis
    return analyze_payload(b"", direction=int(event.get("dir") or 0), provided=provided)


def correlate_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach conservative preceding-request/burst relationships in-place."""
    latest_request: dict[str, dict[str, Any]] = {}
    burst_counts: dict[tuple[str, str, str], int] = {}
    for event in sorted(events, key=lambda item: (int(item.get("ts") or 0), int(item.get("seq") or 0))):
        analysis = event.get("analysis") if isinstance(event.get("analysis"), dict) else {}
        event["analysis"] = analysis
        packet = analysis.get("packet") if isinstance(analysis.get("packet"), dict) else {}
        report_code = str(packet.get("report_code") or "")
        cid = str(event.get("cid") or "-")
        if int(event.get("dir") or 0) == 0:
            latest_request[cid] = event
            analysis["response_correlation"] = {
                "status": "request_anchor",
                "request_seq": int(event.get("seq") or 0),
                "request_report_code": report_code,
            }
            continue
        request = latest_request.get(cid)
        if request is None:
            analysis["response_correlation"] = {
                "status": "unmatched_response",
                "reason": "no preceding request in loaded timeline",
            }
            continue
        delta_ms = int(event.get("ts") or 0) - int(request.get("ts") or 0)
        request_analysis = request.get("analysis") if isinstance(request.get("analysis"), dict) else {}
        request_packet = request_analysis.get("packet") if isinstance(request_analysis.get("packet"), dict) else {}
        key = (cid, str(request.get("id") or request.get("seq") or ""), report_code)
        burst_counts[key] = burst_counts.get(key, 0) + 1
        analysis["response_correlation"] = {
            "status": "preceding_request_observed" if 0 <= delta_ms <= 2000 else "weak_time_association",
            "request_id": str(request.get("id") or ""),
            "request_seq": int(request.get("seq") or 0),
            "request_report_code": str(request_packet.get("report_code") or ""),
            "response_report_code": report_code,
            "delta_ms": delta_ms,
            "burst_index": burst_counts[key],
            "confidence": "observed" if 0 <= delta_ms <= 2000 else "low",
        }
    return events
