from __future__ import annotations

import argparse
import gzip
import json
import math
import re
import struct
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

DFM_TYPED_TIMESTAMP_SHAPES = {
    (68, 0x100A, 0x200E0002, 0x34560001): ("typed_timestamp_current", "telemetry.time.current", "当前采样时间", "confirmed"),
    (68, 0x100A, 0x200D0002, 0x34560001): ("typed_timestamp_current", "telemetry.time.current", "当前采样时间", "confirmed"),
    (68, 0x100A, 0x200F0002, 0x34560001): ("typed_timestamp_current", "telemetry.time.current", "当前采样时间", "confirmed"),
    (80, 0x1001, 0x200E0002, 0x34560001): ("typed_timestamp_session_baseline", "telemetry.time.session_baseline", "会话/缓存基准时间", "observed"),
    (80, 0x1001, 0x200D0002, 0x34560001): ("typed_timestamp_session_baseline", "telemetry.time.session_baseline", "会话/缓存基准时间", "observed"),
    (80, 0x1001, 0x200F0002, 0x34560001): ("typed_timestamp_session_baseline", "telemetry.time.session_baseline", "会话/缓存基准时间", "observed"),
}

_SEMANTIC_PROCESS_TOKENS = (
    "backboardd",
    "backboardservices",
    "springboard",
    "mediaserverd",
    "chronod",
    "duetexpertd",
    "thermalmonitord",
    "locationd",
    "logd",
    "com.apple",
    "coremotion",
    "corebrightness",
    "corefoundation",
)

_PUBGM_0112235B_RECORD_LEN = 0x010D
_PUBGM_0112235B_STATE_OFFSETS = (0xFE, 0x106, 0x10C)


def _pubgm_0112235b_device_account_tail_fields(record: bytes) -> list[dict[str, Any]]:
    """Expose the stable layout and observed tail variants without claiming writability."""
    data = bytes(record or b"")
    if len(data) != _PUBGM_0112235B_RECORD_LEN or data[6:10] != bytes.fromhex("0112235b"):
        return []
    kv = data[0x35:0x73]
    if re.fullmatch(
        rb"model:[^;\x00]+;ver:[^;\x00]+;role_id:[^;\x00]+;"
        rb"inc_id:\d+;obf_id:\d+\x00",
        kv,
    ) is None:
        return []
    if re.fullmatch(rb"[0-9A-Fa-f]{32}", data[0x7B:0x9B]) is None:
        return []
    if re.fullmatch(rb"\d{10}", data[0xA0:0xAA]) is None:
        return []

    state = tuple(data[offset] for offset in _PUBGM_0112235B_STATE_OFFSETS)
    if state == (0x01, 0x01, 0x01):
        state_class = "variant_01_01_01"
    elif state == (0x09, 0x09, 0x02):
        state_class = "variant_09_09_02"
    else:
        state_class = "unmapped"
    source = "observed:46-full-shape-samples"
    return [
        {
            "name": "identity_bundle_layout",
            "value": "kv62+opaque_hex32+account10",
            "offset": 0x35,
            "length": 0x75,
            "source": source,
            "confidence": "high",
        },
        {
            "name": "tail_state_triplet",
            "value": "/".join(f"{value:02x}" for value in state),
            "offset": 0xFE,
            "length": 3,
            "source": source,
            "confidence": "high",
            "non_contiguous_offsets": [f"0x{offset:x}" for offset in _PUBGM_0112235B_STATE_OFFSETS],
        },
        {
            "name": "tail_state_class",
            "value": state_class,
            "offset": 0xFE,
            "length": 3,
            "source": "observed:natural-client-variants;outer-270f-confounded",
            "confidence": "observed",
        },
        {
            "name": "tail_state_mutability",
            "value": "unproven_observe_only",
            "offset": 0xFE,
            "length": 3,
            "source": "causal-review:010a0024-response-attributable-to-outer-270f",
            "confidence": "high",
        },
    ]


def _semantic_profile(
    role: str,
    category: str,
    label_zh: str,
    tier: str,
    confidence: str,
    evidence: Iterable[str],
    *,
    exact_meaning: bool = False,
) -> dict[str, Any]:
    return {
        "role": role,
        "category": category,
        "label_zh": label_zh,
        "tier": tier,
        "confidence": confidence,
        "evidence": tuple(str(item) for item in evidence if item),
        "exact_meaning": bool(exact_meaning),
    }


def _typed_leaf_text_views(record: bytes, layout: dict[str, int]) -> tuple[str, str]:
    """Return raw and historically observed XOR-0xb6 text views.

    The XOR view is evidence for classification only. It is never used to
    rewrite the record and does not turn a family-level guess into an exact
    protocol meaning.
    """
    raw_text = bytes(record or b"").decode("ascii", errors="ignore")
    body_start = max(0, int(layout.get("body_start") or 0))
    record_end = min(len(record), int(layout.get("record_end") or len(record)))
    decoded = bytes((byte ^ 0xB6) for byte in record[body_start:record_end])
    xor_text = decoded.decode("ascii", errors="ignore")
    return raw_text, xor_text


def _payload_semantic_profile(report_code: int, record: bytes) -> dict[str, Any]:
    """Classify exact, observed and approximate semantics for one record.

    Approximate classifications deliberately stay broad.  They answer the
    operator's immediate question (metadata/device/state/probe/control) while
    retaining an explicit boundary around the still-unproven leaf meaning.
    """
    data = bytes(record or b"")
    lower = data.lower()

    if report_code == 0x010A001B:
        return _semantic_profile(
            "parent_container", "report.container", "批量上报父容器", "confirmed", "confirmed", ("report_code",), exact_meaning=True
        )
    if report_code == 0x010A0011:
        return _semantic_profile(
            "server_acknowledged_child_request", "control.acknowledged_child_request", "服务器确认型子请求（保活/握手候选）", "confirmed", "observed", ("paired_leaf_id", "010a0010_ack", "u8_ascii_label")
        )
    if report_code == 0x010A0036:
        label = "mrpcs 配置/资源同步标记" if b"mrpcs" in lower or b".data" in lower else "配置/资源同步标记"
        return _semantic_profile(
            "sync_file_marker", "control.resource_sync", label, "observed", "observed", ("report_code", "resource_name" if b".data" in lower else "historical_role")
        )
    if report_code == 0x010A0056:
        return _semantic_profile(
            "sync_file_save_request", "control.resource_sync", "同步文件保存请求", "observed", "observed", ("report_code", "historical_short_control")
        )
    if report_code == 0x010A0010:
        return _semantic_profile(
            "010a0011_ack_response", "response.ack", "010a0011 子请求回执（leaf_id 回显）", "confirmed", "observed", ("paired_leaf_id", "status_trailer_0324")
        )
    if report_code in {0x010A0024, 0x010A0027, 0x010A0044, 0x010A0057}:
        return _semantic_profile(
            "response_feedback_fields", "response.feedback", "响应反馈/状态字段", "observed", "observed", ("fixed_response_offsets", "direction_and_timeline_required")
        )

    if report_code == 0x0102000A:
        report = _detect_tss_report(data)
        layout = _read_0102000a_layout(data, report) if report else None
        if not layout:
            return _semantic_profile(
                "typed_leaf_unresolved_shape", "telemetry.typed_leaf", "探测遥测叶子（shape 未完整）", "approximate", "approximate", ("report_family", "shape_parse_failed")
            )

        shape = (
            len(data),
            int(layout.get("inner_type") or 0),
            int(layout.get("selector0") or 0),
            int(layout.get("selector1") or 0),
        )
        timestamp = DFM_TYPED_TIMESTAMP_SHAPES.get(shape)
        if timestamp:
            role, category, label, tier = timestamp
            return _semantic_profile(
                role, category, label, tier, "confirmed" if tier == "confirmed" else "observed", ("full_shape", "historical_continuity"), exact_meaning=tier == "confirmed"
            )

        body_layout = _parse_typed_body_structure(data, layout)
        if body_layout and body_layout.get("kind") == "periodic_probe_table":
            return _semantic_profile(
                "periodic_probe_schedule_table",
                "telemetry.probe_scheduler",
                "周期探测调度与结果表（probe_id 含义待证）",
                "observed",
                "high",
                ("body_len_4_plus_n_times_6", "u16_probe_id_raw32_value", "historical_monotonic_tick", "relative_to_probe_0x8000"),
            )
        if body_layout and body_layout.get("kind") == "fixed_word_block":
            return _semantic_profile(
                "fixed_probe_word_block",
                "telemetry.binary_probe.words",
                "固定字状态探测块（字段含义待证）",
                "observed",
                "observed",
                ("body_u32_slots", "inner_type_0x2001", "full_shape"),
            )
        if body_layout and body_layout.get("kind") == "bitmap_word_block":
            return _semantic_profile(
                "probe_bitmap_or_capability_mask",
                "telemetry.binary_probe.bitmap",
                "位图/能力掩码探测块（bit 含义待证）",
                "observed",
                "observed",
                ("body_u32_slots", "zero_and_ffffffff_masks", "inner_type_0x2011", "full_shape"),
            )

        raw_text, xor_text = _typed_leaf_text_views(data, layout)
        combined = f"{raw_text}\n{xor_text}".lower()
        inner_type = int(layout.get("inner_type") or 0)
        if any(token in combined for token in ("uiwindow", "uitransitionview", "uidropshadowview", "uiview")):
            return _semantic_profile(
                "ui_hierarchy_probe", "environment.ui_hierarchy", "UI 层级/前台窗口探测", "observed", "observed", ("xor_text", "ui_tokens", "full_shape")
            )
        has_module = any(token in combined for token in (".dylib", ".framework", "/usr/lib", "frameworks/", ".so"))
        has_process = any(token in combined for token in _SEMANTIC_PROCESS_TOKENS)
        if has_module and has_process:
            return _semantic_profile(
                "module_process_integrity_probe", "environment.module_process", "动态库/进程组合探测", "observed", "observed", ("xor_text", "module_token", "process_token", "full_shape")
            )
        if has_module:
            return _semantic_profile(
                "module_or_dylib_path_probe", "environment.module_integrity", "动态库/Framework 路径探测", "observed", "observed", ("xor_text", "module_token", "full_shape")
            )
        if has_process:
            return _semantic_profile(
                "process_or_callstack_probe", "environment.process_stack", "系统进程/调用栈探测", "observed", "observed", ("xor_text", "process_token", "full_shape")
            )
        if inner_type == 0x100B:
            return _semantic_profile(
                "ui_hierarchy_probe_candidate", "environment.ui_hierarchy", "UI 层级探测（近似）", "approximate", "approximate", ("inner_type_0x100b", "historical_shape_family")
            )
        if inner_type in {0x1105, 0x2000, 0xFFF2}:
            return _semantic_profile(
                "module_path_probe_candidate", "environment.module_integrity", "模块/动态库路径探测（近似）", "approximate", "approximate", (f"inner_type_0x{inner_type:04x}", "historical_shape_family")
            )
        if inner_type in {0x8027, 0x8029}:
            return _semantic_profile(
                "process_stack_probe_candidate", "environment.process_stack", "进程/调用栈探测（近似）", "approximate", "approximate", (f"inner_type_0x{inner_type:04x}", "historical_shape_family")
            )
        return _semantic_profile(
            "typed_leaf_binary_probe", "telemetry.binary_probe", "稳定二进制探测/遥测（字段待证）", "approximate", "approximate", ("full_shape", f"inner_type_0x{inner_type:04x}")
        )

    if report_code & 0xFFFF0000 == 0x01120000:
        has_csob = all(token in lower for token in (b"cs:", b",ob:", b"state:", b",r:", b",p:"))
        has_device = b"model:" in lower or b"ver:" in lower
        has_file = any(token in lower for token in (b"config2.dat", b"config3.dat", b"comm.zip", b"mrpcs_i", b".data"))
        if report_code == 0x0112235B and _pubgm_0112235b_device_account_tail_fields(data):
            return _semantic_profile(
                "device_account_profile_with_tail_state",
                "metadata.device_profile_state",
                "设备/账号绑定画像 + 尾部状态三联（只观察）",
                "observed",
                "high",
                (
                    "full_shape_len269",
                    "identity_bundle_layout",
                    "natural_tail_variants",
                    "outer_270f_causal_confound",
                    "tail_write_unproven",
                ),
            )
        if has_csob:
            return _semantic_profile(
                "csob_state_snapshot", "metadata.state.csob", "CSOB 状态快照", "confirmed", "high", ("cs", "ob", "state", "r", "p"), exact_meaning=True
            )
        if has_device and has_file:
            return _semantic_profile(
                "configuration_file_observation", "metadata.device_profile", "设备画像 + 配置文件引用", "observed", "observed", ("device_profile_key", "configuration_filename")
            )
        if has_device:
            return _semantic_profile(
                "device_profile_metadata", "metadata.device_profile", "设备型号/系统版本画像", "observed", "observed", ("device_profile_key",)
            )
        if has_file or b"dl:" in lower:
            return _semantic_profile(
                "configuration_file_observation", "metadata.file_reference", "配置/规则文件引用", "observed", "observed", ("configuration_filename",)
            )
        if b"state:" in lower or b"cnt:" in lower or b"counter" in lower:
            return _semantic_profile(
                "state_or_counter_metadata", "metadata.state", "状态/计数元数据", "observed", "observed", ("state_or_counter_key",)
            )
        if any(token in lower for token in (b"idevidfv:", b"itsssdkuuid:", b"iappmachuuid:")):
            return _semantic_profile(
                "device_identity_metadata", "metadata.device_identity", "设备身份标识元数据", "observed", "observed", ("device_identifier_key",)
            )
        if any(token in lower for token in (b"vpn:", b"language:", b"iscreencaptured:", b"ios_tp_api")):
            return _semantic_profile(
                "device_environment_metadata", "metadata.device_environment", "设备环境/开关标签", "observed", "observed", ("environment_label_key",)
            )
        if b"historyopenid:" in lower or b"openid" in lower or b"account" in lower:
            return _semantic_profile(
                "account_history_metadata", "metadata.account", "账号/OpenID 历史元数据", "observed", "observed", ("account_label_key",)
            )
        if b"apple root ca" in lower or b"certification authority" in lower:
            return _semantic_profile(
                "certificate_or_trust_observation", "metadata.trust", "证书/信任材料观察", "observed", "observed", ("certificate_text",)
            )
        if b"iteamid:" in lower or b"teamid:" in lower:
            return _semantic_profile(
                "signing_team_metadata", "metadata.signing", "签名 TeamID 元数据", "observed", "observed", ("team_id_key",)
            )
        if b"iappversion:" in lower or b"iappinfo:" in lower:
            return _semantic_profile(
                "application_version_metadata", "metadata.application", "应用版本/组件元数据", "observed", "observed", ("app_version_key",)
            )
        if b"framework" in lower or b".dylib" in lower:
            return _semantic_profile(
                "module_or_framework_observation", "metadata.module", "模块/Framework 元数据", "observed", "observed", ("module_text",)
            )
        if b"addlistener" in lower or b"hdmioutput" in lower:
            return _semantic_profile(
                "runtime_api_or_output_route_observation", "metadata.runtime", "运行时 API/输出路由元数据", "observed", "observed", ("runtime_api_text",)
            )
        if b"error" in lower:
            return _semantic_profile(
                "error_observation", "metadata.error", "错误/异常元数据", "observed", "observed", ("error_text",)
            )
        return _semantic_profile(
            "dynamic_metadata_context", "metadata.context", "结构化元数据（具体子项待证）", "approximate", "approximate", ("metadata_family", "payload_opaque")
        )

    family = (int(report_code) >> 16) & 0xFFFF
    if family == 0x010A:
        return _semantic_profile(
            "control_or_feedback_record", "control.protocol", "控制/反馈记录（具体字段待证）", "approximate", "approximate", ("report_family_0x010a",)
        )
    if family == 0x0102:
        return _semantic_profile(
            "telemetry_leaf", "telemetry.leaf", "探测遥测叶子（具体字段待证）", "approximate", "approximate", ("report_family_0x0102",)
        )
    printable = sum(1 for value in data if 0x20 <= value <= 0x7E)
    printable_ratio = (printable / len(data)) if data else 0.0
    if len(data) <= 64:
        return _semantic_profile(
            "opaque_short_control_candidate",
            "control.opaque_candidate",
            "短控制/状态记录（高概率候选，字段待证）",
            "approximate",
            "approximate",
            ("short_record_shape", f"printable_ratio_{printable_ratio:.2f}"),
        )
    if printable_ratio >= 0.30:
        return _semantic_profile(
            "opaque_text_metadata_candidate",
            "metadata.opaque_text_candidate",
            "文本型元数据记录（高概率候选，字段待证）",
            "approximate",
            "approximate",
            ("printable_density", f"printable_ratio_{printable_ratio:.2f}"),
        )
    return _semantic_profile(
        "opaque_binary_telemetry_candidate",
        "telemetry.opaque_binary_candidate",
        "二进制遥测/环境探测（高概率候选，字段待证）",
        "approximate",
        "approximate",
        ("binary_density", f"printable_ratio_{printable_ratio:.2f}"),
        exact_meaning=False,
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


def _typed_u32_views(raw: bytes) -> dict[str, Any]:
    value = bytes(raw or b"")[:4]
    if len(value) != 4:
        return {"raw_hex": value.hex()}
    be32 = int.from_bytes(value, "big")
    le32 = int.from_bytes(value, "little")
    out: dict[str, Any] = {
        "raw_hex": value.hex(),
        "be32": be32,
        "be32_hex": _fmt_hex(be32, 8),
        "le32": le32,
        "le32_hex": _fmt_hex(le32, 8),
    }
    float_be = struct.unpack(">f", value)[0]
    if math.isfinite(float_be) and (float_be == 0.0 or 1e-6 <= abs(float_be) <= 1e6):
        out["float_be"] = float_be
    return out


def _probe_counter_cadence(
    tick: int,
    value: int,
    probe_id: int,
    global_round: int | None,
) -> tuple[str, str, float | None]:
    if value <= 0 or tick <= 0 or value > tick + 1:
        return "typed_value", "按 probe_id 解释的4字节值", None
    if probe_id == 0x8000:
        return "global_round", "全局调度轮数候选", 1.0
    if not global_round or global_round <= 0:
        return "counter_candidate", "累计计数候选；缺少0x8000轮次基准", None

    round_ratio = value / global_round
    if abs(value - global_round) <= 1:
        return "per_round_candidate", "每调度轮一次候选（与全局轮次相差不超过1）", round_ratio
    if abs(value * 2 - global_round) <= 1:
        return "half_round_candidate", "隔调度轮一次候选（约为全局轮次一半）", round_ratio
    if value <= max(3, int(global_round * 0.1)):
        return "sparse_or_conditional", "低频/启动/条件累计候选", round_ratio
    if value > global_round:
        return "multi_per_round_candidate", "每轮多次累计候选；须连续包确认", round_ratio
    return "sub_round_candidate", "低于每轮频率的累计候选；须连续包确认", round_ratio


def _parse_typed_body_structure(record: bytes, layout: dict[str, int] | None) -> dict[str, Any] | None:
    """Parse only body layouts closed by cross-sample length and cadence evidence.

    Exact probe-id meanings remain unknown.  The parser exposes offsets, raw
    values and evidence-backed scheduling relationships without inventing
    field names or using printable-XOR scoring for these binary layouts.
    """
    if not layout:
        return None
    data = bytes(record or b"")
    start = max(0, int(layout.get("body_start") or 0))
    end = min(len(data), int(layout.get("record_end") or len(data)))
    if start > end:
        return None
    body = data[start:end]
    inner_type = int(layout.get("inner_type") or 0)

    if inner_type == 0xFFF3 and len(body) >= 4 and (len(body) - 4) % 6 == 0:
        tick = int.from_bytes(body[:4], "big")
        selector1 = int(layout.get("selector1") or 0)
        raw_entries = [
            (
                int.from_bytes(body[rel : rel + 2], "big"),
                body[rel + 2 : rel + 6],
                start + rel,
            )
            for rel in range(4, len(body), 6)
        ]
        global_round = next(
            (
                int.from_bytes(raw_value, "big")
                for probe_id, raw_value, _offset in raw_entries
                if probe_id == 0x8000
            ),
            None,
        )
        entries: list[dict[str, Any]] = []
        cadence_counts: Counter[str] = Counter()
        for probe_id, raw_value, offset in raw_entries:
            value_be = int.from_bytes(raw_value, "big")
            cadence, cadence_zh, round_ratio = _probe_counter_cadence(
                tick, value_be, probe_id, global_round
            )
            cadence_counts[cadence] += 1
            item = {
                "index": len(entries),
                "offset": offset,
                "probe_id": _fmt_hex(probe_id, 4),
                "probe_id_value": probe_id,
                "value": _typed_u32_views(raw_value),
                "value_kind": cadence,
                "value_kind_zh": cadence_zh,
                "counter_candidate": cadence != "typed_value",
            }
            if round_ratio is not None:
                item["global_round_ratio_candidate"] = round(round_ratio, 3)
            entries.append(item)
        return {
            "kind": "periodic_probe_table",
            "label_zh": "周期探测调度与结果表",
            "confidence": "confirmed_structure",
            "body_offset": start,
            "body_len": len(body),
            "layout_algebra": f"4 + {len(entries)}×6 = {len(body)}",
            "tick": tick,
            "tick_hex": _fmt_hex(tick, 8),
            "tick_offset": start,
            "historical_reference": {
                "sample_count": 415,
                "duration_seconds": 37290.096,
                "tick_rate_median_per_second": 0.987682,
                "global_round_period_median_seconds": 30.031,
                "scope": "旧fff3连续样本；当前probe集合须独立复核",
            },
            "elapsed_seconds_historical_estimate": round(tick / 0.987682) if tick else 0,
            "selector_tick_match": ((selector1 >> 16) & 0xFFFF) == (tick & 0xFFFF),
            "selector_revision_or_flags": selector1 & 0xFFFF,
            "inner_pair": {
                "left": (int(layout.get("inner_field") or 0) >> 16) & 0xFFFF,
                "right": int(layout.get("inner_field") or 0) & 0xFFFF,
            },
            "entry_count": len(entries),
            "probe_id_registry": "sparse_enum_not_sequence",
            "cadence_counts": dict(cadence_counts),
            "entries": entries,
            "evidence": [
                "body_len=4+n*6",
                "entry=u16_probe_id+raw32_value",
                "selector1_high16_matches_body_tick" if ((selector1 >> 16) & 0xFFFF) == (tick & 0xFFFF) else "selector1_tick_mismatch",
                "historical_fff3_reference_415_samples",
                "cadence_classified_relative_to_probe_0x8000_not_tick_div_value",
            ],
        }

    if inner_type in {0x2001, 0x2011} and len(body) > 0 and len(body) % 4 == 0:
        words = []
        for rel in range(0, len(body), 4):
            views = _typed_u32_views(body[rel : rel + 4])
            be32 = int(views.get("be32") or 0)
            words.append(
                {
                    "index": len(words),
                    "offset": start + rel,
                    "value": views,
                    "set_bits_be": [bit for bit in range(32) if be32 & (1 << bit)],
                    "all_zero": be32 == 0,
                    "all_one": be32 == 0xFFFFFFFF,
                }
            )
        is_bitmap = inner_type == 0x2011
        return {
            "kind": "bitmap_word_block" if is_bitmap else "fixed_word_block",
            "label_zh": "位图/能力掩码探测块" if is_bitmap else "固定字状态探测块",
            "confidence": "confirmed_structure",
            "body_offset": start,
            "body_len": len(body),
            "layout_algebra": f"{len(words)}×u32 = {len(body)}",
            "word_count": len(words),
            "words": words,
            "evidence": [
                "body_len_multiple_of_4",
                "fixed_shape_word_slots",
                "all_zero_and_all_one_masks" if is_bitmap else "mixed_scalar_or_mask_words",
            ],
        }
    return None


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
        return "服务器确认型子请求（保活/握手候选）", "confirmed"
    if report_code == 0x010A0010:
        return "010a0011 回执；leaf_id 原样回显", "confirmed"
    if report_code in {0x010A0024, 0x010A0027, 0x010A0044, 0x010A0057}:
        return ("响应反馈（按字段与前序请求解释）" if direction else "请求上下文"), "observed"
    return "目前不能证明含义", "unknown"


def _observed_payload_role(report_code: int, record: bytes) -> tuple[str, str, tuple[str, ...]]:
    """Backward-compatible tuple view over the richer semantic profile."""
    profile = _payload_semantic_profile(report_code, record)
    return (
        str(profile.get("role") or "unresolved_payload"),
        str(profile.get("confidence") or "unknown"),
        tuple(profile.get("evidence") or ()),
    )


def _deep_report(events: list[dict[str, Any]], *, source: str) -> dict[str, Any]:
    reports: dict[str, dict[str, Any]] = {}
    subtype_counts: Counter[str] = Counter()
    phase_counts: Counter[str] = Counter()
    mirror_actions: Counter[str] = Counter()
    mirror_reasons: Counter[str] = Counter()
    consistency_values: list[float] = []
    source_ages: list[int] = []
    pairable_shape_candidates = 0
    pairable_shape_matches = 0
    shape_match_kinds: Counter[str] = Counter()
    opaque_nodes = 0
    opaque_passthrough = 0
    request_count = 0
    response_count = 0
    timeline: list[tuple[int, int, str]] = []
    accepted_timestamps: Counter[str] = Counter()
    rejected_timestamp_reasons: Counter[str] = Counter()
    rejected_timestamp_samples: list[dict[str, Any]] = []
    semantic_categories: Counter[str] = Counter()
    semantic_labels: Counter[str] = Counter()
    semantic_tiers: Counter[str] = Counter()

    def add_report(
        report_code: int,
        record: bytes,
        event: dict[str, Any],
        *,
        child_index: int | None,
        analysis_node: dict[str, Any] | None = None,
    ) -> None:
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
                "payload_roles": Counter(),
                "payload_evidence": Counter(),
                "semantic_categories": Counter(),
                "semantic_labels_zh": Counter(),
                "semantic_tiers": Counter(),
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
        node = analysis_node if isinstance(analysis_node, dict) else {}
        profile = _payload_semantic_profile(report_code, record)
        if node.get("semantic_category"):
            profile = {
                **profile,
                "role": str(node.get("semantic_role") or profile.get("role") or "unresolved_payload"),
                "category": str(node.get("semantic_category") or profile.get("category") or "unknown"),
                "label_zh": str(node.get("semantic_label_zh") or profile.get("label_zh") or "未解析记录"),
                "tier": str(node.get("semantic_tier") or profile.get("tier") or "unknown"),
                "confidence": str(node.get("semantic_role_confidence") or profile.get("confidence") or "unknown"),
                "evidence": tuple(node.get("semantic_role_evidence") or profile.get("evidence") or ()),
            }
        payload_role = str(profile.get("role") or "unresolved_payload")
        payload_confidence = str(profile.get("confidence") or "unknown")
        payload_evidence = tuple(profile.get("evidence") or ())
        item["payload_roles"][f"{payload_role} ({payload_confidence})"] += 1
        category = str(profile.get("category") or "unknown")
        label_zh = str(profile.get("label_zh") or "未解析记录")
        tier = str(profile.get("tier") or "unknown")
        item["semantic_categories"][category] += 1
        item["semantic_labels_zh"][label_zh] += 1
        item["semantic_tiers"][tier] += 1
        semantic_categories[category] += 1
        semantic_labels[label_zh] += 1
        semantic_tiers[tier] += 1
        if str(item.get("confidence") or "unknown") == "unknown" and tier != "unknown":
            item["confidence"] = tier
            item["meaning"] = label_zh
        for evidence_name in payload_evidence:
            item["payload_evidence"][evidence_name] += 1
        if subtype is not None:
            subtype_counts[f"0x{subtype:02x}"] += 1
        report = _detect_tss_report(record)
        if report_code == 0x0102000A and report:
            layout = _read_0102000a_layout(record, report)
            if layout:
                item["shapes"][_shape_key(layout, len(record))] += 1
        elif report_code == 0x0102000A and isinstance(node.get("shape"), dict):
            node_shape = node["shape"]
            shape_text = ":".join(
                str(node_shape.get(key) or "-")
                for key in ("report_family", "inner_type", "selector0", "selector1", "inner_field", "record_len")
            )
            item["shapes"][shape_text] += 1
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
        for field_item in node.get("fields") if isinstance(node.get("fields"), list) else []:
            if not isinstance(field_item, dict):
                continue
            field_name = str(field_item.get("name") or "field")
            field_value = str(field_item.get("value") or "-")[:160]
            item["fields"][field_name][field_value] += 1
        if report_code == 0x0112235B:
            for field_item in _pubgm_0112235b_device_account_tail_fields(record):
                item["fields"][str(field_item["name"])][str(field_item["value"])] += 1
        if report_code == 0x010A0011 and len(record) >= 25 and 25 + int(record[24]) == len(record):
            item["fields"]["leaf_id_correlation"][_fmt_hex(_read_be32(record, 0x0A), 8)] += 1
            item["fields"]["request_token_opaque"][record[20:24].hex()] += 1
            item["fields"]["client_label"][record[25:].decode("ascii", "replace")[:160]] += 1
        if report_code == 0x010A0010 and len(record) == 0x16:
            item["fields"]["leaf_id_correlation"][_fmt_hex(_read_be32(record, 0x0A), 8)] += 1
            item["fields"]["ack_status"][record[20:22].hex()] += 1
        if report_code in {0x010A0024, 0x010A0027, 0x010A0044, 0x010A0057} and len(record) >= 0x16:
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
        analysis = event.get("analysis") if isinstance(event.get("analysis"), dict) else {}
        packet_analysis = analysis.get("packet") if isinstance(analysis.get("packet"), dict) else {}
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
        else:
            try:
                report_code = int(str(packet_analysis.get("report_code") or "0"), 0)
            except (TypeError, ValueError):
                report_code = 0
            if report_code:
                report_key = _fmt_hex(report_code, 8)
                add_report(report_code, b"", event, child_index=None, analysis_node=packet_analysis)
                for child_node in packet_analysis.get("children") if isinstance(packet_analysis.get("children"), list) else []:
                    if not isinstance(child_node, dict):
                        continue
                    try:
                        child_report = int(str(child_node.get("report_code") or "0"), 0)
                    except (TypeError, ValueError):
                        child_report = 0
                    if child_report:
                        add_report(
                            child_report,
                            b"",
                            event,
                            child_index=child_node.get("index"),
                            analysis_node=child_node,
                        )
        timeline.append((int(event.get("ts") or 0), direction, report_key))
        timestamp_nodes = [packet_analysis]
        timestamp_nodes.extend(
            item for item in packet_analysis.get("children", [])
            if isinstance(item, dict)
        )
        for node in timestamp_nodes:
            timestamps = node.get("timestamps") if isinstance(node.get("timestamps"), dict) else {}
            accepted_items = timestamps.get("accepted")
            if not isinstance(accepted_items, list):
                accepted_items = []
            for accepted in accepted_items:
                if not isinstance(accepted, dict):
                    continue
                accepted_timestamps[
                    f"{accepted.get('source') or 'unknown'}:{accepted.get('field') or 'unknown'}"
                ] += 1
            rejected_items = timestamps.get("rejected")
            if not isinstance(rejected_items, list):
                rejected_items = []
            for rejected in rejected_items:
                if not isinstance(rejected, dict):
                    continue
                reason_text = str(rejected.get("reason") or "unspecified")
                rejected_timestamp_reasons[reason_text] += 1
                if len(rejected_timestamp_samples) < 12:
                    rejected_timestamp_samples.append(
                        {
                            "seq": event.get("seq"),
                            "report_code": node.get("report_code"),
                            "child_index": node.get("index"),
                            "offset": rejected.get("offset"),
                            "value": rejected.get("value"),
                            "reason": reason_text,
                        }
                    )
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
            if reason == "exact_shape_mismatch" or child_action == "candidate":
                pairable_shape_candidates += 1
                if child_action == "candidate" and reason == "ok":
                    pairable_shape_matches += 1
                    shape_match_kinds[str(action.get("shape_match") or "exact")] += 1
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
                **{
                    name: value
                    for name, value in item.items()
                    if name not in {"roles", "payload_roles", "payload_evidence", "semantic_categories", "semantic_labels_zh", "semantic_tiers", "shapes", "fields", "correlations"}
                },
                "observations": int(item["counts"]["request"]) + int(item["counts"]["response"]),
                "roles": dict(item["roles"].most_common()),
                "payload_roles": dict(item["payload_roles"].most_common()),
                "payload_evidence": dict(item["payload_evidence"].most_common()),
                "semantic_categories": dict(item["semantic_categories"].most_common()),
                "semantic_labels_zh": dict(item["semantic_labels_zh"].most_common()),
                "semantic_tiers": dict(item["semantic_tiers"].most_common()),
                "shapes": dict(item["shapes"].most_common()),
                "fields": {name: dict(values.most_common(8)) for name, values in item["fields"].items()},
                "correlations": dict(item["correlations"].most_common(8)),
            }
        )
    unknown = [
        item["report_code"]
        for item in report_rows
        if set((item.get("semantic_categories") or {}).keys()) <= {"unknown"}
    ]
    ratio = response_count / request_count if request_count else None
    return {
        "schema": "tersafe.semantic.v1",
        "reports": report_rows,
        "dynamic_011223_subtypes": dict(subtype_counts.most_common()),
        "semantic_categories": dict(semantic_categories.most_common()),
        "semantic_labels_zh": dict(semantic_labels.most_common()),
        "semantic_tiers": dict(semantic_tiers.most_common()),
        "traffic": {
            "requests": request_count,
            "responses": response_count,
            "response_request_ratio": ratio,
        },
        "response_bursts": {
            "max_per_request_2s": dict(burst_max.most_common()),
            "requests_over_3": dict(bursts.most_common()),
        },
        "timestamps": {
            "accepted": sum(accepted_timestamps.values()),
            "accepted_by_schema": dict(accepted_timestamps.most_common()),
            "rejected": sum(rejected_timestamp_reasons.values()),
            "rejected_reasons": dict(rejected_timestamp_reasons.most_common()),
            "rejected_samples": rejected_timestamp_samples,
        },
        "mirror": {
            "state_phases": dict(phase_counts.most_common()),
            "actions": dict(mirror_actions.most_common()),
            "reasons": dict(mirror_reasons.most_common()),
            "average_consistency": (sum(consistency_values) / len(consistency_values)) if consistency_values else None,
            "max_source_age_ms": max(source_ages) if source_ages else None,
            "shape_match_kinds": dict(shape_match_kinds.most_common()),
            "pairable_shape_candidates": pairable_shape_candidates,
            "pairable_shape_matches": pairable_shape_matches,
            "shape_match_rate": (
                pairable_shape_matches / pairable_shape_candidates if pairable_shape_candidates else None
            ),
            # Backward-compatible aliases for older report consumers.  The
            # rate now includes exact typed-leaf and semantic-compatible CSOB
            # matches; `shape_match_kinds` is authoritative.
            "exact_shape_candidates": pairable_shape_candidates,
            "exact_shape_matches": pairable_shape_matches,
            "exact_shape_hit_rate": (
                pairable_shape_matches / pairable_shape_candidates if pairable_shape_candidates else None
            ),
            "opaque_nodes": opaque_nodes,
            "opaque_passthrough": opaque_passthrough,
            "opaque_passthrough_rate": (opaque_passthrough / opaque_nodes if opaque_nodes else None),
        },
        "unknown_reports": unknown,
        "unknown_note": "近似分类只回答所属大类；精确字段目前不能证明含义时会明确标注“近似”。真正 unknown 仅保留给连 report family 都无法识别的记录。",
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
    timestamps = deep.get("timestamps") or {}
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
            f"- semantic categories: `{_counter_text(deep.get('semantic_categories') or {}, 16)}`",
            f"- semantic evidence tiers: `{_counter_text(deep.get('semantic_tiers') or {}, 8)}`",
            f"- state phases: `{_counter_text(mirror.get('state_phases') or {}, 8)}`",
            f"- mirror actions: `{_counter_text(mirror.get('actions') or {}, 8)}`",
            f"- average consistency: `{mirror.get('average_consistency')}`",
            f"- max source age ms: `{mirror.get('max_source_age_ms')}`",
            f"- validated shape match rate: `{mirror.get('shape_match_rate', mirror.get('exact_shape_hit_rate'))}` ({mirror.get('pairable_shape_matches', mirror.get('exact_shape_matches', 0))}/{mirror.get('pairable_shape_candidates', mirror.get('exact_shape_candidates', 0))})",
            f"- shape match kinds: `{_counter_text(mirror.get('shape_match_kinds') or {}, 8)}`",
            f"- opaque pass-through rate: `{mirror.get('opaque_passthrough_rate')}` ({mirror.get('opaque_passthrough', 0)}/{mirror.get('opaque_nodes', 0)})",
            f"- response burst max/request/2s: `{_counter_text(bursts.get('max_per_request_2s') or {}, 12)}`",
            f"- burst requests over 3: `{_counter_text(bursts.get('requests_over_3') or {}, 12)}`",
            f"- accepted timestamps: `{timestamps.get('accepted', 0)}` (`{_counter_text(timestamps.get('accepted_by_schema') or {}, 8)}`)",
            f"- rejected timestamp candidates: `{timestamps.get('rejected', 0)}` (`{_counter_text(timestamps.get('rejected_reasons') or {}, 6)}`)",
            f"- 65010 connection: `observed={connection_65010.get('observed', False)} status={connection_65010.get('status', 'unknown')} first={connection_65010.get('first_ts')} last={connection_65010.get('last_ts')}`",
            "",
            "### Every ReportCode",
            "",
            "| reportCode | family/subtype | observed | request | response | semantic category / 中文近似义 | evidence tier | observed payload roles | shapes | fields | preceding request |",
            "|---|---|---:|---:|---:|---|---|---|---|---|---|",
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
            f"`{_counter_text(report.get('semantic_categories') or {}, 3)}` / {_counter_text(report.get('semantic_labels_zh') or {}, 3)} | "
            f"`{_counter_text(report.get('semantic_tiers') or {}, 3)}` | "
            f"`{_counter_text(report.get('payload_roles') or {}, 4)}` | "
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
            "### Timestamp Evidence Boundary",
            "",
            "- 只接受 `ob:T1/T2/T3` 和已知 typed-leaf 完整 shape 中的时间字段。",
            "- 普通 BE32、ASCII/hash/string 槽以及跨字段边界候选均拒绝，不再默认高亮。",
            "",
            "| seq | reportCode | child | offset | value | rejected reason |",
            "|---:|---|---:|---:|---:|---|",
        ]
    )
    for item in timestamps.get("rejected_samples") or []:
        lines.append(
            f"| {item.get('seq')} | `{item.get('report_code') or '-'}` | "
            f"{item.get('child_index') if item.get('child_index') is not None else '-'} | "
            f"{item.get('offset')} | {item.get('value')} | {item.get('reason') or '-'} |"
        )
    lines.extend(
        [
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
