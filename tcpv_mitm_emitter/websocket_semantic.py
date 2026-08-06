from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import re
import zipfile
import zlib
from typing import Any
from urllib.parse import urlsplit


SCHEMA = "tcpv.wss_json.analysis.v1"
SEMANTIC_REVISION = 1
MAX_FEATURE_BLOB_BYTES = 8 * 1024 * 1024
MAX_ZIP_ENTRY_BYTES = 16 * 1024 * 1024
MAX_ZIP_ENTRIES = 64
_SUMMARY_SAFE_RE = re.compile(r"[^A-Za-z0-9._:/+-]+")


def _safe_summary_value(value: Any, *, limit: int = 160) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    return _SUMMARY_SAFE_RE.sub("_", text)[:limit] or "-"


def _hex32(value: int | None) -> str:
    return f"0x{int(value) & 0xFFFFFFFF:08x}" if value is not None else ""


def _json_method(value: dict[str, Any]) -> tuple[str, str]:
    for key in ("method", "Method"):
        method = value.get(key)
        if isinstance(method, str) and method.strip():
            return method.strip(), key
    return "", ""


def _int32(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None


def _zip_resource(blob: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "format": "zip" if blob.startswith(b"PK\x03\x04") else "unknown",
        "valid": False,
        "entries": [],
    }
    if result["format"] != "zip":
        result["reason"] = "decoded featureData does not start with a ZIP local-file header"
        return result

    try:
        with zipfile.ZipFile(io.BytesIO(blob), "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                result["reason"] = f"ZIP entry count exceeds safety limit ({MAX_ZIP_ENTRIES})"
                return result
            entries: list[dict[str, Any]] = []
            for info in infos:
                entry: dict[str, Any] = {
                    "name": info.filename,
                    "compressed_size": int(info.compress_size),
                    "size": int(info.file_size),
                    "wire_crc32": _hex32(info.CRC),
                }
                if info.is_dir():
                    entry.update({"kind": "directory", "crc_match": True})
                elif info.file_size > MAX_ZIP_ENTRY_BYTES:
                    entry.update(
                        {
                            "kind": "file",
                            "inspected": False,
                            "reason": f"entry exceeds safety limit ({MAX_ZIP_ENTRY_BYTES} bytes)",
                        }
                    )
                else:
                    with archive.open(info, "r") as source:
                        data = source.read(MAX_ZIP_ENTRY_BYTES + 1)
                    if len(data) > MAX_ZIP_ENTRY_BYTES:
                        entry.update(
                            {
                                "kind": "file",
                                "inspected": False,
                                "reason": "decompressed entry exceeded safety limit",
                            }
                        )
                    else:
                        actual_crc = zlib.crc32(data) & 0xFFFFFFFF
                        zero_count = data.count(0)
                        entry.update(
                            {
                                "kind": "file",
                                "inspected": True,
                                "actual_size": len(data),
                                "actual_crc32": _hex32(actual_crc),
                                "crc_match": actual_crc == (info.CRC & 0xFFFFFFFF),
                                "sha256": hashlib.sha256(data).hexdigest(),
                                "zero_ratio": round(zero_count / len(data), 6) if data else 0.0,
                            }
                        )
                entries.append(entry)
            result.update({"valid": True, "entry_count": len(entries), "entries": entries})
    except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        result["reason"] = f"ZIP parse failed: {type(exc).__name__}"
    return result


def _feature_resource(value: dict[str, Any]) -> dict[str, Any]:
    name = str(value.get("featureName") or "").strip()
    encoded = value.get("featureData")
    wire_crc = _int32(value.get("dataCRC"))
    result: dict[str, Any] = {
        "kind": "ace_feature_resource_push",
        "feature_name": name,
        "wire_crc32": _hex32(wire_crc),
        "base64_valid": False,
        "confidence": "observed",
        "relationship_boundary": (
            "This resource belongs to the current WSS flow. A similarly named MRPCS/LightFeature "
            "message in another TCP flow is a family-name reference only, not a proven causal link or key."
        ),
    }
    if not isinstance(encoded, str) or not encoded.strip():
        result["reason"] = "featureData is missing or is not a Base64 string"
        return result
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        result["reason"] = "featureData is not strict Base64"
        return result
    if len(blob) > MAX_FEATURE_BLOB_BYTES:
        result["reason"] = f"decoded featureData exceeds safety limit ({MAX_FEATURE_BLOB_BYTES} bytes)"
        return result

    actual_crc = zlib.crc32(blob) & 0xFFFFFFFF
    result.update(
        {
            "base64_valid": True,
            "blob_len": len(blob),
            "blob_sha256": hashlib.sha256(blob).hexdigest(),
            "actual_crc32": _hex32(actual_crc),
            "crc_match": wire_crc is not None and actual_crc == wire_crc,
            "crc_scope": "decoded featureData ZIP/blob bytes",
            "archive": _zip_resource(blob),
        }
    )
    return result


def analyze_websocket_payload(
    payload: bytes | bytearray | str,
    *,
    from_client: bool,
    url: str = "",
) -> dict[str, Any]:
    raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload or b"")
    parsed_url = urlsplit(str(url or ""))
    transport = {
        "kind": "wss_json",
        "tls": "decrypted_by_mitmproxy",
        "application_payload": "json_plaintext_if_parseable",
        "host": (parsed_url.hostname or "").lower(),
        "path": parsed_url.path or "/",
        "query_stored": False,
        "direction": "outbound" if from_client else "inbound",
    }
    analysis: dict[str, Any] = {
        "schema": SCHEMA,
        "semantic_revision": SEMANTIC_REVISION,
        "analysis_authoritative": True,
        "analysis_source": "mitmproxy_websocket_message",
        "transport": transport,
        "direction": "request" if from_client else "response",
        "json": {"valid": False, "top_level_type": "unknown", "keys": []},
        "packet": {
            "report_code": "0x00000000",
            "report_family": "wss_json",
            "role": "websocket_message",
            "role_confidence": "observed",
            "semantic_role": "websocket.message",
            "semantic_role_confidence": "observed",
            "semantic_role_evidence": ["mitmproxy_tls_decrypted_websocket_payload"],
            "semantic_category": "transport.websocket.json",
            "semantic_label_zh": "WSS JSON 消息",
            "semantic_tier": "observed",
            "semantic_exact_meaning": False,
            "shape": {"transport": "wss_json", "record_len": len(raw)},
            "fields": [],
            "children": [],
            "timestamps": {"accepted": [], "rejected": []},
        },
        "boundary": (
            "WSS is encrypted on the network by TLS; this event is the TLS-decrypted payload. "
            "No additional application-layer encryption was observed when JSON parsing succeeds."
        ),
    }
    try:
        decoded = raw.decode("utf-8")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        analysis["json"]["reason"] = type(exc).__name__
        return analysis

    analysis["json"]["valid"] = True
    analysis["json"]["top_level_type"] = type(value).__name__
    if not isinstance(value, dict):
        return analysis

    method, method_key = _json_method(value)
    keys = [str(key) for key in value.keys()]
    analysis["json"].update(
        {
            "keys": keys[:64],
            "key_count": len(keys),
            "method": method,
            "method_key": method_key,
        }
    )
    packet = analysis["packet"]
    packet["role"] = method or "json_object"
    packet["semantic_exact_meaning"] = bool(method)
    packet["shape"]["method"] = method or None

    method_categories = {
        "ACELightFeature": ("security.ace.feature_resource", "ACE LightFeature 资源下发"),
        "chatMsg": ("social.chat.message", "大厅聊天消息"),
        "teamRecruitmentInfo": ("social.team.recruitment", "队伍招募信息"),
        "wsConnSucc": ("transport.websocket.connected", "WebSocket 连接成功"),
        "worldChatChannel": ("social.chat.channel", "世界聊天频道"),
        "hotfix": ("game.config.hotfix", "热更新通知"),
        "Ping": ("transport.websocket.heartbeat", "WSS JSON Ping"),
        "Pong": ("transport.websocket.heartbeat", "WSS JSON Pong"),
    }
    if method in method_categories:
        category, label = method_categories[method]
        packet.update(
            {
                "semantic_role": method,
                "semantic_category": category,
                "semantic_label_zh": label,
                "semantic_exact_meaning": True,
            }
        )
    elif method:
        packet.update(
            {
                "semantic_role": method,
                "semantic_category": "websocket.application_method",
                "semantic_label_zh": f"WSS 方法 {method}",
            }
        )

    if method == "ACELightFeature":
        analysis["feature_resource"] = _feature_resource(value)
    return analysis


def format_websocket_summary(analysis: dict[str, Any]) -> str:
    transport = analysis.get("transport") if isinstance(analysis.get("transport"), dict) else {}
    json_info = analysis.get("json") if isinstance(analysis.get("json"), dict) else {}
    method = _safe_summary_value(json_info.get("method") or "unknown")
    parts = [
        "transport=wss_json",
        f"direction={_safe_summary_value(transport.get('direction'))}",
        f"host={_safe_summary_value(transport.get('host'))}",
        f"path={_safe_summary_value(transport.get('path'))}",
        f"json={1 if json_info.get('valid') is True else 0}",
        f"method={method}",
    ]
    resource = analysis.get("feature_resource") if isinstance(analysis.get("feature_resource"), dict) else None
    if resource is not None:
        archive = resource.get("archive") if isinstance(resource.get("archive"), dict) else {}
        parts.extend(
            (
                f"feature_name={_safe_summary_value(resource.get('feature_name'))}",
                f"feature_crc={_safe_summary_value(resource.get('wire_crc32'))}",
                f"feature_crc_ok={1 if resource.get('crc_match') is True else 0}",
                f"feature_blob_len={int(resource.get('blob_len') or 0)}",
                f"zip={1 if archive.get('valid') is True else 0}",
                f"zip_entries={int(archive.get('entry_count') or 0)}",
                "cross_flow_relation=unproven",
            )
        )
    return " ".join(parts)


__all__ = [
    "MAX_FEATURE_BLOB_BYTES",
    "MAX_ZIP_ENTRY_BYTES",
    "SCHEMA",
    "SEMANTIC_REVISION",
    "analyze_websocket_payload",
    "format_websocket_summary",
]
