from __future__ import annotations

import importlib
import os
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class TersafeAnalysis:
    display_payload: bytes
    summary: str
    decode_status: str
    rebuild_status: str = ""
    before_payload: bytes = b""


class TersafeAnalyzer:
    """Lazy bridge to the existing Hello/locaTest tersafe decoder.

    The tcpv package intentionally does not copy the tersafe implementation.
    Set TCPV_TERSAFE_ROOT to a checkout that can import `src.tss.dfm_cn_support`.
    """

    def __init__(self, root: str | None = None) -> None:
        self.root_text = str(root or os.getenv("TCPV_TERSAFE_ROOT", "") or "").strip()
        self.root = Path(self.root_text).expanduser() if self.root_text else Path()
        self._loaded = False
        self._load_error = ""
        self._decode_packet_metadata = None
        self._rebuild_packet_from_beforedump = None

    def analyze(self, packet: bytes) -> TersafeAnalysis:
        packet_bytes = bytes(packet or b"")
        if not packet_bytes:
            return TersafeAnalysis(b"", "import_decode=empty", "empty")
        if not self._ensure_loaded():
            reason = self._load_error or "TCPV_TERSAFE_ROOT not configured"
            return TersafeAnalysis(packet_bytes, f"import_decode=unconfigured reason={_summary_token(reason)}", "unconfigured")

        try:
            decode_meta = self._decode_packet_metadata(packet_bytes, full_scan=True)
        except Exception as exc:
            reason = f"{type(exc).__name__}:{exc}"
            return TersafeAnalysis(packet_bytes, f"import_decode=error reason={_summary_token(reason)}", "decode_error")

        if not isinstance(decode_meta, dict) or not decode_meta.get("ok"):
            reason = str((decode_meta or {}).get("error") or "decode_failed")
            return TersafeAnalysis(packet_bytes, f"import_decode=failed reason={_summary_token(reason)}", "decode_failed")

        try:
            beforedump = bytes.fromhex(str(decode_meta.get("beforedump_hex") or ""))
        except ValueError:
            return TersafeAnalysis(packet_bytes, "import_decode=failed reason=bad_beforedump_hex", "decode_failed")

        rebuild_status = "skip"
        try:
            rebuilt, rebuild_error = self._rebuild_packet_from_beforedump(
                packet_bytes,
                beforedump,
                full_scan=True,
                verify_roundtrip=True,
            )
            rebuild_status = "ok" if rebuilt else f"failed:{rebuild_error or 'rebuild_failed'}"
        except Exception as exc:
            rebuild_status = f"error:{type(exc).__name__}"

        crc = zlib.crc32(beforedump) & 0xFFFFFFFF
        summary = " ".join(
            part
            for part in (
                "import_decode=ok",
                f"report={_report_text(decode_meta.get('report_code'))}",
                f"role={_summary_token(decode_meta.get('report_role') or '-')}",
                f"hint={_summary_token(decode_meta.get('direction_hint') or '-')}",
                f"slice=0x{int(decode_meta.get('slice_offset') or 0):x}",
                f"beforedump={int(decode_meta.get('beforedump_len') or len(beforedump))}",
                f"plain_crc32={crc:08x}",
                f"roundtrip={_summary_token(rebuild_status)}",
            )
            if part
        )
        return TersafeAnalysis(beforedump, summary, "decoded", rebuild_status)

    def _ensure_loaded(self) -> bool:
        if self._loaded:
            return self._decode_packet_metadata is not None and self._rebuild_packet_from_beforedump is not None
        self._loaded = True
        if not self.root_text:
            self._load_error = "TCPV_TERSAFE_ROOT not configured"
            return False
        if not self.root.exists():
            self._load_error = f"root missing:{self.root}"
            return False
        root_text = str(self.root)
        if root_text not in sys.path:
            sys.path.insert(0, root_text)
        try:
            support = importlib.import_module("src.tss.dfm_cn_support")
            self._decode_packet_metadata = getattr(support, "decode_packet_metadata")
            self._rebuild_packet_from_beforedump = getattr(support, "rebuild_packet_from_beforedump")
            return True
        except Exception as exc:
            self._load_error = f"{type(exc).__name__}:{exc}"
            return False


def _report_text(value: Any) -> str:
    try:
        return f"0x{int(value):08x}"
    except (TypeError, ValueError):
        return "-"


def _summary_token(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    return "".join(ch if ch.isalnum() or ch in {"-", "_", ".", ":", "x"} else "_" for ch in text)[:160]
