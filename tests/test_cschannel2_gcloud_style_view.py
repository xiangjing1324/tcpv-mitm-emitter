from __future__ import annotations

from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS


def test_cs2_reuses_the_exact_gcloud_child_compare_component() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    panel = _packet_function(source, "buildCSChannel2Panel")
    shared = _packet_function(source, "buildChildComparePanel")
    adapter = _packet_function(source, "cs2SharedComparablePayload")

    assert 'buildChildComparePanel("", "", "", {' in panel
    assert "beforeParsed: beforeComparable.parsed" in panel
    assert "afterParsed: afterComparable.parsed" in panel
    assert "appendCS2TersafeRecords(" not in panel
    assert "appendCS2PairedFieldTable(" not in panel
    assert "appendCS2GcloudStylePair(" not in panel
    assert "ensureCS2TersafeCompactStyles(" not in panel
    assert 'panel.classList.add("cs2-panel")' in panel
    assert "suppliedBeforeBytes" in shared
    assert "panelOptions.beforeParsed" in shared
    assert "panelOptions.afterParsed" in shared
    assert "cs2SharedDeepestVerifiedBytes(raw)" in adapter


def test_cs2_verified_handshake_uses_secret_free_status_labels() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    panel = _packet_function(source, "buildCSChannel2Panel")
    summary = _packet_function(source, "buildCS2SummaryInsightStrip")
    display = _packet_function(source, "cs2SummaryDisplaySource")

    assert 'handshakeVerification.status === "verified"' in panel
    assert '"握手已验证"' in panel
    assert '"C8 RSA 块精确匹配"' in panel
    assert '"C8 业务 CRC 验证"' in panel
    assert "S8 字段已观察" in panel
    assert 'ticket 保持不透明' in panel
    assert 'handshakeVerified ? " · 已验证" : ""' in summary
    assert 'label: handshakeVerified ? "握手已验证" : "线上帧"' in display
    assert "handshake_verify=c8_" in summary
    assert "handshake_verify=c8_" in display
    for forbidden in ("c8_hex", "s8_hex", "c8_value", "s8_value"):
        assert forbidden not in panel

