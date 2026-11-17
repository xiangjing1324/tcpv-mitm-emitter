from __future__ import annotations

from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS


def test_cs2_uses_gcloud_style_two_sided_node_cards() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    records = _packet_function(source, "appendCS2TersafeRecords")
    pair = _packet_function(source, "appendCS2GcloudStylePair")
    panel = _packet_function(source, "buildCSChannel2Panel")

    assert "appendCS2GcloudStylePair(" in records
    assert "appendCS2PairedFieldTable(" not in records
    assert 'row.className = "child-preview-row cs2-plaintext-pair"' in pair
    assert '"修改前", "before"' in pair
    assert '"修改后", "after"' in pair
    assert 'fold.className = "cs2-batch-fold"' in records
    assert 'summary.textContent = "CSChannel2 批次头"' in records
    assert 'before.length ? "叶子节点替换观察" : "当前叶子结构"' in panel

