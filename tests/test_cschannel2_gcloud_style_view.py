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
    assert '"cs2-panel", "gcloud-tss-decrypted", "gcloud-security-primary", "child-compare-inline"' in panel
    assert 'stack.className = "gcloud-security-deep-stack"' in panel
    assert "suppliedBeforeBytes" in shared
    assert "panelOptions.beforeParsed" in shared
    assert "panelOptions.afterParsed" in shared
    assert "const completeNode = cs2NodeRange(item, source)" in adapter
    assert "semanticRecord," in adapter
    assert "fields: cs2SharedComparableFields(item, source)" in adapter
    assert "bytes.push(...completeNode)" in adapter
    assert "cs2SharedDeepestVerifiedBytes(raw)" not in adapter


def test_cs2_shared_card_keeps_the_complete_application_item_and_field_boundaries() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    child = _packet_function(source, "cs2SharedComparableChild")
    fields = _packet_function(source, "cs2SharedComparableFields")
    hex_structure = _packet_function(source, "childHexStructure")

    assert "recordEnd: recordStart + completeNode.length" in child
    assert "len: completeNode.length" in child
    assert "reportOffset: report ? semanticOffset + report.offset : -1" in child
    assert "cs2ApplicationFields" in child
    assert "cs2FieldRows(item, source, true)" in fields
    assert "field.offset) - start" in fields
    assert "child.cs2ApplicationFields" in hex_structure
    assert '"完整 CSChannel2 node 起点"' in hex_structure
    assert "for (let consumed = 0; consumed < length; consumed += 16)" in hex_structure
    for label in ("项类型", "项子类型", "应用类型码", "附加值", "Unix 秒时间戳", "正文长度"):
        assert label in source


def test_csob_filter_loads_complete_payloads_before_filtering() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    sync = _packet_function(source, "syncLatestEvents")
    apply_filters = _packet_function(source, "applyFilters")

    assert "|| state.filters.csobOnly" in sync
    assert 'include_payload: needPayloadInList ? "1" : "0"' in sync
    assert "async function applyFilters()" in apply_filters
    assert "state.filters.csobOnly && !previousCsobOnly" in apply_filters
    assert "state.events = []" in apply_filters
    assert "await syncLatestEvents({" in apply_filters

