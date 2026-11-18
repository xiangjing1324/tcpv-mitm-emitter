from __future__ import annotations

import json
import subprocess

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
    assert "fields: cs2SharedComparableFields(item, source, Number(payloadNode.offset))" in adapter
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
    assert "cs2FieldRows(item, source, true).filter" in fields
    assert "Number(field.end) <= stop" in fields
    assert "field.offset) - start" in fields
    assert "child.cs2ApplicationFields" in hex_structure
    assert '"完整 CSChannel2 node 起点"' not in hex_structure
    assert "const recordModel = childHexStructure(recordChild, recordBytes, options)" in hex_structure
    assert "semanticOffset + Number(field.offset)" in hex_structure
    assert 'if (label === "Unix 秒时间戳") return "inlineTimestamp"' in source
    assert "const hasTimeTone = isTimestamp || isInlineTimestamp" in source
    assert 'String(kind || "") === "inlineTimestamp"' in source
    assert "for (let consumed = 0; consumed < length; consumed += 16)" in hex_structure
    for label in ("项类型", "项子类型", "应用类型码", "附加值", "Unix 秒时间戳", "正文长度"):
        assert label in source


def test_cs2_mrpcs_empty_ack_is_game_agnostic_and_exposes_fixed_fields() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    detector = _packet_function(source, "cs2MrpcsEmptyAckInfo")
    samples = [
        # DFM
        bytes.fromhex(
            "03 04 14 fa 5c 00 64 00 00 16 4f 02 08 b0 76 01 "
            "c0 b9 70 b3 b5 7a 84 03 e9 00 00 6a fd 9c f8 00 "
            "00 00 00 00 00 00 02 00 00 00 00"
        ),
        # DFM
        bytes.fromhex(
            "03 04 14 a7 be d6 a4 00 00 16 4f 02 08 c9 95 01 "
            "c0 b9 70 b3 cd d7 b3 03 e9 00 00 6a fd 9f 78 00 "
            "00 00 00 00 00 00 02 00 00 00 00"
        ),
        # UAGame: same MRPCS empty-ack structure, different 20-byte association field.
        bytes.fromhex(
            "03 04 14 5f db 06 cd 00 00 16 4f 01 da 99 ad 01 "
            "b1 e2 89 09 37 65 18 03 e9 00 00 6a fd ab 28 00 "
            "00 00 00 00 00 00 02 00 00 00 00"
        ),
    ]
    negative = bytearray(samples[0])
    negative[38] = 1
    script = (
        detector
        + "\nconsole.log(JSON.stringify(["
        + ",".join(f"cs2MrpcsEmptyAckInfo({json.dumps(list(sample))})" for sample in samples)
        + f",cs2MrpcsEmptyAckInfo({json.dumps(list(negative))})"
        + "]));\n"
    )
    result = subprocess.run(["node"], input=script, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    first, second, third, rejected = json.loads(result.stdout)
    assert [first["status"], second["status"], third["status"]] == [2, 2, 2]
    assert [first["bodyLength"], second["bodyLength"], third["bodyLength"]] == [0, 0, 0]
    assert first["associationHex"] == "0xfa5c00640000164f0208b07601c0b970b3b57a84"
    assert third["associationHex"] == "0x5fdb06cd0000164f01da99ad01b1e28909376518"
    assert rejected is None

    fields = _packet_function(source, "cs2FieldRows")
    adapter = _packet_function(source, "cs2SharedComparableChild")
    assert 'label: "MRPCS 关联字段"' in fields
    assert 'label: "确认状态"' in fields
    assert 'child.semanticLabel = "MRPCS 空确认"' in adapter
    assert 'child.semanticRole = "mrpcs_empty_ack"' in adapter


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


def test_cs2_preview_facts_report_node_index_and_exact_resource_names() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    function = _packet_function(source, "cs2SharedPreviewFacts")
    sample = b"xxcs:1/2,ob:a/b;state:00c01857,r:7,p:8;config2.dat|CONFIG3.DAT"
    control = b"cs:1/2;state:00c01857,r:7;config23.dat"
    script = (
        function
        + "\nconsole.log(JSON.stringify(["
        + f"cs2SharedPreviewFacts({json.dumps(list(sample))}, 8),"
        + f"cs2SharedPreviewFacts({json.dumps(list(control))}, 4)"
        + "]));\n"
    )
    result = subprocess.run(["node"], input=script, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    facts, negative = json.loads(result.stdout)
    assert facts == [
        {"label": "CSOB", "value": "第9项（node[8]）"},
        {"label": "资源", "value": "config2.dat · 第9项（node[8]）"},
        {"label": "资源", "value": "config3.dat · 第9项（node[8]）"},
    ]
    assert negative == []


def test_unverified_2001_2011_word_decoders_are_not_rendered() -> None:
    source = APP_JS.read_text(encoding="utf-8")

    for retired in (
        "fixedWordBlock",
        "bitmapWordBlock",
        "固定字状态探测块",
        "位图/能力掩码探测块",
        "正文槽[",
    ):
        assert retired not in source


def test_cs2_facts_live_on_the_collapsed_summary_not_inside_expanded_preview() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    summary = _packet_function(source, "buildCS2SummaryInsightStrip")
    preview = _packet_function(source, "childPreviewRichLines")
    compact_cache = _packet_function(source, "primeCompactEventCaches")

    assert "cs2SummaryFactsFromEvent(ev)" in summary
    assert 'factChip.textContent = csob ? `CSOB · ${fact.value}`' in summary
    assert '"cs2-summary-resource"' in summary
    assert "cs2WatchInnerPreview(chip, ev, summaryText)" in summary
    assert "missingBeforePayload" in summary
    assert "cs2SummaryFactsFromEvent(ev)" in compact_cache
    assert "previewFacts" not in preview

    facts = _packet_function(source, "cs2SummaryFactsFromEvent")
    assert '[["full_pay", "full_len"], ["before_pay", "before_len"]]' in facts
    assert "cs2BeforeApplicationBytes(ev, ev.analysis, bytes)" in facts


def test_cs2_shared_card_renders_every_verified_inner_layer() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    adapter = _packet_function(source, "cs2SharedComparablePayload")
    child = _packet_function(source, "cs2SharedComparableChild")
    preview_box = _packet_function(source, "makeChildPreviewBox")
    layers = _packet_function(source, "appendChildVerifiedLayers")

    assert "cs2SharedVerifiedLayers(item, source)" in adapter
    assert "verifiedLayers: verified.layers" in adapter
    assert "verifiedLayerStops: verified.stops" in adapter
    assert "verifiedLayers" in child
    assert "verifiedLayerStops" in child
    assert "appendChildVerifiedLayers(box, child)" in preview_box
    assert "for (const layer of ordered)" in layers
    assert "appendChildFullHexTable(box, nestedChild, bytes" in layers
    assert "CRC32 通过" in layers
    assert "未展示候选明文" in layers


def test_child_compare_expands_every_node_and_has_sticky_jump_navigation() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    panel = _packet_function(source, "buildChildComparePanel")
    navigator = _packet_function(source, "makeChildNodeNavigator")

    assert "Array.from({length: total}, (_, index) => index)" in panel
    assert "visibleIndices.length < 8" not in panel
    assert "节点未展开显示" not in source
    assert "当前视图优先展示前 8 个" not in source
    assert "makeChildNodeNavigator(" in panel
    assert 'panel.className = "child-compare child-compare-all-nodes"' in panel
    assert "节点导航 · ${ordered.length}项全部展开" in navigator
    assert 'card.scrollIntoView({behavior: "smooth", block: "start"})' in navigator
    assert 'previous.textContent = "上一个"' in navigator
    assert 'next.textContent = "下一个"' in navigator
    assert ".child-node-navigator {" in source
    assert "position: sticky" in source
    assert ".child-compare.child-compare-all-nodes" in source
    assert "overflow: visible" in source


def test_hex_annotations_use_short_chinese_and_stay_on_one_line() -> None:
    source = APP_JS.read_text(encoding="utf-8")
    structure = _packet_function(source, "childHexStructure")
    table = _packet_function(source, "appendChildFullHexTable")
    terms = _packet_function(source, "childUiTerm")
    styles = _packet_function(source, "ensureCS2TersafeCompactStyles")

    for old in (
        "record start(记录起点)",
        "record version",
        "TSS-like framing observed",
        "record total",
        "inner len(内部结构长度)",
        "inner type(shape字段)",
        "selector0(shape选择字0)",
        "selector1(shape选择字1)",
        "inner field(shape字段)",
    ):
        assert old not in structure
    for new in (
        "记录起点",
        "TSS帧",
        "记录长度",
        "报告码",
        "候选序号",
        "内层长度",
        "内层类型",
        "选择字0",
        "选择字1",
        "内层字段",
        "非正文首字节",
    ):
        assert new in structure
    assert 'title.textContent = `完整字节 · ${len} B`' in table
    assert "note.title = note.textContent" in table
    assert 'report: "报告码"' in terms
    assert "white-space:nowrap" in styles
    assert "text-overflow:ellipsis" in styles

