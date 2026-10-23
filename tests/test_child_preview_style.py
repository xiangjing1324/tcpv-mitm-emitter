from __future__ import annotations

import json
import re
import subprocess
import unittest

from test_packet_field_tables import _packet_function
from test_uagame_display_recovery import APP_JS


def _css_block(css: str, prelude: str) -> str:
    """Read one balanced rule, including nested container/media query rules."""
    match = re.search(r"(?m)^\s*" + re.escape(prelude) + r"\s*\{", css)
    if match is None:
        raise AssertionError(f"missing CSS rule: {prelude}")
    depth = 1
    for index in range(match.end(), len(css)):
        depth += (css[index] == "{") - (css[index] == "}")
        if depth == 0:
            return css[match.end():index]
    raise AssertionError(f"unterminated CSS rule: {prelude}")


def _property(rule: str, name: str) -> str:
    matches = re.findall(r"(?:^|;)\s*" + re.escape(name) + r"\s*:\s*([^;]+)", rule)
    if not matches:
        raise AssertionError(f"missing CSS declaration: {name}")
    return re.sub(r"\s+", " ", matches[-1]).strip()


def _base_rule(css: str, selector: str) -> str:
    # A rendered element may receive several simple/combined rules. Resolve
    # their order without accidentally treating a descendant selector or a
    # container-query override as its default rule.
    base = re.split(r"@(?:container|media)\b", css, maxsplit=1)[0]
    rules = [body for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", base)
             if selector in [item.strip() for item in selectors.split(",")]]
    if not rules:
        raise AssertionError(f"missing base CSS rule: {selector}")
    return ";".join(rules)


def _tracks(value: str) -> list[str]:
    # minmax() and repeat() contain spaces; only split outside parentheses.
    return re.findall(r"(?:[^\s()]+|\([^()]*(?:\([^()]*\)[^()]*)*\))+", value)


class ChildPreviewStyleTests(unittest.TestCase):
    """Layout-rule contracts, not a substitute for browser width screenshots."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = APP_JS.read_text(encoding="utf-8")
        cls.baseline = subprocess.check_output(
            ["git", "show", "b6167a0:tcpv_mitm_emitter/app.js"], cwd=APP_JS.parent.parent, text=True
        )
        styles = _packet_function(cls.source, "ensureChildCommonStyles")
        program = """
const installed = [];
const document = {
  createElement: tag => ({ tag, id: '', textContent: '' }),
  getElementById: id => installed.find(style => style.id === id) || null,
  head: { appendChild: style => installed.push(style) },
};
""" + styles + """
ensureChildCommonStyles(); ensureChildCommonStyles();
if (installed.length !== 1) throw new Error('common styles were duplicated');
console.log(JSON.stringify(installed[0].textContent));
"""
        result = subprocess.run(["node"], input=program, capture_output=True, text=True, check=False)
        if result.returncode:
            raise AssertionError(result.stderr[-2000:])
        cls.css = json.loads(result.stdout)

    def query(self, name: str, dimension: str, width: int) -> str:
        match = re.search(rf"@container\s+{name}\s*\(\s*{dimension}\s*:\s*{width}px\s*\)", self.css)
        self.assertIsNotNone(match, f"missing {name} local-width query at {width}px")
        return _css_block(self.css, match.group(0))

    def test_unrelated_production_functions_remain_at_b6167a0(self) -> None:
        names = lambda source: set(re.findall(r"^(?:async )?function (\w+)\(", source, re.M))
        # This follow-up is allowed to change field labels and hierarchy only.
        # Keep every parser, comparison authority, child/hex renderer, style
        # owner and byte-copy path outside that exact presentation scope frozen.
        changed = {"gcloudProtoFieldAlias", "gcloudCompareFieldLabel", "gcloudCompareLeafRows",
                   "buildPacketFieldTable", "installGcloudCompareStyles"}
        added = {"gcloudUnconfirmedLoginResponseField", "gcloudFieldHierarchyEntries", "gcloudFieldDisplayType"}
        self.assertEqual(names(self.baseline) - names(self.source), set(), "production functions were removed")
        self.assertEqual(names(self.source) - names(self.baseline), added, "unexpected new production functions")
        for name in sorted(names(self.baseline) - changed):
            self.assertTrue(_packet_function(self.source, name) == _packet_function(self.baseline, name),
                            f"field presentation work changed unrelated production function {name}")

    def test_preview_uses_its_card_width_without_subgrid_or_shared_tall_rows(self) -> None:
        self.assertNotIn("subgrid", self.css)
        self.assertNotRegex(self.css, r"grid-row\s*:\s*span\s+2\b")
        card = _css_block(self.css, ".child-pair-card")
        preview = _css_block(self.css, ".child-preview-box")
        self.assertEqual(_property(card, "container"), "child-card / inline-size")
        self.assertEqual(_property(preview, "container"), "child-hex / inline-size")
        row = _css_block(self.css, ".child-preview-row")
        self.assertEqual(_property(row, "grid-template-columns"), "minmax(0, 1fr)")
        self.assertEqual(_property(row, "align-items"), "start")
        wide = _css_block(self.query("child-card", "min-width", 1140), ".child-preview-row:not(.child-preview-row-single)")
        self.assertRegex(_property(wide, "grid-template-columns"), r"repeat\(2,\s*minmax\(0,\s*1fr\)\)")
        for media in re.finditer(r"@media\s*\([^{}]+\)", self.css):
            block = _css_block(self.css, media.group(0))
            self.assertNotRegex(block, r"\.child-preview-row\s*\{[^{}]*grid-template-columns",
                                "viewport rules must not override card-local preview layout")

    def test_hex_notes_have_room_on_wide_panels_and_move_below_on_narrow_panels(self) -> None:
        row = _css_block(self.css, ".child-hex-row")
        default_columns = _tracks(_property(row, "grid-template-columns"))
        self.assertEqual(len(default_columns), 3)
        self.assertRegex(default_columns[1], r"minmax\(0,\s*47ch\)")
        note = _css_block(self.css, ".child-hex-note")
        self.assertEqual(_property(note, "grid-column"), "2 / -1")
        self.assertEqual(_property(_css_block(self.css, ".child-hex-note:empty"), "display"), "none")
        wide = self.query("child-hex", "min-width", 760)
        columns = _tracks(_property(_css_block(wide, ".child-hex-row"), "grid-template-columns"))
        self.assertEqual(len(columns), 4)
        self.assertRegex(columns[1], r"minmax\(0,\s*47ch\)")
        self.assertRegex(columns[-1], r"minmax\(160px,\s*1fr\)")
        self.assertIn(_property(_css_block(wide, ".child-hex-note"), "grid-column"), {"auto", "4", "4 / 5"})
        self.assertNotIn(_property(note, "white-space"), {"nowrap", "pre"})
        self.assertNotRegex(note, r"(?:overflow|text-overflow)\s*:\s*(?:hidden|ellipsis)")

    def test_extremely_narrow_hex_keeps_full_scrollable_data_and_natural_row_height(self) -> None:
        narrow = self.query("child-hex", "max-width", 520)
        ascii_rule = _css_block(narrow, ".child-hex-ascii")
        self.assertRegex(_property(ascii_rule, "grid-column"), r"2(?:\s*/\s*-1)?$")
        for selector in (".child-hex-bytes", ".child-hex-ascii"):
            rule = _base_rule(self.css, selector)
            self.assertRegex(_property(rule, "overflow-x"), r"^(?:auto|scroll)$")
            self.assertNotRegex(rule, r"(?:text-overflow\s*:\s*ellipsis|display\s*:\s*none)")
        row = _css_block(self.css, ".child-hex-row")
        for name in ("height", "min-height", "grid-auto-rows"):
            if re.search(r"(?:^|;)\s*" + name + r"\s*:", row):
                self.assertIn(_property(row, name), {"0", "0px", "auto", "min-content", "max-content"})
        # A normal empty-note row must not acquire an artificial second line.
        self.assertNotRegex(row, r"grid-template-rows\s*:\s*(?:repeat\(2|[^;]+\s+[^;]+)")
        # Two-class overrides must win over string/time colors in both themes;
        # fixed pale yellow text is unreadable on a light background.
        for selector in (".child-hex-byte-cell.child-hex-byte-cell-changed",
                         ".child-hex-ascii-cell.child-hex-ascii-cell-changed"):
            self.assertEqual(_property(_base_rule(self.css, selector), "color"), "var(--modified-text)")
        changed_meta = _base_rule(self.css, ".child-rail-meta-changed")
        self.assertEqual(_property(changed_meta, "background"), "var(--modified-bg)")
        self.assertEqual(_property(changed_meta, "color"), "var(--modified-text)")


if __name__ == "__main__":
    unittest.main()
