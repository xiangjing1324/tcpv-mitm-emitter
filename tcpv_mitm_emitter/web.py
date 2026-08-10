INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TCP 包查看器</title>
  <style>
    :root {
      --left-width: 380px;
      --bg: #f4f6f9;
      --panel: #ffffff;
      --line: #d8dee8;
      --text: #1f2937;
      --muted: #5f6b7a;
      --accent: #2f81f7;
      --req: #2b6fc7;
      --resp: #cc3b3b;
      --preview-bg: #eef4ff;
      --preview-line: #cddfff;
      --dump-bg: #f8fafc;
      --dump-head-bg: #eef3f8;
      --chip-bg: #f2f4f8;
      --chip-line: #d8dee8;
      --hex-body-color: #2f3f52;
      --hex-offset-color: #2f81f7;
      --hex-ascii-color: #4a5e74;
      --hex-accent-color: #2f81f7;
      --hex-timestamp-color: #2f7d6b;
      --hex-timestamp-bg: rgba(47, 125, 107, 0.13);
      --hex-timestamp-line: rgba(47, 125, 107, 0.22);
      --hex-idfv-color: #7c3aed;
      --hex-idfv-bg: rgba(124, 58, 237, 0.12);
      --hex-idfv-line: rgba(124, 58, 237, 0.22);
      --hex-history-color: #b45309;
      --hex-history-bg: rgba(180, 83, 9, 0.12);
      --hex-history-line: rgba(180, 83, 9, 0.22);
    }

    :root[data-theme="dark"] {
      --bg: #0b1220;
      --panel: #111827;
      --line: #334155;
      --text: #c7d5e5;
      --muted: #94a3b8;
      --accent: #22d3ee;
      --req: #4c8eda;
      --resp: #d66b6b;
      --preview-bg: #12263a;
      --preview-line: #24425f;
      --dump-bg: #0a1322;
      --dump-head-bg: #0d1a2d;
      --chip-bg: #102436;
      --chip-line: #2b4f6b;
      --hex-body-color: #d1d7e0;
      --hex-offset-color: #61afef;
      --hex-ascii-color: #93a4b8;
      --hex-accent-color: #22d3ee;
      --hex-timestamp-color: #93d7c6;
      --hex-timestamp-bg: rgba(52, 211, 153, 0.13);
      --hex-timestamp-line: rgba(52, 211, 153, 0.20);
      --hex-idfv-color: #c4b5fd;
      --hex-idfv-bg: rgba(167, 139, 250, 0.13);
      --hex-idfv-line: rgba(167, 139, 250, 0.22);
      --hex-history-color: #fdba74;
      --hex-history-bg: rgba(251, 146, 60, 0.13);
      --hex-history-line: rgba(251, 146, 60, 0.22);
    }

    :root[data-theme="github-dark"] {
      --bg: #0d1117;
      --panel: #161b22;
      --line: #30363d;
      --text: #c9d1d9;
      --muted: #8b949e;
      --accent: #58a6ff;
      --req: #58a6ff;
      --resp: #f85149;
      --preview-bg: #1f2937;
      --preview-line: #374151;
      --dump-bg: #0f141a;
      --dump-head-bg: #111a24;
      --chip-bg: #21262d;
      --chip-line: #30363d;
      --hex-body-color: #d0d7de;
      --hex-offset-color: #58a6ff;
      --hex-ascii-color: #8b949e;
      --hex-accent-color: #58a6ff;
      --hex-timestamp-color: #8fd8c4;
      --hex-timestamp-bg: rgba(52, 211, 153, 0.12);
      --hex-timestamp-line: rgba(52, 211, 153, 0.18);
      --hex-idfv-color: #c4b5fd;
      --hex-idfv-bg: rgba(167, 139, 250, 0.12);
      --hex-idfv-line: rgba(167, 139, 250, 0.20);
      --hex-history-color: #fdba74;
      --hex-history-bg: rgba(251, 146, 60, 0.12);
      --hex-history-line: rgba(251, 146, 60, 0.20);
    }

    * { box-sizing: border-box; }

    html, body {
      margin: 0;
      height: 100%;
      background: var(--bg);
      color: var(--text);
      font-family: "SF Mono", "Menlo", "Consolas", monospace;
      font-size: 12px;
      overflow: hidden;
    }

    .app {
      height: 100vh;
      display: grid;
      grid-template-columns: minmax(260px, var(--left-width)) 8px 1fr;
      min-width: 0;
      overflow: hidden;
    }

    .app.sidebar-hidden {
      grid-template-columns: minmax(0, 1fr);
    }

    .app.sidebar-hidden .left,
    .app.sidebar-hidden .splitter {
      display: none;
    }

    .left {
      border-right: 1px solid var(--line);
      background: var(--panel);
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr);
      min-width: 0;
      overflow: hidden;
    }

    .splitter {
      background: color-mix(in srgb, var(--line) 72%, transparent);
      cursor: col-resize;
      user-select: none;
      position: relative;
    }
    .splitter::after {
      content: "";
      position: absolute;
      top: 0;
      bottom: 0;
      left: 2px;
      width: 2px;
      background: color-mix(in srgb, var(--accent) 45%, transparent);
      opacity: 0.0;
      transition: opacity 120ms ease;
    }
    .splitter:hover::after,
    .app.dragging .splitter::after {
      opacity: 1;
    }

    .left-head {
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .left-title {
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.2px;
    }

    .left-tools {
      display: flex;
      align-items: center;
      gap: 6px;
      min-width: 0;
      flex-wrap: wrap;
      justify-content: flex-end;
    }

    .left-tools .count {
      color: var(--muted);
    }

    .left-tools button {
      height: 26px;
      padding: 4px 8px;
    }

    .flow-cols {
      display: grid;
      grid-template-columns: minmax(110px, 1fr) 38px 54px 78px;
      gap: 4px;
      padding: 7px 8px;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
      font-weight: 700;
      background: color-mix(in srgb, var(--panel) 82%, var(--bg));
    }

    #flowList {
      overflow: auto;
      min-height: 0;
      overscroll-behavior: contain;
    }

    .flow-row {
      width: 100%;
      border: 0;
      border-bottom: 1px solid color-mix(in srgb, var(--line) 70%, transparent);
      padding: 6px 8px;
      margin: 0;
      text-align: left;
      font: inherit;
      color: inherit;
      display: grid;
      grid-template-columns: minmax(110px, 1fr) 38px 54px 78px;
      gap: 4px;
      align-items: center;
      cursor: pointer;
      background: var(--panel);
      min-width: 0;
    }

    .flow-row:hover { background: color-mix(in srgb, var(--panel) 75%, var(--accent)); }

    .flow-row.active {
      background: color-mix(in srgb, var(--panel) 70%, var(--accent));
      border-left: 3px solid var(--accent);
      padding-left: 5px;
    }

    .flow-row > div {
      min-width: 0;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .flow-path {
      display: flex;
      align-items: center;
      gap: 5px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      line-height: 1.25;
      min-width: 0;
    }

    .flow-time {
      white-space: nowrap;
      text-align: left;
    }

    .flow-time-open {
      color: var(--accent);
      font-weight: 700;
    }

    .flow-time-closed {
      color: var(--muted);
    }

    .render-window-note {
      margin: 8px 10px;
      padding: 8px 10px;
      border: 1px solid color-mix(in srgb, #f59e0b 46%, var(--line));
      border-radius: 6px;
      background: color-mix(in srgb, #f59e0b 10%, var(--panel));
      color: color-mix(in srgb, #f59e0b 72%, var(--text));
      font-size: 12px;
      line-height: 1.45;
    }

    .badge-tcp {
      color: var(--resp);
      border: 1px solid color-mix(in srgb, var(--resp) 60%, var(--line));
      border-radius: 3px;
      font-weight: 700;
      padding: 0 4px;
      display: inline-block;
      flex: 0 0 auto;
    }

    .badge-kp {
      color: #ffe082;
      background: rgba(245, 158, 11, 0.14);
      border: 1px solid rgba(245, 158, 11, 0.64);
      border-radius: 3px;
      font-weight: 800;
      padding: 0 4px;
      display: inline-block;
      flex: 0 0 auto;
    }

    .flow-cid {
      color: var(--text);
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .right {
      display: grid;
      grid-template-rows: auto auto auto auto auto minmax(0, 1fr);
      background: var(--panel);
      min-width: 0;
      overflow: hidden;
    }

    .tabs {
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 10px;
      color: var(--muted);
      background: color-mix(in srgb, var(--panel) 84%, var(--bg));
      overflow-x: auto;
    }

    .tab.active {
      color: var(--text);
      font-weight: 700;
    }

    .toolbar {
      border-bottom: 1px solid var(--line);
      display: grid;
      grid-template-columns: 76px minmax(260px, 1fr) 78px 88px 232px 96px 106px 92px 88px 118px;
      gap: 8px;
      align-items: center;
      padding: 8px 10px;
      min-width: 0;
    }

    .filterbar {
      border-bottom: 1px solid var(--line);
      display: grid;
      grid-template-columns: minmax(260px, 1fr) 146px 56px 72px 62px 62px 74px 88px 94px 94px 96px 72px 72px;
      gap: 8px;
      align-items: center;
      padding: 8px 10px;
      min-width: 0;
    }

    .filter-check {
      height: 30px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 5px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--chip-bg);
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      cursor: pointer;
      user-select: none;
    }

    .filter-check input {
      width: 14px;
      height: 14px;
      margin: 0;
    }

    .toolbar .headline {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-weight: 700;
      min-width: 0;
    }

    .sidebar-toggle {
      white-space: nowrap;
    }

    input, select, button {
      border: 1px solid var(--line);
      background: var(--chip-bg);
      color: var(--text);
      border-radius: 5px;
      font: inherit;
      padding: 5px 7px;
      height: 28px;
      min-width: 0;
    }

    input.input-invalid {
      border-color: var(--resp);
      box-shadow: 0 0 0 1px color-mix(in srgb, var(--resp) 55%, transparent);
    }

    button {
      cursor: pointer;
      border-color: var(--chip-line);
    }

    button:hover {
      border-color: var(--accent);
    }

    button:disabled {
      cursor: not-allowed;
      opacity: 0.55;
      border-color: var(--line);
    }

    .preview-offset-group {
      display: grid;
      grid-template-columns: 24px 24px minmax(80px, 1fr) 24px 56px;
      gap: 4px;
      align-items: center;
      min-width: 0;
    }

    .preview-offset-label {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      color: var(--muted);
      font-size: 11px;
      border: 1px solid var(--line);
      border-radius: 5px;
      height: 28px;
      background: color-mix(in srgb, var(--chip-bg) 86%, transparent);
    }

    .preview-offset-range {
      width: 100%;
      padding: 0;
      height: 28px;
      background: transparent;
      border: 1px solid var(--line);
      border-radius: 5px;
    }

    .preview-offset-input {
      text-align: right;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
    }

    .mini-btn {
      padding: 0;
      width: 24px;
      min-width: 24px;
      text-align: center;
      font-weight: 700;
    }

    .tool-stat {
      height: 28px;
      border: 1px solid var(--line);
      background: color-mix(in srgb, var(--chip-bg) 86%, transparent);
      border-radius: 5px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--muted);
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
      white-space: nowrap;
      padding: 0 7px;
    }

    .status {
      border-bottom: 1px solid var(--line);
      padding: 6px 10px;
      color: var(--muted);
      background: color-mix(in srgb, var(--panel) 88%, var(--bg));
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .rule-guide {
      border-bottom: 1px solid var(--line);
      padding: 6px 10px;
      color: var(--muted);
      background: color-mix(in srgb, var(--panel) 90%, var(--bg));
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    #events {
      overflow: auto;
      min-height: 0;
      padding: 10px;
      display: block;
      overscroll-behavior: contain;
    }

    .empty {
      border: 1px dashed var(--line);
      border-radius: 8px;
      padding: 18px;
      text-align: center;
      color: var(--muted);
      background: color-mix(in srgb, var(--panel) 90%, var(--bg));
    }

    details {
      border: 0;
      border-bottom: 1px solid color-mix(in srgb, var(--line) 72%, transparent);
      border-radius: 0;
      background: transparent;
      overflow: visible;
      margin: 0;
    }

    details.event-hit > summary {
      background: color-mix(in srgb, var(--accent) 5%, transparent);
    }

    details.event-hit-current {
      border-bottom-color: color-mix(in srgb, var(--accent) 40%, var(--line));
    }

    details.event-hit-current > summary {
      background: color-mix(in srgb, var(--accent) 10%, var(--panel));
    }

    details.no-expand > summary {
      cursor: default;
    }

    details.no-expand > summary::after {
      content: attr(data-no-expand-label);
      margin-left: 8px;
      color: var(--muted);
      font-size: 11px;
      opacity: 0.85;
      flex: 0 0 auto;
    }

    summary {
      list-style: none;
      cursor: pointer;
      padding: 8px 10px 8px 8px;
      border-left: 3px solid var(--line);
      display: flex;
      align-items: center;
      gap: 6px;
      white-space: nowrap;
      font-size: 12px;
      line-height: 1.25;
      min-height: 30px;
      min-width: 0;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
    }

    summary::-webkit-details-marker { display: none; }

    summary:hover {
      background: color-mix(in srgb, var(--panel) 82%, var(--bg));
    }

    details[open] > summary {
      background: color-mix(in srgb, var(--panel) 90%, var(--bg));
    }

    details.event-req > summary { border-left-color: var(--req); }
    details.event-resp > summary { border-left-color: var(--resp); }

    .summary-fixed { flex: 0 0 auto; }

    .summary-ts {
      flex: 0 0 10ch;
    }

    .summary-dir {
      flex: 0 0 4ch;
      text-align: center;
    }

    .summary-len {
      flex: 0 0 9ch;
      text-align: left;
    }

	    .summary-preview {
	      flex: 0 0 auto;
	      min-width: max-content;
	      display: flex;
	      align-items: center;
	      overflow: visible;
	      white-space: nowrap;
	    }

	    .summary-insights {
	      flex: 1 1 auto;
	      min-width: 0;
	      display: flex;
	      align-items: center;
	      gap: 4px;
	      overflow: visible;
	      white-space: nowrap;
	    }

	    .summary-insight-chip {
	      flex: 0 0 auto;
	      min-width: 0;
	      max-width: none;
	      padding: 1px 6px;
	      border: 1px solid var(--summary-chip-line, color-mix(in srgb, var(--accent) 42%, var(--line)));
	      border-radius: 999px;
	      background: var(--summary-chip-bg, color-mix(in srgb, var(--accent) 8%, var(--panel)));
	      color: var(--summary-chip-color, color-mix(in srgb, var(--text) 88%, var(--accent)));
	      font-size: 11px;
	      line-height: 1.35;
	      overflow: visible;
	      text-overflow: clip;
	    }

    .summary-insight-semantic {
      --summary-chip-color: var(--hex-idfv-color);
      --summary-chip-bg: var(--hex-idfv-bg);
      --summary-chip-line: var(--hex-idfv-line);
      font-weight: 700;
    }

    .summary-insight-device {
      --summary-chip-color: #7dd3fc;
      --summary-chip-bg: rgba(14, 165, 233, 0.12);
      --summary-chip-line: rgba(14, 165, 233, 0.28);
    }

    .summary-insight-file {
      --summary-chip-color: #93c5fd;
      --summary-chip-bg: rgba(59, 130, 246, 0.12);
      --summary-chip-line: rgba(59, 130, 246, 0.26);
    }

    .summary-insight-state {
      --summary-chip-color: #86efac;
      --summary-chip-bg: rgba(34, 197, 94, 0.12);
      --summary-chip-line: rgba(34, 197, 94, 0.26);
    }

    .summary-insight-type {
      --summary-chip-color: #cbd5e1;
      --summary-chip-bg: rgba(148, 163, 184, 0.12);
      --summary-chip-line: rgba(148, 163, 184, 0.22);
    }

    .summary-insight-child {
      --summary-chip-color: #fde68a;
      --summary-chip-bg: rgba(245, 158, 11, 0.13);
      --summary-chip-line: rgba(245, 158, 11, 0.26);
    }

    .summary-insight-time {
      --summary-chip-color: var(--hex-timestamp-color);
      --summary-chip-bg: var(--hex-timestamp-bg);
      --summary-chip-line: var(--hex-timestamp-line);
      font-weight: 700;
    }

    .summary-ts,
    .summary-len {
      color: var(--muted);
      opacity: 0.72;
      font-size: 11px;
    }

    .summary-extra {
      flex: 0 1 auto;
      max-width: 20ch;
      color: var(--muted);
      opacity: 0.9;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      min-width: 0;
    }

    .summary-extra:empty {
      display: none;
    }

    .summary-timestamp,
    .summary-idfv,
    .summary-history-openid {
      flex: 0 0 auto;
      padding: 1px 6px;
      border-radius: 999px;
      font-weight: 700;
      line-height: 1.35;
      white-space: nowrap;
    }

    .summary-timestamp {
      border: 1px solid var(--hex-timestamp-line);
      background: var(--hex-timestamp-bg);
      color: var(--hex-timestamp-color);
    }

    .summary-idfv {
      border: 1px solid var(--hex-idfv-line);
      background: var(--hex-idfv-bg);
      color: var(--hex-idfv-color);
    }

    .summary-history-openid {
      border: 1px solid var(--hex-history-line);
      background: var(--hex-history-bg);
      color: var(--hex-history-color);
    }

    .summary-tail {
      flex: 0 0 auto;
      max-width: 16ch;
      overflow: hidden;
      text-overflow: ellipsis;
      color: var(--muted);
      font-size: 11px;
    }

    .dir-badge {
      display: inline-block;
      width: 13px;
      text-align: center;
      font-weight: 700;
    }
    .dir-req { color: var(--req); }
    .dir-resp { color: var(--resp); }

    .len-field {
      display: inline-block;
      width: 5ch;
      text-align: right;
    }

    .preview-hex {
      display: inline-block;
      min-width: 0;
      max-width: none;
      white-space: pre;
      line-height: 1.25;
      background: color-mix(in srgb, var(--preview-bg) 38%, transparent);
      border: 0;
      border-radius: 3px;
      padding: 0 2px;
      color: var(--text);
      overflow: visible;
      text-overflow: clip;
      vertical-align: bottom;
    }

    .preview-byte {
      display: inline-block;
      border-radius: 2px;
      padding: 0 1px;
    }

    .preview-byte-hit {
      border-radius: 2px;
      box-shadow: none;
    }

    .preview-hit-outside {
      border-style: dashed;
      border-width: 1px;
    }

    .preview-hi {
      display: inline-block;
      margin-left: 6px;
      padding: 0 5px;
      border: 1px solid var(--hex-history-line);
      border-radius: 999px;
      background: var(--hex-history-bg);
      color: var(--hex-history-color);
      font-weight: 700;
      line-height: 1.25;
      white-space: nowrap;
      vertical-align: bottom;
    }

    .body {
      border-top: 1px solid var(--line);
      background: color-mix(in srgb, var(--panel) 92%, var(--bg));
      padding: 8px 10px;
    }

    .meta {
      color: var(--muted);
      margin-bottom: 6px;
    }

    .event-readable-summary {
      margin-bottom: 8px;
      display: grid;
      gap: 6px;
      min-width: 0;
    }

    .event-summary-primary {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      min-width: 0;
    }

    .event-summary-chip {
      max-width: 100%;
      min-width: 0;
      padding: 5px 8px;
      border: 1px solid var(--chip-line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--chip-bg) 88%, transparent);
      color: var(--text);
      line-height: 1.35;
      overflow-wrap: anywhere;
    }

    .event-summary-chip-report,
    .event-summary-chip-protect {
      border-color: color-mix(in srgb, var(--accent) 58%, var(--line));
    }

    .event-summary-chip-sim,
    .event-summary-chip-mode,
    .event-summary-chip-match {
      color: color-mix(in srgb, var(--text) 88%, var(--accent));
    }

    .event-summary-chip-warn {
      border-color: color-mix(in srgb, #f59e0b 62%, var(--line));
      background: color-mix(in srgb, #f59e0b 12%, var(--panel));
      color: color-mix(in srgb, #f59e0b 78%, var(--text));
    }

    .event-summary-transport {
      display: flex;
      flex-wrap: wrap;
      gap: 5px 10px;
      color: var(--muted);
      font-size: 11px;
      min-width: 0;
    }

    .event-summary-debug {
      color: var(--muted);
      font-size: 12px;
    }

    .event-summary-debug summary {
      cursor: pointer;
      width: fit-content;
    }

    .event-summary-debug pre {
      margin: 5px 0 0;
      padding: 7px 8px;
      border: 1px dashed var(--line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--dump-bg) 78%, var(--panel));
      color: var(--muted);
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }

    .analysis-grid {
      margin-top: 10px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 10px;
      align-items: start;
    }

    .analysis-debug-details {
      margin-top: 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--panel) 90%, var(--bg));
      overflow: hidden;
    }

    .analysis-debug-details > summary {
      cursor: pointer;
      user-select: none;
      padding: 7px 10px;
      font-weight: 700;
      color: var(--muted);
      border-bottom: 1px solid transparent;
    }

    .analysis-debug-details[open] > summary {
      border-bottom-color: var(--line);
    }

    .analysis-debug-details .analysis-grid {
      margin: 0;
      padding: 10px;
    }

    .analysis-card {
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--panel) 92%, var(--bg));
      overflow: hidden;
    }

    .analysis-card-head {
      padding: 6px 10px;
      border-bottom: 1px solid var(--line);
      font-weight: 700;
      letter-spacing: 0.01em;
      color: var(--text);
      background: color-mix(in srgb, var(--chip-bg) 86%, transparent);
    }

    .analysis-card-meta .analysis-card-head {
      color: color-mix(in srgb, var(--accent) 82%, var(--text));
    }

    .analysis-card-strings .analysis-card-head {
      color: color-mix(in srgb, var(--resp) 68%, var(--text));
    }

    .analysis-card-xor .analysis-card-head {
      color: color-mix(in srgb, var(--req) 72%, var(--text));
    }

    .analysis-card-body {
      padding: 8px 10px;
      display: grid;
      gap: 8px;
      min-width: 0;
      max-height: min(520px, 56vh);
      overflow: auto;
      overscroll-behavior: contain;
    }

    .analysis-card-strings .analysis-card-body {
      max-height: min(620px, 62vh);
    }

    .analysis-chip-list {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      min-width: 0;
    }

    .analysis-chip {
      display: inline-flex;
      align-items: center;
      max-width: 100%;
      min-height: 24px;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid var(--chip-line);
      background: color-mix(in srgb, var(--chip-bg) 88%, transparent);
      color: var(--text);
      line-height: 1.25;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .analysis-chip-soft {
      color: var(--muted);
    }

    .analysis-section-title {
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .analysis-list {
      display: grid;
      gap: 6px;
      min-width: 0;
    }

    .analysis-row {
      display: grid;
      grid-template-columns: 72px minmax(0, 1fr);
      gap: 8px;
      min-width: 0;
      align-items: start;
    }

    .analysis-row-label {
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding-top: 1px;
    }

    .analysis-row-value {
      min-width: 0;
      color: var(--text);
      white-space: pre-wrap;
      word-break: break-word;
      line-height: 1.4;
    }

    .analysis-string-list {
      display: grid;
      gap: 6px;
      min-width: 0;
    }

    .analysis-string-item {
      display: grid;
      grid-template-columns: minmax(92px, max-content) minmax(0, 1fr);
      gap: 10px;
      min-width: 0;
      align-items: start;
    }

    .analysis-string-off {
      color: var(--muted);
      font-size: 11px;
      padding-top: 2px;
      white-space: nowrap;
    }

    .analysis-string-text {
      min-width: 0;
      line-height: 1.4;
      word-break: break-word;
    }

    .analysis-string-compare {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      min-width: 0;
    }

    .analysis-string-side {
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--dump-bg) 84%, var(--panel));
      padding: 6px 7px;
      display: grid;
      gap: 6px;
    }

    .analysis-string-side-before {
      border-color: color-mix(in srgb, #f59e0b 42%, var(--line));
    }

    .analysis-string-side-after {
      border-color: color-mix(in srgb, var(--resp) 42%, var(--line));
    }

    .analysis-string-side-label {
      color: var(--text);
      font-weight: 700;
      line-height: 1.25;
    }

    .analysis-empty {
      color: var(--muted);
      line-height: 1.4;
    }

    .analysis-note {
      color: var(--muted);
      line-height: 1.45;
      font-size: 12px;
      padding: 6px 8px;
      border: 1px dashed var(--line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--panel) 88%, transparent);
    }

    .dump-grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 10px;
    }

    .dump-grid-request,
    .dump-grid-response {
      align-items: start;
    }

    .dump-grid > .child-compare-inline {
      grid-column: 1 / -1;
      width: 100%;
      min-width: 0;
      overflow-x: hidden;
    }

    .dump-grid-request.dump-grid-decrypted {
      grid-template-columns: repeat(2, minmax(520px, 1fr));
      grid-template-rows: auto;
      align-items: start;
      overflow-x: auto;
      scrollbar-gutter: stable;
    }

    .dump-grid-request.dump-grid-decrypted .dump-panel-full,
    .dump-grid-request.dump-grid-decrypted .string-result-inline,
    .dump-grid-request.dump-grid-decrypted .child-compare-inline {
      grid-column: 1 / 3;
    }

    .dump-grid-request.dump-grid-decrypted.has-raw-compare .dump-panel-full {
      grid-column: 1;
    }

    .dump-grid-request.dump-grid-decrypted.has-raw-compare .dump-panel-raw-after {
      grid-column: 2;
    }

    .dump-grid-request.dump-grid-decrypted .dump-panel-before {
      grid-column: 1;
    }

    .dump-grid-request.dump-grid-decrypted .dump-panel-decoded {
      grid-column: 2;
    }

    .dump-grid-request.dump-grid-decrypted.child-structure-current-only,
    .dump-grid-request.child-structure-current-only {
      grid-template-columns: minmax(0, 1fr);
      overflow-x: hidden;
    }

    .dump-grid-request.dump-grid-decrypted.child-structure-current-only > .dump-panel-full,
    .dump-grid-request.dump-grid-decrypted.child-structure-current-only > .dump-panel-raw-after,
    .dump-grid-request.dump-grid-decrypted.child-structure-current-only > .dump-panel-before,
    .dump-grid-request.dump-grid-decrypted.child-structure-current-only > .dump-panel-decoded,
    .dump-grid-request.dump-grid-decrypted.child-structure-current-only > .string-result-inline,
    .dump-grid-request.dump-grid-decrypted.child-structure-current-only > .child-compare-inline,
    .dump-grid-request.child-structure-current-only > .dump-panel-full,
    .dump-grid-request.child-structure-current-only > .dump-panel-raw-after,
    .dump-grid-request.child-structure-current-only > .dump-panel-before,
    .dump-grid-request.child-structure-current-only > .dump-panel-decoded,
    .dump-grid-request.child-structure-current-only > .string-result-inline,
    .dump-grid-request.child-structure-current-only > .child-compare-inline {
      grid-column: 1 / -1;
      width: 100%;
      min-width: 0;
    }

    .dump-panel {
      min-width: 0;
    }

    .dump-label {
      margin-bottom: 6px;
      padding: 6px 10px;
      border-radius: 6px;
      font-weight: 700;
      letter-spacing: 0.01em;
      border: 1px solid var(--line);
      color: var(--text);
      background: color-mix(in srgb, var(--panel) 94%, var(--bg));
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .dump-label-note {
      display: inline-flex;
      align-items: center;
      min-height: 18px;
      padding: 1px 7px;
      border-radius: 999px;
      border: 1px solid var(--chip-line);
      background: color-mix(in srgb, var(--chip-bg) 80%, transparent);
      color: var(--muted);
      font-size: 11px;
      line-height: 1.35;
      letter-spacing: 0;
    }

    .dump-label-timestamp {
      border-color: var(--hex-timestamp-line);
      background: var(--hex-timestamp-bg);
      color: var(--hex-timestamp-color);
    }

    .dump-label-idfv {
      border-color: var(--hex-idfv-line);
      background: var(--hex-idfv-bg);
      color: var(--hex-idfv-color);
    }

    .dump-label-history-openid {
      border-color: var(--hex-history-line);
      background: var(--hex-history-bg);
      color: var(--hex-history-color);
    }

    .dump-label-semantic {
      border-color: color-mix(in srgb, var(--accent) 38%, var(--chip-line));
      background: color-mix(in srgb, var(--accent) 11%, var(--panel));
      color: color-mix(in srgb, var(--text) 82%, var(--accent));
    }

    .dump-panel-full .dump-label {
      border-color: color-mix(in srgb, var(--req) 52%, var(--line));
      background: color-mix(in srgb, var(--req) 12%, var(--panel));
      color: color-mix(in srgb, var(--req) 65%, var(--text));
    }

    .dump-panel-decoded .dump-label {
      border-color: color-mix(in srgb, var(--resp) 52%, var(--line));
      background: color-mix(in srgb, var(--resp) 12%, var(--panel));
      color: color-mix(in srgb, var(--resp) 68%, var(--text));
    }

    .dump-panel-raw-after .dump-label {
      border-color: color-mix(in srgb, var(--resp) 52%, var(--line));
      background: color-mix(in srgb, var(--resp) 10%, var(--panel));
      color: color-mix(in srgb, var(--resp) 66%, var(--text));
    }

    .dump-panel-before .dump-label {
      border-color: color-mix(in srgb, #f59e0b 52%, var(--line));
      background: color-mix(in srgb, #f59e0b 13%, var(--panel));
      color: color-mix(in srgb, #f59e0b 76%, var(--text));
    }

    .dump-panel-single .dump-label {
      border-color: color-mix(in srgb, var(--line) 85%, var(--text));
    }

    .dump-panel-empty .dump-label {
      opacity: 0.88;
    }

    .dump-empty {
      min-height: 118px;
      display: flex;
      align-items: center;
      padding: 14px 16px;
      border: 1px dashed var(--line);
      border-radius: 6px;
      background:
        repeating-linear-gradient(
          -45deg,
          color-mix(in srgb, var(--dump-bg) 88%, transparent),
          color-mix(in srgb, var(--dump-bg) 88%, transparent) 8px,
          color-mix(in srgb, var(--panel) 92%, transparent) 8px,
          color-mix(in srgb, var(--panel) 92%, transparent) 16px
        );
      color: var(--muted);
      line-height: 1.55;
      white-space: normal;
    }

	    .hex-shell {
	      border: 1px solid var(--line);
	      border-radius: 6px;
	      background: var(--dump-bg);
	      overflow: auto;
	      scrollbar-gutter: stable;
	    }

	    .hex-shell::-webkit-scrollbar {
	      width: 10px;
	      height: 10px;
	    }

	    .hex-shell::-webkit-scrollbar-track {
	      background: color-mix(in srgb, var(--dump-bg) 82%, var(--panel));
	    }

	    .hex-shell::-webkit-scrollbar-thumb {
	      border: 2px solid color-mix(in srgb, var(--dump-bg) 82%, var(--panel));
	      border-radius: 999px;
	      background: color-mix(in srgb, var(--accent) 52%, var(--muted));
	    }

	    .dump-fold > summary.dump-label {
	      list-style: none;
	      cursor: pointer;
	      border-left: 0;
	      min-height: 0;
	      margin-bottom: 0;
	      user-select: none;
	    }

	    .dump-fold > summary.dump-label::-webkit-details-marker {
	      display: none;
	    }

	    .dump-fold > summary.dump-label::after {
	      content: "展开";
	      margin-left: auto;
	      color: var(--muted);
	      font-size: 11px;
	      font-weight: 700;
	    }

	    .dump-fold[open] > summary.dump-label {
	      margin-bottom: 6px;
	    }

	    .dump-fold[open] > summary.dump-label::after {
	      content: "收起";
	    }

	    .dump-grid-request.dump-grid-decrypted .dump-panel-before .hex-shell,
	    .dump-grid-request.dump-grid-decrypted .dump-panel-decoded .hex-shell {
	      max-height: none;
	    }

    .dump-panel-full .hex-shell {
      border-color: color-mix(in srgb, var(--req) 42%, var(--line));
      box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--req) 10%, transparent);
    }

    .dump-panel-decoded .hex-shell {
      border-color: color-mix(in srgb, var(--resp) 42%, var(--line));
      box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--resp) 10%, transparent);
    }

    .dump-panel-raw-after .hex-shell {
      border-color: color-mix(in srgb, var(--resp) 42%, var(--line));
      box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--resp) 8%, transparent);
    }

    .dump-panel-before .hex-shell {
      border-color: color-mix(in srgb, #f59e0b 42%, var(--line));
      box-shadow: inset 0 0 0 1px color-mix(in srgb, #f59e0b 10%, transparent);
    }

    .hex-head {
      position: sticky;
      top: 0;
      z-index: 1;
      padding: 5px 9px;
      border-bottom: 1px solid var(--line);
      background: var(--dump-head-bg);
      color: var(--muted);
      white-space: pre;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
    }

    .hex-body {
      margin: 0;
      padding: 7px 9px 8px;
      white-space: pre;
      line-height: 1.34;
      word-break: normal;
      overflow-wrap: normal;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
      color: var(--hex-body-color);
      tab-size: 2;
    }

    .hex-offset {
      color: var(--hex-offset-color);
      font-weight: 700;
    }

    .hex-bytes {
      color: var(--hex-body-color);
    }

    .hex-byte-changed {
      color: #ffd36a;
      background: rgba(255, 179, 46, 0.24);
      border-radius: 3px;
      box-shadow: 0 0 0 1px rgba(255, 179, 46, 0.18);
    }

    .hex-byte-timestamp {
      color: var(--hex-timestamp-color);
      background: var(--hex-timestamp-bg);
      border-radius: 3px;
      box-shadow: 0 0 0 1px var(--hex-timestamp-line);
    }

    .hex-byte-idfv {
      color: var(--hex-idfv-color);
      background: var(--hex-idfv-bg);
      border-radius: 3px;
      box-shadow: 0 0 0 1px var(--hex-idfv-line);
    }

    .hex-byte-history {
      color: var(--hex-history-color);
      background: var(--hex-history-bg);
      border-radius: 3px;
      box-shadow: 0 0 0 1px var(--hex-history-line);
    }

    .hex-ascii {
      color: var(--hex-ascii-color);
      opacity: 0.82;
    }

    .hex-ascii-compact {
      color: color-mix(in srgb, var(--hex-ascii-color) 70%, var(--muted));
    }

    .hex-ascii-bar {
      color: color-mix(in srgb, var(--hex-accent-color) 72%, var(--line));
      font-weight: 700;
    }

    .hex-comment {
      color: color-mix(in srgb, var(--accent) 64%, var(--muted));
      display: inline-block;
      max-width: none;
      white-space: pre;
      overflow-wrap: normal;
      word-break: normal;
      vertical-align: top;
    }

    .hex-comment-block {
      display: block;
      margin-left: 9ch;
      margin-top: 2px;
      margin-bottom: 2px;
      padding: 2px 8px;
      border-left: 2px solid color-mix(in srgb, var(--accent) 42%, var(--line));
      border-radius: 0 4px 4px 0;
      background: color-mix(in srgb, var(--accent) 7%, transparent);
      max-width: min(148ch, calc(100vw - 240px));
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: normal;
      line-height: 1.38;
    }

    .tree-shell {
      margin-top: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--dump-bg) 88%, var(--panel));
      overflow: auto;
      max-height: min(720px, 70vh);
    }

    .tree-compare-row {
      margin-top: 10px;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      align-items: start;
    }

    .tree-compare-panel {
      min-width: 0;
    }

    .tree-shell-compare {
      margin-top: 0;
      max-height: min(760px, 72vh);
    }

    .child-compare {
      margin-top: 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--dump-bg) 96%, var(--panel));
      overflow: hidden;
    }

    .child-compare-head {
      padding: 6px 9px;
      border-bottom: 1px solid var(--line);
      background: color-mix(in srgb, var(--chip-bg) 72%, transparent);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
      font-weight: 700;
    }

    .child-compare-head small {
      color: var(--muted);
      font-weight: 400;
    }

    .child-compare-grid {
      padding: 6px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(760px, 100%), 1fr));
      gap: 6px;
      align-items: start;
    }

    .child-pair-card {
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--dump-bg) 98%, var(--panel));
      padding: 0;
      display: grid;
      gap: 0;
      line-height: 1.35;
      overflow: hidden;
    }

    .child-card-result-changed {
      border-color: color-mix(in srgb, #22c55e 44%, var(--line));
      background: color-mix(in srgb, #22c55e 2%, var(--dump-bg));
    }

    .child-card-result-same {
      border-color: color-mix(in srgb, #f59e0b 48%, var(--line));
      background: color-mix(in srgb, #f59e0b 3%, var(--dump-bg));
    }

    .child-card-result-struct {
      border-color: color-mix(in srgb, var(--resp) 46%, var(--line));
      background: color-mix(in srgb, var(--resp) 3%, var(--dump-bg));
    }

    .child-pair-title,
    .child-side-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      min-width: 0;
      font-weight: 700;
    }

    .child-pair-title {
      padding: 5px 8px;
      border-bottom: 1px solid color-mix(in srgb, var(--line) 78%, transparent);
      background: color-mix(in srgb, var(--chip-bg) 54%, transparent);
    }

    .child-title-badges {
      display: inline-flex;
      align-items: center;
      justify-content: flex-end;
      gap: 6px;
      min-width: 0;
      flex-wrap: wrap;
    }

    .child-pair-sides {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 6px;
      min-width: 0;
      align-items: start;
      padding: 6px;
    }

    .child-side {
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--dump-bg) 90%, var(--panel));
      padding: 6px 7px;
      display: grid;
      align-content: start;
      gap: 4px;
    }

	    .string-result-panel {
	      border: 1px solid var(--line);
	      border-radius: 6px;
	      background: color-mix(in srgb, var(--panel) 92%, var(--bg));
	      overflow: hidden;
	      min-width: 0;
	    }

    .string-result-head {
      padding: 4px 9px;
      border-bottom: 1px solid var(--line);
      background: color-mix(in srgb, var(--chip-bg) 84%, transparent);
      color: var(--text);
      font-weight: 700;
    }

	    .string-result-grid {
	      display: grid;
	      grid-template-columns: repeat(2, minmax(0, 1fr));
	      gap: 6px;
	      padding: 6px 8px;
	      max-height: min(300px, 36vh);
	      overflow: auto;
	    }

    .string-result-side {
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: color-mix(in srgb, var(--dump-bg) 82%, var(--panel));
      padding: 5px 7px;
    }

    .string-result-side-before {
      border-color: color-mix(in srgb, #f59e0b 42%, var(--line));
    }

    .string-result-side-after {
      border-color: color-mix(in srgb, var(--resp) 42%, var(--line));
    }

    .string-result-label {
      margin-bottom: 3px;
      font-weight: 700;
      color: var(--text);
    }

	    .string-result-side pre {
	      margin: 0;
	      white-space: pre-wrap;
	      overflow-wrap: anywhere;
	      color: color-mix(in srgb, var(--muted) 86%, var(--text));
	      line-height: 1.28;
	      font-size: 11px;
	    }

    .child-side-before {
      border-color: color-mix(in srgb, #f59e0b 42%, var(--line));
      background: color-mix(in srgb, #f59e0b 4%, var(--dump-bg));
    }

    .child-side-after {
      border-color: color-mix(in srgb, var(--resp) 42%, var(--line));
      background: color-mix(in srgb, var(--resp) 4%, var(--dump-bg));
    }

    .child-side-label {
      flex: 0 0 auto;
      color: var(--muted);
      font-size: 11px;
      border: 1px solid var(--chip-line);
      border-radius: 999px;
      padding: 1px 7px;
      background: color-mix(in srgb, var(--chip-bg) 80%, transparent);
    }

    .child-status {
      flex: 0 0 auto;
      border: 1px solid var(--chip-line);
      border-radius: 999px;
      padding: 1px 7px;
      font-size: 11px;
      color: var(--text);
      background: color-mix(in srgb, var(--chip-bg) 82%, transparent);
      white-space: nowrap;
    }

    .child-status-changed {
      border-color: color-mix(in srgb, #22c55e 58%, var(--line));
      color: color-mix(in srgb, #22c55e 78%, var(--text));
    }

    .child-status-same {
      border-color: color-mix(in srgb, #f59e0b 58%, var(--line));
      color: color-mix(in srgb, #f59e0b 82%, var(--text));
    }

    .child-status-struct {
      border-color: color-mix(in srgb, var(--resp) 58%, var(--line));
      color: color-mix(in srgb, var(--resp) 76%, var(--text));
    }

    .child-action-status-keep {
      border-color: color-mix(in srgb, #22c55e 62%, var(--line));
      color: color-mix(in srgb, #22c55e 82%, var(--text));
    }

    .child-action-status-clean,
    .child-action-status-drop,
    .child-action-status-neutral {
      border-color: color-mix(in srgb, #f97316 64%, var(--line));
      color: color-mix(in srgb, #f97316 86%, var(--text));
    }

    .child-action-status-replace {
      border-color: color-mix(in srgb, var(--resp) 68%, var(--line));
      color: color-mix(in srgb, var(--resp) 82%, var(--text));
    }

    .child-action-status-observe {
      border-color: color-mix(in srgb, var(--muted) 58%, var(--line));
      color: var(--muted);
    }

    .child-card-line {
      color: var(--muted);
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 12px;
    }

    .child-card-line-long {
      white-space: pre-wrap;
      overflow: visible;
      text-overflow: clip;
      overflow-wrap: anywhere;
    }

    .child-card-rule {
      color: color-mix(in srgb, var(--accent) 76%, var(--text));
    }

    .child-card-parse {
      color: color-mix(in srgb, var(--muted) 82%, var(--text));
    }

    .child-card-observation {
      color: color-mix(in srgb, #22c55e 76%, var(--text));
      font-weight: 600;
    }

    .child-card-line strong {
      color: var(--text);
      font-weight: 700;
    }

    .child-debug-details {
      border-top: 1px dashed color-mix(in srgb, var(--line) 75%, transparent);
      margin-top: 1px;
      padding-top: 3px;
      color: var(--muted);
      font-size: 11px;
    }

    .child-debug-title {
      color: color-mix(in srgb, var(--muted) 82%, var(--text));
      font-weight: 700;
      margin-bottom: 4px;
    }

    .child-debug-details pre {
      margin: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      color: color-mix(in srgb, var(--muted) 82%, var(--text));
    }

    .child-compare-note {
      padding: 0 10px 9px;
      color: var(--muted);
      line-height: 1.45;
    }

    .tree-compare-before .tree-shell {
      border-color: color-mix(in srgb, #f59e0b 42%, var(--line));
      box-shadow: inset 0 0 0 1px color-mix(in srgb, #f59e0b 8%, transparent);
    }

    .tree-compare-after .tree-shell {
      border-color: color-mix(in srgb, var(--resp) 42%, var(--line));
      box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--resp) 8%, transparent);
    }

    .tree-compare-empty {
      min-height: 96px;
      margin: 0;
    }

    .tree-head {
      padding: 6px 9px;
      border-bottom: 1px solid var(--line);
      background: var(--dump-head-bg);
      color: var(--muted);
      font-weight: 700;
      letter-spacing: 0.01em;
    }

    .tree-body {
      margin: 0;
      padding: 8px 9px;
      white-space: pre;
      line-height: 1.5;
      color: var(--hex-body-color);
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
    }

    .tree-token {
      border-radius: 3px;
      padding: 0 2px;
    }

    .tree-node {
      color: var(--hex-offset-color);
      font-weight: 700;
    }

    .tree-report {
      color: color-mix(in srgb, var(--accent) 82%, var(--text));
      font-weight: 700;
    }

    .tree-type {
      color: color-mix(in srgb, var(--resp) 70%, var(--text));
    }

    .tree-id {
      color: color-mix(in srgb, #f59e0b 82%, var(--text));
    }

    .tree-keep {
      color: color-mix(in srgb, #f59e0b 90%, var(--text));
      border: 1px solid color-mix(in srgb, #f59e0b 46%, var(--line));
      background: color-mix(in srgb, #f59e0b 12%, transparent);
    }

    .tree-value {
      color: color-mix(in srgb, #22c55e 78%, var(--text));
    }

    @media (max-width: 980px) {
      .app {
        grid-template-columns: 1fr;
        grid-template-rows: 42% 58%;
      }
      .app.sidebar-hidden {
        grid-template-rows: 1fr;
      }
      .splitter { display: none; }
      .left {
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }
      .toolbar,
      .filterbar {
        grid-template-columns: 1fr 1fr;
      }
      .tree-compare-row {
        grid-template-columns: 1fr;
      }
      .child-compare-grid {
        grid-template-columns: 1fr;
      }
      .child-pair-sides {
        grid-template-columns: 1fr;
      }
		      .string-result-grid {
		        grid-template-columns: 1fr;
		      }
		      .analysis-string-compare {
		        grid-template-columns: 1fr;
		      }
		      .summary-insights {
		        display: none;
		      }
	    }

    @media (max-width: 1380px) {
      .analysis-grid {
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      }
    }

    @media (min-width: 1180px) {
      .dump-grid {
        grid-template-columns: repeat(auto-fit, minmax(min(520px, 100%), 1fr));
        align-items: start;
      }

	      .dump-grid-request.dump-grid-decrypted {
	        grid-template-columns: repeat(2, minmax(520px, 1fr));
	        grid-template-rows: auto;
	        align-items: start;
	      }

		      .dump-grid-request.dump-grid-decrypted .dump-panel-full {
		        grid-column: 1 / 3;
		        grid-row: auto;
		        width: auto;
		        max-width: none;
		      }

		      .dump-grid-request.dump-grid-decrypted.has-raw-compare .dump-panel-full {
		        grid-column: 1;
		      }

		      .dump-grid-request.dump-grid-decrypted.has-raw-compare .dump-panel-raw-after {
		        grid-column: 2;
		        grid-row: auto;
		      }

	      .dump-grid-request.dump-grid-decrypted.has-string-results .dump-panel-full {
	        grid-row: auto;
	      }

		      .dump-grid-request.dump-grid-decrypted .dump-panel-full .hex-shell,
		      .dump-grid-request.dump-grid-decrypted .dump-panel-raw-after .hex-shell {
		        width: auto;
		        max-width: 100%;
		        max-height: min(260px, 30vh);
	      }

	      .dump-grid-request.dump-grid-decrypted .dump-panel-before {
	        grid-column: 1;
	        grid-row: auto;
	      }

	      .dump-grid-request.dump-grid-decrypted .dump-panel-decoded {
	        grid-column: 2;
	        grid-row: auto;
	      }

	      .dump-grid-request.dump-grid-decrypted .dump-panel-before .hex-shell,
	      .dump-grid-request.dump-grid-decrypted .dump-panel-decoded .hex-shell {
	        max-height: none;
	        min-width: 0;
	      }

	      .dump-grid-request.dump-grid-decrypted .string-result-inline {
	        grid-column: 1 / 3;
	        grid-row: auto;
	        margin-top: 0;
	      }

	      .dump-grid-request.dump-grid-decrypted .child-compare-inline {
	        grid-column: 1 / 3;
	        grid-row: auto;
	        margin-top: 0;
	        overflow-x: hidden;
	      }

	      .dump-grid-request.dump-grid-decrypted.has-string-results .child-compare-inline {
	        grid-column: 1 / 3;
	        grid-row: auto;
	      }
	    }
  </style>
</head>
<body>
  <div class="app" id="appRoot">
    <section class="left" id="leftPane">
      <div class="left-head">
        <div class="left-title">连接列表</div>
        <div class="left-tools">
          <span id="flowCount" class="count">0</span>
          <input id="importFileInput" type="file" accept=".txt,.jsonl,.gz,.tcpvflow.jsonl,.tcpvflow.jsonl.gz" hidden />
          <button id="importFlowBtn" title="导入 txt 或 .tcpvflow.jsonl.gz 文件">导入</button>
          <button id="reloadBtn">刷新</button>
          <button id="saveFlowBtn" title="把当前 flow 保存到服务器归档目录">保存</button>
          <button id="exportFlowBtn" title="导出当前 flow 为 .tcpvflow.jsonl.gz">导出</button>
          <button id="deleteFlowBtn" title="仅删除 TCPView 中该 flow 的展示记录和 Redis 缓存，不关闭网络连接">删除记录</button>
        </div>
      </div>
      <div class="flow-cols">
        <div>路径</div>
        <div>类型</div>
        <div>大小</div>
        <div>时长</div>
      </div>
      <div id="flowList"></div>
    </section>

    <div class="splitter" id="splitter" aria-label="Resize panels" role="separator"></div>

    <section class="right" id="rightPane">
      <div class="tabs">
        <span class="tab active">数据流</span>
        <span class="tab">连接</span>
        <span class="tab">时间</span>
        <span class="tab">备注</span>
      </div>
      <div class="toolbar">
        <button id="toggleSidebarBtn" class="sidebar-toggle" type="button" title="隐藏左侧连接列表，把宽度让给包视图。">隐藏列表</button>
        <div id="selectedFlowTitle" class="headline">未选择连接</div>
        <select id="hideAscii">
          <option value="0">ASCII</option>
          <option value="1">隐藏ASCII</option>
        </select>
        <select id="previewBytes">
          <option value="16">16 byte</option>
          <option value="24">24 byte</option>
          <option value="32">32 byte</option>
          <option value="48">48 byte</option>
          <option value="64">64 byte</option>
          <option value="80">80 byte</option>
          <option value="96">96 byte</option>
          <option value="128">128 byte</option>
        </select>
        <div class="preview-offset-group" title="Preview window offset. Shift preview window forward without expanding body.">
          <span class="preview-offset-label">偏移</span>
          <button id="previewOffsetPrev" class="mini-btn" type="button" title="Shift preview window backward.">-</button>
          <input id="previewOffsetRange" class="preview-offset-range" type="range" min="0" max="4096" step="1" value="0" />
          <button id="previewOffsetNext" class="mini-btn" type="button" title="Shift preview window forward.">+</button>
          <input id="previewOffsetInput" class="preview-offset-input" type="number" min="0" max="65535" step="1" value="0" />
        </div>
        <select id="previewSpace" title="Insert an extra separator every 16 bytes in preview and hex body.">
          <option value="1">16字节分隔 开</option>
          <option value="0">16字节分隔 关</option>
        </select>
        <select id="bodyTone">
          <option value="slate">正文 灰蓝</option>
          <option value="cyan">正文 青色</option>
          <option value="mint">正文 绿色</option>
          <option value="amber">正文 琥珀</option>
          <option value="rose">正文 玫红</option>
          <option value="violet">正文 紫色</option>
        </select>
        <select id="expandMode" title="包体只会因手动点击或已记录展开状态打开；预览/悬停预取不会自动展开。">
          <option value="smart">展开 手动</option>
          <option value="on">展开 手动</option>
          <option value="off">展开 关</option>
        </select>
        <select id="autoRefresh" title="Auto Follow: continuously pull latest packets. Manual: pause updates.">
          <option value="1">自动跟随</option>
          <option value="0">手动暂停</option>
        </select>
        <select id="themeMode">
          <option value="github-dark">GitHub Dark</option>
          <option value="dark">Dark</option>
          <option value="light">Light</option>
          <option value="system">System</option>
        </select>
      </div>
      <div class="filterbar">
        <input id="prefixRule" list="ruleExamples" placeholder="搜索当前显示包：输入十六进制，如 0a92 或 3366" />
        <datalist id="ruleExamples">
          <option value="0a 92"></option>
          <option value="33 66 00 0b"></option>
          <option value="01 0a 00 13"></option>
        </datalist>
        <input id="highlightMode" type="hidden" value="full_contains" />
        <input id="ruleColor" type="hidden" value="#ffd166" />
        <button id="searchApplyBtn" title="搜索当前显示包">搜索</button>
        <button id="searchPrevBtn" title="跳到上一个命中包">上一个</button>
        <button id="searchNextBtn" title="跳到下一个命中包">下一个</button>
        <div id="searchHitStat" class="tool-stat" title="current hit / total hit">--/--</div>
        <select id="filterDir" title="Filter by request or response direction.">
          <option value="all">全部方向</option>
          <option value="req">只看请求</option>
          <option value="resp">只看响应</option>
        </select>
        <input id="filterMinLen" type="number" min="0" step="1" placeholder="最小长度" />
        <input id="filterMaxLen" type="number" min="0" step="1" placeholder="最大长度" />
        <label class="filter-check" title="只显示包含 cs/ob/state 的 CSOB 包">
          <input id="filterCsobOnly" type="checkbox" />
          <span>CSOB</span>
        </label>
        <button id="filterApplyBtn" title="Apply current filters.">过滤</button>
        <button id="filterClearBtn" title="Clear all filters.">清空</button>
      </div>
      <div class="rule-guide">搜索当前显示包（解密成功时就是解密后的内容）：输入一段十六进制，空格和 0x 可省略，按 Enter 搜索；最多扫描每包前 8KB。方向和长度可继续过滤。</div>
      <div class="status" id="status">__STATUS_BOOT__</div>
      <div id="events">__INITIAL_EVENTS__</div>
    </section>
  </div>
  <script>window.TCPV_CONFIG = __APP_CONFIG__;</script>
  <script defer src="/app.js?v=__APP_JS_VERSION__"></script>
</body>
</html>
"""
