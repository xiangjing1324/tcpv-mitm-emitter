INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TCP Flow Viewer</title>
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
      grid-template-columns: minmax(110px, 1fr) 38px 54px 40px;
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
      grid-template-columns: minmax(110px, 1fr) 38px 54px 40px;
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
      display: block;
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

    .badge-tcp {
      color: var(--resp);
      border: 1px solid color-mix(in srgb, var(--resp) 60%, var(--line));
      border-radius: 3px;
      font-weight: 700;
      padding: 0 4px;
      display: inline-block;
      margin-right: 5px;
    }

    .right {
      display: grid;
      grid-template-rows: auto auto auto minmax(0, 1fr);
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
      grid-template-columns: minmax(220px, 1fr) 140px 72px 78px 88px 96px 106px 92px 88px 118px;
      gap: 8px;
      align-items: center;
      padding: 8px 10px;
      min-width: 0;
    }

    .toolbar .headline {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-weight: 700;
      min-width: 0;
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
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel);
      overflow: hidden;
      margin: 0 0 8px 0;
    }

    summary {
      list-style: none;
      cursor: pointer;
      padding: 7px 9px;
      border-left: 4px solid var(--line);
      display: flex;
      align-items: center;
      gap: 4px;
      white-space: nowrap;
      font-size: 12px;
      line-height: 1.25;
      min-height: 26px;
      min-width: 0;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
    }

    summary::-webkit-details-marker { display: none; }

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
      flex: 1 1 auto;
      min-width: 0;
      display: flex;
      align-items: center;
      overflow: hidden;
      white-space: nowrap;
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

    .summary-tail {
      flex: 0 0 auto;
      max-width: 10ch;
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

    .preview-mark {
      border-radius: 3px;
      padding: 1px 4px;
    }

    .preview-hex {
      display: inline-block;
      min-width: 0;
      max-width: 100%;
      white-space: pre;
      line-height: 1.25;
      background: color-mix(in srgb, var(--chip-bg) 82%, transparent);
      border: 1px solid color-mix(in srgb, var(--preview-line) 70%, var(--line));
      border-radius: 4px;
      padding: 0 5px;
      color: var(--text);
      overflow: hidden;
      text-overflow: ellipsis;
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

    .hex-shell {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--dump-bg);
      overflow-x: auto;
    }

    .hex-head {
      padding: 6px 9px;
      border-bottom: 1px solid var(--line);
      background: var(--dump-head-bg);
      color: var(--muted);
      white-space: pre;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
    }

    .hex-body {
      margin: 0;
      padding: 8px 9px;
      white-space: pre;
      line-height: 1.45;
      word-break: normal;
      overflow-wrap: normal;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
      color: var(--hex-body-color);
    }

    .hex-offset {
      color: var(--hex-offset-color);
      font-weight: 700;
    }

    .hex-bytes {
      color: var(--hex-body-color);
    }

    .hex-ascii {
      color: var(--hex-ascii-color);
    }

    .hex-ascii-bar {
      color: color-mix(in srgb, var(--hex-accent-color) 72%, var(--line));
      font-weight: 700;
    }

    @media (max-width: 980px) {
      .app {
        grid-template-columns: 1fr;
        grid-template-rows: 42% 58%;
      }
      .splitter { display: none; }
      .left {
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }
      .toolbar {
        grid-template-columns: 1fr 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="app" id="appRoot">
    <section class="left" id="leftPane">
      <div class="left-head">
        <div class="left-title">Flows</div>
        <div class="left-tools">
          <span id="flowCount" class="count">0</span>
          <button id="reloadBtn">Reload</button>
          <button id="deleteFlowBtn">Delete Flow</button>
        </div>
      </div>
      <div class="flow-cols">
        <div>Path</div>
        <div>Type</div>
        <div>Size</div>
        <div>Time</div>
      </div>
      <div id="flowList"></div>
    </section>

    <div class="splitter" id="splitter" aria-label="Resize panels" role="separator"></div>

    <section class="right" id="rightPane">
      <div class="tabs">
        <span class="tab active">Stream Data</span>
        <span class="tab">Connection</span>
        <span class="tab">Timing</span>
        <span class="tab">Comment</span>
      </div>
      <div class="toolbar">
        <div id="selectedFlowTitle" class="headline">No flow selected</div>
        <input id="prefixRule" placeholder="highlight prefix" />
        <input id="ruleColor" type="color" value="#ffd166" />
        <select id="hideAscii">
          <option value="0">ASCII</option>
          <option value="1">NoASCII</option>
        </select>
        <select id="previewBytes">
          <option value="16">16 byte</option>
          <option value="24">24 byte</option>
          <option value="32">32 byte</option>
          <option value="48">48 byte</option>
          <option value="64">64 byte</option>
          <option value="80">80 byte</option>
        </select>
        <select id="previewSpace" title="Insert an extra separator every 16 bytes in preview and hex body.">
          <option value="1">Gap16 On</option>
          <option value="0">Gap16 Off</option>
        </select>
        <select id="bodyTone">
          <option value="slate">Body Slate</option>
          <option value="cyan">Body Cyan</option>
          <option value="mint">Body Mint</option>
          <option value="amber">Body Amber</option>
          <option value="rose">Body Rose</option>
          <option value="violet">Body Violet</option>
        </select>
        <select id="autoRefresh" title="Auto Follow: continuously pull latest packets. Manual: pause updates.">
          <option value="1">Auto Follow</option>
          <option value="0">Manual</option>
        </select>
        <select id="themeMode">
          <option value="github-dark">GitHub Dark</option>
          <option value="dark">Dark</option>
          <option value="light">Light</option>
          <option value="system">System</option>
        </select>
      </div>
      <div class="status" id="status">__STATUS_BOOT__</div>
      <div id="events">__INITIAL_EVENTS__</div>
    </section>
  </div>
  <script defer src="/app.js?v=__APP_JS_VERSION__"></script>
</body>
</html>
"""
