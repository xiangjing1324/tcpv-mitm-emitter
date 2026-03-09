INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TCP Analysis Viewer</title>
  <style>
    :root {
      --bg-grad-1: #0b1220;
      --bg-grad-2: #111827;
      --card: #111827;
      --ink: #a8b8cc;
      --ink-strong: #c7d5e5;
      --sub: #94a3b8;
      --line: #334155;
      --accent: #22d3ee;
      --input-bg: #0f172a;
      --input-line: #334155;
      --btn-bg: #102436;
      --btn-line: #2b4f6b;
      --details-bg: #0f172a;
      --details-body-bg: #0b1220;
      --preview-bg: #12263a;
      --preview-line: #24425f;
      --preview-ink: #9fb3c8;
      --dump-bg: #0a1322;
      --dump-head-bg: #0d1a2d;
      --dump-head-ink: #90a5bf;
      --dump-ink: #a8bad0;
      --dump-font-size: 12px;
    }
    :root[data-theme="light"] {
      --bg-grad-1: #eef2ff;
      --bg-grad-2: #f4f6f8;
      --card: #ffffff;
      --ink: #1f2937;
      --ink-strong: #111827;
      --sub: #6b7280;
      --line: #e5e7eb;
      --accent: #0f766e;
      --input-bg: #ffffff;
      --input-line: #cbd5e1;
      --btn-bg: #ecfeff;
      --btn-line: #99f6e4;
      --details-bg: #ffffff;
      --details-body-bg: #f9fafb;
      --preview-bg: #eef7ff;
      --preview-line: #c9e2ff;
      --preview-ink: #1f2937;
      --dump-bg: #f8fafc;
      --dump-head-bg: #f1f5f9;
      --dump-head-ink: #64748b;
      --dump-ink: #1f2937;
      --dump-font-size: 12px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: linear-gradient(180deg, var(--bg-grad-1) 0%, var(--bg-grad-2) 40%);
      color: var(--ink);
      font-family: "SF Mono", "Menlo", "Consolas", monospace;
    }
    .wrap {
      max-width: 1200px;
      margin: 0 auto;
      padding: 16px;
    }
    .panel {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 12px;
      margin-bottom: 12px;
    }
    .row {
      display: grid;
      grid-template-columns: repeat(9, minmax(120px, 1fr));
      gap: 8px;
      align-items: center;
    }
    @media (max-width: 1000px) {
      .row { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
    }
    label {
      font-size: 12px;
      color: var(--sub);
      display: block;
      margin-bottom: 4px;
    }
    select, input, button {
      width: 100%;
      padding: 8px;
      border: 1px solid var(--input-line);
      border-radius: 8px;
      background: var(--input-bg);
      color: var(--ink);
      font: inherit;
    }
    button {
      background: var(--btn-bg);
      border-color: var(--btn-line);
      cursor: pointer;
    }
    button:hover { border-color: var(--accent); }
    .hint {
      color: var(--sub);
      font-size: 12px;
      margin-top: 8px;
    }
    #events {
      display: grid;
      gap: 8px;
      min-height: 120px;
    }
    details {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--details-bg);
      overflow: hidden;
    }
    summary {
      list-style: none;
      cursor: pointer;
      padding: 8px 10px;
      border-left: 4px solid #d1d5db;
      color: var(--ink-strong);
      display: flex;
      align-items: center;
      gap: 6px;
      white-space: nowrap;
      font-size: 12px;
    }
    summary::-webkit-details-marker { display: none; }
    .summary-fixed { flex: 0 0 auto; }
    .summary-preview {
      flex: 1 1 auto;
      min-width: 120px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .summary-tail {
      flex: 0 1 auto;
      max-width: 9ch;
      white-space: nowrap;
      text-align: right;
      font-size: 11px;
      opacity: 0.62;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    details.event-req > summary { border-left-color: #4c8eda; }
    details.event-resp > summary { border-left-color: #d66b6b; }
    .dir-badge {
      display: inline-block;
      width: 14px;
      text-align: center;
      font-weight: 700;
      margin-right: 2px;
    }
    .dir-req { color: #4c8eda; }
    .dir-resp { color: #d66b6b; }
    .preview-mark {
      border-radius: 3px;
      padding: 1px 4px;
    }
    .preview-hex {
      display: inline-block;
      white-space: pre;
      font-variant-ligatures: none;
      color: var(--preview-ink);
      background: var(--preview-bg);
      border: 1px solid var(--preview-line);
      border-radius: 4px;
      padding: 0 6px;
    }
    .len-field {
      display: inline-block;
      width: 6ch;
      text-align: center;
    }
    .body {
      border-top: 1px solid var(--line);
      padding: 8px 10px;
      font-size: 12px;
      background: var(--details-body-bg);
    }
    pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-all;
      line-height: 1.5;
    }
    .meta { color: var(--sub); margin-bottom: 6px; }
    .hex-shell {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--dump-bg);
      overflow-x: auto;
    }
    .hex-head {
      padding: 6px 10px;
      border-bottom: 1px solid var(--line);
      background: var(--dump-head-bg);
      color: var(--dump-head-ink);
      font-size: var(--dump-font-size);
      font-family: "SF Mono", "Menlo", "Consolas", monospace;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
      letter-spacing: 0;
      line-height: 1.45;
      white-space: pre;
    }
    .hex-body {
      margin: 0;
      padding: 8px 10px;
      color: var(--dump-ink);
      white-space: pre;
      word-break: normal;
      overflow-wrap: normal;
      line-height: 1.45;
      font-size: var(--dump-font-size);
      font-family: "SF Mono", "Menlo", "Consolas", monospace;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
      letter-spacing: 0;
    }
    .status {
      color: var(--sub);
      font-size: 12px;
      padding: 2px 0;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="panel">
      <div class="row">
        <div>
          <label for="accountSelect">Account</label>
          <select id="accountSelect">__ACCOUNT_OPTIONS__</select>
        </div>
        <div>
          <label for="connSelect">Connection</label>
          <select id="connSelect"></select>
        </div>
        <div>
          <label for="prefixRule">Highlight Prefix</label>
          <input id="prefixRule" placeholder="e.g. 160301" />
        </div>
        <div>
          <label for="ruleColor">Rule Color</label>
          <input id="ruleColor" type="color" value="#ffd166" />
        </div>
        <div>
          <label for="hideAscii">Hide ASCII</label>
          <select id="hideAscii">
            <option value="0">No</option>
            <option value="1">Yes</option>
          </select>
        </div>
        <div>
          <label for="previewBytes">Preview Bytes</label>
          <select id="previewBytes">
            <option value="16">16</option>
            <option value="24">24</option>
            <option value="32">32</option>
          </select>
        </div>
        <div>
          <label for="previewSpace">Preview Space</label>
          <select id="previewSpace">
            <option value="0">No</option>
            <option value="1">Yes</option>
          </select>
        </div>
        <div>
          <label for="autoRefresh">Auto Refresh</label>
          <select id="autoRefresh">
            <option value="1">On</option>
            <option value="0">Off</option>
          </select>
        </div>
        <div>
          <label for="themeMode">Theme</label>
          <select id="themeMode">
            <option value="dark">Dark</option>
            <option value="light">Light</option>
            <option value="system">System</option>
          </select>
        </div>
        <div>
          <label>&nbsp;</label>
          <button id="reloadBtn">Reload Accounts</button>
        </div>
      </div>
      <div class="hint">Incremental pull by stream id (no websocket). Prefix highlight matches preview bytes only. Preview Bytes also controls hex row width (16/24/32).</div>
      <div class="status" id="status">__STATUS_BOOT__</div>
    </div>

    <div class="panel">
      <div class="row" style="grid-template-columns: 1fr 220px;">
        <div class="hint">Message stream (click row to expand full payload)</div>
        <button id="moreBtn">Load More</button>
      </div>
      <div id="events">__INITIAL_EVENTS__</div>
    </div>
  </div>

  <script defer src="/app.js?v=__APP_JS_VERSION__"></script>
</body>
</html>
"""
