const state = {
  flowId: "",
  allFlows: [],
  flows: [],
  afterId: null,
  hasMore: true,
  events: [],
  loading: false,
  syncToken: 0,
  autoRefresh: true,
  tick: 0,
  expandedIds: new Set(),
  collapsedIds: new Set(),
  themeMode: "github-dark",
  search: {
    active: false,
    text: "",
    mode: "full_contains",
    color: "#ffd166",
    rules: [],
    invalidCount: 0,
  },
  filters: {
    dir: "all",
    minLen: "",
    maxLen: "",
    csobOnly: false,
    aceMode: "all",
  },
  hitEventIds: [],
  hitCursor: -1,
  pendingHitScroll: false,
  filteredCount: 0,
  dumpScrollLeft: new Map(),
  sidebarHidden: false,
  gcloud9001PairIndex: null,
  gcloudAceStatsCache: null,
  aceOverviewRefreshTimer: 0,
  serverClockOffsetMs: 0,
};

const el = {
  appRoot: document.getElementById("appRoot"),
  splitter: document.getElementById("splitter"),
  leftPane: document.getElementById("leftPane"),
  rightPane: document.getElementById("rightPane"),
  sidebarToggle: document.getElementById("toggleSidebarBtn"),
  flowList: document.getElementById("flowList"),
  flowCount: document.getElementById("flowCount"),
  selectedTitle: document.getElementById("selectedFlowTitle"),
  importFile: document.getElementById("importFileInput"),
  importFlow: document.getElementById("importFlowBtn"),
  saveFlow: document.getElementById("saveFlowBtn"),
  exportFlow: document.getElementById("exportFlowBtn"),
  reload: document.getElementById("reloadBtn"),
  deleteFlow: document.getElementById("deleteFlowBtn"),
  prefix: document.getElementById("prefixRule"),
  searchApply: document.getElementById("searchApplyBtn"),
  searchPrev: document.getElementById("searchPrevBtn"),
  searchNext: document.getElementById("searchNextBtn"),
  searchHitStat: document.getElementById("searchHitStat"),
  highlightMode: document.getElementById("highlightMode"),
  color: document.getElementById("ruleColor"),
  filterDir: document.getElementById("filterDir"),
  filterMinLen: document.getElementById("filterMinLen"),
  filterMaxLen: document.getElementById("filterMaxLen"),
  filterCsobOnly: document.getElementById("filterCsobOnly"),
  filterAceMode: document.getElementById("filterAceMode"),
  filterApply: document.getElementById("filterApplyBtn"),
  filterClear: document.getElementById("filterClearBtn"),
  hideAscii: document.getElementById("hideAscii"),
  previewBytes: document.getElementById("previewBytes"),
  previewOffsetRange: document.getElementById("previewOffsetRange"),
  previewOffsetInput: document.getElementById("previewOffsetInput"),
  previewOffsetPrev: document.getElementById("previewOffsetPrev"),
  previewOffsetNext: document.getElementById("previewOffsetNext"),
  previewSpace: document.getElementById("previewSpace"),
  bodyTone: document.getElementById("bodyTone"),
  expandMode: document.getElementById("expandMode"),
  autoRefresh: document.getElementById("autoRefresh"),
  themeMode: document.getElementById("themeMode"),
  events: document.getElementById("events"),
  status: document.getElementById("status"),
};

const systemThemeQuery = window.matchMedia
  ? window.matchMedia("(prefers-color-scheme: dark)")
  : null;

const BODY_TONES = {
  slate: { body: "#d0d7de", offset: "#58a6ff", ascii: "#8b949e", accent: "#58a6ff" },
  cyan: { body: "#d2f1ff", offset: "#33b3ff", ascii: "#9ec3d1", accent: "#22d3ee" },
  mint: { body: "#cffce2", offset: "#22c55e", ascii: "#8dc9a7", accent: "#34d399" },
  amber: { body: "#ffe7b8", offset: "#f59e0b", ascii: "#d5b482", accent: "#f59e0b" },
  rose: { body: "#ffd3df", offset: "#f43f5e", ascii: "#cf9faf", accent: "#fb7185" },
  violet: { body: "#e2d4ff", offset: "#8b5cf6", ascii: "#b6a1d8", accent: "#a78bfa" },
};

const TCPV_CONFIG = window.TCPV_CONFIG && typeof window.TCPV_CONFIG === "object" ? window.TCPV_CONFIG : {};
const cfgNumber = (key, fallback) => {
  const value = Number(TCPV_CONFIG[key]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
};
const cfgNonNegativeNumber = (key, fallback) => {
  const value = Number(TCPV_CONFIG[key]);
  return Number.isFinite(value) && value >= 0 ? value : fallback;
};
const MAX_FULL_SCAN_BYTES = 8192;
const MAX_EVENTS_IN_MEMORY = cfgNonNegativeNumber("max_events_in_memory", 0);
const EVENTS_FETCH_LIMIT = cfgNumber("fetch_limit", 500);
const INITIAL_DRAIN_PAGES = cfgNumber("initial_drain_pages", 4);
const GCLOUD_INITIAL_DRAIN_PAGES = Math.max(INITIAL_DRAIN_PAGES, 16);
const PREVIEW_OFFSET_MAX = 4096;
const PAYLOAD_PREFETCH_DELAY_MS = 220;
const PAYLOAD_CACHE_MAX_ENTRIES = 24;
const PAYLOAD_CACHE_MAX_BYTES = 6 * 1024 * 1024;
const WINDOW_PREFETCH_BUDGET_AUTO = 16;
const WINDOW_PREFETCH_BUDGET_MANUAL = 48;
const SUMMARY_BADGE_HYDRATE_BUDGET_AUTO = 96;
const SUMMARY_BADGE_HYDRATE_BUDGET_MANUAL = 192;
const MAX_RENDER_EVENTS_AUTO = 2000;
const MAX_RENDER_EVENTS_MANUAL = 5000;
const GCLOUD_MAX_RENDER_EVENTS_AUTO = 5000;
const GCLOUD_MAX_RENDER_EVENTS_MANUAL = 20000;
const DUMP_SCROLL_CACHE_MAX = 800;
const AUTO_EXPAND_ON_COUNT = 3;
const AUTO_EXPAND_SMART_COUNT = 2;
const ANALYSIS_ASCII_MIN_LEN = 4;
const ANALYSIS_ASCII_MAX_ITEMS = 12;
const ANALYSIS_UTF8_MIN_CHARS = 2;
const ANALYSIS_UTF8_MAX_ITEMS = 8;
const ANALYSIS_BASE64_MAX_ITEMS = 6;
const ANALYSIS_BASE64_MAX_BYTES = 512;
const GCLOUD_BASE64_ANALYSIS_CACHE_MAX = 512;
const ANALYSIS_XOR_SCAN_MAX_BYTES = 768;
const PRINTABLE_RUN_ANCHOR_PATTERNS = [
  /\d{10,24}/,
  /(idevhw|idevsysver|iappversion|iappname|iappinfo)/i,
  /(cs:|ob:|state:|stat:|status:|model:|ver:|inc_id:|obf_id:|appname:|appid:|uuid:|client:|bundle:|mrp|mrpcs_|mrcp|\.data|com\.|cn=|ou=|ip(hone|ad)\d|android|tersafe|config2\.dat|config3\.dat|comm\.zip)/i,
];
const PACKET_FILE_REFERENCE_REGEX = /\b(?:mrpcs?|mrcp|mrp)[A-Za-z0-9_.-]*(?:\.(?:data|dat|cfg|zip|bin))?\b|\b(?:config2|config3|comm|tersafe)[A-Za-z0-9_.-]*\.(?:dat|zip|data|cfg|bin)\b/gi;
const PACKET_STATE_REFERENCE_REGEX = /\b(?:state|stat|status):[^\x00;\r\n|]+/gi;
const IDFV_FIELD_REGEX = /\biDevIDFV[:=][0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b/g;
const HISTORY_OPENID_FIELD_REGEX = /\bHistory(?:Open)?ID[:=][0-9A-Za-z_.-]+\b/g;
const XOR_TEXT_KEYWORDS = [
  "/usr/sbin",
  "dylib",
  "springboard",
  "backboardservices",
  "backboardd",
  "mediaserverd",
  "com.apple",
  "mobilesafari",
  "preferences",
  "shadowrocket",
  "spotlight",
  "coremotion",
  "virtualaudio",
  "uiwindow",
  "uitransitionview",
  "uidropshadowview",
  "uiview",
  "uiviewcontroller",
  "uiapplication",
  "airdrop",
  "airdropalertui",
  "sharing",
  "tersafe",
  "mrp",
  "mrpcs",
  "mrcp",
  "mrpcs_",
  "mrpcs_i",
  "mrpcs_i_vv",
  "mrpcs_i_vv.data",
  "i_vv.data",
  ".data",
  "config2.dat",
  "config3.dat",
  "comm.zip",
];
const XOR_COMMON_KEYS = [0xb6, 0x3c, 0xb3, 0x8e];
const XOR_KEY_PRIORITY = new Map([
  [0xb6, 4],
  [0x3c, 3],
  [0xb3, 2],
  [0x8e, 1],
]);
const GCLOUD_BASE64_ANALYSIS_CACHE = new Map();
const TIMESTAMP_SECONDS_MIN = 1_672_531_200; // 2023-01-01
const TIMESTAMP_SECONDS_MAX = 1_893_456_000; // 2030-01-01
const TIMESTAMP_MAX_MARKS_PER_DUMP = 8;
const TSS_PARENT_TRAILER_MAGIC_HEX = "1234567887654321";
const KNOWN_0102000A_TIMESTAMP_LAYOUTS = [
  { len: 68, innerType: 0x100a, selector0: 0x200e0002, selector1: 0x34560001, offsets: [0x40], label: "dfm-current" },
  { len: 80, innerType: 0x1001, selector0: 0x200e0002, selector1: 0x34560001, offsets: [0x20], label: "dfm-session" },
  { len: 68, innerType: 0x100a, selector0: 0x200d0002, selector1: 0x34560001, offsets: [0x40], label: "dfm-current-200d" },
  { len: 80, innerType: 0x1001, selector0: 0x200d0002, selector1: 0x34560001, offsets: [0x20], label: "dfm-session-200d" },
  { len: 68, innerType: 0x100a, selector0: 0x200f0002, selector1: 0x34560001, offsets: [0x40], label: "dfm-current-200f" },
  { len: 80, innerType: 0x1001, selector0: 0x200f0002, selector1: 0x34560001, offsets: [0x20], label: "dfm-session-200f" },
  { len: 68, innerType: 0x810b, selector0: 0x21650002, selector1: 0x34560001, offsets: [0x40], label: "uagame-current" },
  { len: 160, innerType: 0x8023, selector0: 0x21650002, selector1: 0x34560001, offsets: [0x58], label: "uagame-current-8023" },
  { innerType: 0x8418, selector0: 0x21650002, selector1: 0x34560001, offsetFromEnd: 0x14, label: "uagame-tail-8418" },
  { len: 80, innerType: 0x8102, selector0: 0x21650002, selector1: 0x34560001, offsets: [0x20], label: "uagame-session" },
];

const payloadCache = new Map();
const payloadInFlight = new Map();
let payloadCacheBytes = 0;
let previewOffsetRenderTimer = 0;
const UTF8_DECODER_FATAL =
  typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8", { fatal: true }) : null;

function setStatus(text) {
  if (el.status) {
    el.status.textContent = text;
  }
}

function normalizeAccounts(raw) {
  if (Array.isArray(raw)) return raw;
  if (raw && Array.isArray(raw.items)) return raw.items;
  if (raw && typeof raw === "object" && raw.account) return [raw];
  return [];
}

function resolveThemeMode(mode) {
  const normalized = String(mode || "").toLowerCase();
  if (normalized === "github-dark" || normalized === "dark" || normalized === "light") {
    return normalized;
  }
  if (normalized === "system") {
    return systemThemeQuery && systemThemeQuery.matches ? "github-dark" : "light";
  }
  return "github-dark";
}

function applyTheme() {
  const resolved = resolveThemeMode(state.themeMode);
  document.documentElement.setAttribute("data-theme", resolved);
}

function applyBodyTone() {
  const toneName = String((el.bodyTone && el.bodyTone.value) || "slate").toLowerCase();
  const tone = BODY_TONES[toneName] || BODY_TONES.slate;
  const rootStyle = document.documentElement.style;
  rootStyle.setProperty("--hex-body-color", tone.body);
  rootStyle.setProperty("--hex-offset-color", tone.offset);
  rootStyle.setProperty("--hex-ascii-color", tone.ascii);
  rootStyle.setProperty("--hex-accent-color", tone.accent);
}

function installPreviewSummaryStyles() {
  const styleId = "tcpv-preview-summary-style";
  let style = document.getElementById(styleId);
  if (!style) {
    style = document.createElement("style");
    style.id = styleId;
    document.head.appendChild(style);
  }
  style.textContent = `
    .summary-preview {
      flex: 0 0 auto;
      min-width: max-content;
      overflow: visible;
    }
    .summary-insights {
      flex: 1 1 auto;
      overflow: visible;
    }
    .summary-insight-chip {
      flex: 0 0 auto;
      max-width: none;
      border-color: var(--summary-chip-line, color-mix(in srgb, var(--accent) 42%, var(--line)));
      background: var(--summary-chip-bg, color-mix(in srgb, var(--accent) 8%, var(--panel)));
      color: var(--summary-chip-color, color-mix(in srgb, var(--text) 88%, var(--accent)));
      overflow: visible;
      text-overflow: clip;
    }
    .summary-insight-semantic {
      --summary-chip-color: var(--hex-idfv-color);
      --summary-chip-bg: var(--hex-idfv-bg);
      --summary-chip-line: var(--hex-idfv-line);
      font-weight: 700;
    }
    .summary-insight-synth {
      --summary-chip-color: #a7f3d0;
      --summary-chip-bg: rgba(16, 185, 129, 0.16);
      --summary-chip-line: rgba(52, 211, 153, 0.42);
      font-weight: 800;
    }
    .summary-insight-opaque {
      --summary-chip-color: #fcd34d;
      --summary-chip-bg: rgba(245, 158, 11, 0.16);
      --summary-chip-line: rgba(251, 191, 36, 0.45);
      font-weight: 800;
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
    .summary-insight-gcloud {
      --summary-chip-color: #bae6fd;
      --summary-chip-bg: rgba(14, 165, 233, 0.13);
      --summary-chip-line: rgba(56, 189, 248, 0.34);
      font-weight: 800;
    }
    .summary-insight-proto {
      --summary-chip-color: #d9f99d;
      --summary-chip-bg: rgba(132, 204, 22, 0.12);
      --summary-chip-line: rgba(163, 230, 53, 0.30);
      font-weight: 750;
    }
    .summary-insight-control {
      --summary-chip-color: #fcd34d;
      --summary-chip-bg: rgba(245, 158, 11, 0.13);
      --summary-chip-line: rgba(251, 191, 36, 0.34);
      font-weight: 800;
    }
    .summary-insight-ace {
      --summary-chip-color: #fda4af;
      --summary-chip-bg: rgba(244, 63, 94, 0.13);
      --summary-chip-line: rgba(251, 113, 133, 0.38);
      font-weight: 850;
    }
    .summary-insight-carrier {
      --summary-chip-color: #fdba74;
      --summary-chip-bg: rgba(249, 115, 22, 0.12);
      --summary-chip-line: rgba(251, 146, 60, 0.34);
      font-weight: 750;
    }
    .summary-insights:has(.summary-insight-ace) {
      overflow: hidden;
    }
    .summary-insights:has(.summary-insight-ace) .summary-insight-chip {
      max-width: 18ch;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .summary-insights:has(.summary-insight-ace) .summary-insight-ace,
    .summary-insights:has(.summary-insight-ace) .summary-insight-carrier,
    .summary-insights:has(.summary-insight-ace) .summary-insight-type {
      max-width: none;
    }
    .preview-hex {
      max-width: none;
      overflow: visible;
      text-overflow: clip;
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
    .semantic-timeline {
      margin: 8px 8px 12px;
      padding: 10px 12px;
      border: 1px solid color-mix(in srgb, var(--accent) 30%, var(--line));
      border-radius: 8px;
      background: color-mix(in srgb, var(--panel) 92%, var(--accent) 8%);
      display: grid;
      gap: 7px;
    }
    .semantic-timeline-title {
      color: var(--text);
      font-weight: 800;
      letter-spacing: .02em;
    }
    .semantic-timeline-row {
      display: grid;
      grid-template-columns: minmax(92px, 120px) minmax(0, 1fr);
      gap: 8px;
      align-items: start;
      font-size: 12px;
    }
    .semantic-timeline-label {
      color: var(--muted);
      font-weight: 700;
    }
    .semantic-timeline-track {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      min-width: 0;
    }
    .semantic-timeline-chip {
      padding: 2px 6px;
      border: 1px solid color-mix(in srgb, var(--accent) 26%, var(--line));
      border-radius: 999px;
      background: color-mix(in srgb, var(--panel) 90%, var(--accent) 10%);
      color: var(--text);
      white-space: nowrap;
    }
    .semantic-timeline-chip-risk {
      border-color: rgba(248, 113, 113, .45);
      background: rgba(248, 113, 113, .10);
      color: #fca5a5;
    }
  `;
}

function installFlowListBadgeStyles() {
  const styleId = "tcpv-flow-list-badge-style";
  let style = document.getElementById(styleId);
  if (!style) {
    style = document.createElement("style");
    style.id = styleId;
    document.head.appendChild(style);
  }
  style.textContent = `
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
    .badge-tcp {
      flex: 0 0 auto;
      margin-right: 0;
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
    .flow-cols > :last-child,
    .flow-time {
      text-align: right;
    }
    .flow-time {
      white-space: nowrap;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-variant-numeric: tabular-nums;
      font-feature-settings: "tnum" 1;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
  `;
}

function installDumpAsciiRowStyles() {
  const styleId = "tcpv-dump-ascii-row-style";
  let style = document.getElementById(styleId);
  if (!style) {
    style = document.createElement("style");
    style.id = styleId;
    document.head.appendChild(style);
  }
  style.textContent = `
    .hex-ascii-under-line {
      display: block;
      color: color-mix(in srgb, var(--hex-ascii-color) 74%, var(--muted));
      opacity: 0.82;
    }
    .hex-ascii-under {
      color: color-mix(in srgb, var(--hex-ascii-color) 82%, var(--text));
    }
    .hex-ascii-under-spacer {
      color: transparent;
      user-select: none;
    }
    .hex-byte-crc-tail {
      color: color-mix(in srgb, #facc15 88%, var(--text));
      background: color-mix(in srgb, #facc15 22%, transparent);
      border-radius: 2px;
      font-weight: 850;
    }
    .dump-grid-request.dump-grid-decrypted.dump-grid-current-only,
    .dump-grid-request.dump-grid-current-only {
      grid-template-columns: minmax(0, 1fr);
      overflow-x: hidden;
    }
    .dump-grid-request.dump-grid-decrypted.dump-grid-current-only > .dump-panel-full,
    .dump-grid-request.dump-grid-decrypted.dump-grid-current-only > .dump-panel-raw-after,
    .dump-grid-request.dump-grid-decrypted.dump-grid-current-only > .dump-panel-before,
    .dump-grid-request.dump-grid-decrypted.dump-grid-current-only > .dump-panel-decoded,
    .dump-grid-request.dump-grid-decrypted.dump-grid-current-only > .string-result-inline,
    .dump-grid-request.dump-grid-decrypted.dump-grid-current-only > .child-compare-inline,
    .dump-grid-request.dump-grid-current-only > .dump-panel-full,
    .dump-grid-request.dump-grid-current-only > .dump-panel-raw-after,
    .dump-grid-request.dump-grid-current-only > .dump-panel-before,
    .dump-grid-request.dump-grid-current-only > .dump-panel-decoded,
    .dump-grid-request.dump-grid-current-only > .string-result-inline,
    .dump-grid-request.dump-grid-current-only > .child-compare-inline {
      grid-column: 1 / -1;
      width: 100%;
      min-width: 0;
    }
    .tree-compare-row.tree-compare-single {
      grid-template-columns: minmax(0, 1fr);
    }
    .gcloud-brief {
      margin: 8px 0 10px;
      padding: 8px 10px;
      border: 1px solid color-mix(in srgb, #38bdf8 30%, var(--line));
      border-radius: 8px;
      background: color-mix(in srgb, var(--panel) 91%, #0ea5e9 9%);
      display: grid;
      gap: 7px;
    }
    .gcloud-brief-control {
      border-color: color-mix(in srgb, #f59e0b 34%, var(--line));
      background: color-mix(in srgb, var(--panel) 92%, #f59e0b 8%);
    }
    .gcloud-brief-fragment {
      border-color: color-mix(in srgb, #facc15 36%, var(--line));
      background: color-mix(in srgb, var(--panel) 92%, #facc15 8%);
    }
    .gcloud-brief-ace {
      border-color: color-mix(in srgb, #fb7185 38%, var(--line));
      background: color-mix(in srgb, var(--panel) 92%, #e11d48 8%);
    }
    .gcloud-brief-kick {
      border-color: color-mix(in srgb, #ef4444 52%, var(--line));
      background: color-mix(in srgb, var(--panel) 90%, #b91c1c 10%);
      box-shadow: inset 3px 0 0 color-mix(in srgb, #ef4444 76%, transparent);
    }
    .gcloud-brief-kick .gcloud-kv-value {
      white-space: pre-wrap;
    }
    .gcloud-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 10px;
      min-width: 0;
      flex-wrap: wrap;
    }
    .gcloud-title {
      min-width: 0;
      flex: 1 1 280px;
      color: var(--text);
      font-weight: 850;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .gcloud-chip-list {
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-end;
      gap: 5px;
      min-width: 0;
    }
    .gcloud-chip {
      padding: 2px 6px;
      border: 1px solid color-mix(in srgb, #38bdf8 30%, var(--line));
      border-radius: 999px;
      background: color-mix(in srgb, var(--panel) 90%, #38bdf8 10%);
      color: var(--text);
      font-weight: 700;
      white-space: nowrap;
    }
    .gcloud-chip-control {
      border-color: color-mix(in srgb, #f59e0b 38%, var(--line));
      background: rgba(245, 158, 11, 0.12);
    }
    .gcloud-chip-proto {
      border-color: color-mix(in srgb, #84cc16 34%, var(--line));
      background: rgba(132, 204, 22, 0.11);
    }
    .gcloud-chip-ace {
      border-color: color-mix(in srgb, #fb7185 42%, var(--line));
      background: rgba(244, 63, 94, 0.12);
      color: color-mix(in srgb, #fecdd3 82%, var(--text));
    }
    .gcloud-chip-kick {
      border-color: color-mix(in srgb, #ef4444 58%, var(--line));
      background: rgba(220, 38, 38, 0.16);
      color: color-mix(in srgb, #fecaca 88%, var(--text));
      font-weight: 850;
    }
    .gcloud-kv-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 6px;
      align-items: start;
    }
    .gcloud-kv {
      min-width: 0;
      padding: 6px 7px;
      border: 1px solid color-mix(in srgb, var(--line) 72%, transparent);
      border-radius: 6px;
      background: color-mix(in srgb, var(--panel) 86%, var(--bg));
    }
    .gcloud-kv-label {
      margin-bottom: 2px;
      color: var(--muted);
      font-weight: 750;
      font-size: 11px;
    }
    .gcloud-kv-value {
      color: var(--text);
      overflow-wrap: anywhere;
      line-height: 1.35;
    }
    .gcloud-readable {
      min-width: 0;
      display: grid;
      gap: 5px;
      padding-top: 2px;
    }
    .gcloud-readable-title {
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
    }
    .gcloud-readable-list {
      min-width: 0;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 5px;
    }
    .gcloud-readable-string {
      min-width: 0;
      padding: 6px 8px;
      border: 1px solid color-mix(in srgb, #22c55e 34%, var(--line));
      border-radius: 6px;
      background: color-mix(in srgb, var(--panel) 89%, #16a34a 11%);
      color: color-mix(in srgb, #dcfce7 86%, var(--text));
      line-height: 1.45;
      overflow-wrap: anywhere;
      white-space: pre-wrap;
    }
    .gcloud-fact-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      border-top: 1px solid color-mix(in srgb, var(--line) 72%, transparent);
      border-bottom: 1px solid color-mix(in srgb, var(--line) 72%, transparent);
    }
    .gcloud-fact {
      min-width: 0;
      display: grid;
      grid-template-columns: minmax(74px, max-content) minmax(0, 1fr);
      gap: 8px;
      align-items: start;
      padding: 5px 8px;
    }
    .gcloud-fact:nth-child(odd) {
      border-right: 1px solid color-mix(in srgb, var(--line) 68%, transparent);
    }
    .gcloud-fact:nth-child(n + 3) {
      border-top: 1px solid color-mix(in srgb, var(--line) 52%, transparent);
    }
    .gcloud-fact-wide {
      grid-column: 1 / -1;
      border-right: 0 !important;
    }
    .gcloud-fact-label,
    .gcloud-context-label {
      color: var(--muted);
      font-weight: 750;
      white-space: nowrap;
    }
    .gcloud-fact-value {
      min-width: 0;
      color: var(--text);
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .gcloud-context-rail {
      min-width: 0;
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      gap: 4px 14px;
      padding: 1px 8px;
      color: color-mix(in srgb, var(--muted) 82%, var(--text));
      font-size: 11px;
      line-height: 1.35;
    }
    .gcloud-context-item {
      min-width: 0;
      display: inline-flex;
      gap: 5px;
      align-items: baseline;
      overflow-wrap: anywhere;
    }
    .gcloud-context-value {
      min-width: 0;
      color: color-mix(in srgb, var(--text) 88%, var(--muted));
      overflow-wrap: anywhere;
    }
    .gcloud-evidence-details {
      min-width: 0;
      border-top: 1px dashed color-mix(in srgb, var(--line) 62%, transparent);
      padding-top: 4px;
    }
    .gcloud-evidence-details > summary {
      cursor: pointer;
      color: var(--muted);
      font-size: 11px;
      font-weight: 750;
      list-style: none;
    }
    .gcloud-evidence-details > summary::-webkit-details-marker {
      display: none;
    }
    .gcloud-evidence-list {
      display: grid;
      gap: 4px;
      margin-top: 5px;
      padding: 0 8px 2px;
    }
    .gcloud-evidence-row {
      display: grid;
      grid-template-columns: minmax(74px, max-content) minmax(0, 1fr);
      gap: 8px;
      color: color-mix(in srgb, var(--muted) 82%, var(--text));
      line-height: 1.35;
    }
    .gcloud-evidence-row strong {
      color: var(--muted);
      font-weight: 750;
    }
    .gcloud-node-details > summary {
      cursor: pointer;
      color: var(--muted);
      font-weight: 800;
      list-style: none;
    }
    .gcloud-node-details > summary::-webkit-details-marker {
      display: none;
    }
    .gcloud-tree-details > summary {
      cursor: pointer;
      color: var(--text);
      font-weight: 850;
      list-style: none;
    }
    .gcloud-tree-details > summary::-webkit-details-marker {
      display: none;
    }
    .gcloud-proto-tree {
      margin-top: 7px;
      display: grid;
      gap: 3px;
      font-family: var(--mono);
      font-size: 12px;
    }
    .gcloud-tree-row {
      --depth: 0;
      display: grid;
      grid-template-columns: minmax(120px, 220px) minmax(68px, 92px) minmax(220px, 1.25fr) minmax(180px, 1fr);
      gap: 8px;
      align-items: start;
      margin-left: calc(var(--depth) * 18px);
      padding: 4px 6px;
      border-left: 2px solid color-mix(in srgb, #38bdf8 35%, transparent);
      background: color-mix(in srgb, var(--panel) 90%, var(--bg));
    }
    .gcloud-tree-tone-meta {
      border-left-color: color-mix(in srgb, #38bdf8 68%, transparent);
    }
    .gcloud-tree-tone-structure {
      border-left-color: color-mix(in srgb, #2dd4bf 62%, transparent);
    }
    .gcloud-tree-tone-text {
      border-left-color: color-mix(in srgb, #4ade80 62%, transparent);
    }
    .gcloud-tree-tone-number {
      border-left-color: color-mix(in srgb, #fbbf24 66%, transparent);
    }
    .gcloud-tree-tone-binary {
      border-left-color: color-mix(in srgb, #fb7185 66%, transparent);
    }
    .gcloud-tree-tone-data {
      border-left-color: color-mix(in srgb, var(--muted) 42%, transparent);
    }
    .gcloud-tree-key {
      min-width: 0;
      color: #7dd3fc;
      font-weight: 850;
      overflow-wrap: anywhere;
    }
    .gcloud-tree-tone-structure > .gcloud-tree-key {
      color: #5eead4;
    }
    .gcloud-tree-tone-text > .gcloud-tree-key {
      color: #86efac;
    }
    .gcloud-tree-tone-number > .gcloud-tree-key {
      color: #fcd34d;
    }
    .gcloud-tree-tone-binary > .gcloud-tree-key {
      color: #fda4af;
    }
    .gcloud-tree-type {
      color: color-mix(in srgb, var(--muted) 84%, var(--text));
      font-weight: 750;
      white-space: nowrap;
    }
    .gcloud-tree-value {
      min-width: 0;
      color: var(--text);
      overflow-wrap: anywhere;
      display: grid;
      gap: 3px;
    }
    .gcloud-tree-value-empty {
      color: var(--muted);
    }
    .gcloud-tree-primary {
      min-width: 0;
      overflow-wrap: anywhere;
    }
    .gcloud-tree-facts {
      display: flex;
      flex-wrap: wrap;
      gap: 3px 5px;
      min-width: 0;
    }
    .gcloud-tree-fact {
      max-width: 100%;
      display: inline-flex;
      align-items: baseline;
      gap: 5px;
      padding: 1px 4px;
      border: 1px solid color-mix(in srgb, var(--line) 58%, transparent);
      border-radius: 4px;
      background: color-mix(in srgb, var(--bg) 78%, transparent);
      color: color-mix(in srgb, var(--muted) 86%, var(--text));
      font-size: 11px;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .gcloud-tree-fact-label {
      color: color-mix(in srgb, var(--muted) 75%, var(--text));
      font-weight: 800;
      white-space: nowrap;
    }
    .gcloud-tree-fact-label::after {
      content: ":";
    }
    .gcloud-tree-fact-value {
      min-width: 0;
      color: inherit;
      overflow-wrap: anywhere;
    }
    .gcloud-tree-fact-source {
      border-color: color-mix(in srgb, #94a3b8 52%, var(--line));
      color: #cbd5e1;
    }
    .gcloud-tree-fact-envelope {
      border-color: color-mix(in srgb, #f59e0b 58%, var(--line));
      color: #fbbf24;
      background: rgba(245, 158, 11, 0.08);
    }
    .gcloud-tree-fact-header {
      border-color: color-mix(in srgb, #38bdf8 55%, var(--line));
      color: #7dd3fc;
      background: rgba(56, 189, 248, 0.07);
    }
    .gcloud-tree-fact-length {
      border-color: color-mix(in srgb, #84cc16 52%, var(--line));
      color: #bef264;
      background: rgba(132, 204, 22, 0.07);
    }
    .gcloud-tree-fact-time,
    .gcloud-tree-fact-text {
      border-color: color-mix(in srgb, #22c55e 52%, var(--line));
      color: #86efac;
      background: rgba(34, 197, 94, 0.07);
    }
    .gcloud-tree-fact-number {
      border-color: color-mix(in srgb, #eab308 52%, var(--line));
      color: #fde047;
      background: rgba(234, 179, 8, 0.07);
    }
    .gcloud-tree-fact-data {
      border-color: color-mix(in srgb, #ec4899 43%, var(--line));
      color: #f9a8d4;
      background: rgba(236, 72, 153, 0.055);
    }
    .gcloud-tree-fact-warning {
      border-color: color-mix(in srgb, #fb7185 52%, var(--line));
      color: #fda4af;
      background: rgba(251, 113, 133, 0.065);
    }
    .gcloud-tree-raw {
      min-width: 0;
      color: color-mix(in srgb, var(--muted) 78%, var(--text));
      font-size: 11px;
      line-height: 1.45;
      overflow-wrap: anywhere;
    }
    .gcloud-tree-raw-empty {
      color: color-mix(in srgb, var(--muted) 54%, transparent);
    }
    .gcloud-tree-raw-container {
      color: color-mix(in srgb, #94a3b8 76%, var(--text));
      font-style: italic;
    }
    .gcloud-tree-raw-decoded {
      color: color-mix(in srgb, #f9a8d4 72%, var(--text));
    }
    .gcloud-tree-raw-layered {
      display: grid;
      gap: 3px;
      color: color-mix(in srgb, var(--muted) 78%, var(--text));
    }
    .gcloud-tree-raw-source {
      color: color-mix(in srgb, #94a3b8 80%, var(--text));
    }
    .gcloud-tree-raw-layered .gcloud-tree-raw-decoded {
      color: color-mix(in srgb, #f9a8d4 76%, var(--text));
    }
    .gcloud-tree-fact-raw {
      flex-basis: 100%;
      display: grid;
      grid-template-columns: minmax(82px, auto) minmax(0, 1fr);
      white-space: normal;
    }
    @media (max-width: 1100px) {
      .gcloud-tree-row {
        grid-template-columns: minmax(110px, 190px) minmax(64px, 82px) minmax(0, 1fr);
      }
      .gcloud-tree-raw {
        grid-column: 3;
      }
    }
    .gcloud-node-list {
      margin-top: 6px;
      display: grid;
      gap: 4px;
    }
    .gcloud-node-row {
      display: grid;
      grid-template-columns: minmax(142px, 220px) minmax(0, 1fr);
      gap: 8px;
      align-items: start;
      padding: 5px 6px;
      border: 1px solid color-mix(in srgb, var(--line) 62%, transparent);
      border-radius: 6px;
      background: color-mix(in srgb, var(--panel) 88%, var(--bg));
    }
    .gcloud-node-path {
      color: #7dd3fc;
      font-weight: 800;
      overflow-wrap: anywhere;
    }
    .gcloud-node-value {
      color: var(--text);
      overflow-wrap: anywhere;
    }
    .gcloud-note {
      color: var(--muted);
      line-height: 1.45;
    }
    #filterAceMode {
      min-width: 158px;
      border-color: color-mix(in srgb, #fb7185 35%, var(--line));
    }
    .filterbar {
      grid-template-columns: minmax(260px, 1fr) 146px 56px 72px 62px 62px 74px 158px 88px 94px 94px 96px 72px 72px;
    }
    #filterAceMode[hidden] {
      display: none;
    }
    .right {
      container-type: inline-size;
    }
    @container (max-width: 1500px) {
      .filterbar {
        display: flex;
        flex-wrap: wrap;
      }
      #prefixRule {
        flex: 1 1 260px;
      }
      #highlightMode {
        flex: 0 0 146px;
      }
      #ruleColor {
        flex: 0 0 56px;
      }
      #filterAceMode {
        flex: 1 1 180px;
      }
      #filterDir {
        flex: 0 0 104px;
      }
      #filterMinLen,
      #filterMaxLen {
        flex: 1 1 94px;
      }
      .filter-check {
        flex: 0 0 96px;
      }
      #searchApplyBtn,
      #filterApplyBtn,
      #filterClearBtn {
        flex: 0 0 72px;
      }
      #searchPrevBtn,
      #searchNextBtn {
        flex: 0 0 62px;
      }
      #searchHitStat {
        flex: 0 0 74px;
      }
    }
    .ace-flow-overview {
      margin: 0;
      padding: 10px 14px;
      border-top: 1px solid color-mix(in srgb, #fb7185 24%, var(--line));
      border-bottom: 1px solid color-mix(in srgb, #fb7185 24%, var(--line));
      background: color-mix(in srgb, var(--panel) 95%, #e11d48 5%);
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .ace-flow-overview-title {
      color: var(--text);
      font-weight: 850;
    }
    .ace-flow-overview-chips {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }
    .ace-flow-overview-chip {
      padding: 3px 7px;
      border: 1px solid color-mix(in srgb, #fb7185 30%, var(--line));
      border-radius: 4px;
      background: color-mix(in srgb, var(--panel) 90%, #e11d48 10%);
      color: var(--text);
      white-space: nowrap;
    }
    .ace-flow-overview-chip-active {
      border-color: #fb7185;
      color: #fecdd3;
      font-weight: 800;
    }
    .gcloud-ace-deep {
      margin: 10px 8px 12px;
      border-color: color-mix(in srgb, #fb7185 38%, var(--line));
      background: color-mix(in srgb, var(--panel) 95%, #e11d48 5%);
    }
    .gcloud-security-deep-stack {
      display: grid;
      gap: 10px;
    }
    .gcloud-security-deep-stack > .gcloud-ace-deep,
    .gcloud-security-deep-stack > .gcloud-tss-decrypted {
      margin: 10px 8px 0;
    }
    .gcloud-security-deep-stack > .gcloud-tss-decrypted {
      margin-top: 0;
      margin-bottom: 12px;
      border-color: color-mix(in srgb, #22c55e 42%, var(--line));
      background: color-mix(in srgb, var(--panel) 96%, #22c55e 4%);
    }
    .tss-crypto-status {
      padding: 7px 9px;
      border-bottom: 1px solid var(--line);
      overflow-wrap: anywhere;
      font-weight: 750;
    }
    .tss-crypto-status-ok {
      color: color-mix(in srgb, #22c55e 72%, var(--text));
      background: color-mix(in srgb, var(--dump-bg) 92%, #22c55e 8%);
    }
    .tss-crypto-status-error {
      color: color-mix(in srgb, #f59e0b 78%, var(--text));
      background: color-mix(in srgb, var(--dump-bg) 92%, #f59e0b 8%);
    }
    .ace-deep-lineage {
      display: flex;
      align-items: center;
      gap: 5px;
      flex-wrap: wrap;
      padding: 7px 8px;
      border-bottom: 1px solid color-mix(in srgb, #fb7185 24%, var(--line));
      background: color-mix(in srgb, var(--dump-bg) 90%, #e11d48 10%);
    }
    .ace-deep-layer {
      max-width: 100%;
      padding: 2px 6px;
      border: 1px solid color-mix(in srgb, #fb7185 32%, var(--line));
      border-radius: 4px;
      color: var(--text);
      background: color-mix(in srgb, var(--panel) 88%, #e11d48 12%);
      overflow-wrap: anywhere;
    }
    .ace-deep-arrow {
      color: var(--muted);
      font-weight: 850;
    }
    @media (max-width: 980px) {
      .filterbar {
        grid-template-columns: 1fr 1fr;
      }
      #filterAceMode {
        min-width: 0;
      }
      .gcloud-chip-list {
        justify-content: flex-start;
      }
      .gcloud-fact-grid {
        grid-template-columns: minmax(0, 1fr);
      }
      .gcloud-fact:nth-child(odd) {
        border-right: 0;
      }
      .gcloud-fact:nth-child(n + 2) {
        border-top: 1px solid color-mix(in srgb, var(--line) 52%, transparent);
      }
    }
      .tss-recursive-tree {
      margin: 6px 0 0;
      border: 1px solid color-mix(in srgb, #a855f7 30%, var(--line));
      border-radius: 6px;
      overflow: hidden;
    }
    .tss-recursive-tree-head {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 7px 9px;
      border-bottom: 1px solid color-mix(in srgb, #a855f7 24%, var(--line));
      background: color-mix(in srgb, var(--dump-bg) 88%, #a855f7 12%);
      font-weight: 750;
    }
    .tss-recursive-status {
      font-size: 11px;
      padding: 1px 7px;
      border-radius: 10px;
      font-weight: 700;
    }
    .tss-recursive-status-ok {
      color: color-mix(in srgb, #22c55e 72%, var(--text));
      background: color-mix(in srgb, var(--dump-bg) 90%, #22c55e 10%);
    }
    .tss-recursive-status-candidate {
      color: color-mix(in srgb, #f59e0b 82%, var(--text));
      background: color-mix(in srgb, var(--dump-bg) 90%, #f59e0b 10%);
    }
    .tss-recursive-tree-nodes { padding: 4px 6px 6px; }
    .tss-recursive-node { margin: 2px 0; }
    .tss-recursive-node > summary {
      display: flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
      list-style: none;
      padding: 4px 6px;
      border: 1px solid var(--line);
      border-radius: 4px;
      background: var(--panel);
    }
    .tss-recursive-node > summary::-webkit-details-marker { display: none; }
    .tss-recursive-node-status {
      flex: 0 0 auto;
      width: 16px;
      height: 16px;
      line-height: 16px;
      text-align: center;
      border-radius: 3px;
      font-weight: 850;
      font-size: 12px;
    }
    .tss-recursive-node-status-ok { color: #16a34a; background: #dcfce7; }
    .tss-recursive-node-status-candidate { color: #b45309; background: #fef3c7; }
    .tss-recursive-node-status-error { color: #dc2626; background: #fee2e2; }
    .tss-recursive-node-name {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-weight: 700;
      overflow-wrap: anywhere;
    }
    .tss-recursive-node-meta {
      margin-left: auto;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 11px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .tss-recursive-node-body {
      margin: 2px 0 4px 20px;
      padding: 4px 6px;
      border-left: 2px solid color-mix(in srgb, #a855f7 34%, var(--line));
      background: color-mix(in srgb, var(--panel) 94%, #a855f7 6%);
    }
    .tss-recursive-line {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 11px;
      overflow-wrap: anywhere;
      padding: 1px 0;
      color: var(--text);
    }
    .tss-recursive-line-ok { color: color-mix(in srgb, #22c55e 72%, var(--text)); }
    .tss-recursive-line-error { color: color-mix(in srgb, #dc2626 70%, var(--text)); }
    .tss-recursive-line-xor { color: color-mix(in srgb, #a855f7 72%, var(--text)); font-weight: 700; }
    .tss-recursive-line-string { color: color-mix(in srgb, #059669 70%, var(--text)); }
    .tss-recursive-line-hex { color: var(--muted); }
    .tss-recursive-node-children { margin-top: 2px; }
`;
}

function installAceFilterControl() {
  const filterbar = document.querySelector(".filterbar");
  if (!filterbar) return;
  let select = document.getElementById("filterAceMode");
  if (!select) {
    select = document.createElement("select");
    select.id = "filterAceMode";
    select.title = "TGCP/GCloud command 分类；覆盖 65010、17500、20001 flow。";
    filterbar.insertBefore(select, el.filterDir || null);
  }
  el.filterAceMode = select;
  select.addEventListener("change", () => {
    state.filters = {
      ...state.filters,
      aceMode: normalizeAceFilterMode(select.value),
    };
    saveRules();
    saveAppliedFilters();
    renderEvents();
  });
}

function normalizeFilterDir(rawDir) {
  const dir = String(rawDir || "").trim().toLowerCase();
  if (dir === "req" || dir === "resp") {
    return dir;
  }
  return "all";
}

function normalizeFilterLen(rawValue) {
  const text = String(rawValue || "").trim();
  if (!text) return "";
  const num = Number(text);
  if (!Number.isFinite(num) || num < 0) return "";
  return String(Math.floor(num));
}

function normalizeAceFilterMode(rawMode) {
  const mode = String(rawMode || "").trim().toLowerCase();
  if ([
    "account_login",
    "ace_all",
    "ace_antidata",
    "ace_ack",
    "ace_light",
    "ace_transfer",
    "cstss_all",
    "gcloud_heartbeat",
    "gcloud_network",
    "gcloud_4013",
    "tgcp_control",
  ].includes(mode)) {
    return mode;
  }
  return "all";
}

function normalizeFilterState(rawDir, rawMinLen, rawMaxLen, rawCsobOnly = false, rawAceMode = "all") {
  let minLen = normalizeFilterLen(rawMinLen);
  let maxLen = normalizeFilterLen(rawMaxLen);
  if (minLen && maxLen && Number(minLen) > Number(maxLen)) {
    const oldMin = minLen;
    minLen = maxLen;
    maxLen = oldMin;
  }
  return {
    dir: normalizeFilterDir(rawDir),
    minLen,
    maxLen,
    csobOnly: rawCsobOnly === true || rawCsobOnly === "1",
    aceMode: normalizeAceFilterMode(rawAceMode),
  };
}

function normalizePreviewOffset(rawValue) {
  const num = Number(rawValue);
  if (!Number.isFinite(num) || num <= 0) return 0;
  return Math.min(PREVIEW_OFFSET_MAX, Math.floor(num));
}

function getPreviewOffset() {
  if (!el.previewOffsetInput) return 0;
  return normalizePreviewOffset(el.previewOffsetInput.value);
}

function setPreviewOffsetControls(rawValue) {
  const offset = normalizePreviewOffset(rawValue);
  if (el.previewOffsetInput) {
    el.previewOffsetInput.value = String(offset);
  }
  if (el.previewOffsetRange) {
    el.previewOffsetRange.value = String(offset);
  }
  return offset;
}

function schedulePreviewOffsetRender() {
  if (previewOffsetRenderTimer) {
    clearTimeout(previewOffsetRenderTimer);
  }
  previewOffsetRenderTimer = window.setTimeout(() => {
    previewOffsetRenderTimer = 0;
    renderEvents();
  }, 90);
}

function applyPreviewOffset(rawValue, renderNow = false) {
  const offset = setPreviewOffsetControls(rawValue);
  saveRules();
  if (renderNow) {
    renderEvents();
  } else {
    schedulePreviewOffsetRender();
  }
  return offset;
}

function getPreviewOffsetStep() {
  const bytesPerRow = getBytesPerRow();
  return Math.max(1, Math.floor(bytesPerRow / 2));
}

function getExpectedPreviewWindowLen(ev, previewOffset, previewLen) {
  const packetLen = Number(ev && ev.len);
  if (Number.isFinite(packetLen) && packetLen >= 0) {
    if (previewOffset >= packetLen) return 0;
    return Math.min(previewLen, Math.max(0, packetLen - previewOffset));
  }
  return Math.max(0, Number(previewLen || 0));
}

async function apiJson(url) {
  const requestStartedMs = Date.now();
  const resp = await fetch(url, { cache: "no-store" });
  const responseReceivedMs = Date.now();
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`HTTP ${resp.status} ${resp.statusText}: ${body.slice(0, 200)}`);
  }
  const serverNowMs = Number(resp.headers.get("X-TCPV-Server-Time-Ms"));
  if (Number.isFinite(serverNowMs) && serverNowMs > 0) {
    const localMidpointMs = (requestStartedMs + responseReceivedMs) / 2;
    state.serverClockOffsetMs = serverNowMs - localMidpointMs;
  }
  return resp.json();
}

async function apiPost(url) {
  const resp = await fetch(url, { method: "POST", cache: "no-store" });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`HTTP ${resp.status} ${resp.statusText}: ${body.slice(0, 200)}`);
  }
  return resp.json();
}

async function apiPostBytes(url, bytes) {
  const resp = await fetch(url, {
    method: "POST",
    cache: "no-store",
    headers: { "Content-Type": "application/octet-stream" },
    body: bytes,
  });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`HTTP ${resp.status} ${resp.statusText}: ${body.slice(0, 200)}`);
  }
  return resp.json();
}

async function apiGetEvent(account, eventId) {
  const params = new URLSearchParams({
    account: String(account || ""),
    id: String(eventId || ""),
  });
  return apiJson(`/event?${params.toString()}`);
}

function buildPayloadCacheKey(account, eventId) {
  return `${String(account || "")}|${String(eventId || "")}`;
}

function trimPayloadCache() {
  while (
    payloadCache.size > PAYLOAD_CACHE_MAX_ENTRIES ||
    payloadCacheBytes > PAYLOAD_CACHE_MAX_BYTES
  ) {
    const firstKey = payloadCache.keys().next().value;
    if (!firstKey) break;
    const firstRec = payloadCache.get(firstKey);
    payloadCache.delete(firstKey);
    if (firstRec && Number.isFinite(firstRec.size)) {
      payloadCacheBytes = Math.max(0, payloadCacheBytes - Number(firstRec.size || 0));
    }
  }
}

function clearPayloadCache() {
  payloadCache.clear();
  payloadInFlight.clear();
  payloadCacheBytes = 0;
}

function readPayloadCache(account, eventId) {
  const key = buildPayloadCacheKey(account, eventId);
  const rec = payloadCache.get(key);
  if (!rec || !rec.detail) return null;
  payloadCache.delete(key);
  payloadCache.set(key, rec);
  return rec.detail;
}

function writePayloadCache(account, eventId, detail) {
  const normalized = detail && typeof detail === "object" ? detail : null;
  const pay = String(normalized && normalized.pay ? normalized.pay : "");
  if (!pay) return;

  const key = buildPayloadCacheKey(account, eventId);
  const old = payloadCache.get(key);
  if (old && Number.isFinite(old.size)) {
    payloadCacheBytes = Math.max(0, payloadCacheBytes - Number(old.size || 0));
  }

  const rec = {
    detail: {
      pay,
      full_pay: String(normalized.full_pay || ""),
      full_len: Number.isFinite(Number(normalized.full_len)) ? Number(normalized.full_len) : undefined,
      full_pfx: String(normalized.full_pfx || ""),
      before_pay: String(normalized.before_pay || ""),
      before_len: Number.isFinite(Number(normalized.before_len)) ? Number(normalized.before_len) : undefined,
      before_pfx: String(normalized.before_pfx || ""),
      raw_pay: String(normalized.raw_pay || ""),
      raw_len: Number.isFinite(Number(normalized.raw_len)) ? Number(normalized.raw_len) : undefined,
      raw_pfx: String(normalized.raw_pfx || ""),
      pfx: String(normalized.pfx || ""),
      cid: String(normalized.cid || ""),
      proxy_username: String(normalized.proxy_username || ""),
      summary: String(normalized.summary || ""),
      seq: Number.isFinite(Number(normalized.seq)) ? Number(normalized.seq) : undefined,
      msg_idx: Number.isFinite(Number(normalized.msg_idx)) ? Number(normalized.msg_idx) : undefined,
      chunk_idx: Number.isFinite(Number(normalized.chunk_idx)) ? Number(normalized.chunk_idx) : undefined,
      modified: normalized.modified === true || String(normalized.modified || "") === "1",
      modification_evidence: Array.isArray(normalized.modification_evidence)
        ? normalized.modification_evidence.map((item) => String(item || "")).filter(Boolean)
        : [],
      analysis: normalized.analysis && typeof normalized.analysis === "object" ? normalized.analysis : {},
    },
    size:
      pay.length
      + String(normalized.full_pay || "").length
      + String(normalized.before_pay || "").length
      + String(normalized.raw_pay || "").length,
  };
  payloadCache.set(key, rec);
  payloadCacheBytes += rec.size;
  trimPayloadCache();
}

async function fetchEventPayload(account, eventId) {
  const cached = readPayloadCache(account, eventId);
  if (cached) return cached;

  const key = buildPayloadCacheKey(account, eventId);
  if (payloadInFlight.has(key)) {
    return payloadInFlight.get(key);
  }

  const task = apiGetEvent(account, eventId)
    .then((detail) => {
      writePayloadCache(account, eventId, detail);
      const replay = readPayloadCache(account, eventId);
      return replay || detail;
    })
    .finally(() => {
      payloadInFlight.delete(key);
    });

  payloadInFlight.set(key, task);
  return task;
}

function prefetchEventPayload(account, eventId) {
  const accountText = String(account || "").trim();
  const idText = String(eventId || "").trim();
  if (!accountText || !idText) return;
  const key = buildPayloadCacheKey(accountText, idText);
  if (payloadCache.has(key) || payloadInFlight.has(key)) return;
  fetchEventPayload(accountText, idText)
    .then(() => {
      schedulePreviewOffsetRender();
    })
    .catch((_e) => {});
}

function loadRules() {
  const appliedSearchText = localStorage.getItem("tcpv_applied_rule_prefix") || "";
  const appliedSearchMode = "full_contains";
  const appliedSearchColor = localStorage.getItem("tcpv_applied_rule_color") || "#ffd166";
  const draftSearchText = localStorage.getItem("tcpv_rule_prefix");
  const draftSearchMode = "full_contains";
  const draftSearchColor = localStorage.getItem("tcpv_rule_color");
  const appliedFilterDir = localStorage.getItem("tcpv_applied_filter_dir") || "all";
  const appliedFilterMinLen = localStorage.getItem("tcpv_applied_filter_min_len") || "";
  const appliedFilterMaxLen = localStorage.getItem("tcpv_applied_filter_max_len") || "";
  const appliedFilterCsobOnly = localStorage.getItem("tcpv_applied_filter_csob_only") === "1";
  const appliedFilterAceMode = normalizeAceFilterMode(localStorage.getItem("tcpv_applied_filter_ace_mode") || "all");
  const previewOffset = localStorage.getItem("tcpv_preview_offset") || "0";

  el.prefix.value = draftSearchText !== null ? draftSearchText : appliedSearchText;
  if (el.highlightMode) {
    el.highlightMode.value = draftSearchMode || appliedSearchMode;
  }
  el.color.value = draftSearchColor || appliedSearchColor;
  if (el.filterDir) {
    el.filterDir.value = localStorage.getItem("tcpv_filter_dir_draft") || appliedFilterDir;
  }
  if (el.filterMinLen) {
    el.filterMinLen.value = localStorage.getItem("tcpv_filter_min_len_draft") || appliedFilterMinLen;
  }
  if (el.filterMaxLen) {
    el.filterMaxLen.value = localStorage.getItem("tcpv_filter_max_len_draft") || appliedFilterMaxLen;
  }
  if (el.filterCsobOnly) {
    const draftCsobOnly = localStorage.getItem("tcpv_filter_csob_only_draft");
    el.filterCsobOnly.checked = draftCsobOnly !== null ? draftCsobOnly === "1" : appliedFilterCsobOnly;
  }
  if (el.filterAceMode) {
    el.filterAceMode.value = normalizeAceFilterMode(
      localStorage.getItem("tcpv_filter_ace_mode_draft") || appliedFilterAceMode
    );
  }
  el.hideAscii.value = localStorage.getItem("tcpv_hide_ascii") || "0";
  const savedPreviewBytes = String(localStorage.getItem("tcpv_preview_bytes") || "").trim();
  const allowedPreviewBytes = new Set(["16", "24", "32", "48", "64", "80", "96", "128"]);
  const initialPreviewBytes = allowedPreviewBytes.has(savedPreviewBytes) ? savedPreviewBytes : "16";
  el.previewBytes.value = initialPreviewBytes;
  if (savedPreviewBytes !== initialPreviewBytes) {
    localStorage.setItem("tcpv_preview_bytes", initialPreviewBytes);
  }
  setPreviewOffsetControls(previewOffset);
  if (el.previewOffsetRange) {
    el.previewOffsetRange.max = String(PREVIEW_OFFSET_MAX);
  }
  if (el.previewOffsetInput) {
    el.previewOffsetInput.max = String(PREVIEW_OFFSET_MAX);
  }
  if (el.previewSpace) {
    el.previewSpace.value = localStorage.getItem("tcpv_preview_space") || "1";
  }
  if (el.bodyTone) {
    el.bodyTone.value = localStorage.getItem("tcpv_body_tone") || "slate";
  }
  if (el.expandMode) {
    const savedExpandMode = String(localStorage.getItem("tcpv_expand_mode") || "").trim();
    const initialExpandMode = savedExpandMode === "on" ? "smart" : savedExpandMode || "smart";
    el.expandMode.value = initialExpandMode;
    if (savedExpandMode !== initialExpandMode) {
      localStorage.setItem("tcpv_expand_mode", initialExpandMode);
    }
  }
  el.autoRefresh.value = localStorage.getItem("tcpv_auto_refresh") || "1";
  el.themeMode.value = localStorage.getItem("tcpv_theme_mode") || "github-dark";

  state.autoRefresh = el.autoRefresh.value === "1";
  state.themeMode = el.themeMode.value;
  setSidebarHidden(localStorage.getItem("tcpv_sidebar_hidden") === "1", false);
  state.search = buildAppliedSearchState(appliedSearchText, appliedSearchMode, appliedSearchColor);
  state.filters = normalizeFilterState(
    appliedFilterDir,
    appliedFilterMinLen,
    appliedFilterMaxLen,
    appliedFilterCsobOnly,
    appliedFilterAceMode,
  );
  applyTheme();
  applyBodyTone();
  updateSearchDraftState();
  updateSearchUi();

  const splitRaw = Number(localStorage.getItem("tcpv_split_left") || "380");
  const split = Number.isFinite(splitRaw) ? splitRaw : 380;
  setSplitWidth(split, false);
}

function saveRules() {
  localStorage.setItem("tcpv_rule_prefix", (el.prefix.value || "").trim().toLowerCase());
  if (el.highlightMode) {
    localStorage.setItem("tcpv_highlight_mode", el.highlightMode.value || "full_contains");
  }
  localStorage.setItem("tcpv_rule_color", el.color.value);
  if (el.filterDir) {
    localStorage.setItem("tcpv_filter_dir_draft", el.filterDir.value || "all");
  }
  if (el.filterMinLen) {
    localStorage.setItem("tcpv_filter_min_len_draft", el.filterMinLen.value || "");
  }
  if (el.filterMaxLen) {
    localStorage.setItem("tcpv_filter_max_len_draft", el.filterMaxLen.value || "");
  }
  if (el.filterCsobOnly) {
    localStorage.setItem("tcpv_filter_csob_only_draft", el.filterCsobOnly.checked ? "1" : "0");
  }
  if (el.filterAceMode) {
    localStorage.setItem("tcpv_filter_ace_mode_draft", normalizeAceFilterMode(el.filterAceMode.value));
  }
  localStorage.setItem("tcpv_hide_ascii", el.hideAscii.value);
  localStorage.setItem("tcpv_preview_bytes", el.previewBytes.value);
  localStorage.setItem("tcpv_preview_offset", String(getPreviewOffset()));
  if (el.previewSpace) {
    localStorage.setItem("tcpv_preview_space", el.previewSpace.value || "1");
  }
  if (el.bodyTone) {
    localStorage.setItem("tcpv_body_tone", el.bodyTone.value || "slate");
  }
  if (el.expandMode) {
    localStorage.setItem("tcpv_expand_mode", el.expandMode.value || "smart");
  }
  localStorage.setItem("tcpv_auto_refresh", el.autoRefresh.value);
  localStorage.setItem("tcpv_theme_mode", el.themeMode.value);
}

function saveAppliedSearch() {
  localStorage.setItem("tcpv_applied_rule_prefix", state.search.text || "");
  localStorage.setItem("tcpv_applied_highlight_mode", state.search.mode || "full_contains");
  localStorage.setItem("tcpv_applied_rule_color", state.search.color || "#ffd166");
}

function saveAppliedFilters() {
  localStorage.setItem("tcpv_applied_filter_dir", state.filters.dir || "all");
  localStorage.setItem("tcpv_applied_filter_min_len", state.filters.minLen || "");
  localStorage.setItem("tcpv_applied_filter_max_len", state.filters.maxLen || "");
  localStorage.setItem("tcpv_applied_filter_csob_only", state.filters.csobOnly ? "1" : "0");
  localStorage.setItem("tcpv_applied_filter_ace_mode", state.filters.aceMode || "all");
}

function getExpandMode() {
  if (!el.expandMode) return "smart";
  const mode = String(el.expandMode.value || "").toLowerCase();
  if (mode === "on" || mode === "off" || mode === "smart") {
    return mode;
  }
  return "smart";
}

function updateSidebarToggle() {
  if (!el.sidebarToggle) return;
  el.sidebarToggle.textContent = state.sidebarHidden ? "显示列表" : "隐藏列表";
  el.sidebarToggle.title = state.sidebarHidden
    ? "显示左侧连接列表。"
    : "隐藏左侧连接列表，把宽度让给 raw / before / after。";
  el.sidebarToggle.setAttribute("aria-pressed", state.sidebarHidden ? "true" : "false");
}

function setSidebarHidden(hidden, persist = true) {
  state.sidebarHidden = !!hidden;
  if (el.appRoot) {
    el.appRoot.classList.toggle("sidebar-hidden", state.sidebarHidden);
  }
  updateSidebarToggle();
  if (persist) {
    localStorage.setItem("tcpv_sidebar_hidden", state.sidebarHidden ? "1" : "0");
  }
}

function setSplitWidth(px, persist = true) {
  const minWidth = 260;
  const maxByScreen = Math.max(420, Math.floor(window.innerWidth * 0.7));
  const maxWidth = Math.min(900, maxByScreen);
  const safe = Math.max(minWidth, Math.min(maxWidth, Math.floor(px || 380)));
  el.appRoot.style.setProperty("--left-width", `${safe}px`);
  if (persist) {
    localStorage.setItem("tcpv_split_left", String(safe));
  }
}

function setupSplitter() {
  if (!el.splitter) return;

  let dragging = false;
  let startX = 0;
  let startWidth = 380;

  const onMove = (ev) => {
    if (!dragging) return;
    const dx = ev.clientX - startX;
    setSplitWidth(startWidth + dx, false);
  };

  const onUp = () => {
    if (!dragging) return;
    dragging = false;
    el.appRoot.classList.remove("dragging");
    const raw = getComputedStyle(el.appRoot).getPropertyValue("--left-width");
    const width = Number(String(raw || "").replace("px", ""));
    if (Number.isFinite(width)) {
      localStorage.setItem("tcpv_split_left", String(Math.floor(width)));
    }
    window.removeEventListener("pointermove", onMove);
    window.removeEventListener("pointerup", onUp);
  };

  el.splitter.addEventListener("pointerdown", (ev) => {
    dragging = true;
    startX = ev.clientX;
    const raw = getComputedStyle(el.appRoot).getPropertyValue("--left-width");
    startWidth = Number(String(raw || "").replace("px", "")) || 380;
    el.appRoot.classList.add("dragging");
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  });

  window.addEventListener("resize", () => {
    const raw = Number(localStorage.getItem("tcpv_split_left") || "380");
    setSplitWidth(raw, false);
  });
}

function getProxyUsername(rawValue) {
  return String(rawValue || "").trim();
}

function extractAccountInfoFromCid(cidText) {
  const match = String(cidText || "").match(/\[acc:([^\]]+)\]/i);
  return match ? String(match[1] || "").trim() : "";
}

function stripDecoratorsFromCid(cidText) {
  return String(cidText || "").replace(/\s*\[(?:acc|kp):[^\]]+\]/gi, "").trim();
}

function formatSize(bytes) {
  const n = Number(bytes || 0);
  if (!Number.isFinite(n) || n <= 0) return "0b";
  if (n < 1024) return `${n}b`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}kb`;
  return `${(n / (1024 * 1024)).toFixed(1)}mb`;
}

function formatDuration(durationMs) {
  const ms = Number(durationMs || 0);
  if (!Number.isFinite(ms) || ms <= 0) return "0ms";
  if (ms < 1000) return `${Math.floor(ms)}ms`;
  const sec = Math.floor(ms / 1000);
  const hours = Math.floor(sec / 3600);
  const minutes = Math.floor((sec % 3600) / 60);
  const seconds = sec % 60;
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

// TCPView on these servers is operated in China Standard Time.  Do not let
// the browser/OS timezone silently turn a 14:59 packet into 06:59 UTC.
const DISPLAY_TIME_OFFSET_MS = 8 * 60 * 60 * 1000;

function displayTimeParts(ts) {
  const value = Number(ts || 0);
  if (!Number.isFinite(value)) return null;
  const d = new Date(value + DISPLAY_TIME_OFFSET_MS);
  if (!Number.isFinite(d.getTime())) return null;
  return {
    yyyy: String(d.getUTCFullYear()).padStart(4, "0"),
    mm: String(d.getUTCMonth() + 1).padStart(2, "0"),
    dd: String(d.getUTCDate()).padStart(2, "0"),
    hh: String(d.getUTCHours()).padStart(2, "0"),
    mi: String(d.getUTCMinutes()).padStart(2, "0"),
    ss: String(d.getUTCSeconds()).padStart(2, "0"),
  };
}

function formatFlowTimestamp(ts) {
  const value = Number(ts || 0);
  if (!Number.isFinite(value) || value <= 0) return "-";
  const date = new Date(value);
  return `${formatTs(value)}.${String(date.getMilliseconds()).padStart(3, "0")}`;
}

// TCPV_RECENT_FLOW_ACTIVITY_V1: blue means packets were seen recently.
const FLOW_POST_CLOSE_ACTIVITY_GRACE_MS = 5 * 1000;
const FLOW_ACTIVITY_FRESH_MS = 90 * 1000;

function getFlowPacketActivity(item, nowMs = Date.now()) {
  const lastPacketRaw = Number(item && (item.last_packet_ts || item.last_ts));
  const lastPacketTs = Number.isFinite(lastPacketRaw) && lastPacketRaw > 0 ? lastPacketRaw : 0;
  const tcpEndRaw = Number(item && item.tcp_end_ts);
  const tcpEndTs = Number.isFinite(tcpEndRaw) && tcpEndRaw > 0 ? tcpEndRaw : 0;
  const idleMs = lastPacketTs > 0 ? Math.max(0, Number(nowMs) - lastPacketTs) : Number.POSITIVE_INFINITY;
  return {
    lastPacketTs,
    tcpEndTs,
    idleMs,
    fresh: lastPacketTs > 0 && idleMs <= FLOW_ACTIVITY_FRESH_MS,
    postClose: tcpEndTs > 0 && lastPacketTs > tcpEndTs + FLOW_POST_CLOSE_ACTIVITY_GRACE_MS,
  };
}

function isFlowOpen(item, nowMs = Date.now()) {
  if (!item || typeof item !== "object") return false;
  const activity = getFlowPacketActivity(item, nowMs);
  // A reused flow id may keep an old tcp_end while a new socket is actively
  // appending packets.  Treat it as active only while those writes are fresh;
  // the grace window excludes normal background-writer tail packets.
  if (activity.tcpEndTs > 0) return activity.postClose && activity.fresh;
  let lifecycleOpen = false;
  if (typeof item.is_open === "boolean") {
    lifecycleOpen = item.is_open;
  } else {
    const status = String(item.status || "").trim().toLowerCase();
    if (status === "open") lifecycleOpen = true;
    else if (status === "closed") lifecycleOpen = false;
    else {
      const endedTs = Number(item.ended_ts || 0);
      lifecycleOpen = !Number.isFinite(endedTs) || endedTs <= 0;
    }
  }
  // A missing close event must not leave a ghost row blue forever.  If there
  // is packet history, blue is reserved for activity within the last 90s.
  return lifecycleOpen && (activity.lastPacketTs <= 0 || activity.fresh);
}

const FLOW_PAIR_START_GAP_MS = 15 * 1000;

function getFlowTimeInfo(item, nowMs = Date.now()) {
  const tcpStartRaw = Number(item && item.tcp_start_ts);
  const tcpStartTs = Number.isFinite(tcpStartRaw) && tcpStartRaw > 0 ? tcpStartRaw : 0;
  const firstPacketRaw = Number(item && item.first_packet_ts);
  const firstPacketTs = Number.isFinite(firstPacketRaw) && firstPacketRaw > 0 ? firstPacketRaw : 0;
  const firstRaw = Number(item && (item.first_ts || item.last_ts));
  const legacyFirstTs = Number.isFinite(firstRaw) && firstRaw > 0 ? firstRaw : 0;
  const firstTs = tcpStartTs || legacyFirstTs || firstPacketTs;
  const activity = getFlowPacketActivity(item, nowMs);
  const lastPacketTs = activity.lastPacketTs;
  const lastRaw = Number(item && item.last_ts);
  const lastTs = Number.isFinite(lastRaw) && lastRaw > 0 ? lastRaw : firstTs;
  const tcpEndTs = activity.tcpEndTs;
  const endedRaw = Number(item && item.ended_ts);
  const endedTs = Number.isFinite(endedRaw) && endedRaw > 0 ? endedRaw : 0;
  const open = isFlowOpen(item, nowMs);
  const reopenedByActivity = open && activity.postClose;
  const lifecycleSaysOpen = tcpEndTs <= 0 && (
    item && (item.is_open === true || String(item.status || "").trim().toLowerCase() === "open")
  );
  const staleOpen = lifecycleSaysOpen && !open && activity.lastPacketTs > 0 && !activity.fresh;
  const recordedEndTs = Math.max(
    firstTs,
    open ? (lastPacketTs || lastTs) : (reopenedByActivity ? (lastPacketTs || lastTs) : (tcpEndTs || endedTs || lastTs)),
  );
  const displayEndTs = open ? Math.max(firstTs, Number(nowMs) || recordedEndTs) : recordedEndTs;
  const durationRaw = Number(item && item.duration_ms);
  const hasAuthoritativeDuration = Number.isFinite(durationRaw) && durationRaw >= 0;
  const fallbackDuration = hasAuthoritativeDuration ? durationRaw : 0;
  const durationMs = open
    ? (firstTs > 0 ? Math.max(displayEndTs - firstTs, 0) : fallbackDuration)
    : (staleOpen && firstTs > 0
      ? Math.max(recordedEndTs - firstTs, 0)
      : (hasAuthoritativeDuration
        ? fallbackDuration
        : (firstTs > 0 ? Math.max(displayEndTs - firstTs, 0) : 0)));
  const rawStatusSource = String(item && item.status_source || "").trim();
  const statusSource = reopenedByActivity
    ? "post_tcp_end_activity"
    : staleOpen ? "recent_activity_timeout"
      : tcpEndTs > 0 ? "tcp_end"
        : (!open && rawStatusSource) ? rawStatusSource
          : tcpStartTs > 0 ? "tcp_start" : (rawStatusSource || "legacy");
  return {
    firstTs,
    recordedEndTs,
    displayEndTs,
    durationMs,
    open,
    tcpStartTs,
    tcpEndTs,
    firstPacketTs,
    lastPacketTs,
    statusSource,
    idleMs: activity.idleMs,
    reopenedByActivity,
  };
}

function flowLifecycleStateText(time) {
  const source = String(time && time.statusSource || "");
  if (source === "post_tcp_end_activity") {
    return "正在写入（旧 tcp_end 后仍收到新包）";
  }
  if (time && time.open) return "活跃（90秒内收到数据）";
  if (source === "recent_activity_timeout") {
    return "超过90秒没有新包，按非活跃显示";
  }
  if (source === "tcp_end") return "tcp_end 已确认";
  if (source === "runtime_restart_last_packet") {
    return "MITM 重启时按末包收口（未收到 tcp_end）";
  }
  return "已收口（未收到 tcp_end）";
}

function getFlowPairKind(item) {
  const cid = stripDecoratorsFromCid(item && item.last_cid).toLowerCase();
  if (/:(?:65010)\b/.test(cid)) return "gcloud";
  if (/:443\b/.test(cid)) return "tersafe";
  return "";
}

function buildPairedFlowTimeIndex(rows, nowMs = Date.now()) {
  const byAccount = new Map();
  const result = new Map();

  for (const item of Array.isArray(rows) ? rows : []) {
    const accountInfo = extractAccountInfoFromCid(item && item.last_cid);
    const flowId = String(item && item.account || "");
    const time = getFlowTimeInfo(item, nowMs);
    const kind = getFlowPairKind(item);
    if (!accountInfo || !flowId || !kind || time.firstTs <= 0) continue;
    if (!byAccount.has(accountInfo)) byAccount.set(accountInfo, []);
    byAccount.get(accountInfo).push({ flowId, time, kind });
  }

  for (const [accountInfo, accountRows] of byAccount.entries()) {
    const gcloudRows = accountRows.filter((row) => row.kind === "gcloud");
    const tersafeRows = accountRows.filter((row) => row.kind === "tersafe");
    const candidates = [];
    for (const gcloud of gcloudRows) {
      for (const tersafe of tersafeRows) {
        const startGapMs = Math.abs(gcloud.time.firstTs - tersafe.time.firstTs);
        if (startGapMs <= FLOW_PAIR_START_GAP_MS) {
          candidates.push({ gcloud, tersafe, startGapMs });
        }
      }
    }
    candidates.sort((a, b) => a.startGapMs - b.startGapMs);

    const used = new Set();
    for (const candidate of candidates) {
      const { gcloud, tersafe, startGapMs } = candidate;
      if (used.has(gcloud.flowId) || used.has(tersafe.flowId)) continue;
      used.add(gcloud.flowId);
      used.add(tersafe.flowId);
      const overlapStartTs = Math.max(gcloud.time.firstTs, tersafe.time.firstTs);
      const overlapEndTs = Math.min(gcloud.time.displayEndTs, tersafe.time.displayEndTs);
      const overlapDurationMs = Math.max(overlapEndTs - overlapStartTs, 0);
      const durationMs = overlapDurationMs > 0
        ? overlapDurationMs
        : Math.min(gcloud.time.durationMs, tersafe.time.durationMs);
      const open = gcloud.time.open && tersafe.time.open;
      result.set(gcloud.flowId, {
        accountInfo,
        durationMs,
        open,
        socketDurationMs: gcloud.time.durationMs,
        partnerFlowId: tersafe.flowId,
        startGapMs,
      });
      result.set(tersafe.flowId, {
        accountInfo,
        durationMs,
        open,
        socketDurationMs: tersafe.time.durationMs,
        partnerFlowId: gcloud.flowId,
        startGapMs,
      });
    }
  }

  return result;
}

function usePreviewSpace() {
  if (!el.previewSpace) return true;
  return String(el.previewSpace.value || "1") !== "0";
}

function getGroupGap() {
  return usePreviewSpace() ? " " : "";
}

function getHexGroupSizes(bytesPerRow) {
  const sizes = [];
  let remain = Math.max(1, Number(bytesPerRow) || 0);
  while (remain > 0) {
    const size = Math.min(16, remain);
    sizes.push(size);
    remain -= size;
  }
  return sizes;
}

function getFlowRowPath(item) {
  const rawCid = String(item.last_cid || "");
  const cid = stripDecoratorsFromCid(rawCid);
  if (cid) return cid;
  return "(waiting cid)";
}

function hasOpenEventDetails() {
  return !!(el.events && typeof el.events.querySelector === "function" && el.events.querySelector("details[data-event-id][open]"));
}

function setupWheelRouting() {
  const routeWheel = (scrollEl, delta) => {
    if (!scrollEl) return false;
    const dy = Number(delta) || 0;
    if (!dy) return false;
    const before = scrollEl.scrollTop;
    const maxTop = Math.max(0, scrollEl.scrollHeight - scrollEl.clientHeight);
    if (maxTop <= 0) return false;

    const next = Math.max(0, Math.min(maxTop, before + dy));
    if (next === before) return false;
    scrollEl.scrollTop = next;
    return true;
  };

  const normalizeDeltaY = (ev) => {
    const raw = Number(ev && ev.deltaY);
    if (Number.isFinite(raw) && raw !== 0) return raw;
    const legacy = Number(ev && ev.wheelDelta);
    if (Number.isFinite(legacy) && legacy !== 0) return -legacy;
    const detail = Number(ev && ev.detail);
    if (Number.isFinite(detail) && detail !== 0) return detail * 16;
    return 0;
  };

  const onAnyWheel = (ev) => {
    const delta = normalizeDeltaY(ev);
    if (!delta) return;

    const target = ev.target;
    let inLeft = false;
    let inRight = false;

    if (target && typeof target.closest === "function") {
      inLeft = !!target.closest("#leftPane");
      inRight = !!target.closest("#rightPane");
    }

    if (!inLeft && !inRight && Number.isFinite(ev.clientX) && el.leftPane) {
      const rect = el.leftPane.getBoundingClientRect();
      if (ev.clientX <= rect.right) inLeft = true;
      else inRight = true;
    }

    if (inRight && routeWheel(el.events, delta)) {
      ev.preventDefault();
      return;
    }

    if (inLeft && routeWheel(el.flowList, delta)) {
      ev.preventDefault();
    }
  };

  window.addEventListener("wheel", onAnyWheel, { passive: false, capture: true });
  window.addEventListener("mousewheel", onAnyWheel, { passive: false, capture: true });
}

function updateActionButtons() {
  if (el.deleteFlow) {
    el.deleteFlow.disabled = !state.flowId;
  }
  if (el.saveFlow) {
    el.saveFlow.disabled = !state.flowId;
  }
  if (el.exportFlow) {
    el.exportFlow.disabled = !state.flowId;
  }
}

function renderFlowList() {
  const rows = state.flows;
  const nowMs = Date.now() + Number(state.serverClockOffsetMs || 0);
  const pairedFlowTime = buildPairedFlowTimeIndex(rows, nowMs);
  el.flowCount.textContent = `${rows.length}`;
  el.flowList.innerHTML = "";
  updateActionButtons();

  if (rows.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No flow data yet";
    el.flowList.appendChild(empty);
    return;
  }

  for (const item of rows) {
    const flowId = String(item.account || "");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `flow-row${flowId === state.flowId ? " active" : ""}`;
    btn.title = flowId;

    const path = document.createElement("div");
    path.className = "flow-path";
    const tcpBadge = document.createElement("span");
    tcpBadge.className = "badge-tcp";
    tcpBadge.textContent = "TCP";
    path.appendChild(tcpBadge);
    const proxyUsername = getProxyUsername(item && item.proxy_username);
    if (proxyUsername) {
      const proxyBadge = document.createElement("span");
      proxyBadge.className = "badge-kp";
      proxyBadge.textContent = `kp:${proxyUsername}`;
      path.appendChild(proxyBadge);
    }
    const cidText = document.createElement("span");
    cidText.className = "flow-cid";
    cidText.textContent = getFlowRowPath(item);
    path.appendChild(cidText);

    const proto = document.createElement("div");
    proto.textContent = "TCP";

    const size = document.createElement("div");
    size.textContent = formatSize(item.total_bytes ?? item.total);

    const duration = document.createElement("div");
    const socketTime = getFlowTimeInfo(item, nowMs);
    const pairTime = pairedFlowTime.get(flowId);
    // The flow row represents this TCP socket, so its primary duration and
    // open/closed state must come from this socket's tcp_start/tcp_end.  A
    // paired GCloud/Tersafe overlap is correlation evidence only and remains
    // available in the tooltip below.
    const durationMs = socketTime.durationMs;
    const open = socketTime.open;
    duration.className = `flow-time ${open ? "flow-time-open" : "flow-time-closed"}`;
    duration.textContent = formatDuration(durationMs);
    const socketState = flowLifecycleStateText(socketTime);
    const socketTimeTitle = [
      `开始 ${formatFlowTimestamp(socketTime.firstTs)}`,
      `结束 ${socketTime.open ? "进行中" : formatFlowTimestamp(socketTime.recordedEndTs)}`,
      `时长 ${formatDuration(socketTime.durationMs)}`,
      socketState,
      `source=${socketTime.statusSource}`,
      socketTime.firstPacketTs > 0 ? `首包 ${formatFlowTimestamp(socketTime.firstPacketTs)}` : "",
      socketTime.lastPacketTs > 0 ? `末包 ${formatFlowTimestamp(socketTime.lastPacketTs)}` : "",
    ].filter(Boolean).join("；");
    if (pairTime) {
      const stateText = open ? "进行中" : "已结束";
      duration.title = `${socketTimeTitle}；配套 GCloud/Tersafe ${stateText}（开始相差 ${Math.round(pairTime.startGapMs / 1000)}s，重叠 ${formatDuration(pairTime.durationMs)}）`;
    } else {
      duration.title = socketTimeTitle;
    }
    btn.title = `${flowId}\n${socketTimeTitle}`;

    btn.appendChild(path);
    btn.appendChild(proto);
    btn.appendChild(size);
    btn.appendChild(duration);

    btn.addEventListener("click", () => {
      selectFlow(flowId).catch((e) => setStatus(`select flow error: ${e.message}`));
    });

    el.flowList.appendChild(btn);
  }
}

function resetEventStateForFlowChange() {
  state.dumpScrollLeft.clear();
  state.events = [];
  state.gcloud9001PairIndex = null;
  state.gcloudAceStatsCache = null;
  state.afterId = null;
  state.hasMore = true;
  state.expandedIds.clear();
  state.collapsedIds.clear();
  state.hitEventIds = [];
  state.hitCursor = -1;
  state.filteredCount = 0;
  clearPayloadCache();
}

// TCPV_LATEST_EVENT_CID_V1: aggregate rows use the newest event CID.
async function hydrateAggregateFlowLatestCids(rows) {
  const items = Array.isArray(rows) ? rows : [];
  return Promise.all(items.map(async (item) => {
    const flowId = String(item && item.account || "").trim();
    const proxyUsername = String(item && item.proxy_username || "").trim();
    // UUID socket rows already own an unambiguous CID.  Only legacy aggregate
    // ids shared with the KeyProxy username need the extra read-only lookup.
    if (!flowId || !proxyUsername || flowId !== proxyUsername) return item;
    try {
      const connections = await apiJson(
        `/connections?account=${encodeURIComponent(flowId)}&recent=1`,
      );
      const latestCid = String(
        Array.isArray(connections) && connections[0] && connections[0].cid || "",
      ).trim();
      if (!latestCid || latestCid === String(item.last_cid || "")) return item;
      return { ...item, last_cid: latestCid, last_cid_source: "latest_stream_event" };
    } catch (_error) {
      return item;
    }
  }));
}

async function loadFlows(resetSelection = false, preferredFlowId = "") {
  const raw = await apiJson("/accounts");
  const data = await hydrateAggregateFlowLatestCids(normalizeAccounts(raw));
  state.allFlows = data;
  const visible = data;
  const prev = state.flowId;
  state.flows = visible;

  if (resetSelection) {
    state.flowId = "";
  }

  const preferred = String(preferredFlowId || "").trim();
  if (!state.flowId && preferred && visible.some((x) => String(x.account || "") === preferred)) {
    state.flowId = preferred;
  }

  if (!state.flowId && !resetSelection && prev && visible.some((x) => String(x.account || "") === prev)) {
    state.flowId = prev;
  }

  if (!state.flowId && visible.length > 0) {
    state.flowId = String(visible[0].account || "");
  }

  if (state.flowId && !visible.some((x) => String(x.account || "") === state.flowId)) {
    state.flowId = visible.length > 0 ? String(visible[0].account || "") : "";
  }

  if (state.flowId !== prev) {
    resetEventStateForFlowChange();
  }

  renderFlowList();
  renderSelectedTitle();
}

function renderSelectedTitle() {
  updateActionButtons();
  if (!state.flowId) {
    el.selectedTitle.textContent = "No flow selected";
    updateAceFilterUi();
    return;
  }

  const item = state.flows.find((x) => String(x.account || "") === state.flowId);
  if (!item) {
    el.selectedTitle.textContent = "Flow selected";
    updateAceFilterUi();
    return;
  }

  const rawCid = String(item.last_cid || "");
  const cid = stripDecoratorsFromCid(rawCid);
  const proxyUsername = getProxyUsername(item && item.proxy_username);
  const proxyText = proxyUsername ? `[kp:${proxyUsername}]` : "";
  const text = [proxyText, cid].filter(Boolean).join(" ");
  const time = getFlowTimeInfo(item);
  const dateTs = Number(time.firstTs || 0);
  const dateText = dateTs > 0 ? `[${formatDateOnly(dateTs)}]` : "";
  const lifecycleText = [
    `开始 ${formatFlowTimestamp(time.firstTs)}`,
    `结束 ${time.open ? "进行中" : formatFlowTimestamp(time.recordedEndTs)}`,
    `时长 ${formatDuration(time.durationMs)}`,
    flowLifecycleStateText(time),
  ].join("  |  ");
  if (currentFlowLooksLikeGcloud65010(null, rawCid)) {
    const gcloudPort = gcloudTargetPortFromText(rawCid) || "GCloud";
    const totalCount = Number(item.total_count || 0);
    const countText = totalCount > 0 ? `${totalCount}包` : "";
    const sizeText = formatSize(item.total_bytes ?? item.total);
    el.selectedTitle.textContent = [
      `${dateText} ${gcloudPort} · TGCP/GCloud`.trim(),
      text || "Flow selected",
      countText,
      sizeText,
      lifecycleText,
    ].filter(Boolean).join("  |  ");
  } else {
    el.selectedTitle.textContent = [`${dateText} ${text || "Flow selected"}`.trim(), lifecycleText].join("  |  ");
  }
  el.selectedTitle.title = lifecycleText;
  updateAceFilterUi();
}

function getCurrentFlowMeta() {
  if (!state.flowId) return null;
  return state.flows.find((x) => String(x.account || "") === state.flowId) || null;
}

function currentFlowLooksLikePort8092(ev = null, summaryText = "") {
  const flow = getCurrentFlowMeta();
  const parts = [
    summaryText,
    ev && ev.summary,
    flow && flow.listen_tag,
    flow && flow.source_port,
  ];
  const raw = parts.map((part) => String(part || "")).join(" ").toLowerCase();
  return /\bport8092\b|(?:^|\D)8092(?:\D|$)/.test(raw);
}

function gcloudTargetPortFromText(...values) {
  for (const value of values) {
    const raw = String(value || "");
    const arrow = raw.match(/->[^\s:]+:(65010|17500|20001)(?:\D|$)/i);
    if (arrow) return arrow[1];
    const explicit = raw.match(/\btarget_port=(65010|17500|20001)\b/i);
    if (explicit) return explicit[1];
  }
  return "";
}

function currentFlowLooksLikeGcloud65010(ev = null, summaryText = "") {
  const flow = getCurrentFlowMeta();
  const parts = [
    summaryText,
    ev && ev.summary,
    ev && ev.cid,
    flow && flow.last_cid,
    flow && flow.listen_tag,
    flow && flow.source_port,
  ];
  const raw = parts.map((part) => String(part || "")).join(" ").toLowerCase();
  return /\btgcp65010\b|\bgcloud\b|(?:^|\D)(?:65010|17500|20001)(?:\D|$)/.test(raw);
}

async function selectFlow(flowId) {
  if (!flowId) return;
  if (state.flowId !== flowId) {
    state.flowId = flowId;
  }
  state.syncToken += 1;
  resetEventStateForFlowChange();
  renderFlowList();
  renderSelectedTitle();
  updateSearchUi();
  renderEvents();
  setStatus("loading selected flow...");
  const initialPages = currentFlowLooksLikeGcloud65010() ? GCLOUD_INITIAL_DRAIN_PAGES : INITIAL_DRAIN_PAGES;
  const flow = getCurrentFlowMeta();
  const expectedPackets = Math.max(0, Number(flow && flow.total_count) || 0);
  const expectedPages = expectedPackets > 0 ? Math.ceil(expectedPackets / EVENTS_FETCH_LIMIT) + 1 : 1;
  await syncLatestEvents({
    drain: true,
    maxPages: Math.max(initialPages, Math.min(expectedPages, 1000)),
    force: true,
  });
}

async function syncLatestEvents(options = {}) {
  const force = !!(options && options.force);
  if (!state.flowId || (state.loading && !force)) return;
  const requestFlowId = state.flowId;
  const requestToken = state.syncToken;
  const drain = !!(options && options.drain);
  const maxPagesRaw = Number(options && options.maxPages);
  const maxPages = Number.isFinite(maxPagesRaw) && maxPagesRaw > 0 ? Math.floor(maxPagesRaw) : 1;
  state.loading = true;

  try {
    const modeSpec = parseHighlightMode(state.search.mode || "full_contains");
    const needPayloadInList = state.search.active && modeSpec.scope === "full";
    const includeAnalysisInList = false;
    let page = 0;
    let changed = false;
    let shouldRenderEmpty = false;

    while (page < maxPages) {
      const params = new URLSearchParams({
        account: requestFlowId,
        limit: String(EVENTS_FETCH_LIMIT),
        include_payload: needPayloadInList ? "1" : "0",
        include_analysis: includeAnalysisInList ? "1" : "0",
      });
      if (state.afterId) {
        params.set("after_id", state.afterId);
      }
      const data = await apiJson(`/events?${params.toString()}`);
      if (requestFlowId !== state.flowId || requestToken !== state.syncToken) {
        return;
      }

      const rows = Array.isArray(data.events) ? data.events : [];
      if (!needPayloadInList) {
        for (const ev of rows) {
          if (ev && typeof ev === "object") {
            ev.pay = "";
          }
        }
      }
      if (rows.length > 0) {
        state.events.push(...rows);
        if (MAX_EVENTS_IN_MEMORY > 0 && state.events.length > MAX_EVENTS_IN_MEMORY) {
          state.events = state.events.slice(-MAX_EVENTS_IN_MEMORY);
        }
        changed = true;
      } else if (state.events.length === 0) {
        shouldRenderEmpty = true;
      }

      state.afterId = data.last_id || state.afterId;
      state.hasMore = !!data.has_more;
      page += 1;
      if (!drain || !state.hasMore || rows.length <= 0) {
        break;
      }
    }

    if (changed || shouldRenderEmpty) {
      renderEvents();
    }
  } catch (e) {
    if (requestFlowId === state.flowId && requestToken === state.syncToken) {
      setStatus(`sync error: ${e.message}`);
    }
  } finally {
    if (requestFlowId === state.flowId && requestToken === state.syncToken) {
      state.loading = false;
    }
  }
}

async function clearCurrentFlow() {
  const flowId = String(state.flowId || "").trim();
  if (!flowId) return;

  const currentOrder = state.flows.map((x) => String(x.account || ""));
  const currentIdx = currentOrder.indexOf(flowId);
  let preferredFlowId = "";
  if (currentIdx >= 0) {
    for (let i = currentIdx + 1; i < currentOrder.length; i++) {
      const candidate = currentOrder[i];
      if (candidate && candidate !== flowId) {
        preferredFlowId = candidate;
        break;
      }
    }
    if (!preferredFlowId) {
      for (let i = currentIdx - 1; i >= 0; i--) {
        const candidate = currentOrder[i];
        if (candidate && candidate !== flowId) {
          preferredFlowId = candidate;
          break;
        }
      }
    }
  }

  try {
    await apiPost(`/flows/clear?account=${encodeURIComponent(flowId)}`);
  } catch (e) {
    setStatus(`clear flow warning: ${e.message}`);
  }

  state.events = [];
  state.afterId = null;
  state.hasMore = true;
  state.dumpScrollLeft.clear();
  state.expandedIds.clear();
  state.collapsedIds.clear();
  state.hitEventIds = [];
  state.hitCursor = -1;
  state.filteredCount = 0;

  await loadFlows(true, preferredFlowId);
  if (state.flowId) {
    await selectFlow(state.flowId);
  } else {
    renderEvents();
  }
  setStatus("TCPView 记录和缓存已删除；网络连接未关闭");
}

async function importFlowFile(file) {
  if (!file) return;
  const bytes = await file.arrayBuffer();
  const result = await apiPostBytes(`/imports?filename=${encodeURIComponent(file.name || "import.txt")}`, bytes);
  const account = String(result.account || "");
  await loadFlows(true, account);
  if (account) {
    await selectFlow(account);
  }
  setStatus(`imported ${result.events || 0} packets from ${file.name || "file"}`);
}

async function saveCurrentFlow() {
  const flowId = String(state.flowId || "").trim();
  if (!flowId) return;
  const result = await apiPost(`/flows/save?account=${encodeURIComponent(flowId)}`);
  setStatus(`saved ${result.events || 0} packets -> ${result.filename || result.path || "archive"}`);
}

async function exportCurrentFlow() {
  const flowId = String(state.flowId || "").trim();
  if (!flowId) return;
  const resp = await fetch(`/flows/export?account=${encodeURIComponent(flowId)}`, { cache: "no-store" });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`HTTP ${resp.status} ${resp.statusText}: ${body.slice(0, 200)}`);
  }
  const blob = await resp.blob();
  const disposition = resp.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const filename = match ? match[1] : `${flowId.replace(/[^a-z0-9_.-]+/gi, "_")}.tcpvflow.jsonl.gz`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  setStatus(`exported ${filename}`);
}

function b64ToBytes(base64Text) {
  try {
    const bin = atob(base64Text || "");
    const out = new Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch (_e) {
    return [];
  }
}

function b64ToBytesLimited(base64Text, maxBytes) {
  const limit = Number(maxBytes || 0);
  if (!Number.isFinite(limit) || limit <= 0) return [];

  const compact = String(base64Text || "").replace(/\s+/g, "");
  if (!compact) return [];

  const charsNeeded = Math.ceil(limit / 3) * 4;
  let chunk = compact.slice(0, charsNeeded);
  const mod = chunk.length % 4;
  if (mod !== 0) {
    chunk = chunk.padEnd(chunk.length + (4 - mod), "=");
  }

  const decoded = b64ToBytes(chunk);
  if (decoded.length <= limit) return decoded;
  return decoded.slice(0, limit);
}

function b64ToBytesWindow(base64Text, startOffset, windowLen) {
  const start = Math.max(0, Number(startOffset || 0));
  const size = Math.max(0, Number(windowLen || 0));
  if (!Number.isFinite(start) || !Number.isFinite(size) || size <= 0) return [];

  const need = start + size;
  const decoded = b64ToBytesLimited(base64Text, need);
  if (!Array.isArray(decoded) || decoded.length <= start) return [];
  return decoded.slice(start, start + size);
}

function formatTs(ts) {
  try {
    const { yyyy, mm, dd, hh, mi, ss } = displayTimeParts(ts);
    return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
  } catch (_e) {
    return String(ts || 0);
  }
}

function formatDateOnly(ts) {
  try {
    const { yyyy, mm, dd } = displayTimeParts(ts);
    return `${yyyy}-${mm}-${dd}`;
  } catch (_e) {
    return String(ts || 0);
  }
}

function formatTsShort(ts) {
  try {
    const { hh, mi, ss } = displayTimeParts(ts);
    return `${hh}:${mi}:${ss}`;
  } catch (_e) {
    return String(ts || 0);
  }
}

function getBytesPerRow() {
  const raw = Number(el.previewBytes.value || "16");
  return [16, 24, 32, 48, 64, 80, 96, 128].includes(raw) ? raw : 16;
}

function normalizeDumpAnnotationText(text) {
  return String(text || "").replace(/\s+/g, " ").trim();
}

function splitDumpAnnotationLines(text) {
  return String(text || "")
    .split(/\n\s*(?:(?=\/\/)|\/\/\s*)?/)
    .map((part) => normalizeDumpAnnotationText(part.replace(/^\/\/\s*/, "")))
    .filter(Boolean);
}

function canonicalDumpAnnotationKey(text) {
  const normalized = normalizeDumpAnnotationText(text);
  const state = normalized.match(/\bstate[:=]([^,\s]+)(?:[, ]+r[:=]([^,\s]+))?(?:[, ]+p[:=]([^,\s]+))?/i);
  if (state) {
    return [
      "state",
      String(state[1] || "").toLowerCase(),
      String(state[2] || "").toLowerCase(),
      String(state[3] || "").toLowerCase(),
    ].join("|");
  }
  const cs = normalized.match(/\bcs[:=]([^,\s;|]+)/i);
  if (cs) {
    return ["cs", String(cs[1] || "").toLowerCase()].join("|");
  }
  return normalized.toLowerCase();
}

function addDumpAnnotationLine(bucket, text, maxLines = 4) {
  const line = normalizeDumpAnnotationText(text);
  if (!line) return;
  const key = canonicalDumpAnnotationKey(line);
  for (let index = 0; index < bucket.length; index += 1) {
    const existing = bucket[index];
    const existingKey = canonicalDumpAnnotationKey(existing);
    if (existingKey === key) {
      if (line.length > existing.length) bucket[index] = line;
      return;
    }
    const lowerLine = line.toLowerCase();
    const lowerExisting = existing.toLowerCase();
    if (lowerExisting.includes(lowerLine)) return;
    if (lowerLine.includes(lowerExisting)) {
      bucket[index] = line;
      return;
    }
  }
  if (bucket.length < maxLines) bucket.push(line);
}

function trimPrintableRunPrefix(start, text, minLen = ANALYSIS_ASCII_MIN_LEN) {
  let off = Number(start || 0);
  let current = String(text || "");
  if (!current) return { off, text: "", kind: "" };

  let anchorIndex = -1;
  for (const pattern of PRINTABLE_RUN_ANCHOR_PATTERNS) {
    const match = current.match(pattern);
    if (!match || match.index == null || match.index <= 0) continue;
    if (anchorIndex === -1 || match.index < anchorIndex) {
      anchorIndex = match.index;
    }
  }
  if (anchorIndex > 0 && anchorIndex <= 8) {
    const prefix = current.slice(0, anchorIndex);
    const semanticPrefix = prefix.replace(/[:=_-]+$/g, "");
    const keepSemanticPrefix = /^[A-Za-z][A-Za-z0-9_]{3,20}$/i.test(semanticPrefix);
    if (!keepSemanticPrefix) {
      off += anchorIndex;
      current = current.slice(anchorIndex);
    }
  }

  const leadingNoise = current.match(/^[^A-Za-z0-9/]{1,4}/);
  if (leadingNoise && current.length - leadingNoise[0].length >= minLen) {
    off += leadingNoise[0].length;
    current = current.slice(leadingNoise[0].length);
  }

  const accountMatch = current.match(/\d{10,24}/);
  if (accountMatch && accountMatch.index != null && accountMatch.index > 0 && accountMatch.index <= 4) {
    off += accountMatch.index;
    current = accountMatch[0];
  }

  return {
    off,
    text: current,
    kind: inferStringKind(current),
  };
}

function buildDumpAnnotationIndex(items, bytesPerRow) {
  const grouped = new Map();
  if (!Array.isArray(items) || items.length <= 0) return grouped;
  const width = Math.max(1, Number(bytesPerRow || 16));
  for (const item of items) {
    const off = Number(item && item.off);
    const rawText = normalizeDumpAnnotationText(item && item.text ? item.text : "");
    if (!Number.isFinite(off) || off < 0 || !rawText) continue;
    const rowBase = Math.floor(off / width) * width;
    const bucket = grouped.get(rowBase) || [];
    addDumpAnnotationLine(bucket, rawText, 2);
    grouped.set(rowBase, bucket);
  }
  return new Map(Array.from(grouped.entries(), ([rowBase, bucket]) => [rowBase, bucket.join("\n// ")]));
}

function extractPrintableRunsForDumpAnnotations(byteValues, minLen = ANALYSIS_ASCII_MIN_LEN, maxItems = ANALYSIS_ASCII_MAX_ITEMS) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
  const out = [];
  let start = -1;
  let chars = [];
  const flush = () => {
    if (start >= 0 && chars.length >= minLen) {
      const refined = trimPrintableRunPrefix(start, chars.join(""), minLen);
      const text = normalizeDumpAnnotationText(refined.text);
      if (text.length >= minLen) {
        out.push({
          off: refined.off,
          text,
          kind: refined.kind || inferStringKind(text),
        });
      }
    }
    start = -1;
    chars = [];
  };
  for (let i = 0; i < byteValues.length; i += 1) {
    const byte = byteValues[i];
    if (byte >= 32 && byte < 127) {
      if (start < 0) start = i;
      chars.push(String.fromCharCode(byte));
    } else {
      flush();
    }
  }
  flush();

  const unique = [];
  const seen = new Set();
  for (const item of out) {
    const key = `${item.off}|${item.text}|${item.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(item);
    if (unique.length >= maxItems) break;
  }
  return unique;
}

function mergeDumpAnnotationIndexes(...indexes) {
  const merged = new Map();
  for (const index of indexes) {
    if (!(index instanceof Map)) continue;
    for (const [rowBase, text] of index.entries()) {
      const lines = splitDumpAnnotationLines(text);
      if (lines.length <= 0) continue;
      const bucket = splitDumpAnnotationLines(merged.get(rowBase) || "");
      for (const line of lines) {
        addDumpAnnotationLine(bucket, line, 4);
      }
      if (bucket.length > 0) merged.set(rowBase, bucket.join("\n// "));
    }
  }
  return merged;
}

function dumpAnnotationItemsFromBase64(base64Text) {
  const bytes = b64ToBytes(base64Text);
  if (!Array.isArray(bytes) || bytes.length <= 0) return [];
  return collectAnalysisStringItems(
    extractPrintableRunsForDumpAnnotations(bytes, ANALYSIS_ASCII_MIN_LEN, ANALYSIS_ASCII_MAX_ITEMS * 2),
    extractUtf8Runs(bytes, ANALYSIS_UTF8_MIN_CHARS, ANALYSIS_UTF8_MAX_ITEMS),
    extractBase64DecodedRuns(bytes, ANALYSIS_BASE64_MAX_ITEMS)
  );
}

function getDumpAnnotationIndex(ev, source, base64Text = "") {
  const bytesPerRow = getBytesPerRow();
  if (base64Text) {
    return buildDumpAnnotationIndex(dumpAnnotationItemsFromBase64(base64Text), bytesPerRow);
  }
  const analysis = getEventAnalysis(ev);
  if (!analysis) return new Map();
  if (source === "full") {
    const items = [
      ...(Array.isArray(analysis.fullStrings) ? analysis.fullStrings : []),
      ...(Array.isArray(analysis.fullUtf8Strings) ? analysis.fullUtf8Strings : []),
    ];
    return buildDumpAnnotationIndex(items, bytesPerRow);
  }
  if (source === "before") {
    const items = [
      ...(Array.isArray(analysis.beforeStrings) ? analysis.beforeStrings : []),
      ...(Array.isArray(analysis.beforeUtf8Strings) ? analysis.beforeUtf8Strings : []),
      ...(Array.isArray(analysis.beforeBase64Strings) ? analysis.beforeBase64Strings : []),
    ];
    return buildDumpAnnotationIndex(items, bytesPerRow);
  }
  if (source !== "decoded") return new Map();
  const items = [
    ...(Array.isArray(analysis.decodedStrings) ? analysis.decodedStrings : []),
    ...(Array.isArray(analysis.decodedUtf8Strings) ? analysis.decodedUtf8Strings : []),
    ...(Array.isArray(analysis.decodedBase64Strings) ? analysis.decodedBase64Strings : []),
  ];
  return buildDumpAnnotationIndex(items, bytesPerRow);
}

function buildTimestampAnnotationIndex(items, bytesPerRow) {
  const grouped = new Map();
  if (!Array.isArray(items) || items.length <= 0) return grouped;
  const width = Math.max(1, Number(bytesPerRow || 16));
  for (const item of items) {
    const off = Number(item && item.start);
    const text = normalizeDumpAnnotationText(item && item.text ? item.text : "");
    if (!Number.isFinite(off) || off < 0 || !text) continue;
    const rowBase = Math.floor(off / width) * width;
    const bucket = grouped.get(rowBase) || [];
    addDumpAnnotationLine(bucket, text, 3);
    grouped.set(rowBase, bucket);
  }
  return new Map(Array.from(grouped.entries(), ([rowBase, bucket]) => [rowBase, bucket.join("\n// ")]));
}

function buildChangedOffsetSet(leftBase64, rightBase64) {
  const left = b64ToBytes(leftBase64);
  const right = b64ToBytes(rightBase64);
  if (!Array.isArray(left) || !Array.isArray(right) || left.length === 0 || right.length === 0) {
    return null;
  }
  const maxLen = Math.max(left.length, right.length);
  const changed = new Set();
  for (let i = 0; i < maxLen; i += 1) {
    if (left[i] !== right[i]) changed.add(i);
  }
  return changed.size > 0 ? changed : null;
}

function buildRangeOffsetSet(ranges) {
  if (!Array.isArray(ranges) || ranges.length <= 0) return null;
  const offsets = new Set();
  for (const range of ranges) {
    const start = Math.max(0, Math.floor(Number(range && range.start)));
    const end = Math.max(start, Math.floor(Number(range && range.end)));
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) continue;
    for (let off = start; off < end; off += 1) {
      offsets.add(off);
    }
  }
  return offsets.size > 0 ? offsets : null;
}

function findTrailingChecksumCandidate(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length < 8) return null;
  const sepOffset = byteValues.length - 5;
  if (byteValues[sepOffset] !== 0) return null;
  const tail = byteValues.slice(byteValues.length - 4);
  if (tail.length !== 4 || tail.every((byte) => Number(byte || 0) === 0)) return null;
  const report = detectTssReport(byteValues);
  const nearby = byteValues.slice(Math.max(0, sepOffset - 96), sepOffset);
  const textBeforeTail = extractPrintableRuns(nearby, 4, 8, { fullText: true })
    .map((item) => String(item.text || ""))
    .join(" ");
  const hasSemanticText = /(?:mrp|mrpc|mrpcs|mrcp)[\w.-]*|\.data\b|model:|ver:|state:|\d{10,24}/i.test(textBeforeTail);
  if (!report && !hasSemanticText) return null;
  const tailHex = tail.map((byte) => childHexByteText(byte)).join(" ");
  return {
    sepOffset,
    tailStart: byteValues.length - 4,
    tailEnd: byteValues.length,
    tailHex,
    text: `尾部候选 ${hexOffsetText(sepOffset)}=00 分割；${hexOffsetText(byteValues.length - 4)}-${hexOffsetText(byteValues.length - 1)} CRC?/校验尾 ${tailHex}`,
  };
}

function mergeAnnotationLine(annotationIndex, rowBase, text) {
  const base = Math.max(0, Math.floor(Number(rowBase)));
  const value = String(text || "").trim();
  if (!(annotationIndex instanceof Map) || !Number.isFinite(base) || !value) return;
  const existing = String(annotationIndex.get(base) || "").trim();
  if (!existing) {
    annotationIndex.set(base, value);
    return;
  }
  if (existing.includes(value)) return;
  annotationIndex.set(base, `${existing}\n// ${value}`);
}

function formatHexDump(base64Text, hideAscii, annotationIndex = null, options = {}) {
  const bytes = b64ToBytes(base64Text);
  const bytesPerRow = getBytesPerRow();
  const groupSizes = getHexGroupSizes(bytesPerRow);
  const groupGap = getGroupGap();
  const compactAscii = !!(options && options.compactAscii);
  const changedOffsets = options && options.changedOffsets instanceof Set ? options.changedOffsets : null;
  const timestampOffsets = buildRangeOffsetSet(options && Array.isArray(options.timestampRanges) ? options.timestampRanges : []);
  const idfvOffsets = buildRangeOffsetSet(options && Array.isArray(options.idfvRanges) ? options.idfvRanges : []);
  const historyOffsets = buildRangeOffsetSet(options && Array.isArray(options.historyRanges) ? options.historyRanges : []);
  const checksumTail = options && options.showTailChecksum ? findTrailingChecksumCandidate(bytes) : null;
  const checksumTailOffsets = checksumTail
    ? buildRangeOffsetSet([{ start: checksumTail.sepOffset, end: checksumTail.tailEnd }])
    : null;
  const annotations = annotationIndex instanceof Map ? new Map(annotationIndex) : new Map();
  if (checksumTail) {
    mergeAnnotationLine(
      annotations,
      Math.floor(Number(checksumTail.sepOffset) / bytesPerRow) * bytesPerRow,
      checksumTail.text,
    );
  }
  const groupWidths = groupSizes.map((size) => size * 3 - 1);
  const hexWidth = groupWidths.reduce((acc, width) => acc + width, 0) + groupGap.length * (groupSizes.length - 1);

  let col = 0;
  const headCols = groupSizes
    .map((size) => {
      const cols = Array.from({ length: size }, (_x, idx) =>
        (col + idx).toString(16).padStart(2, "0")
      ).join(" ");
      col += size;
      return cols;
    })
    .join(groupGap);

  const headerCore = `offset  ${headCols}`.padEnd(8 + hexWidth, " ");
  const asciiHead = compactAscii ? "|asc|" : "|ascii|";
  const header = hideAscii ? headerCore : `${headerCore}  ${asciiHead}`;
  if (bytes.length === 0) {
    return { header, rows: [] };
  }

  const rows = [];
  for (let i = 0; i < bytes.length; i += bytesPerRow) {
    const chunk = bytes.slice(i, i + bytesPerRow);
    let offsetInChunk = 0;
    const rowParts = groupSizes.map((size, idx) => {
      const part = chunk.slice(offsetInChunk, offsetInChunk + size);
      offsetInChunk += size;
      const partHex = part.map((v) => v.toString(16).padStart(2, "0")).join(" ");
      return partHex.padEnd(groupWidths[idx], " ");
    });
    const hexPadded = rowParts.join(groupGap);
    const offset = i.toString(16).padStart(6, "0");
    const changedIndexes = changedOffsets
      ? chunk.map((_v, idx) => changedOffsets.has(i + idx))
      : [];
    const timestampIndexes = timestampOffsets
      ? chunk.map((_v, idx) => timestampOffsets.has(i + idx))
      : [];
    const idfvIndexes = idfvOffsets
      ? chunk.map((_v, idx) => idfvOffsets.has(i + idx))
      : [];
    const historyIndexes = historyOffsets
      ? chunk.map((_v, idx) => historyOffsets.has(i + idx))
      : [];
    const checksumTailIndexes = checksumTailOffsets
      ? chunk.map((_v, idx) => checksumTailOffsets.has(i + idx))
      : [];
    if (hideAscii) {
      rows.push({
        offset,
        hex: hexPadded,
        bytes: chunk,
        groupSizes,
        groupWidths,
        groupGap,
        changedIndexes,
        timestampIndexes,
        idfvIndexes,
        historyIndexes,
        checksumTailIndexes,
        ascii: "",
        compactAscii,
        comment: String(annotations.get(i) || ""),
      });
      continue;
    }
    const asciiStats = dumpAsciiStats(chunk);
    let ascii = chunk.map((v) => dumpAsciiChar(v)).join("");
    if (compactAscii && ascii.length > 10) {
      ascii = `${ascii.slice(0, 10)}…`;
    }
    rows.push({
      offset,
      hex: hexPadded,
      bytes: chunk,
      groupSizes,
      groupWidths,
      groupGap,
      changedIndexes,
      timestampIndexes,
      idfvIndexes,
      historyIndexes,
      checksumTailIndexes,
      ascii,
      asciiPrintableCount: asciiStats.printableCount,
      asciiMaxRun: asciiStats.maxRun,
      compactAscii,
      comment: String(annotations.get(i) || ""),
    });
  }
  return { header, rows, checksumTail };
}

function renderHexBytesHtml(row) {
  if (!row || !Array.isArray(row.bytes) || !Array.isArray(row.groupSizes)) {
    return `<span class="hex-bytes">${escapeHtml(row && row.hex ? row.hex : "")}</span>`;
  }
  let offsetInChunk = 0;
  const parts = row.groupSizes.map((size, groupIndex) => {
    const bytes = row.bytes.slice(offsetInChunk, offsetInChunk + size);
    const marks = Array.isArray(row.changedIndexes)
      ? row.changedIndexes.slice(offsetInChunk, offsetInChunk + size)
      : [];
    const timestampMarks = Array.isArray(row.timestampIndexes)
      ? row.timestampIndexes.slice(offsetInChunk, offsetInChunk + size)
      : [];
    const idfvMarks = Array.isArray(row.idfvIndexes)
      ? row.idfvIndexes.slice(offsetInChunk, offsetInChunk + size)
      : [];
    const historyMarks = Array.isArray(row.historyIndexes)
      ? row.historyIndexes.slice(offsetInChunk, offsetInChunk + size)
      : [];
    const checksumTailMarks = Array.isArray(row.checksumTailIndexes)
      ? row.checksumTailIndexes.slice(offsetInChunk, offsetInChunk + size)
      : [];
    offsetInChunk += size;
    const html = bytes
      .map((value, idx) => {
        const hex = value.toString(16).padStart(2, "0");
        if (timestampMarks[idx]) return `<span class="hex-byte-timestamp">${hex}</span>`;
        if (idfvMarks[idx]) return `<span class="hex-byte-idfv">${hex}</span>`;
        if (historyMarks[idx]) return `<span class="hex-byte-history">${hex}</span>`;
        if (checksumTailMarks[idx]) return `<span class="hex-byte-crc-tail">${hex}</span>`;
        return marks[idx] ? `<span class="hex-byte-changed">${hex}</span>` : escapeHtml(hex);
      })
      .join(" ");
    const width = Array.isArray(row.groupWidths) ? Number(row.groupWidths[groupIndex]) : size * 3 - 1;
    return html + "&nbsp;".repeat(Math.max(0, width - (bytes.length * 3 - 1)));
  });
  const gap = escapeHtml(String(row.groupGap || "  "));
  return `<span class="hex-bytes">${parts.join(gap)}</span>`;
}

function isPrintableAsciiByte(byte) {
  const value = Number(byte || 0) & 0xff;
  return value >= 32 && value <= 126;
}

function dumpAsciiChar(byte) {
  const value = Number(byte || 0) & 0xff;
  if (isPrintableAsciiByte(value)) return String.fromCharCode(value);
  return " ";
}

function dumpAsciiStats(bytes) {
  const values = Array.isArray(bytes) ? bytes : [];
  let printableCount = 0;
  let currentRun = 0;
  let maxRun = 0;
  for (const byte of values) {
    if (isPrintableAsciiByte(byte)) {
      printableCount += 1;
      currentRun += 1;
      maxRun = Math.max(maxRun, currentRun);
    } else {
      currentRun = 0;
    }
  }
  return { printableCount, maxRun };
}

function shouldRenderAsciiUnderRow(row) {
  const printableCount = Number(row && row.asciiPrintableCount);
  const maxRun = Number(row && row.asciiMaxRun);
  if (!Number.isFinite(printableCount) || printableCount <= 0) return false;
  return maxRun >= 3 || printableCount >= 5;
}

function renderHexAsciiUnderHtml(row) {
  if (!row || !Array.isArray(row.bytes) || !Array.isArray(row.groupSizes)) return "";
  if (!shouldRenderAsciiUnderRow(row)) return "";
  let offsetInChunk = 0;
  const parts = row.groupSizes.map((size, groupIndex) => {
    const bytes = row.bytes.slice(offsetInChunk, offsetInChunk + size);
    offsetInChunk += size;
    const text = bytes.map((byte) => ` ${dumpAsciiChar(byte)}`).join(" ");
    const width = Array.isArray(row.groupWidths) ? Number(row.groupWidths[groupIndex]) : size * 3 - 1;
    return escapeHtml(text.padEnd(Math.max(0, width), " "));
  });
  const gap = escapeHtml(String(row.groupGap || "  "));
  const spacerWidth = String(row.offset || "").length + 1;
  const spacer = "&nbsp;".repeat(Math.max(0, spacerWidth));
  return `<span class="hex-ascii-under-line"><span class="hex-ascii-under-spacer">${spacer}</span><span class="hex-ascii-under">${parts.join(gap)}</span></span>`;
}

function renderHexBodyHtml(dump, hideAscii, options = {}) {
  if (!dump || !Array.isArray(dump.rows) || dump.rows.length === 0) {
    return "";
  }
  const blockComments = !!(options && options.blockComments);
  const asciiRows = !!(options && options.asciiRows);
  return dump.rows
    .map((row) => {
      const offsetHtml = `<span class="hex-offset">${escapeHtml(row.offset)}</span>`;
      const hexHtml = renderHexBytesHtml(row);
      if (hideAscii) {
        const blockCommentHtml = blockComments && row.comment
          ? `\n<span class="hex-comment hex-comment-block">// ${escapeHtml(row.comment)}</span>`
          : "";
        const commentHtml = !blockComments && row.comment ? ` <span class="hex-comment">// ${escapeHtml(row.comment)}</span>` : "";
        return `${offsetHtml} ${hexHtml}${commentHtml}${blockCommentHtml}`;
      }
      const asciiHtml =
        `<span class="hex-ascii-bar">|</span>` +
        `<span class="hex-ascii${row.compactAscii ? " hex-ascii-compact" : ""}">${escapeHtml(row.ascii)}</span>` +
        `<span class="hex-ascii-bar">|</span>`;
      const commentHtml = !blockComments && row.comment ? ` <span class="hex-comment">// ${escapeHtml(row.comment)}</span>` : "";
      const asciiUnderHtml = asciiRows ? `\n${renderHexAsciiUnderHtml(row)}` : "";
      const blockCommentHtml = blockComments && row.comment
        ? `\n<span class="hex-comment hex-comment-block">// ${escapeHtml(row.comment)}</span>`
        : "";
      return `${offsetHtml} ${hexHtml} ${asciiHtml}${commentHtml}${asciiUnderHtml}${blockCommentHtml}`;
    })
    .join("\n");
}

function normalizeHex(text) {
  return String(text || "").toLowerCase().replace(/[^0-9a-f]/g, "");
}

function normalizeHexColor(rawColor, fallbackColor = "") {
  const text = String(rawColor || "").trim();
  if (!text) return fallbackColor;
  if (/^#[0-9a-f]{6}$/i.test(text) || /^#[0-9a-f]{3}$/i.test(text)) {
    return text.toLowerCase();
  }
  if (/^[0-9a-f]{6}$/i.test(text) || /^[0-9a-f]{3}$/i.test(text)) {
    return `#${text.toLowerCase()}`;
  }
  return fallbackColor;
}

function parseHighlightMode(rawMode) {
  const mode = String(rawMode || "").trim().toLowerCase();
  const known = {
    preview_contains: { key: "preview_contains", scope: "preview", mode: "contains" },
    preview_prefix: { key: "preview_prefix", scope: "preview", mode: "prefix" },
    preview_exact: { key: "preview_exact", scope: "preview", mode: "exact" },
    full_contains: { key: "full_contains", scope: "full", mode: "contains" },
    full_prefix: { key: "full_prefix", scope: "full", mode: "prefix" },
    full_exact: { key: "full_exact", scope: "full", mode: "exact" },
  };
  return known[mode] || known.full_contains;
}

function parseHighlightPattern(rawInput) {
  const raw = String(rawInput || "").trim();
  if (!raw) {
    return { tokens: [], invalid: false };
  }

  const compact = raw
    .toLowerCase()
    .replace(/0x/g, "")
    .replace(/[^0-9a-fx?*]/g, "");

  if (!compact) {
    return { tokens: [], invalid: false };
  }
  if (compact.length % 2 !== 0) {
    return { tokens: [], invalid: true };
  }

  const tokens = [];
  for (let i = 0; i < compact.length; i += 2) {
    const pair = compact.slice(i, i + 2);
    if (pair === "xx" || pair === "??" || pair === "**") {
      tokens.push(null);
      continue;
    }
    if (/^[0-9a-f]{2}$/.test(pair)) {
      tokens.push(parseInt(pair, 16));
      continue;
    }
    return { tokens: [], invalid: true };
  }

  const fixedCount = tokens.filter((x) => x !== null).length;
  if (fixedCount <= 0) {
    return { tokens: [], invalid: true };
  }
  return { tokens, invalid: false };
}

function parseHighlightRules(rawInput, fallbackColor) {
  const text = String(rawInput || "").trim();
  if (!text) {
    return { rules: [], invalidCount: 0 };
  }

  const parts = text
    .split(/[;\n]+/)
    .map((x) => x.trim())
    .filter((x) => x.length > 0);

  if (parts.length === 0) {
    return { rules: [], invalidCount: 0 };
  }

  const rules = [];
  let invalidCount = 0;
  const defaultColor = normalizeHexColor(fallbackColor, "#ffd166");

  for (const part of parts) {
    let patternText = part;
    let colorText = "";
    const atIdx = part.lastIndexOf("@");
    if (atIdx > 0) {
      patternText = part.slice(0, atIdx).trim();
      colorText = part.slice(atIdx + 1).trim();
    }

    const parsed = parseHighlightPattern(patternText);
    if (parsed.invalid || !Array.isArray(parsed.tokens) || parsed.tokens.length === 0) {
      invalidCount += 1;
      continue;
    }
    const color = normalizeHexColor(colorText, defaultColor);
    rules.push({
      tokens: parsed.tokens,
      color,
    });
  }

  return { rules, invalidCount };
}

function buildAppliedSearchState(rawText, rawMode, rawColor) {
  const modeSpec = parseHighlightMode(rawMode);
  const text = String(rawText || "").trim();
  const color = normalizeHexColor(rawColor, "#ffd166");
  if (!text) {
    return {
      active: false,
      text: "",
      mode: modeSpec.key,
      color,
      rules: [],
      invalidCount: 0,
    };
  }

  const parsed = parseHighlightRules(text, color);
  const active = parsed.invalidCount === 0 && parsed.rules.length > 0;
  return {
    active,
    text,
    mode: modeSpec.key,
    color,
    rules: active ? parsed.rules : [],
    invalidCount: parsed.invalidCount,
  };
}

function updateSearchDraftState() {
  const draft = buildAppliedSearchState(
    el.prefix ? el.prefix.value : "",
    el.highlightMode ? el.highlightMode.value : "full_contains",
    el.color ? el.color.value : "#ffd166",
  );
  if (el.prefix) {
    const invalid = draft.invalidCount > 0;
    el.prefix.classList.toggle("input-invalid", invalid);
    if (invalid) {
      el.prefix.title = "请输入完整的十六进制字节，例如 0a92 或 01 0a 00 13";
    } else {
      el.prefix.title = "搜索当前显示包的前 8KB；空格和 0x 可省略，按 Enter 开始";
    }
  }
  return draft;
}

function updateSearchUi() {
  const totalHits = Array.isArray(state.hitEventIds) ? state.hitEventIds.length : 0;
  const currentHit = totalHits > 0 && state.hitCursor >= 0 ? state.hitCursor + 1 : 0;
  if (el.searchHitStat) {
    el.searchHitStat.textContent = state.search.active ? `${currentHit}/${totalHits}` : "--/--";
    el.searchHitStat.title = state.search.active
      ? `current hit ${currentHit}, total hit ${totalHits}`
      : "no active highlight search";
  }
  if (el.searchPrev) {
    el.searchPrev.disabled = totalHits <= 0;
  }
  if (el.searchNext) {
    el.searchNext.disabled = totalHits <= 0;
  }
}

function getFilterDraftState() {
  return normalizeFilterState(
    el.filterDir ? el.filterDir.value : "all",
    el.filterMinLen ? el.filterMinLen.value : "",
    el.filterMaxLen ? el.filterMaxLen.value : "",
    el.filterCsobOnly ? el.filterCsobOnly.checked : false,
    el.filterAceMode ? el.filterAceMode.value : "all",
  );
}

function findPatternMatches(byteValues, patternTokens, mode = "contains", maxMatches = 12) {
  if (!Array.isArray(byteValues) || byteValues.length === 0) return [];
  if (!Array.isArray(patternTokens) || patternTokens.length === 0) return [];

  const plen = patternTokens.length;
  if (plen > byteValues.length) return [];

  const ranges = [];
  const matcher = (start) => {
    for (let j = 0; j < plen; j++) {
      const token = patternTokens[j];
      if (token !== null && token !== byteValues[start + j]) {
        return false;
      }
    }
    return true;
  };

  if (mode === "exact") {
    if (plen !== byteValues.length) return [];
    if (matcher(0)) {
      ranges.push({ start: 0, end: plen });
    }
    return ranges;
  }

  if (mode === "prefix") {
    if (matcher(0)) {
      ranges.push({ start: 0, end: plen });
    }
    return ranges;
  }

  for (let start = 0; start <= byteValues.length - plen; start++) {
    if (!matcher(start)) continue;

    ranges.push({ start, end: start + plen });
    if (ranges.length >= maxMatches) break;
    start += Math.max(0, plen - 1);
  }
  return ranges;
}

function mergeRuleMatches(byteValues, rules, mode, maxMatches = 16) {
  if (!Array.isArray(rules) || rules.length === 0) return [];
  const all = [];
  for (const rule of rules) {
    if (!rule || !Array.isArray(rule.tokens) || rule.tokens.length === 0) continue;
    const ranges = findPatternMatches(byteValues, rule.tokens, mode, maxMatches);
    for (const range of ranges) {
      all.push({
        start: range.start,
        end: range.end,
        color: rule.color || "",
      });
      if (all.length >= maxMatches) {
        return all;
      }
    }
  }
  return all;
}

function projectRangesToWindow(ranges, windowStart, windowLen) {
  if (!Array.isArray(ranges) || ranges.length === 0) return [];
  const begin = Math.max(0, Number(windowStart || 0));
  const finish = begin + Math.max(0, Number(windowLen || 0));
  if (!(finish > begin)) return [];
  const clipped = [];
  for (const r of ranges) {
    const start = Math.max(begin, Number(r.start || 0));
    const end = Math.min(finish, Number(r.end || 0));
    if (end <= start) continue;
    clipped.push({ start: start - begin, end: end - begin, color: r.color || "" });
  }
  return clipped;
}

function formatPreviewBytesText(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length === 0) return "";
  const gap16 = usePreviewSpace();
  let previewText = "";
  for (let i = 0; i < byteValues.length; i++) {
    if (i > 0) {
      previewText += gap16 && i % 16 === 0 ? "  " : " ";
    }
    previewText += byteValues[i].toString(16).padStart(2, "0");
  }
  return previewText;
}

function collect010a0011HiLabelsFromBytes(byteValues, maxItems = 3) {
  if (!Array.isArray(byteValues) || byteValues.length < 8) return [];
  const limit = Math.max(1, Number(maxItems || 3));
  const labels = [];
  const seen = new Set();
  const marker = [0x01, 0x0a, 0x00, 0x11];
  for (let offset = 0; offset + marker.length <= byteValues.length; offset += 1) {
    if (!marker.every((value, index) => byteValues[offset + index] === value)) continue;
    const windowBytes = byteValues.slice(offset + marker.length, Math.min(byteValues.length, offset + 80));
    const text = bytesToLatin1String(windowBytes);
    const match = text.match(/(?:^|[^0-9A-Za-z_])(hi_?(?:x|[0-9]{1,6}))(?![0-9A-Za-z_])/i);
    if (!match) continue;
    const label = match[1].replace(/^hi_/i, "hi");
    const key = label.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    labels.push(label);
    if (labels.length >= limit) break;
  }
  return labels;
}

function collectEvent010a0011HiLabels(ev, previewBytes) {
  const sources = [];
  if (Array.isArray(previewBytes) && previewBytes.length > 0) sources.push(previewBytes);
  for (const key of ["pfx", "full_pfx", "before_pfx", "raw_pfx"]) {
    const bytes = bytesFromHexPrefix(ev && ev[key], 384);
    if (bytes.length > 0) sources.push(bytes);
  }
  for (const key of ["pay", "full_pay", "before_pay", "raw_pay"]) {
    const bytes = b64ToBytesLimited(String(ev && ev[key] ? ev[key] : ""), 2048);
    if (bytes.length > 0) sources.push(bytes);
  }

  const labels = [];
  const seen = new Set();
  for (const source of sources) {
    for (const label of collect010a0011HiLabelsFromBytes(source, 3)) {
      const key = label.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      labels.push(label);
      if (labels.length >= 3) return labels;
    }
  }
  return labels;
}

function getEvent010a0011HiLabels(ev, previewBytes) {
  if (!ev || typeof ev !== "object") return [];
  if (Array.isArray(ev.__tcpvHiPreviewLabels)) {
    return ev.__tcpvHiPreviewLabels;
  }
  const labels = collectEvent010a0011HiLabels(ev, previewBytes);
  ev.__tcpvHiPreviewLabels = labels;
  return labels;
}

function eventPayloadSearchText(ev) {
  if (!ev || typeof ev !== "object") return "";
  const parts = [String(ev.summary || "")];
  for (const key of ["pfx", "full_pfx", "before_pfx", "raw_pfx"]) {
    const bytes = bytesFromHexPrefix(ev[key], 4096);
    if (bytes.length > 0) parts.push(bytesToLatin1String(bytes));
  }
  for (const key of ["pay", "full_pay", "before_pay", "raw_pay"]) {
    const bytes = b64ToBytesLimited(String(ev[key] || ""), 8192);
    if (bytes.length > 0) parts.push(bytesToLatin1String(bytes));
  }
  return parts.join("\n");
}

function eventHasCsob(ev) {
  if (!ev || typeof ev !== "object") return false;
  if (typeof ev.__tcpvHasCsob === "boolean") return ev.__tcpvHasCsob;
  const analysis = ev.analysis && typeof ev.analysis === "object" ? ev.analysis : null;
  const hasCsobAnalysis = Boolean(
    analysis
    && String(analysis.schema || "") === "tersafe.semantic.v1"
    && (
      /csob/i.test(String(analysis.direction || ""))
      || String(analysis.direction || "") === "8091_to_8092"
      || String(analysis.direction || "") === "8091_record"
      || String(analysis.source_key || "").includes("valorant:")
    )
  );
  const text = eventPayloadSearchText(ev);
  const hasCsOb = /cs:[^\x00;]{1,240},ob:/i.test(text);
  const hasCs = /cs:[^\x00;]{1,240}/i.test(text);
  const hasState = /state:[0-9a-f]{8},r:/i.test(text);
  const hasCsobSummary = /cs\/ob\/state|状态\s+state:|csob(?:_mirror|语义镜像|状态快照|状态候选)/i.test(text);
  const hasReport = /0x010a001b|010a001b/i.test(text) || /\x01\x0a\x00\x1b/.test(text);
  const matched = hasCsobAnalysis || hasCsobSummary || (hasCsOb && (hasState || hasReport)) || (hasCs && hasState && hasReport);
  ev.__tcpvHasCsob = matched;
  return matched;
}

function primeCompactEventCaches(ev) {
  if (!ev || typeof ev !== "object") return;
  getEvent010a0011HiLabels(ev, []);
  eventHasCsob(ev);
}

function renderPreviewBytes(previewSpan, byteValues, highlightRanges, plainTextHint = "") {
  if (!previewSpan) return;
  previewSpan.textContent = "";
  if (!Array.isArray(byteValues) || byteValues.length === 0) return;

  const hasHighlights = Array.isArray(highlightRanges) && highlightRanges.length > 0;
  if (!hasHighlights) {
    previewSpan.textContent = plainTextHint || formatPreviewBytesText(byteValues);
    return;
  }

  const gap16 = usePreviewSpace();
  const colorByIndex = new Array(byteValues.length).fill("");
  for (const r of highlightRanges) {
    const start = Math.max(0, Number(r.start || 0));
    const end = Math.min(byteValues.length, Number(r.end || 0));
    const color = r.color || "";
    for (let i = start; i < end; i++) {
      if (!colorByIndex[i]) {
        colorByIndex[i] = color;
      }
    }
  }

  for (let i = 0; i < byteValues.length; i++) {
    if (i > 0) {
      previewSpan.appendChild(document.createTextNode(gap16 && i % 16 === 0 ? "  " : " "));
    }

    const byteNode = document.createElement("span");
    byteNode.className = "preview-byte";
    byteNode.textContent = byteValues[i].toString(16).padStart(2, "0");
    const hitColor = colorByIndex[i];
    if (hitColor) {
      byteNode.className += " preview-byte-hit";
      byteNode.style.background = hitColor;
    }
    previewSpan.appendChild(byteNode);
  }
}

function getPreviewInfo(ev, needFullScan = false) {
  const previewLen = getBytesPerRow();
  const previewOffset = getPreviewOffset();
  const eventId = getEventId(ev);
  const flowId = String(state.flowId || "");
  const cacheKey = `${previewLen}|${previewOffset}|${usePreviewSpace() ? 1 : 0}|${flowId}|${eventId}`;
  if (!needFullScan && ev && ev.__tcpvPreviewCacheKey === cacheKey && ev.__tcpvPreviewInfo) {
    return ev.__tcpvPreviewInfo;
  }

  const inlinePay = String(ev && ev.pay ? ev.pay : "");
  let pay = inlinePay;
  let hasCachedPayload = false;
  let previewBytes = b64ToBytesWindow(pay, previewOffset, previewLen);
  if (previewBytes.length <= 0 && !pay && flowId && eventId) {
    const cached = readPayloadCache(flowId, eventId);
    const cachedPay = String(cached && cached.pay ? cached.pay : "");
    if (cachedPay) {
      pay = cachedPay;
      hasCachedPayload = true;
      previewBytes = b64ToBytesWindow(pay, previewOffset, previewLen);
    }
  }

  let fallbackBytes = [];
  if (previewBytes.length <= 0) {
    const fallback = normalizeHex(ev && ev.pfx ? ev.pfx : "");
    fallbackBytes = (fallback.match(/.{1,2}/g) || []).map((x) => parseInt(x, 16));
    previewBytes = fallbackBytes.slice(previewOffset, previewOffset + previewLen);
  }

  let scanBytes = previewBytes;
  if (needFullScan) {
    const fullScan = b64ToBytesLimited(pay, MAX_FULL_SCAN_BYTES);
    if (fullScan.length > 0) {
      scanBytes = fullScan;
    } else if (fallbackBytes.length > 0) {
      scanBytes = fallbackBytes;
    }
  }

  const expectedWindowLen = getExpectedPreviewWindowLen(ev, previewOffset, previewLen);
  const missingWindowBytes = Math.max(0, expectedWindowLen - previewBytes.length);
  const needsWindowFetch =
    !needFullScan &&
    !inlinePay &&
    !hasCachedPayload &&
    !!flowId &&
    !!eventId &&
    missingWindowBytes > 0;

  const previewInfo = {
    previewBytes,
    scanBytes,
    previewOffset,
    expectedWindowLen,
    missingWindowBytes,
    needsWindowFetch,
    previewText: formatPreviewBytesText(previewBytes),
    hiPreviewLabels: getEvent010a0011HiLabels(ev, previewBytes),
  };
  if (!needFullScan && ev && typeof ev === "object") {
    ev.__tcpvPreviewCacheKey = cacheKey;
    ev.__tcpvPreviewInfo = previewInfo;
  }
  return previewInfo;
}

function estimatePayloadByteLen(ev) {
  if (ev && Number.isFinite(ev.__tcpvPayloadLen)) {
    return ev.__tcpvPayloadLen;
  }
  const text = String(ev && ev.pay ? ev.pay : "").replace(/\s+/g, "");
  if (!text) return 0;
  const len = text.length;
  let pad = 0;
  if (text.endsWith("==")) pad = 2;
  else if (text.endsWith("=")) pad = 1;
  const payloadLen = Math.max(0, Math.floor((len * 3) / 4) - pad);
  if (ev && typeof ev === "object") {
    ev.__tcpvPayloadLen = payloadLen;
  }
  return payloadLen;
}

function getEventExtraInfo(ev) {
  const keys = ["extra_info", "extra", "info", "note", "tag"];
  for (const k of keys) {
    const value = ev ? ev[k] : "";
    const text = String(value || "").trim();
    if (text) return text;
  }
  return "";
}

function getEventId(ev) {
  const streamId = String(ev.id ?? "").trim();
  if (streamId) return streamId;
  return `${ev.ts ?? 0}|${ev.cid ?? ""}|${ev.seq ?? 0}|${ev.msg_idx ?? -1}|${ev.chunk_idx ?? -1}|${ev.dir ?? -1}|${ev.len ?? -1}`;
}

function formatHexValue(value, width = 0) {
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  const safe = Math.max(0, Math.floor(num));
  const hex = safe.toString(16);
  return `0x${width > 0 ? hex.padStart(width, "0") : hex}`;
}

function readBe16(byteValues, offset) {
  if (!Array.isArray(byteValues) || offset < 0 || offset + 1 >= byteValues.length) return null;
  return ((byteValues[offset] & 0xff) << 8) | (byteValues[offset + 1] & 0xff);
}

function readBe32(byteValues, offset) {
  if (!Array.isArray(byteValues) || offset < 0 || offset + 3 >= byteValues.length) return null;
  return (
    ((byteValues[offset] & 0xff) << 24) |
    ((byteValues[offset + 1] & 0xff) << 16) |
    ((byteValues[offset + 2] & 0xff) << 8) |
    (byteValues[offset + 3] & 0xff)
  ) >>> 0;
}

function readLe32(byteValues, offset) {
  if (!Array.isArray(byteValues) || offset < 0 || offset + 3 >= byteValues.length) return null;
  return (
    (byteValues[offset] & 0xff) |
    ((byteValues[offset + 1] & 0xff) << 8) |
    ((byteValues[offset + 2] & 0xff) << 16) |
    ((byteValues[offset + 3] & 0xff) << 24)
  ) >>> 0;
}

function readBeFloat32(byteValues, offset) {
  if (!Array.isArray(byteValues) || offset < 0 || offset + 3 >= byteValues.length) return null;
  try {
    const raw = Uint8Array.from(byteValues.slice(offset, offset + 4));
    return new DataView(raw.buffer).getFloat32(0, false);
  } catch (_e) {
    return null;
  }
}

function compactDurationSeconds(seconds) {
  const value = Math.max(0, Math.round(Number(seconds) || 0));
  if (value < 60) return `${value}秒`;
  const minutes = Math.floor(value / 60);
  const remain = value % 60;
  if (minutes < 60) return `${minutes}分${String(remain).padStart(2, "0")}秒`;
  const hours = Math.floor(minutes / 60);
  return `${hours}时${String(minutes % 60).padStart(2, "0")}分`;
}

function isPlausibleTimestampSeconds(value) {
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= TIMESTAMP_SECONDS_MIN && seconds <= TIMESTAMP_SECONDS_MAX;
}

function formatTimestampClock(seconds) {
  if (!Number.isFinite(Number(seconds))) return "";
  try {
    const { hh, mi, ss } = displayTimeParts(Number(seconds) * 1000);
    return `${hh}:${mi}:${ss}`;
  } catch (_e) {
    return "";
  }
}

function recordLayoutBaseShift(record, report) {
  if (!report || !Array.isArray(record)) return null;
  const shift = Number(report.offset) - 6;
  if (!Number.isFinite(shift)) return null;
  if (shift < -6 || shift > 8) return null;
  return shift;
}

function read0102000aLayout(record, report) {
  const shift = recordLayoutBaseShift(record, report);
  if (shift === null) return null;
  const lenOffset = shift + 4;
  const innerTypeOffset = shift + 0x16;
  const selector0Offset = shift + 0x18;
  const selector1Offset = shift + 0x1c;
  const innerFieldOffset = shift + 0x20;
  if (lenOffset < 0 || innerFieldOffset + 3 >= record.length) return null;
  const declaredLen = readBe16(record, lenOffset);
  const normalizedLen = Number.isFinite(declaredLen) && declaredLen > 0 ? declaredLen : record.length - shift;
  const bodyStart = Math.max(0, shift + 0x24);
  const recordEnd = Math.min(record.length, Math.max(bodyStart, shift + normalizedLen));
  return {
    shift,
    len: normalizedLen,
    innerLen: readBe16(record, shift + 0x14),
    innerType: readBe16(record, innerTypeOffset),
    selector0: readBe32(record, selector0Offset),
    selector1: readBe32(record, selector1Offset),
    innerField: readBe32(record, innerFieldOffset),
    bodyStart,
    bodyEnd: recordEnd,
    bodyLen: Math.max(0, recordEnd - bodyStart),
  };
}

function typedRaw32Views(byteValues, offset) {
  const raw = Array.isArray(byteValues) ? byteValues.slice(offset, offset + 4) : [];
  const be32 = readBe32(byteValues, offset);
  const le32 = readLe32(byteValues, offset);
  const floatBe = readBeFloat32(byteValues, offset);
  return {
    rawHex: raw.map((value) => Number(value).toString(16).padStart(2, "0")).join(""),
    be32,
    le32,
    floatBe: Number.isFinite(floatBe) && (floatBe === 0 || (Math.abs(floatBe) >= 1e-6 && Math.abs(floatBe) <= 1e6)) ? floatBe : null,
  };
}

function classifyProbeCounterCadence(tick, value, probeId, globalRound) {
  const safeTick = Number(tick);
  const safeValue = Number(value);
  if (!Number.isFinite(safeValue) || safeValue <= 0 || safeTick <= 0 || safeValue > safeTick + 1) {
    return { kind: "typedValue", label: "按 probe_id 解释的4字节值", roundRatio: null };
  }
  if (Number(probeId) === 0x8000) return { kind: "globalRound", label: "全局调度轮数候选", roundRatio: 1 };
  const safeRound = Number(globalRound);
  if (!Number.isFinite(safeRound) || safeRound <= 0) {
    return { kind: "counterCandidate", label: "累计计数候选；缺少0x8000轮次基准", roundRatio: null };
  }
  const roundRatio = safeValue / safeRound;
  if (Math.abs(safeValue - safeRound) <= 1) {
    return { kind: "perRound", label: "每调度轮一次候选（与全局轮次相差不超过1）", roundRatio };
  }
  if (Math.abs((safeValue * 2) - safeRound) <= 1) {
    return { kind: "halfRound", label: "隔调度轮一次候选（约为全局轮次一半）", roundRatio };
  }
  if (safeValue <= Math.max(3, Math.floor(safeRound * 0.1))) {
    return { kind: "sparse", label: "低频/启动/条件累计候选", roundRatio };
  }
  if (safeValue > safeRound) {
    return { kind: "multiPerRound", label: "每轮多次累计候选；须连续包确认", roundRatio };
  }
  return { kind: "subRound", label: "低于每轮频率的累计候选；须连续包确认", roundRatio };
}

function parseTypedBodyStructure(record, layout) {
  if (!Array.isArray(record) || !layout) return null;
  const bodyStart = Math.max(0, Number(layout.bodyStart || 0));
  const bodyEnd = Math.min(record.length, Number.isFinite(Number(layout.bodyEnd)) ? Number(layout.bodyEnd) : record.length);
  if (bodyStart > bodyEnd) return null;
  const bodyLen = Math.max(0, bodyEnd - bodyStart);
  const innerType = Number(layout.innerType);

  if (innerType === 0xfff3 && bodyLen >= 4 && (bodyLen - 4) % 6 === 0) {
    const tick = readBe32(record, bodyStart);
    const rawEntries = [];
    for (let offset = bodyStart + 4; offset + 5 < bodyEnd; offset += 6) {
      const probeId = readBe16(record, offset);
      const value = typedRaw32Views(record, offset + 2);
      rawEntries.push({ offset, probeId, value });
    }
    const globalEntry = rawEntries.find((entry) => Number(entry.probeId) === 0x8000);
    const globalRound = globalEntry ? Number(globalEntry.value.be32) : null;
    const entries = [];
    const cadenceCounts = { perRound: 0, halfRound: 0, sparse: 0, multiPerRound: 0, subRound: 0, counterCandidate: 0, globalRound: 0, typedValue: 0 };
    for (const rawEntry of rawEntries) {
      const { offset, probeId, value } = rawEntry;
      const cadence = classifyProbeCounterCadence(tick, value.be32, probeId, globalRound);
      cadenceCounts[cadence.kind] = Number(cadenceCounts[cadence.kind] || 0) + 1;
      entries.push({
        index: entries.length,
        offset,
        probeId,
        value,
        valueKind: cadence.kind,
        valueKindLabel: cadence.label,
        roundRatio: cadence.roundRatio,
      });
    }
    const selector1 = Number(layout.selector1 || 0) >>> 0;
    return {
      kind: "periodicProbeTable",
      label: "周期探测调度与结果表",
      confidence: "结构已确认 / probe_id 含义待证",
      bodyStart,
      bodyLen,
      algebra: `4 + ${entries.length}×6 = ${bodyLen}`,
      tick,
      historicalReference: {
        sampleCount: 415,
        durationSeconds: 37290.096,
        tickRateMedian: 0.987682,
        globalRoundPeriodMedianSeconds: 30.031,
        scope: "旧fff3连续样本；当前probe集合须独立复核",
      },
      elapsedSecondsHistoricalEstimate: tick ? Math.round(tick / 0.987682) : 0,
      selectorTickMatch: (((selector1 >>> 16) & 0xffff) === (Number(tick || 0) & 0xffff)),
      selectorRevisionOrFlags: selector1 & 0xffff,
      innerPair: {
        left: (Number(layout.innerField || 0) >>> 16) & 0xffff,
        right: Number(layout.innerField || 0) & 0xffff,
      },
      probeIdRegistry: "sparseEnumNotSequence",
      cadenceCounts,
      entries,
    };
  }

  if ([0x2001, 0x2011].includes(innerType) && bodyLen > 0 && bodyLen % 4 === 0) {
    const words = [];
    for (let offset = bodyStart; offset + 3 < bodyEnd; offset += 4) {
      const value = typedRaw32Views(record, offset);
      const setBits = [];
      for (let bit = 0; bit < 32; bit += 1) {
        if ((Number(value.be32) >>> bit) & 1) setBits.push(bit);
      }
      words.push({
        index: words.length,
        offset,
        value,
        setBits,
        allZero: Number(value.be32) === 0,
        allOne: Number(value.be32) === 0xffffffff,
      });
    }
    const isBitmap = innerType === 0x2011;
    return {
      kind: isBitmap ? "bitmapWordBlock" : "fixedWordBlock",
      label: isBitmap ? "位图/能力掩码探测块" : "固定字状态探测块",
      confidence: "结构已确认 / 字段含义待证",
      bodyStart,
      bodyLen,
      algebra: `${words.length}×u32 = ${bodyLen}`,
      words,
    };
  }
  return null;
}

function layoutMatchesKnownTimestampShape(layout, shape) {
  if (!layout || !shape) return false;
  const shapeLen = Number(shape.len);
  if (Number.isFinite(shapeLen) && Number(layout.len) !== shapeLen) return false;
  return (
    Number(layout.innerType) === Number(shape.innerType) &&
    Number(layout.selector0) === Number(shape.selector0) &&
    Number(layout.selector1) === Number(shape.selector1)
  );
}

function timestampOffsetsForKnownShape(layout, shape) {
  const offsets = [];
  const shift = Number(layout && layout.shift) || 0;
  for (const offset of shape && Array.isArray(shape.offsets) ? shape.offsets : []) {
    offsets.push(shift + Number(offset));
  }
  const offsetFromEnd = Number(shape && shape.offsetFromEnd);
  if (Number.isFinite(offsetFromEnd) && Number.isFinite(Number(layout && layout.len))) {
    offsets.push(shift + Number(layout.len) - offsetFromEnd);
  }
  return offsets.filter((offset, index, all) => (
    Number.isFinite(offset) && offset >= 0 && all.indexOf(offset) === index
  ));
}

function timestampShapeDisplay(label) {
  const value = String(label || "").trim();
  const labels = {
    "dfm-current": "DFM当前秒",
    "dfm-session": "DFM会话基准秒",
    "dfm-current-200d": "DFM当前秒/200D分支",
    "dfm-session-200d": "DFM会话基准秒/200D分支",
    "dfm-current-200f": "DFM当前秒/200F分支",
    "dfm-session-200f": "DFM会话基准秒/200F分支",
    "uagame-current": "UAGame当前秒",
    "uagame-current-8023": "UAGame当前秒/8023",
    "uagame-tail-8418": "UAGame尾部当前秒/8418",
    "uagame-session": "UAGame会话基准秒",
  };
  return labels[value] || value;
}

function buildTimestampRange(start, value, label) {
  const seconds = Number(value);
  const clock = formatTimestampClock(seconds);
  const offsetText = formatHexValue(start);
  const kind = String(label || "known");
  const display = timestampShapeDisplay(kind);
  const labelText = display && display !== "known" ? `[${display}] ` : "";
  return {
    start,
    end: start + 4,
    value: seconds,
    kind,
    text: `时间戳 ${labelText}${clock || seconds} @${offsetText}`,
  };
}

function bytesToLatin1String(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  let out = "";
  for (const byte of byteValues) {
    out += String.fromCharCode(Number(byte || 0) & 0xff);
  }
  return out;
}

function findPacketAsciiField(text, key) {
  const raw = String(text || "");
  const needle = `${String(key || "").toLowerCase()}:`;
  if (!needle || needle === ":") return null;
  const lower = raw.toLowerCase();
  const start = lower.indexOf(needle);
  if (start < 0) return null;
  const valueStart = start + needle.length;
  let end = valueStart;
  while (end < raw.length) {
    const code = raw.charCodeAt(end);
    if (code === 0 || code === 10 || code === 13 || raw[end] === ";") break;
    end += 1;
  }
  const value = raw.slice(valueStart, end).trim();
  if (!value) return null;
  return {
    key,
    start,
    valueStart,
    end,
    raw: raw.slice(start, end),
    value,
  };
}

function parseStateFieldParts(value) {
  const raw = String(value || "").trim();
  const match = raw.match(/^([^,\x00;\r\n]+)(?:,r:([^,\x00;\r\n]*))?(?:,p:([^\x00;\r\n]*))?/i);
  if (!match) return { state: raw, r: "", p: "" };
  return {
    state: String(match[1] || "").trim(),
    r: String(match[2] || "").trim(),
    p: String(match[3] || "").trim(),
  };
}

function describeObTriplet(value) {
  const parts = String(value || "").split("/");
  if (parts.length < 8) return null;
  const triplet = parts.slice(5, 8).map((item) => String(item || "").trim());
  if (triplet.some((item) => !item)) return null;
  const zeroed = triplet.every((item) => /^0+$/.test(item));
  const seconds = triplet.map((item) => timestampSecondsFromToken(item));
  const active = seconds.every((item) => Number.isFinite(Number(item)));
  const raw = triplet.join("/");
  if (zeroed) {
    return {
      kind: "zeroed",
      text: "ob5/6/7=zeroed",
      title: `ob5/ob6/ob7 ${raw}`,
    };
  }
  if (active) {
    const clocks = seconds.map((item, index) => formatTimestampClock(item) || triplet[index]);
    return {
      kind: "active",
      text: `ob5/6/7 ${clocks.join(" / ")}`,
      title: `ob5/ob6/ob7 ${raw}`,
    };
  }
  return {
    kind: "present",
    text: `ob5/6/7 ${raw}`,
    title: `ob5/ob6/ob7 ${raw}`,
  };
}

function packetSemanticInfoFromText(text) {
  const raw = String(text || "");
  if (!raw) return null;
  const cs = findPacketAsciiField(raw, "cs");
  const ob = findPacketAsciiField(raw, "ob");
  const state = findPacketAsciiField(raw, "state");
  if (!cs || (!ob && !state)) return null;

  const labelParts = ["cs"];
  if (ob) labelParts.push("ob");
  if (state) labelParts.push("state");
  const label = labelParts.join("/");
  const stateParts = state ? parseStateFieldParts(state.value) : null;
  const obTriplet = ob ? describeObTriplet(ob.value) : null;
  const textSuffix = obTriplet && obTriplet.kind === "zeroed" ? " ob=0" : "";
  const titleBits = [
    `${label} @${formatHexValue(cs.start)}`,
    cs ? `cs=${compactText(cs.value, 96)}` : "",
    ob ? `ob=${compactText(ob.value, 96)}` : "",
    obTriplet ? obTriplet.text : "",
    stateParts ? `state=${stateParts.state}` : "",
    stateParts && stateParts.r ? `r=${stateParts.r}` : "",
    stateParts && stateParts.p ? `p=${stateParts.p}` : "",
  ].filter(Boolean);
  const annotations = [];
  annotations.push({
    off: cs.start,
    text: `${label} cs=${compactText(cs.value, 84)}`,
  });
  if (ob) {
    annotations.push({
      off: ob.start,
      text: obTriplet ? `${obTriplet.text}` : `ob=${compactText(ob.value, 84)}`,
    });
  }
  if (state && stateParts) {
    const stateText = [
      `state=${stateParts.state}`,
      stateParts.r ? `r=${stateParts.r}` : "",
      stateParts.p ? `p=${stateParts.p}` : "",
    ].filter(Boolean).join(" ");
    annotations.push({
      off: state.start,
      text: stateText,
    });
  }
  return {
    kind: "semantic",
    label,
    text: `${label}${textSuffix}`,
    title: titleBits.join(" | "),
    cs,
    ob,
    state,
    stateParts,
    obTriplet,
    annotations,
  };
}

function collectPacketSemanticInfoFromBytes(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return null;
  return packetSemanticInfoFromText(bytesToLatin1String(byteValues));
}

function collectPacketSemanticInfoForPayload(base64Text) {
  const bytes = b64ToBytes(base64Text);
  return collectPacketSemanticInfoFromBytes(bytes);
}

function semanticCachePart(text) {
  const raw = String(text || "");
  if (!raw) return "0";
  return `${raw.length}:${raw.slice(0, 256)}:${raw.slice(-64)}`;
}

function getEventPacketSemanticInfo(ev) {
  const key = [
    getEventId(ev),
    semanticCachePart(ev && ev.before_pay),
    semanticCachePart(ev && ev.pay),
    String(ev && ev.pfx ? ev.pfx : "").slice(0, 384),
    String(ev && ev.before_pfx ? ev.before_pfx : "").slice(0, 384),
    String(ev && ev.full_pfx ? ev.full_pfx : "").slice(0, 384),
  ].join("|");
  if (ev && ev.__tcpvSemanticKey === key) {
    return ev.__tcpvSemanticInfo || null;
  }

  let info = null;
  for (const base64Text of [String(ev && ev.before_pay ? ev.before_pay : ""), String(ev && ev.pay ? ev.pay : "")]) {
    if (!base64Text) continue;
    info = collectPacketSemanticInfoForPayload(base64Text);
    if (info) break;
  }
  if (!info) {
    for (const keyName of ["before_pfx", "pfx", "full_pfx"]) {
      const bytes = bytesFromHexPrefix(ev && ev[keyName], 256);
      info = collectPacketSemanticInfoFromBytes(bytes);
      if (info) break;
    }
  }
  if (ev && typeof ev === "object") {
    ev.__tcpvSemanticKey = key;
    ev.__tcpvSemanticInfo = info || null;
  }
  return info || null;
}

function buildPacketSemanticAnnotationIndex(info, bytesPerRow) {
  const grouped = new Map();
  const annotations = info && Array.isArray(info.annotations) ? info.annotations : [];
  if (annotations.length <= 0) return grouped;
  const width = Math.max(1, Number(bytesPerRow || 16));
  for (const item of annotations) {
    const off = Number(item && item.off);
    const text = normalizeDumpAnnotationText(item && item.text ? item.text : "");
    if (!Number.isFinite(off) || off < 0 || !text) continue;
    const rowBase = Math.floor(off / width) * width;
    const bucket = grouped.get(rowBase) || [];
    addDumpAnnotationLine(bucket, text, 3);
    grouped.set(rowBase, bucket);
  }
  return new Map(Array.from(grouped.entries(), ([rowBase, bucket]) => [rowBase, bucket.join("\n// ")]));
}

function collectObTimestampTripletRanges(byteValues, baseOffset = 0, sourceLabel = "ob") {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
  const text = bytesToLatin1String(byteValues);
  const ranges = [];
  for (const match of text.matchAll(/\bob:([^\x00;\r\n]+)/gi)) {
    const group = String(match[1] || "");
    const groupStart = Number(match.index || 0) + String(match[0] || "").length - group.length;
    const parts = group.split("/");
    if (parts.length < 8) continue;

    let cursor = 0;
    const triplet = [];
    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index];
      const start = groupStart + cursor;
      const end = start + part.length;
      cursor = end - groupStart + 1;
      if (index < 5 || index > 7) continue;
      const seconds = timestampSecondsFromToken(part);
      if (!Number.isFinite(Number(seconds))) {
        triplet.length = 0;
        break;
      }
      triplet.push({
        index,
        start: Number(baseOffset || 0) + start,
        end: Number(baseOffset || 0) + end,
        value: Number(seconds),
        raw: part,
      });
    }

    if (triplet.length !== 3) continue;
    const clocks = triplet.map((item) => formatTimestampClock(item.value) || item.raw);
    const tripletText = clocks.join(" / ");
    for (const item of triplet) {
      const offsetText = formatHexValue(item.start);
      ranges.push({
        start: item.start,
        end: item.end,
        value: item.value,
        kind: `ob${item.index}_triplet`,
        triplet: true,
        tripletLabel: sourceLabel,
        text: `三时间戳 ${sourceLabel}:ob${item.index} ${formatTimestampDateTime(item.value) || item.raw} @${offsetText}；连续 ob5/ob6/ob7 ${tripletText}`,
      });
    }
  }
  return ranges;
}

function collectRecordTimestampRanges(record, baseOffset) {
  if (!Array.isArray(record) || record.length < 0x24) return [];
  const report = detectTssReport(record);
  if (!report || Number(report.value) !== 0x0102000a) return [];

  const layout = read0102000aLayout(record, report);
  const ranges = new Map();
  for (const item of collectObTimestampTripletRanges(record, baseOffset, "0102000a")) {
    const start = Number(item && item.start);
    if (!Number.isFinite(start) || ranges.has(start)) continue;
    ranges.set(start, item);
  }
  if (layout) {
    for (const shape of KNOWN_0102000A_TIMESTAMP_LAYOUTS) {
      if (!layoutMatchesKnownTimestampShape(layout, shape)) continue;
      for (const fullOffset of timestampOffsetsForKnownShape(layout, shape)) {
        const offset = Number(layout.shift) + Number(fullOffset);
        const value = readBe32(record, offset);
        if (!isPlausibleTimestampSeconds(value)) continue;
        const absolute = Number(baseOffset || 0) + offset;
        ranges.set(absolute, buildTimestampRange(absolute, value, shape.label));
      }
    }
  }
  return Array.from(ranges.values()).sort((a, b) => Number(a.start) - Number(b.start));
}

function collectTimestampHighlightsFromBytes(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length < 4) return [];
  const ranges = new Map();
  const addRanges = (items) => {
    for (const item of items || []) {
      const start = Number(item && item.start);
      if (!Number.isFinite(start) || start < 0 || ranges.has(start)) continue;
      ranges.set(start, item);
      if (ranges.size >= TIMESTAMP_MAX_MARKS_PER_DUMP) break;
    }
  };

  const parsed = parseTssChildRecords(byteValues);
  if (parsed && Array.isArray(parsed.children) && parsed.children.length > 0) {
    for (const child of parsed.children) {
      if (!child || child.truncated) continue;
      const childOffset = Number(child.offset);
      const childLen = Number(child.len);
      if (!Number.isFinite(childOffset) || !Number.isFinite(childLen)) continue;
      const recordStart = childOffset + 4;
      const record = byteValues.slice(recordStart, recordStart + childLen);
      addRanges(collectRecordTimestampRanges(record, recordStart));
      if (ranges.size >= TIMESTAMP_MAX_MARKS_PER_DUMP) break;
    }
  }

  addRanges(collectRecordTimestampRanges(byteValues, 0));
  return Array.from(ranges.values()).sort((a, b) => Number(a.start) - Number(b.start));
}

function collectTimestampHighlightsForPayload(base64Text) {
  const bytes = b64ToBytes(base64Text);
  return collectTimestampHighlightsFromBytes(bytes);
}

function mergeTimestampHighlightItems(...groups) {
  const byStart = new Map();
  for (const group of groups) {
    for (const item of Array.isArray(group) ? group : []) {
      const start = Number(item && item.start);
      const end = Number(item && item.end);
      if (!Number.isFinite(start) || start < 0 || !Number.isFinite(end) || end <= start) continue;
      const previous = byStart.get(start);
      if (!previous) {
        byStart.set(start, item);
        continue;
      }
      const previousText = String(previous && previous.text ? previous.text : "");
      const text = String(item && item.text ? item.text : "");
      const previousCandidate = /候选/.test(previousText);
      const currentCandidate = /候选/.test(text);
      if (previousCandidate && !currentCandidate) byStart.set(start, item);
    }
  }
  return Array.from(byStart.values()).sort((a, b) => Number(a.start) - Number(b.start));
}

function collectChildTimestampHighlightsForPayload(base64Text, summaryText = "") {
  const bytes = b64ToBytes(base64Text);
  if (!Array.isArray(bytes) || bytes.length <= 0) return [];
  const nodes = comparableNodesFromBytes(bytes);
  if (!Array.isArray(nodes) || nodes.length <= 0) return [];
  const timestampHintMap = parseSummaryChildTimestampHints(summaryText);
  const out = [];
  for (const node of nodes) {
    const childBytes = comparableNodeBytes(bytes, node);
    if (!Array.isArray(childBytes) || childBytes.length <= 0) continue;
    const recordStart = Number(childRecordAbsoluteStart(node));
    if (!Number.isFinite(recordStart) || recordStart < 0) continue;
    const hints = normalizeChildTimestampHints(node, childBytes, timestampHintMap);
    const structure = childHexStructure(node, childBytes, { timestampHints: hints });
    for (const item of Array.isArray(structure.timestamps) ? structure.timestamps : []) {
      const start = recordStart + Number(item && item.start);
      const end = recordStart + Number(item && item.end);
      if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end > bytes.length) continue;
      const childLabel = Number.isFinite(Number(node && node.index)) ? `child${Number(node.index)}` : "node";
      out.push({
        ...item,
        start,
        end,
        text: `${childLabel} ${String(item && item.text ? item.text : "时间戳")}`,
      });
    }
  }
  return mergeTimestampHighlightItems(out);
}

function collectIdfvHighlightsFromBytes(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
  const text = bytesToLatin1String(byteValues);
  const ranges = [];
  IDFV_FIELD_REGEX.lastIndex = 0;
  for (const match of text.matchAll(IDFV_FIELD_REGEX)) {
    const raw = String(match && match[0] ? match[0] : "");
    const start = Number(match && match.index);
    if (!raw || !Number.isFinite(start)) continue;
    const sepIndex = raw.indexOf(":") >= 0 ? raw.indexOf(":") : raw.indexOf("=");
    const uuid = sepIndex >= 0 ? raw.slice(sepIndex + 1).toUpperCase() : "";
    ranges.push({
      start,
      end: start + raw.length,
      valueStart: sepIndex >= 0 ? start + sepIndex + 1 : start,
      valueEnd: start + raw.length,
      uuid,
      text: `iDevIDFV ${uuid || raw} @${formatHexValue(start)}`,
    });
  }
  return ranges;
}

function collectIdfvHighlightsForPayload(base64Text) {
  return collectIdfvHighlightsFromBytes(b64ToBytes(base64Text));
}

function collectHistoryOpenidHighlightsFromBytes(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
  const text = bytesToLatin1String(byteValues);
  const ranges = [];
  HISTORY_OPENID_FIELD_REGEX.lastIndex = 0;
  for (const match of text.matchAll(HISTORY_OPENID_FIELD_REGEX)) {
    const raw = String(match && match[0] ? match[0] : "");
    const start = Number(match && match.index);
    if (!raw || !Number.isFinite(start)) continue;
    const sepIndex = raw.indexOf(":") >= 0 ? raw.indexOf(":") : raw.indexOf("=");
    const value = sepIndex >= 0 ? raw.slice(sepIndex + 1) : "";
    ranges.push({
      start,
      end: start + raw.length,
      valueStart: sepIndex >= 0 ? start + sepIndex + 1 : start,
      valueEnd: start + raw.length,
      value,
      text: `HistoryOpenID ${value || raw} @${formatHexValue(start)}`,
    });
  }
  return ranges;
}

function collectHistoryOpenidHighlightsForPayload(base64Text) {
  return collectHistoryOpenidHighlightsFromBytes(b64ToBytes(base64Text));
}

function obTripletItemIndex(item) {
  const match = String(item && item.kind ? item.kind : "").match(/^ob([567])_/i);
  return match ? Number(match[1]) : NaN;
}

function summarizeTimestampHighlights(ranges) {
  const items = Array.isArray(ranges) ? ranges : [];
  if (items.length <= 0) return "";
  const tripletGroups = new Map();
  for (const item of items) {
    if (!item || !item.triplet) continue;
    const key = String(item.tripletLabel || "ob");
    const bucket = tripletGroups.get(key) || [];
    bucket.push(item);
    tripletGroups.set(key, bucket);
  }
  for (const [label, bucket] of tripletGroups.entries()) {
    const ordered = bucket
      .slice()
      .sort((a, b) => (obTripletItemIndex(a) - obTripletItemIndex(b)) || (Number(a.start) - Number(b.start)));
    if (ordered.length < 3) continue;
    const firstThree = ordered.slice(0, 3);
    if (![5, 6, 7].every((index, pos) => obTripletItemIndex(firstThree[pos]) === index)) continue;
    const clocks = firstThree.map((item) => formatTimestampClock(item.value) || String(item.value || ""));
    const offsets = firstThree.map((item) => formatHexValue(item.start)).join(", ");
    const extra = items.length > 3 ? `, ...x${items.length}` : "";
    return `三时间 ${clocks.join(" / ")} (${label}: ${offsets})${extra}`;
  }
  const preview = items
    .slice(0, 3)
    .map((item) => {
      const clock = formatTimestampClock(item.value);
      return `${formatHexValue(item.start)}${clock ? ` ${clock}` : ""}`;
    })
    .join(", ");
  return items.length > 3 ? `${preview}, ...x${items.length}` : preview;
}

function summarizeIdfvHighlights(ranges) {
  const items = Array.isArray(ranges) ? ranges : [];
  if (items.length <= 0) return "iDevIDFV 已标注";
  const seen = new Set();
  const shown = [];
  for (const item of items) {
    const uuid = String(item && item.uuid ? item.uuid : "").trim();
    if (!uuid || seen.has(uuid)) continue;
    seen.add(uuid);
    shown.push(uuid);
    if (shown.length >= 2) break;
  }
  const suffix = items.length > shown.length ? `, ...x${items.length}` : "";
  return shown.length > 0 ? `iDevIDFV ${shown.join(" / ")}${suffix}` : `iDevIDFV x${items.length}`;
}

function summarizeHistoryOpenidHighlights(ranges) {
  const items = Array.isArray(ranges) ? ranges : [];
  if (items.length <= 0) return "HistoryOpenID 已标注";
  const seen = new Set();
  const shown = [];
  for (const item of items) {
    const value = String(item && item.value ? item.value : "").trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    shown.push(value);
    if (shown.length >= 3) break;
  }
  const suffix = items.length > shown.length ? `, ...x${items.length}` : "";
  return shown.length > 0 ? `HistoryOpenID ${shown.join(" / ")}${suffix}` : `HistoryOpenID x${items.length}`;
}

function getEventTimestampHighlights(ev) {
  const eventId = getEventId(ev);
  const key = `${eventId}|${String(ev && ev.pay ? ev.pay : "").length}|${String(ev && ev.before_pay ? ev.before_pay : "").length}`;
  if (ev && ev.__tcpvTimestampCacheKey === key && Array.isArray(ev.__tcpvTimestampHighlights)) {
    return ev.__tcpvTimestampHighlights;
  }
  const all = new Map();
  for (const base64Text of [String(ev && ev.pay ? ev.pay : ""), String(ev && ev.before_pay ? ev.before_pay : "")]) {
    if (!base64Text) continue;
    for (const item of collectTimestampHighlightsForPayload(base64Text)) {
      const start = Number(item && item.start);
      if (!Number.isFinite(start) || all.has(start)) continue;
      all.set(start, item);
    }
  }
  const result = Array.from(all.values()).sort((a, b) => Number(a.start) - Number(b.start));
  if (ev && typeof ev === "object") {
    ev.__tcpvTimestampCacheKey = key;
    ev.__tcpvTimestampHighlights = result;
  }
  return result;
}

function getEventIdfvHighlights(ev, summaryText = "") {
  const eventId = getEventId(ev);
  const key = `${eventId}|${String(summaryText || "").length}|${String(ev && ev.pay ? ev.pay : "").length}|${String(ev && ev.before_pay ? ev.before_pay : "").length}`;
  if (ev && ev.__tcpvIdfvCacheKey === key && Array.isArray(ev.__tcpvIdfvHighlights)) {
    return ev.__tcpvIdfvHighlights;
  }
  const all = new Map();
  for (const base64Text of [String(ev && ev.pay ? ev.pay : ""), String(ev && ev.before_pay ? ev.before_pay : "")]) {
    if (!base64Text) continue;
    for (const item of collectIdfvHighlightsForPayload(base64Text)) {
      const uuid = String(item && item.uuid ? item.uuid : "");
      const start = Number(item && item.start);
      if (!Number.isFinite(start)) continue;
      const keyPart = `${uuid || "idfv"}:${start}`;
      if (!all.has(keyPart)) all.set(keyPart, item);
    }
  }
  const result = Array.from(all.values()).sort((a, b) => Number(a.start) - Number(b.start));
  if (ev && typeof ev === "object") {
    ev.__tcpvIdfvCacheKey = key;
    ev.__tcpvIdfvHighlights = result;
  }
  return result;
}

function getEventHistoryOpenidHighlights(ev, summaryText = "") {
  const eventId = getEventId(ev);
  const key = `${eventId}|${String(summaryText || "").length}|${String(ev && ev.pay ? ev.pay : "").length}|${String(ev && ev.before_pay ? ev.before_pay : "").length}`;
  if (ev && ev.__tcpvHistoryOpenidCacheKey === key && Array.isArray(ev.__tcpvHistoryOpenidHighlights)) {
    return ev.__tcpvHistoryOpenidHighlights;
  }
  const all = new Map();
  for (const base64Text of [String(ev && ev.pay ? ev.pay : ""), String(ev && ev.before_pay ? ev.before_pay : "")]) {
    if (!base64Text) continue;
    for (const item of collectHistoryOpenidHighlightsForPayload(base64Text)) {
      const value = String(item && item.value ? item.value : "");
      const start = Number(item && item.start);
      if (!Number.isFinite(start)) continue;
      const keyPart = `${value || "history"}:${start}`;
      if (!all.has(keyPart)) all.set(keyPart, item);
    }
  }
  const result = Array.from(all.values()).sort((a, b) => Number(a.start) - Number(b.start));
  if (ev && typeof ev === "object") {
    ev.__tcpvHistoryOpenidCacheKey = key;
    ev.__tcpvHistoryOpenidHighlights = result;
  }
  return result;
}

function syncSummaryTimestampBadge(summaryNode, ev) {
  if (!summaryNode || typeof summaryNode.querySelectorAll !== "function") return;
  for (const node of summaryNode.querySelectorAll(".summary-timestamp")) {
    node.remove();
  }
  const timestampHighlights = getEventTimestampHighlights(ev);
  if (timestampHighlights.length <= 0) return;
  const timestampSpan = document.createElement("span");
  timestampSpan.className = "summary-timestamp";
  timestampSpan.textContent = `ts×${timestampHighlights.length}`;
  timestampSpan.title = summarizeTimestampHighlights(timestampHighlights);
  const tail = summaryNode.querySelector(".summary-tail");
  if (tail) {
    summaryNode.insertBefore(timestampSpan, tail);
  } else {
    summaryNode.appendChild(timestampSpan);
  }
}

function syncSummaryHiBadge(summaryNode, ev) {
  if (!summaryNode || typeof summaryNode.querySelector !== "function") return;
  const previewWrap = summaryNode.querySelector(".summary-preview");
  if (!previewWrap || typeof previewWrap.querySelectorAll !== "function") return;
  for (const node of previewWrap.querySelectorAll(".preview-hi")) {
    node.remove();
  }
  const preview = getPreviewInfo(ev, false);
  const labels = Array.isArray(preview && preview.hiPreviewLabels) ? preview.hiPreviewLabels : [];
  if (labels.length <= 0) return;
  const hiPreview = document.createElement("span");
  hiPreview.className = "preview-hi";
  hiPreview.textContent = labels.join(" ");
  hiPreview.title = `010a0011 hi preview: ${labels.join(" ")}`;
  const closingBracket = Array.from(previewWrap.childNodes)
    .reverse()
    .find((node) => node.nodeType === Node.TEXT_NODE && String(node.textContent || "").includes("]"));
  if (closingBracket) {
    previewWrap.insertBefore(hiPreview, closingBracket);
  } else {
    previewWrap.appendChild(hiPreview);
  }
}

function syncSummaryIdfvBadge(summaryNode, ev, summaryText = "") {
  if (!summaryNode || typeof summaryNode.querySelectorAll !== "function") return;
  for (const node of summaryNode.querySelectorAll(".summary-idfv")) {
    node.remove();
  }
  const summaryCount = Number.parseInt(readSummaryValue(summaryText, "idfv") || "0", 10);
  const idfvHighlights = getEventIdfvHighlights(ev, summaryText);
  const count = Math.max(Number.isFinite(summaryCount) ? summaryCount : 0, idfvHighlights.length);
  if (count <= 0) return;
  const idfvSpan = document.createElement("span");
  idfvSpan.className = "summary-idfv";
  idfvSpan.textContent = `iDevIDFV×${count}`;
  idfvSpan.title = summarizeIdfvHighlights(idfvHighlights);
  const tail = summaryNode.querySelector(".summary-tail");
  if (tail) {
    summaryNode.insertBefore(idfvSpan, tail);
  } else {
    summaryNode.appendChild(idfvSpan);
  }
}

function syncSummaryHistoryOpenidBadge(summaryNode, ev, summaryText = "") {
  if (!summaryNode || typeof summaryNode.querySelectorAll !== "function") return;
  for (const node of summaryNode.querySelectorAll(".summary-history-openid")) {
    node.remove();
  }
  const summaryCount = Number.parseInt(readSummaryValue(summaryText, "history") || "0", 10);
  const historyHighlights = getEventHistoryOpenidHighlights(ev, summaryText);
  const count = Math.max(Number.isFinite(summaryCount) ? summaryCount : 0, historyHighlights.length);
  if (count <= 0) return;
  const historySpan = document.createElement("span");
  historySpan.className = "summary-history-openid";
  historySpan.textContent = `HistoryOpenID×${count}`;
  historySpan.title = summarizeHistoryOpenidHighlights(historyHighlights);
  const tail = summaryNode.querySelector(".summary-tail");
  if (tail) {
    summaryNode.insertBefore(historySpan, tail);
  } else {
    summaryNode.appendChild(historySpan);
  }
}

function shortenText(text, maxLen = 120) {
  const normalized = String(text || "").replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLen) return normalized;
  return `${normalized.slice(0, maxLen - 3)}...`;
}

function trimDumpScrollCache() {
  while (state.dumpScrollLeft.size > DUMP_SCROLL_CACHE_MAX) {
    const oldestKey = state.dumpScrollLeft.keys().next().value;
    if (!oldestKey) break;
    state.dumpScrollLeft.delete(oldestKey);
  }
}

function makeDumpScrollKey(eventId, toneClass, title) {
  const ev = String(eventId || "").trim();
  const tone = String(toneClass || "").trim();
  const label = String(title || "").trim();
  return `${ev}|${tone || label || "dump"}`;
}

function rememberDumpScrollNode(node) {
  if (!node || typeof node !== "object") return;
  const key = String(node.dataset.scrollKey || "").trim();
  if (!key) return;
  const left = Number(node.scrollLeft || 0);
  if (!Number.isFinite(left) || left <= 0) {
    state.dumpScrollLeft.delete(key);
    return;
  }
  state.dumpScrollLeft.set(key, left);
  trimDumpScrollCache();
}

function snapshotDumpScrollPositions(root = el.events) {
  if (!root || typeof root.querySelectorAll !== "function") return;
  for (const node of root.querySelectorAll(".hex-shell[data-scroll-key]")) {
    rememberDumpScrollNode(node);
  }
}

function restoreDumpScrollNode(node) {
  if (!node || typeof node !== "object") return;
  const key = String(node.dataset.scrollKey || "").trim();
  if (!key || !state.dumpScrollLeft.has(key)) return;
  const savedLeft = Number(state.dumpScrollLeft.get(key) || 0);
  if (!Number.isFinite(savedLeft) || savedLeft <= 0) return;
  const apply = () => {
    node.scrollLeft = savedLeft;
  };
  apply();
  requestAnimationFrame(apply);
}

function restoreDumpScrollPositions(root) {
  if (!root || typeof root.querySelectorAll !== "function") return;
  for (const node of root.querySelectorAll(".hex-shell[data-scroll-key]")) {
    restoreDumpScrollNode(node);
  }
}

function attachDumpScrollPersistence(node, key) {
  if (!node || typeof node !== "object") return;
  node.dataset.scrollKey = String(key || "");
  node.addEventListener(
    "scroll",
    () => {
      rememberDumpScrollNode(node);
    },
    { passive: true }
  );
}

function inferStringKind(text) {
  const normalized = String(text || "").trim();
  const lower = normalized.toLowerCase();
  if (/^\d{10,24}$/.test(normalized)) return "account";
  if (/[\u3400-\u9fff]/u.test(normalized)) return "utf8-cjk";
  if (/[^\u0000-\u007f]/.test(normalized)) return "utf8";
  if (/^[A-Za-z0-9+/_-]{12,}={0,2}$/.test(normalized)) return "base64";
  if (normalized.startsWith("com.") || normalized.split(".").length >= 3) return "bundle";
  if (/cs:[^\x00;]+(?:,ob:[^\x00;]+)?/i.test(normalized)) return /state:/i.test(normalized) ? "cs/ob/state" : "cs/ob";
  if (/state:[^,\x00;]+,r:[^\x00;]+,p:[^\x00;]+/i.test(normalized)) return "state/r/p";
  if (normalized.includes("/") || lower.includes(".dylib") || lower.includes("springboard")) return "path";
  if (normalized.includes(":") && normalized.includes(";")) return "kv";
  if (normalized.includes(":") && normalized.length <= 64) return "field";
  return "ascii";
}

function normalizeVisibleText(text) {
  return String(text || "").replace(/\s+/g, " ").trim();
}

function decodeUtf8Strict(byteValues) {
  if (!UTF8_DECODER_FATAL || !Array.isArray(byteValues) || byteValues.length <= 0) return "";
  try {
    return UTF8_DECODER_FATAL.decode(new Uint8Array(byteValues));
  } catch {
    return "";
  }
}

function looksMeaningfulText(text, minChars = 2, requireNonAscii = false) {
  const normalized = normalizeVisibleText(text);
  if (normalized.length < minChars || normalized.includes("\ufffd")) return false;

  const chars = Array.from(normalized);
  if (chars.length < minChars) return false;

  let visible = 0;
  let nonAscii = 0;
  let alphaNum = 0;
  let cjk = 0;
  for (const ch of chars) {
    const code = ch.codePointAt(0) || 0;
    if (code < 32 || (code >= 127 && code <= 159)) continue;
    visible += 1;
    if (code >= 32 && code < 127) {
      if (
        (code >= 48 && code <= 57) ||
        (code >= 65 && code <= 90) ||
        (code >= 97 && code <= 122)
      ) {
        alphaNum += 1;
      }
    } else {
      nonAscii += 1;
      if ((code >= 0x3400 && code <= 0x9fff) || (code >= 0xf900 && code <= 0xfaff)) {
        cjk += 1;
      }
    }
  }
  if (visible < minChars) return false;
  if (requireNonAscii && nonAscii <= 0) return false;
  if (cjk >= 2) return true;
  if (cjk === 1) return false;
  if (alphaNum >= Math.max(3, minChars - 1)) return true;
  if (nonAscii >= 3 && chars.length >= Math.max(4, minChars)) return true;
  return false;
}

function isUtf8ContinuationByte(byte) {
  return byte >= 0x80 && byte <= 0xbf;
}

function readUtf8Span(byteValues, offset) {
  if (!Array.isArray(byteValues) || offset < 0 || offset >= byteValues.length) return 0;
  const b0 = byteValues[offset] & 0xff;
  if (b0 >= 32 && b0 < 127) return 1;
  if (b0 < 0xc2) return 0;

  if (b0 <= 0xdf) {
    if (offset + 1 >= byteValues.length) return 0;
    return isUtf8ContinuationByte(byteValues[offset + 1] & 0xff) ? 2 : 0;
  }

  if (b0 <= 0xef) {
    if (offset + 2 >= byteValues.length) return 0;
    const b1 = byteValues[offset + 1] & 0xff;
    const b2 = byteValues[offset + 2] & 0xff;
    if (!isUtf8ContinuationByte(b1) || !isUtf8ContinuationByte(b2)) return 0;
    if (b0 === 0xe0 && b1 < 0xa0) return 0;
    if (b0 === 0xed && b1 >= 0xa0) return 0;
    return 3;
  }

  if (b0 <= 0xf4) {
    if (offset + 3 >= byteValues.length) return 0;
    const b1 = byteValues[offset + 1] & 0xff;
    const b2 = byteValues[offset + 2] & 0xff;
    const b3 = byteValues[offset + 3] & 0xff;
    if (!isUtf8ContinuationByte(b1) || !isUtf8ContinuationByte(b2) || !isUtf8ContinuationByte(b3)) return 0;
    if (b0 === 0xf0 && b1 < 0x90) return 0;
    if (b0 === 0xf4 && b1 >= 0x90) return 0;
    return 4;
  }

  return 0;
}

function extractUtf8Runs(byteValues, minChars = ANALYSIS_UTF8_MIN_CHARS, maxItems = ANALYSIS_UTF8_MAX_ITEMS) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
  const out = [];
  const seen = new Set();

  for (let i = 0; i < byteValues.length && out.length < maxItems; ) {
    const firstSpan = readUtf8Span(byteValues, i);
    if (firstSpan <= 1) {
      i += 1;
      continue;
    }

    let end = i;
    let hasMultiByte = false;
    while (end < byteValues.length) {
      const span = readUtf8Span(byteValues, end);
      if (span <= 0) break;
      if (span > 1) hasMultiByte = true;
      end += span;
    }
    if (!hasMultiByte || end <= i) {
      i += 1;
      continue;
    }

    const text = normalizeVisibleText(decodeUtf8Strict(byteValues.slice(i, end)));
    if (looksMeaningfulText(text, minChars, true)) {
      const item = {
        off: i,
        text: shortenText(text, 96),
        kind: inferStringKind(text),
      };
      const key = `${item.off}|${item.kind}|${item.text}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push(item);
      }
    }
    i = end > i ? end : i + 1;
  }
  return out;
}

function normalizeBase64Candidate(text) {
  const compact = String(text || "").replace(/\s+/g, "");
  if (compact.length < 8) return "";
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(compact)) return "";
  const noPadding = compact.replace(/=+$/, "");
  if (noPadding.length < 8 || noPadding.length % 4 === 1) return "";
  const standard = compact.replace(/-/g, "+").replace(/_/g, "/");
  const padNeeded = (4 - (standard.length % 4)) % 4;
  return `${standard}${"=".repeat(padNeeded)}`;
}

function describeDecodedBytes(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return null;

  const utf8Text = normalizeVisibleText(decodeUtf8Strict(byteValues));
  if (looksMeaningfulText(utf8Text, 3, false)) {
    return {
      text: shortenText(utf8Text, 96),
      kind: inferStringKind(utf8Text),
    };
  }

  const utf8Runs = extractUtf8Runs(byteValues, 2, 1);
  if (utf8Runs.length > 0) {
    return {
      text: shortenText(utf8Runs[0].text, 96),
      kind: utf8Runs[0].kind || "utf8",
    };
  }

  const asciiRuns = extractPrintableRuns(byteValues, 4, 3);
  if (asciiRuns.length > 0) {
    const joined = shortenText(asciiRuns.map((item) => item.text).join(" | "), 96);
    return {
      text: joined,
      kind: inferStringKind(joined),
    };
  }

  return null;
}

function extractBase64DecodedRuns(byteValues, maxItems = ANALYSIS_BASE64_MAX_ITEMS) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
  const asciiRuns = extractPrintableRuns(byteValues, 8, 24);
  const out = [];
  const seen = new Set();
  const tokenRe = /[A-Za-z0-9+/_-]{8,}={0,2}/g;

  for (const run of asciiRuns) {
    const matches = String(run.text || "").matchAll(tokenRe);
    for (const match of matches) {
      const token = String(match[0] || "").trim();
      const normalized = normalizeBase64Candidate(token);
      if (!normalized) continue;

      const decodedBytes = b64ToBytesLimited(normalized, ANALYSIS_BASE64_MAX_BYTES);
      if (!Array.isArray(decodedBytes) || decodedBytes.length < 4) continue;

      const decoded = describeDecodedBytes(decodedBytes);
      if (!decoded || !String(decoded.text || "").trim()) continue;

      const off = Number(run.off || 0) + Number(match.index || 0);
      const rendered = `${decoded.text} <= ${shortenText(token, 44)}`;
      const kind =
        decoded.kind && String(decoded.kind).startsWith("utf8") ? "base64→utf8" : "base64→ascii";
      const key = `${off}|${rendered}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        off,
        text: rendered,
        kind,
      });
      if (out.length >= maxItems) return out;
    }
  }

  return out;
}

function extractPrintableRuns(byteValues, minLen = ANALYSIS_ASCII_MIN_LEN, maxItems = ANALYSIS_ASCII_MAX_ITEMS, options = {}) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
  const keepFullText = Boolean(options && options.fullText);
  const out = [];
  let start = -1;
  let chars = [];
  const flush = () => {
    if (start >= 0 && chars.length >= minLen) {
      const refined = trimPrintableRunPrefix(start, chars.join(""), minLen);
      if (String(refined.text || "").length >= minLen) {
        out.push(refined);
      }
    }
    start = -1;
    chars = [];
  };
  for (let i = 0; i < byteValues.length; i++) {
    const byte = byteValues[i];
    if (byte >= 32 && byte < 127) {
      if (start < 0) start = i;
      chars.push(String.fromCharCode(byte));
    } else {
      flush();
    }
  }
  flush();

  const unique = [];
  const seen = new Set();
  for (const item of out) {
    const text = keepFullText ? String(item.text || "") : shortenText(item.text, 96);
    const key = `${item.off}|${text}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push({
      off: item.off,
      text,
      kind: item.kind,
    });
    if (unique.length >= maxItems) break;
  }
  return unique;
}

function parseTssSummary(summaryText) {
  const raw = String(summaryText || "").trim();
  if (!raw) return null;
  const meta = {
    raw,
    code: null,
    role: "",
    hint: "",
    family: "",
    slot: "",
    sliceOffset: null,
    beforedumpLen: null,
    score: "",
    referenceLevel: "",
    lead: "",
    xor: null,
  };
  const readValue = (key) => {
    const match = raw.match(new RegExp(`${key}=([^\\s)]+)`));
    return match ? match[1] : "";
  };
  meta.code = readValue("code") || "";
  meta.role = readValue("role") || "";
  meta.hint = readValue("hint") || "";
  meta.family = readValue("family") || "";
  meta.slot = readValue("slot") || "";
  const sliceText = readValue("slice");
  if (sliceText && /^0x[0-9a-f]+$/i.test(sliceText)) {
    meta.sliceOffset = Number.parseInt(sliceText, 16);
  }
  const beforedumpText = readValue("beforedump");
  if (/^\d+$/.test(beforedumpText)) {
    meta.beforedumpLen = Number.parseInt(beforedumpText, 10);
  }
  meta.score = readValue("score") || "";
  meta.referenceLevel = readValue("ref") || "";
  meta.lead = readValue("lead") || "";
  const xorMatch = raw.match(/xor\((.+)\)$/);
  if (xorMatch) {
    const xorRaw = xorMatch[1] || "";
    const keyMatch = xorRaw.match(/key=(0x[0-9a-f]+)/i);
    const typeMatch = xorRaw.match(/type=(0x[0-9a-f]+)/i);
    const previewMatch = xorRaw.match(/preview=(.+)$/i);
    meta.xor = {
      key: keyMatch ? keyMatch[1] : "",
      type: typeMatch ? typeMatch[1] : "",
      preview: previewMatch ? previewMatch[1].trim() : "",
    };
  }
  return meta;
}

function escapeRegexLiteral(text) {
  return String(text || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function readSummaryValue(summaryText, key) {
  const raw = String(summaryText || "");
  const safeKey = escapeRegexLiteral(key);
  const match = raw.match(new RegExp(`(?:^|\\s)${safeKey}=([^\\s)]+)`));
  return match ? match[1] : "";
}

function parseSummaryKeyValues(summaryText) {
  const raw = String(summaryText || "").trim();
  const out = { raw };
  for (const key of [
    "sim",
    "mode",
    "match",
    "reason",
    "report",
    "tpl",
    "code",
    "role",
    "hint",
    "family",
    "slot",
    "slice",
    "beforedump",
    "score",
    "ref",
    "lead",
    "outer_id",
    "outer_id_reason",
    "inner_id",
    "inner_id_reason",
    "node_id",
  ]) {
    out[key] = readSummaryValue(raw, key);
  }
  return out;
}

function decodeSummaryToken(text) {
  const raw = String(text || "").trim();
  if (!raw || raw === "-") return "";
  try {
    return decodeURIComponent(raw);
  } catch (_e) {
    return raw;
  }
}

function parseReportCodeNumber(value) {
  if (typeof value === "number" && Number.isFinite(value)) return Math.floor(value);
  const text = String(value || "").trim().toLowerCase();
  if (!text || text === "-") return null;
  const compact = text.startsWith("0x") ? text.slice(2) : text;
  if (!/^[0-9a-f]{1,8}$/i.test(compact)) return null;
  const parsed = Number.parseInt(compact, 16);
  return Number.isFinite(parsed) ? parsed : null;
}

function formatReportCodeText(value) {
  const parsed = parseReportCodeNumber(value);
  return Number.isFinite(parsed) ? `0x${parsed.toString(16).padStart(8, "0")}` : "-";
}

function reportBusinessLabel(value) {
  const parsed = parseReportCodeNumber(value);
  if (!Number.isFinite(parsed)) return "";
  if (parsed === 0x010a001b) return "父容器";
  if (parsed === 0x010a0011) return "服务器确认型子请求（保活/握手候选）";
  if (parsed === 0x010a0010) return "010a0011 回执（leaf_id 回显）";
  if (parsed === 0x0102000a) return "typed leaf shell（按完整 shape 分类）";
  if (Math.floor(parsed / 0x100) === 0x011223) return `动态 metadata event family（subtype=0x${(parsed & 0xff).toString(16).padStart(2, "0")}）`;
  const family = Math.floor(parsed / 0x10000) & 0xffff;
  if (family === 0x0112) return "metadata family（payload 证据不足）";
  if (family === 0x010a) return "容器/元数据节点";
  if (family === 0x0102) return "叶子节点";
  return "未知业务节点";
}

function translatedReasonText(reason) {
  const raw = String(reason || "").trim();
  if (!raw || raw === "-") return "";
  const exact = {
    "0102000a_already_neutral": "0102000a 已是中和/清理形态",
    no_library_match: "没有命中可用录制源",
    strict_unreplaced_required: "严格替换要求下仍有节点未替换",
    strict_preserve_whitelist: "严格白名单保护",
    same_length_source_unchanged: "同长来源与目标一致",
    no_same_length_source: "没有同长录制源",
    record_length_mismatch: "记录长度不匹配",
    child_slot_length_mismatch: "child 槽位长度不匹配",
    unsafe_beforedump_length_changed: "解密结构长度变化，不安全",
    unsafe_packet_length_changed: "外层封包长度变化，不安全",
    target_rebuild_same_original: "目标重建后仍等于原包",
    target_cleanup_structure_invalid: "目标清理结构校验失败",
    port8092_original_blocked: "8092 原包策略拦截",
    fallback_original: "回退使用原包",
    target_graph_unavailable: "目标包无法解析成结构图",
    guarded_original: "保护规则要求保留原包",
    response_isolated_original: "响应异常隔离，保留原包",
    target_preserve: "命中保护目标策略",
    neutralized_fallback: "无可用安全替换源，已执行兜底清理",
    child_request_flag_0x11_patch: "0102000a 请求标志 0x11->0x01 修补",
  };
  if (exact[raw]) return `${exact[raw]}（${raw}）`;
  if (raw.includes("strict_preserve_whitelist")) return `严格白名单保护（${raw}）`;
  if (raw.includes("account_patch_neutral_timestamp") || raw.includes("timestamp")) return `时间戳/账号时间字段保护（${raw}）`;
  if (raw.includes("value_area_zero")) return `兜底清理 value 区域（${raw}）`;
  if (raw.includes("neutralize")) return `兜底清理（${raw}）`;
  if (raw.includes("blocklist")) return `命中黑名单清理规则（${raw}）`;
  if (raw.includes("device_preserve")) return `设备字段保护（${raw}）`;
  if (raw.includes("local_self_preserve_ack_010a0010")) return `010a0011 本地原样保全并等待 010a0010 回执（${raw}）`;
  if (raw.includes("010a0011_reserved_for_acknowledged_request")) return `010a0011 是服务器确认型请求，禁止用作其他 child 的通用替代（${raw}）`;
  if (raw.includes("010a0011")) return `010a0011 不可删除保护（${raw}）`;
  if (raw.includes("011223")) return `011223xx 动态 metadata subtype（${raw}）`;
  return raw;
}

function isAlreadyNeutralReason(reason) {
  return /already_neutral|已中和|已清理/.test(String(reason || ""));
}

function simulationStatusText(status, mode, reason) {
  const value = String(status || "").trim();
  const modeValue = String(mode || "").trim();
  if (!value) return "";
  if (value === "preserved_target_allowed") return "仿真结果：命中保护规则，允许原样保留";
  if (value === "neutralized_fallback") return "仿真结果：无可用安全替换源，已执行兜底清理";
  if (value === "no_library_match" && modeValue === "target_neutralize") return "仿真结果：无可用录制源，已执行兜底清理";
  if (value === "no_library_match") return "仿真结果：无可用录制源，已执行兜底清理";
  if (value === "simulated_changed") return "仿真结果：已按录制源重组替换";
  if (value === "simulated_same_target") return "仿真结果：重组后与目标一致";
  if (value === "fallback_original") return "仿真结果：回退保留原包";
  if (value === "response_isolated_original") return "仿真结果：响应异常隔离，保留原包";
  if (value === "guarded_original" || value === "guarded_followup_original") return "仿真结果：保护规则要求保留原包";
  if (value === "rebuild_failed") return "仿真结果：重建失败，回退原包";
  const reasonText = translatedReasonText(reason);
  return reasonText ? `仿真结果：${value}，${reasonText}` : `仿真结果：${value}`;
}

function simulationModeText(mode) {
  const value = String(mode || "").trim();
  const labels = {
    target: "组包模式：使用目标原文",
    target_neutralize: "组包模式：目标原文兜底清理",
    target_cleanup: "组包模式：目标结构清理",
    fallback_target: "组包模式：回退目标原文",
    same_length_copy: "组包模式：同长来源复制",
    assembly: "组包模式：录制源重组",
  };
  return labels[value] || (value ? `组包模式：${value}` : "");
}

function simulationMatchText(match) {
  const value = String(match || "").trim();
  const labels = {
    target_preserve: "匹配策略：保护目标，不替换",
    target_cleanup: "匹配策略：目标清理",
    none: "匹配策略：未命中录制源",
  };
  return labels[value] || (value ? `匹配策略：${value}` : "");
}

function idPatchResultText(scopeLabel, result, reason) {
  const value = decodeSummaryToken(result);
  if (!value || value === "none") return "";
  const labels = {
    patch: "已替换",
    nochange: "计划替换但字节未变",
    keep: "保留",
    skip: "跳过",
  };
  const reasonText = translatedReasonText(decodeSummaryToken(reason)) || decodeSummaryToken(reason);
  const resultText = labels[value] || value;
  return reasonText ? `${scopeLabel}：${resultText}，原因 ${reasonText}` : `${scopeLabel}：${resultText}`;
}

function innerNodeIdSummaryText(rawValue) {
  const text = decodeSummaryToken(rawValue);
  if (!text) return "";
  const counts = innerNodeIdCounts(text);
  const bits = [];
  const labels = [
    ["replace", "替换"],
    ["keep", "保留"],
    ["clean", "清理"],
    ["drop", "删除"],
  ];
  for (const [key, label] of labels) {
    if (Number.isFinite(counts[key])) {
      bits.push(`${label}${counts[key]}`);
    }
  }
  return bits.length ? `内层 child/leaf：${bits.join("，")}` : "";
}

function innerNodeIdCounts(rawValue) {
  const text = decodeSummaryToken(rawValue);
  const counts = {};
  for (const item of text.split(",")) {
    const [key, value] = item.split(":");
    if (!key) continue;
    const num = Number.parseInt(value || "0", 10);
    counts[key] = Number.isFinite(num) ? num : 0;
  }
  return counts;
}

function summaryPrimaryItems(ev, summaryText) {
  const kv = parseSummaryKeyValues(summaryText);
  const isRequest = Number(ev && ev.dir) === 0;
  const opaqueUndecrypted = isOpaqueUndecryptedSummary(summaryText);
  const items = [];
  const reportText = formatReportCodeText(kv.report || kv.code);
  if (reportText !== "-") {
    const label = reportBusinessLabel(reportText);
    items.push({
      kind: "report",
      text: `${opaqueUndecrypted ? "未解密外层" : "解密 report"}：${reportText}${label ? `，${label}` : ""}，${isRequest ? "请求" : "响应"}`,
    });
  }
  const simText = simulationStatusText(kv.sim, kv.mode, kv.reason);
  if (simText) items.push({ kind: kv.sim === "neutralized_fallback" ? "warn" : "sim", text: simText });
  const modeText = simulationModeText(kv.mode);
  if (modeText) items.push({ kind: kv.mode === "target_neutralize" ? "warn" : "mode", text: modeText });
  const matchText = simulationMatchText(kv.match);
  if (matchText) items.push({ kind: kv.match === "target_preserve" ? "protect" : "match", text: matchText });
  const outerText = idPatchResultText("外层ID", kv.outer_id, kv.outer_id_reason);
  if (outerText) {
    items.push({ kind: kv.outer_id === "patch" ? "warn" : "protect", text: outerText });
  }
  const innerText = idPatchResultText("内层账号ID", kv.inner_id, kv.inner_id_reason);
  if (innerText) {
    items.push({ kind: kv.inner_id === "patch" ? "warn" : "protect", text: innerText });
  }
  const nodeText = innerNodeIdSummaryText(kv.node_id);
  if (nodeText) {
    items.push({ kind: "match", text: nodeText });
  }
  const reasonText = translatedReasonText(kv.reason);
  if (reasonText && kv.reason !== "no_library_match") {
    items.push({ kind: "reason", text: `原因：${reasonText}` });
  }
  return { kv, items };
}

function isDecodedFlowEvent(ev, summaryText = "") {
  const raw = String(summaryText || (ev && ev.summary) || "");
  if (Number(ev && ev.dir) !== 0) return false;
  if (String(ev && ev.before_pay ? ev.before_pay : "")) return true;
  if (Number(ev && ev.before_len) > 0) return true;
  return /\[TSS\/类型\]|\bchild_total=|\bchild_detail=|\bsim=|\bbeforedump=/.test(raw);
}

function bytesFromHexPrefix(hexText, maxBytes = 192) {
  const compact = normalizeHex(hexText).slice(0, Math.max(0, Number(maxBytes || 0)) * 2);
  const out = [];
  for (let i = 0; i + 1 < compact.length; i += 2) {
    out.push(Number.parseInt(compact.slice(i, i + 2), 16));
  }
  return out.filter((value) => Number.isFinite(value));
}

function parseFlexibleInt(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  const parsed = raw.toLowerCase().startsWith("0x")
    ? Number.parseInt(raw.slice(2), 16)
    : Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function gcloudAuthoritativeAnalysis(ev) {
  const analysis = ev && ev.analysis && typeof ev.analysis === "object" ? ev.analysis : null;
  if (!analysis) return null;
  return analysis.analysis_authoritative === true
    && String(analysis.schema || "") === "tcpv.gcloud.analysis.v1"
    ? analysis
    : null;
}

function gcloudProducerTransport(ev) {
  const analysis = gcloudAuthoritativeAnalysis(ev);
  return analysis && analysis.transport && typeof analysis.transport === "object"
    ? analysis.transport
    : {};
}

function isGcloud65010Summary(summaryText = "", ev = null) {
  const raw = String(summaryText || "");
  return !!gcloudAuthoritativeAnalysis(ev)
    || /\btransport=tgcp65010\b/i.test(raw)
    || /\bbeforedump=gcloud_4013\b/i.test(raw)
    || (/\bcommand=0x(?:1001|1002|4013|9001)\b/i.test(raw) && /\b65010\b|tgcp/i.test(raw));
}

function isWssJsonSummary(summaryText = "", ev = null) {
  const raw = String(summaryText || (ev && ev.summary) || "");
  if (/\btransport=wss_json\b/i.test(raw)) return true;
  const analysis = ev && ev.analysis && typeof ev.analysis === "object" ? ev.analysis : null;
  return !!(analysis && analysis.schema === "tcpv.wss_json.analysis.v1");
}

function getWssJsonAnalysis(ev) {
  const analysis = ev && ev.analysis && typeof ev.analysis === "object" ? ev.analysis : null;
  return analysis && analysis.schema === "tcpv.wss_json.analysis.v1" ? analysis : null;
}

function buildWssSummaryInsights(ev, summaryText = "") {
  const analysis = getWssJsonAnalysis(ev);
  const jsonInfo = analysis && analysis.json && typeof analysis.json === "object" ? analysis.json : {};
  const resource = analysis && analysis.feature_resource && typeof analysis.feature_resource === "object"
    ? analysis.feature_resource
    : null;
  const method = String(jsonInfo.method || readSummaryValue(summaryText, "method") || "WSS JSON");
  const items = [
    { kind: "gcloud", text: method, title: "TLS 解密后的 WebSocket JSON method/Method" },
    { kind: "type", text: Number(ev && ev.dir) === 0 ? "客户端→服务端" : "服务端→客户端" },
    { kind: "match", text: jsonInfo.valid === false ? "JSON 解析失败" : "JSON 明文" },
  ];
  if (resource) {
    const archive = resource.archive && typeof resource.archive === "object" ? resource.archive : {};
    items.push({
      kind: "file",
      text: resource.feature_name || "ACE feature resource",
      title: "当前 WSS flow 中观察到的 featureName",
    });
    items.push({
      kind: resource.crc_match === true ? "protect" : "warn",
      text: `blob CRC32 ${resource.crc_match === true ? "MATCH" : resource.crc_match === false ? "MISMATCH" : "UNKNOWN"}`,
      title: `${resource.wire_crc32 || "-"} / ${resource.actual_crc32 || "-"}`,
    });
    if (archive.valid === true) {
      items.push({ kind: "child", text: `ZIP entries ${Number(archive.entry_count || 0)}` });
    }
  }
  return items.filter((item) => item && item.text);
}

function parseGcloud65010Summary(summaryText = "", ev = null) {
  const raw = String(summaryText || "").trim();
  const commandText = readSummaryValue(raw, "command");
  const producerTransport = gcloudProducerTransport(ev);
  const producerCommandText = String(producerTransport.command || "");
  const command = parseFlexibleInt(commandText || producerCommandText);
  return {
    raw,
    transport: readSummaryValue(raw, "transport") || String(producerTransport.kind || "tgcp65010"),
    targetPort: readSummaryValue(raw, "target_port"),
    command,
    commandText: command !== null ? formatHexValue(command, 4) : (commandText || producerCommandText),
    direction: readSummaryValue(raw, "direction") || String(producerTransport.direction || ""),
    seq: readSummaryValue(raw, "seq") || String(producerTransport.sequence ?? ""),
    crypto: readSummaryValue(raw, "crypto"),
    plainLen: readSummaryValue(raw, "plain_len"),
    padding: readSummaryValue(raw, "padding"),
    beforedump: readSummaryValue(raw, "beforedump"),
    gcloudType: readSummaryValue(raw, "gcloud_type"),
    gcloudTypes: readSummaryValue(raw, "gcloud_types"),
    gcloudTypeSource: readSummaryValue(raw, "gcloud_type_source"),
    gcloudTypeConfidence: readSummaryValue(raw, "gcloud_type_confidence"),
    gcloudTypeBasis: readSummaryValue(raw, "gcloud_type_basis"),
    gcloudSchema: readSummaryValue(raw, "gcloud_schema"),
    gcloudOpcode: readSummaryValue(raw, "gcloud_opcode"),
    gcloudMessageId: readSummaryValue(raw, "gcloud_message_id"),
    gcloudMessageSeq: readSummaryValue(raw, "gcloud_message_seq"),
    gcloudContext: readSummaryValue(raw, "gcloud_context"),
    gcloudInferredType: readSummaryValue(raw, "gcloud_inferred_type"),
    gcloudFocus: readSummaryValue(raw, "gcloud_focus"),
    gcloudProto: readSummaryValue(raw, "gcloud_proto"),
  };
}

function isUagameGcloudMeta(meta) {
  if (!meta || typeof meta !== "object") return false;
  return String(meta.gcloudProto || "").toLowerCase().startsWith("uagame_")
    || String(meta.gcloudSchema || "").toLowerCase().startsWith("uagame_");
}

function isUagamePrivateFragmentMeta(meta) {
  return String(meta && meta.gcloudProto || "").toLowerCase() === "uagame_private_frame";
}

const GCLOUD_UAGAME_OPCODE_NAMES = new Map([
  [0x08000001, { name: "CSAccountLoginReq", label: "账号登录请求" }],
  [0x08000005, { name: "UAGameHeartbeatOrTimeSync", label: "心跳/时间同步" }],
  [0x08000006, { name: "CSAccountReconnectLoginReq", label: "账号重连登录请求" }],
  [0x08100001, { name: "CSAccountLoginRes", label: "账号登录响应" }],
  [0x08100003, { name: "CSAceSendAntiDataNtf", label: "ACE AntiData 上报" }],
  [0x08000161, { name: "UAGameSocialChatSend", label: "社交聊天发送" }],
  [0x08000162, { name: "UAGameSocialFeedPush", label: "社交动态/邀请推送" }],
  [0x08000188, { name: "UAGameSpeedNodeList", label: "测速/加速节点列表" }],
  [0x08010505, { name: "UAGameLoadoutScheme", label: "配装方案" }],
  [0x08f40501, { name: "UAGameBattlePassConfig", label: "战斗通行证配置" }],
  [0x08f4050a, { name: "UAGameBattlePassConfig", label: "战斗通行证配置" }],
  [0x08f4081a, { name: "UAGameQQAuthorizationRedirect", label: "QQ 授权跳转" }],
  [0x0b000001, { name: "UAGameActivityCatalog", label: "活动目录" }],
  [0x0b000002, { name: "UAGameActivityDetail", label: "活动详情" }],
  [0x0b000009, { name: "UAGameActivityProgress", label: "活动进度" }],
  [0x0b00001c, { name: "UAGameActivityEmptyState", label: "活动空状态" }],
  [0x0b000050, { name: "UAGameAdvertisementBanner", label: "广告横幅" }],
  [0x0d000001, { name: "UAGameNamedJsonConfig", label: "命名 JSON 配置" }],
  [0x0d000002, { name: "UAGameLocalizationFeatureTable", label: "本地化功能表" }],
  [0x0d000003, { name: "UAGameNumericKeyValueTable", label: "数字键值配置表" }],
  [0x0d000004, { name: "UAGameNumericParameterTable", label: "数字参数配置表" }],
  [0x0d000006, { name: "UAGameTextConfigResponse", label: "文本配置响应" }],
  [0x25000001, { name: "UAGameRankingProfileShape", label: "排行榜玩家资料" }],
  [0x25000005, { name: "UAGameRankingProfileShape", label: "排行榜玩家资料" }],
  [0x09100001, { name: "UAGameSocialPlayerProfile", label: "社交玩家资料" }],
  [0x09100002, { name: "UAGameSocialPlayerProfile", label: "社交玩家资料" }],
  [0x09100005, { name: "UAGameSocialRosterPush", label: "社交列表推送" }],
  [0x09100007, { name: "UAGameSocialRosterPush", label: "社交列表推送" }],
  [0x08e00000, { name: "UAGameClientResourceTelemetry", label: "客户端资源遥测" }],
  [0x29000003, { name: "UAGameCompactKeySetUpdate", label: "紧凑键集合更新" }],
  [0x1d000011, { name: "UAGameActivityBenefitCatalog", label: "运营活动/福利目录批量获取" }],
  [0x1d000012, { name: "UAGameActivityBenefitDetail", label: "运营活动/福利条目详情/状态" }],
  [0x1d000017, { name: "UAGameTypeValueTable", label: "类型值配置表" }],
  [0x34000110, { name: "UAGameServerTuple", label: "服务器地址元组" }],
]);

// 65010 的 command 本身就是稳定的业务类型名。这里保留英文原名作为
// 协议锚点，同时为常见命令提供人工校正的中文业务短语；其余命令再按
// CamelCase 词元翻译。这样新出现的 CS* 命令也能立即得到可读中文，且
// 不会把中文标签反写进原始 payload 或破坏请求/响应配对。
const GCLOUD_CS_COMMAND_STEM_LABELS = new Map([
  ["AccountLogin", "账号登录"],
  ["AccountGetPlayerProfile", "获取账号玩家资料"],
  ["AceSendAntiData", "ACE 反作弊数据上报"],
  ["AceSendLightFeatureData", "ACE 轻量特征数据上报"],
  ["AceAntiDataTransfer", "ACE 反作弊数据传输"],
  ["AceAntiData", "ACE 反作弊数据"],
  ["TssHeartbeat", "TSS 心跳"],
  ["TssLoadReportConfig", "TSS 加载上报配置"],
  ["TSSPlayerQueryScnLimit", "TSS 玩家场景限制查询"],
  ["OnlineHeartbeat", "在线心跳"],
  ["HeroGrowLineRewardView", "查看英雄成长线奖励"],
  ["GetBoxInfo", "获取宝箱信息"],
  ["MallGetRecycleGoods", "获取商城回收商品"],
  ["SeasonGetInfo", "获取赛季信息"],
  ["SeasonGetTotalData", "获取赛季汇总数据"],
  ["AuctionAutoLoadGuidePrice", "拍卖行自动加载指导价"],
  ["PlayerPromptGet", "获取玩家提示"],
  ["SettingGetValueByKey", "按键获取设置值"],
  ["SwitchLoadModuleStatus", "加载功能模块状态"],
  ["ShopGetGameItemConfig", "获取商店游戏物品配置"],
  ["PlayerCheckGameCenterSubscriptionStatus", "检查玩家游戏中心订阅状态"],
  ["FriendList", "好友列表"],
  ["TeamMemberChangeT", "队伍成员变更"],
  ["TeamInfoT", "队伍信息"],
  ["StateGetInfo", "获取状态信息"],
  ["DepositGetExtensionProps", "获取仓库扩展属性"],
  ["ShopGetLotteryInfo", "获取商店抽奖信息"],
  ["WAssemblySkinInfoGet", "获取武器装配皮肤信息"],
  ["PrepareTDMMapBoard", "备战团队竞技地图面板"],
  ["PlayerInfoGetMarkProps", "获取玩家标记属性"],
  ["SettingPutKeyValue", "写入设置键值"],
  ["GuideGetMatchCount", "获取引导匹配次数"],
  ["ShopGetClickedRedDot", "获取商店已点击红点"],
  ["MallGetBuyGoods", "获取商城可购买商品"],
  ["ActivityGet", "获取活动"],
  ["WAssemblyGetDesign", "获取武器装配方案"],
  ["TeamEquipPositionChangeT", "队伍装备位置变更"],
  ["ReportIDC", "上报 IDC"],
  ["PlayerInfoAddButtonHasBeenClicked", "记录玩家信息按钮已点击"],
  ["GatewayKickPlayer", "网关强制玩家下线"],
]);

const GCLOUD_CS_COMMAND_TOKEN_LABELS = new Map([
  ["Get", "获取"], ["Set", "设置"], ["Put", "写入"], ["Load", "加载"],
  ["Send", "发送"], ["Check", "检查"], ["Query", "查询"], ["Add", "添加"],
  ["Update", "更新"], ["Change", "变更"], ["Take", "领取"], ["Receive", "领取"],
  ["Withdraw", "撤单"], ["Transfer", "传输"], ["Unlock", "解锁"], ["Reconnect", "重连"],
  ["Info", "信息"], ["Data", "数据"], ["Config", "配置"], ["Cfg", "配置"],
  ["Status", "状态"], ["List", "列表"], ["Type", "类型"], ["Value", "值"],
  ["Values", "多个值"], ["Key", "键"], ["Record", "记录"], ["Records", "记录"],
  ["Count", "次数"], ["Version", "版本"], ["Detail", "详情"], ["Profile", "资料"],
  ["Player", "玩家"], ["Account", "账号"], ["Friend", "好友"], ["Team", "队伍"],
  ["Member", "成员"], ["Hero", "英雄"], ["Role", "角色"], ["Guide", "引导"],
  ["Shop", "商店"], ["Mall", "商城"], ["Auction", "拍卖行"], ["Market", "市场"],
  ["Deposit", "仓库"], ["Collection", "收藏品"], ["Armory", "军械库"], ["Safehouse", "安全屋"],
  ["Season", "赛季"], ["Activity", "活动"], ["Quest", "任务"], ["Rank", "排行"],
  ["Tournament", "锦标赛"], ["Battle", "战斗"], ["Pass", "通行证"], ["Bp", "战斗通行证"],
  ["Reward", "奖励"], ["Rewards", "奖励"], ["Award", "奖励"], ["Goods", "商品"],
  ["Item", "物品"], ["Items", "物品"], ["Props", "属性"], ["Attr", "属性"],
  ["Attribute", "属性"], ["Quality", "品质"], ["Price", "价格"], ["Currency", "货币"],
  ["Game", "游戏"],
  ["Exchange", "兑换"], ["Buy", "购买"], ["Sell", "出售"], ["Order", "订单"],
  ["Pre", "预购"], ["Daily", "每日"], ["Limit", "限制"], ["Total", "汇总"],
  ["Skin", "皮肤"], ["Gun", "枪械"], ["Equip", "装备"], ["Outfit", "装扮"],
  ["Assembly", "装配"], ["W", "武器"], ["Design", "方案"], ["Position", "位置"],
  ["Map", "地图"], ["Board", "面板"], ["Room", "房间"], ["Match", "匹配"],
  ["TDM", "团队竞技"], ["Tdm", "团队竞技"], ["Raid", "突袭"], ["Settlement", "结算"],
  ["Mandel", "曼德尔"], ["Brick", "金砖"], ["Vehicle", "载具"], ["Prepare", "备战"],
  ["Switch", "功能开关"], ["Module", "模块"], ["System", "系统"], ["Func", "功能"],
  ["Setting", "设置"], ["State", "状态"], ["Online", "在线"], ["Heartbeat", "心跳"],
  ["Prompt", "提示"], ["Red", "红"], ["Dot", "点"], ["Clicked", "已点击"],
  ["Localization", "本地化"], ["Text", "文本"], ["Patch", "补丁"], ["Quick", "快速"],
  ["Report", "上报"], ["Log", "日志"], ["History", "历史"], ["Historical", "历史"],
  ["Moment", "动态"], ["Apply", "申请"], ["Recommend", "推荐"], ["Black", "黑"],
  ["Basic", "基础"], ["Base", "基础"], ["Extension", "扩展"], ["Recovery", "找回"],
  ["Amount", "数量"], ["Mark", "标记"], ["Share", "分享"], ["Distribution", "分发"],
  ["Auto", "自动"], ["Retro", "补发"], ["Peak", "巅峰"], ["Accumulate", "累计"],
  ["Line", "线"], ["Grow", "成长"], ["View", "查看"], ["Show", "展示"],
  ["Mystical", "神秘"], ["Mystery", "神秘"], ["Lucky", "幸运"], ["Nest", "巢"],
  ["Lottery", "抽奖"], ["Guess", "竞猜"], ["Schedule", "赛程"], ["Country", "地区"],
  ["Zone", "分区"], ["Percentage", "百分比"], ["Aux", "辅助"], ["Badge", "徽章"],
  ["Pendant", "挂饰"], ["Avatars", "头像"], ["Styles", "样式"], ["Unlocked", "已解锁"],
  ["Merchants", "商人"], ["Presets", "预设"], ["Box", "宝箱"], ["Label", "标签"],
  ["No", "编号"], ["Media", "媒体"], ["Mapping", "映射"], ["Theme", "主题"],
  ["Bundle", "礼包"], ["Time", "时间"], ["Video", "视频"], ["Inspect", "巡查"],
  ["Mail", "邮件"], ["Lobby", "大厅"], ["Ad", "广告"], ["Live", "直播"],
  ["Pay", "支付"], ["Creator", "创作者"], ["Hub", "中心"], ["Code", "码"],
  ["Recharge", "充值"], ["Reputation", "声望"], ["Jump", "跳转"], ["Back", "回归"],
  ["Level", "等级"], ["Second", "二级"], ["Pwd", "密码"], ["Join", "加入"],
  ["Ds", "DS"], ["Center", "中心"], ["Subscription", "订阅"], ["Struct", "结构"],
  ["Trigger", "触发"], ["Extra", "额外"], ["Scn", "场景"], ["Chat", "聊天"],
  ["Light", "轻量"], ["Feature", "特征"], ["Anti", "反作弊"], ["Ace", "ACE"],
  ["Tss", "TSS"], ["TSS", "TSS"], ["IDC", "IDC"], ["CDN", "CDN"],
  ["SKU", "SKU"], ["SOL", "SOL"], ["MP", "多人模式"], ["ID", "ID"], ["Id", "ID"],
  ["New", "新版"], ["All", "全部"], ["Is", "是否"], ["And", "并"], ["By", "按"],
  ["Login", "登录"], ["Roll", "轮换"], ["Chall", "挑战"], ["Roundtrip", "往返"],
  ["Dir", "方向"], ["Armedforce", "武装力量"], ["Stu", "学生"], ["Priv", "权益"],
  ["Tlog", "TLog"], ["Tglog", "TGLog"], ["Agent", "代理"], ["Mossai", "Mossai"],
]);

const GCLOUD_COMMAND_FULL_LABELS = new Map([
  ["GCloudHeartbeatReq", "GCloud 心跳请求"],
  ["GCloudHeartbeatRes", "GCloud 心跳响应"],
  ["GCloudNetworkStatusReq", "GCloud 网络状态请求"],
  ["GCloudNetworkStatusRes", "GCloud 网络状态响应"],
]);

function gcloudReadableTypeName(value) {
  return String(value || "")
    .replace(/Candidate\b/g, "")
    .replace(/((?:Req|Res|Rsp|Ntf))B$/i, "$1")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function gcloudCommandChineseLabel(value) {
  const name = gcloudReadableTypeName(value);
  if (!name) return "";
  if (GCLOUD_COMMAND_FULL_LABELS.has(name)) return GCLOUD_COMMAND_FULL_LABELS.get(name);
  if (!/^CS[A-Za-z0-9_]+$/.test(name)) return "";
  let stem = name.slice(2);
  let suffix = "";
  const suffixMatch = stem.match(/(Req|Res|Rsp|Ntf|Ack)$/);
  if (suffixMatch) {
    stem = stem.slice(0, -suffixMatch[1].length);
    suffix = ({ Req: "请求", Res: "响应", Rsp: "响应", Ntf: "通知", Ack: "确认" })[suffixMatch[1]] || "";
  }
  const exact = GCLOUD_CS_COMMAND_STEM_LABELS.get(stem);
  if (exact) return `${exact}${suffix}`;
  const words = stem.match(/[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+/g) || [];
  const translated = words.map((word) => {
    if (word === "T") return "";
    return GCLOUD_CS_COMMAND_TOKEN_LABELS.get(word) || word;
  }).join("")
    .replace(/战斗通行证战斗通行证/g, "战斗通行证")
    .replace(/黑列表/g, "黑名单")
    .trim();
  return /[\u3400-\u9fff]/u.test(translated) ? `${translated}${suffix}` : "";
}

function gcloudCommandDisplay(value) {
  const name = gcloudReadableTypeName(value);
  if (!name) return "";
  const label = gcloudCommandChineseLabel(name);
  return label ? `${label} · ${name}` : name;
}

function gcloudUagameOpcodeInfo(meta) {
  if (!isUagameGcloudMeta(meta)) return null;
  const opcode = parseFlexibleInt(meta.gcloudOpcode);
  if (opcode === null) return null;
  const mapped = GCLOUD_UAGAME_OPCODE_NAMES.get(opcode) || null;
  const inferred = gcloudReadableTypeName(meta.gcloudInferredType);
  return {
    opcode,
    opcodeText: formatHexValue(opcode, 8),
    name: mapped ? mapped.name : inferred,
    label: mapped ? mapped.label : inferred,
    mapped: !!mapped,
  };
}

function gcloudUagameOpcodeDisplay(meta) {
  const info = gcloudUagameOpcodeInfo(meta);
  if (!info) return "";
  if (info.label && info.name) return `${info.label} · ${info.name} [${info.opcodeText}]`;
  if (info.label) return `${info.label} [${info.opcodeText}]`;
  if (info.name) return `${info.name} [${info.opcodeText}]`;
  return `UAGame ${info.opcodeText}`;
}

function gcloudUagameEnvelopeAnchorText() {
  return "body_len BE32 @ header+0x00 · opcode BE32 @ header+0x04 · marker abab @ header+0x26 · body @ header+0x28";
}

function gcloudUagame4013Insights(meta, commandName = "") {
  if (!isUagameGcloudMeta(meta) || isUagamePrivateFragmentMeta(meta)) return [];
  const opcodeInfo = gcloudUagameOpcodeInfo(meta);
  const opcodeDisplay = gcloudUagameOpcodeDisplay(meta);
  const name = gcloudReadableTypeName(commandName || (opcodeInfo && opcodeInfo.name));
  const label = opcodeInfo && opcodeInfo.label
    ? opcodeInfo.label
    : (name && name !== opcodeDisplay ? name : opcodeDisplay.replace(/^UAGame\s+/i, ""));
  if (!label) return [];
  return [{
    kind: opcodeInfo && opcodeInfo.mapped ? "gcloud" : "type",
    text: opcodeDisplay || label,
    title: `${name || "UAGame message"} · 4013 decrypted · ${gcloudUagameEnvelopeAnchorText()}`,
  }];
}

function gcloudEventPayloadStatusText(proto, meta) {
  if (proto && proto.ok) {
    const count = Array.isArray(proto.flat) ? proto.flat.length : 0;
    return count > 0 ? `Protobuf · ${count} fields` : "Protobuf body";
  }
  if (isUagamePrivateFragmentMeta(meta)) return "private fragment";
  if (isUagameGcloudMeta(meta)) return "UAGame binary body";
  return "Protobuf fragment";
}

function analyzeUagamePrivateFragment(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  const markerOffsets = [];
  for (let index = 0; index + 1 < bytes.length; index += 1) {
    if (bytes[index] === 0xab && bytes[index + 1] === 0xab) markerOffsets.push(index);
    if (markerOffsets.length >= 4) break;
  }
  const markerOffset = markerOffsets.length > 0 ? markerOffsets[0] : null;
  const prefix = bytes.slice(0, 4).map(childHexByteText).join("");
  const family = prefix.startsWith("f402") ? "f4" : prefix.startsWith("f802") ? "f8" : "private";
  const payloadStart = markerOffset === null ? null : markerOffset + 2;
  const payloadPrefix = payloadStart === null ? "" : gcloudHexBytes(bytes.slice(payloadStart, payloadStart + 16), 16);
  return { family, prefix, markerOffset, markerOffsets, payloadStart, payloadPrefix, totalLen: bytes.length };
}

function parseGcloudHandshakeWire(bytes) {
  const raw = Array.isArray(bytes) ? bytes : [];
  if (raw.length < 24 || raw[0] !== 0x33 || raw[1] !== 0x66) return null;
  const command = ((raw[6] & 0xff) << 8) | (raw[7] & 0xff);
  if (command !== 0x1001 && command !== 0x1002) return null;
  const headerLen = (
    ((raw[13] & 0xff) * 0x1000000)
    + ((raw[14] & 0xff) << 16)
    + ((raw[15] & 0xff) << 8)
    + (raw[16] & 0xff)
  ) >>> 0;
  const payloadLen = (
    ((raw[17] & 0xff) * 0x1000000)
    + ((raw[18] & 0xff) << 16)
    + ((raw[19] & 0xff) << 8)
    + (raw[20] & 0xff)
  ) >>> 0;
  const method = raw[21] & 0xff;
  if (method !== 3) {
    return {
      command,
      method,
      keyLength: null,
      keyHex: "",
      headerLen,
      payloadLen,
      frameLen: raw.length,
      valid: true,
      reason: "non_method3",
    };
  }
  const keyLength = ((raw[22] & 0xff) << 8) | (raw[23] & 0xff);
  const keyStart = 24;
  const keyEnd = keyStart + keyLength;
  const keyInNativeRange = keyLength >= 1 && keyLength <= 64;
  const keyComplete = keyEnd <= raw.length && keyEnd <= headerLen;
  const frameBoundaryValid = headerLen >= keyEnd
    && headerLen <= raw.length
    && headerLen + payloadLen === raw.length;
  const keyBytes = keyComplete ? raw.slice(keyStart, keyEnd) : [];
  return {
    command,
    method,
    keyLength,
    keyHex: keyBytes.map((byte) => (byte & 0xff).toString(16).padStart(2, "0")).join(""),
    headerLen,
    payloadLen,
    frameLen: raw.length,
    valid: keyInNativeRange && keyComplete && frameBoundaryValid,
    keyInNativeRange,
    keyComplete,
    frameBoundaryValid,
    reason: !keyInNativeRange
      ? "method3_key_length_out_of_range"
      : !keyComplete
        ? "method3_key_truncated"
        : !frameBoundaryValid
          ? "tgcp_frame_boundary_mismatch"
          : "native_variable_length_method3",
  };
}

function gcloudWireHandshakeEvidence(ev) {
  const sources = [
    ["forwarded", "raw_pay"],
    ["received", "full_pay"],
    ["current", "pay"],
  ];
  const seen = new Set();
  const out = [];
  for (const [label, key] of sources) {
    const encoded = String(ev && ev[key] ? ev[key] : "");
    if (!encoded || seen.has(encoded)) continue;
    seen.add(encoded);
    const parsed = parseGcloudHandshakeWire(b64ToBytes(encoded));
    if (parsed) out.push({ ...parsed, source: label, sourceField: key });
  }
  return out;
}

function gcloudProducerHandshakeDiagnostics(ev) {
  const analysis = gcloudAuthoritativeAnalysis(ev) || {};
  const transport = gcloudProducerTransport(ev);
  const mitm = analysis.mitm && typeof analysis.mitm === "object" ? analysis.mitm : {};
  const validation = analysis.validation && typeof analysis.validation === "object" ? analysis.validation : {};
  const first = (...values) => values.find((value) => value !== undefined && value !== null && value !== "");
  return {
    command: first(transport.command, mitm.command),
    direction: first(transport.direction, mitm.direction, analysis.direction),
    method: first(transport.key_method, mitm.key_method, mitm.method),
    keyLength: first(transport.key_length, mitm.key_length),
    headerLen: first(transport.header_len, mitm.header_len),
    frameLen: first(transport.frame_len, mitm.frame_len),
    rewriteBefore: first(transport.rewrite_before_length, mitm.rewrite_before_length),
    rewriteAfter: first(transport.rewrite_after_length, mitm.rewrite_after_length),
    sessionStage: first(transport.session_stage, mitm.session_stage),
    keysReady: first(transport.keys_ready, mitm.keys_ready),
    fallbackReason: first(transport.fallback_reason, mitm.fallback_reason, validation.fallback_reason),
    handshakeFailedAfterRewrite: first(
      transport.handshake_failed_after_rewrite,
      mitm.handshake_failed_after_rewrite,
      validation.handshake_failed_after_rewrite,
    ),
  };
}

function gcloudHandshakeDiagnosticRows(ev, evidence = null) {
  const wires = Array.isArray(evidence) ? evidence : gcloudWireHandshakeEvidence(ev);
  const producer = gcloudProducerHandshakeDiagnostics(ev);
  const rows = [];
  const producerCore = [
    producer.command ? `command=${producer.command}` : "",
    producer.direction ? `direction=${producer.direction}` : "",
    producer.method !== undefined ? `method=${producer.method}` : "",
    producer.keyLength !== undefined ? `key_length=${producer.keyLength}` : "",
    producer.headerLen !== undefined ? `header_len=${producer.headerLen}` : "",
    producer.frameLen !== undefined ? `frame_len=${producer.frameLen}` : "",
  ].filter(Boolean);
  if (producerCore.length > 0) rows.push({ label: "Producer handshake", value: producerCore.join(" · ") });
  for (const wire of wires) {
    const label = wire.source === "received" ? "Wire key (received/original)" : wire.source === "forwarded" ? "Wire key (forwarded)" : "Wire key (current)";
    if (wire.method === 3) {
      rows.push({
        label,
        value: `method=3 · key_len=${wire.keyLength} · header_len=${wire.headerLen} · frame_len=${wire.frameLen} · valid=${wire.valid ? "yes" : "no"} · key=${wire.keyHex || "<truncated>"}`,
      });
    } else {
      rows.push({ label, value: `method=${wire.method} · header_len=${wire.headerLen} · frame_len=${wire.frameLen}` });
    }
  }
  const rewrite = [
    producer.rewriteBefore !== undefined ? `before_len=${producer.rewriteBefore}` : "",
    producer.rewriteAfter !== undefined ? `after_len=${producer.rewriteAfter}` : "",
  ].filter(Boolean);
  if (rewrite.length > 0) rows.push({ label: "Rewrite", value: rewrite.join(" · ") });
  const state = [
    producer.sessionStage !== undefined ? `session_stage=${producer.sessionStage}` : "",
    producer.keysReady !== undefined ? `keys_ready=${producer.keysReady}` : "",
    producer.handshakeFailedAfterRewrite !== undefined
      ? `handshake_failed_after_rewrite=${producer.handshakeFailedAfterRewrite}`
      : "",
  ].filter(Boolean);
  if (state.length > 0) rows.push({ label: "Session", value: state.join(" · ") });
  const failure = [
    producer.fallbackReason ? `fallback_reason=${producer.fallbackReason}` : "",
    producer.handshakeFailedAfterRewrite === true
      ? "fail_closed_after_one_sided_rewrite"
      : "",
  ].filter(Boolean);
  if (failure.length > 0) rows.push({ label: "Handshake failure", value: failure.join(" · ") });
  return rows;
}

function getGcloudPreviewBytes(ev, maxBytes = 384) {
  const pay = String(ev && ev.pay ? ev.pay : "");
  if (pay) {
    const bytes = b64ToBytes(pay);
    if (bytes.length > 0) return { bytes, source: "pay", complete: true };
  }
  for (const keyName of ["pfx", "before_pfx", "full_pfx", "raw_pfx"]) {
    const bytes = bytesFromHexPrefix(ev && ev[keyName], maxBytes);
    if (bytes.length > 0) {
      return { bytes, source: keyName, complete: false };
    }
  }
  return { bytes: [], source: "", complete: false };
}

function readGcloudBe16(bytes, offset) {
  if (!Array.isArray(bytes) || offset + 2 > bytes.length) return null;
  return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
}

function readGcloudBe32(bytes, offset) {
  if (!Array.isArray(bytes) || offset + 4 > bytes.length) return null;
  return (
    ((bytes[offset] & 0xff) * 0x1000000)
    + ((bytes[offset + 1] & 0xff) << 16)
    + ((bytes[offset + 2] & 0xff) << 8)
    + (bytes[offset + 3] & 0xff)
  ) >>> 0;
}

function readGcloudBe48(bytes, offset) {
  if (!Array.isArray(bytes) || offset + 6 > bytes.length) return null;
  let value = 0;
  for (let i = 0; i < 6; i += 1) {
    value = value * 0x100 + (bytes[offset + i] & 0xff);
  }
  return Number.isSafeInteger(value) ? value : null;
}

function parseGcloudTgcpFrame(bytes) {
  if (!Array.isArray(bytes) || bytes.length < 8 || bytes[0] !== 0x33 || bytes[1] !== 0x66) {
    return null;
  }
  const command = readGcloudBe16(bytes, 6);
  return {
    magic: "33 66",
    command,
    commandText: command !== null ? formatHexValue(command, 4) : "-",
    sideByte: bytes.length > 8 ? bytes[8] : null,
    seqByte: bytes.length > 12 ? bytes[12] : null,
    headerLen: readGcloudBe32(bytes, 13),
    payloadLen: readGcloudBe32(bytes, 17),
    totalLen: bytes.length,
    prefix: bytes.slice(0, Math.min(16, bytes.length)).map(childHexByteText).join(" "),
  };
}

function normalizeGcloudDirection(ev, meta = null) {
  const raw = String(meta && meta.direction ? meta.direction : "").trim().toLowerCase();
  if (raw === "outbound" || raw === "client" || raw === "request" || raw === "req") return "outbound";
  if (raw === "inbound" || raw === "server" || raw === "response" || raw === "resp") return "inbound";
  const dir = Number(ev && ev.dir);
  if (dir === 0) return "outbound";
  if (dir === 1) return "inbound";
  return raw || "";
}

function gcloudEventTsMs(ev) {
  const raw = Number(ev && ev.ts);
  if (!Number.isFinite(raw) || raw <= 0) return null;
  return raw < 10000000000 ? raw * 1000 : raw;
}

function parseGcloud9001Control(bytes, frame = null) {
  const tgcp = frame || parseGcloudTgcpFrame(bytes);
  if (!tgcp || tgcp.command !== 0x9001) return null;
  const extensionStart = 21;
  const extensionEnd = 45;
  if (!Array.isArray(bytes) || bytes.length < extensionEnd) {
    return {
      ok: false,
      complete: false,
      reason: "当前 raw/prefix 不足 45 字节，暂时看不到 9001 扩展字段。",
    };
  }
  const extension = bytes.slice(extensionStart, extensionEnd);
  const controlId = readGcloudBe32(bytes, extensionStart);
  const tickLen = readGcloudBe16(bytes, extensionStart + 4);
  const tick48 = readGcloudBe48(bytes, extensionStart + 6);
  const flag = readGcloudBe32(bytes, extensionStart + 12);
  const reserved = bytes.slice(extensionStart + 16, extensionEnd);
  const tickHex = tick48 !== null ? `0x${tick48.toString(16).padStart(12, "0")}` : "-";
  return {
    ok: true,
    complete: true,
    extension,
    extensionHex: extension.map(childHexByteText).join(""),
    extensionText: gcloudHexBytes(extension, 32),
    controlId,
    tickLen,
    tick48,
    tickHex,
    flag,
    reserved,
    reservedHex: gcloudHexBytes(reserved, 16),
    reservedZero: reserved.every((byte) => (byte & 0xff) === 0),
    shapeOk: tgcp.headerLen === 45 && tgcp.payloadLen === 0,
  };
}

function gcloud9001IndexSignature() {
  if (!Array.isArray(state.events) || state.events.length <= 0) return "empty";
  const first = state.events[0];
  const last = state.events[state.events.length - 1];
  return `${state.flowId || ""}|${state.events.length}|${getEventId(first)}|${getEventId(last)}`;
}

function getGcloud9001PairIndex() {
  const signature = gcloud9001IndexSignature();
  if (state.gcloud9001PairIndex && state.gcloud9001PairIndex.signature === signature) {
    return state.gcloud9001PairIndex;
  }
  const byExtension = new Map();
  const events = Array.isArray(state.events) ? state.events : [];
  events.forEach((candidate, index) => {
    const summary = String(candidate && candidate.summary ? candidate.summary : "");
    if (!isGcloud65010Summary(summary, candidate)) return;
    const meta = parseGcloud65010Summary(summary, candidate);
    if (meta.command !== 0x9001) return;
    const preview = getGcloudPreviewBytes(candidate, 64);
    const frame = parseGcloudTgcpFrame(preview.bytes);
    const control = parseGcloud9001Control(preview.bytes, frame);
    if (!control || !control.ok || !control.extensionHex) return;
    const direction = normalizeGcloudDirection(candidate, meta);
    const bucket = byExtension.get(control.extensionHex) || { outbound: [], inbound: [] };
    const entry = {
      ev: candidate,
      index,
      id: getEventId(candidate),
      direction,
      tsMs: gcloudEventTsMs(candidate),
      seq: frame ? frame.seqByte : null,
      frame,
      control,
    };
    if (direction === "outbound") bucket.outbound.push(entry);
    else if (direction === "inbound") bucket.inbound.push(entry);
    byExtension.set(control.extensionHex, bucket);
  });
  state.gcloud9001PairIndex = { signature, byExtension };
  return state.gcloud9001PairIndex;
}

function findGcloud9001Pair(ev, control, meta = null) {
  if (!control || !control.ok || !control.extensionHex) return null;
  const index = getGcloud9001PairIndex();
  const bucket = index && index.byExtension ? index.byExtension.get(control.extensionHex) : null;
  if (!bucket) return null;
  const direction = normalizeGcloudDirection(ev, meta);
  const currentId = getEventId(ev);
  const currentTs = gcloudEventTsMs(ev);
  const candidates = direction === "outbound" ? bucket.inbound : direction === "inbound" ? bucket.outbound : [];
  let best = null;
  for (const candidate of candidates) {
    if (!candidate || candidate.id === currentId) continue;
    let signedMs = null;
    let rttMs = null;
    if (currentTs !== null && candidate.tsMs !== null) {
      signedMs = direction === "outbound" ? candidate.tsMs - currentTs : currentTs - candidate.tsMs;
      rttMs = Math.abs(signedMs);
    }
    const score = signedMs === null ? 1000000000 + Math.abs((candidate.index || 0)) : (signedMs < -5 ? 1000000 + Math.abs(signedMs) : Math.abs(signedMs));
    if (!best || score < best.score) {
      best = {
        ...candidate,
        score,
        rttMs,
        signedMs,
      };
    }
  }
  return best;
}

function readGcloudVarint(bytes, pos, end) {
  const limit = Math.min(Array.isArray(bytes) ? bytes.length : 0, Number(end || 0));
  let value = 0;
  let bigValue = typeof BigInt === "function" ? BigInt(0) : null;
  let shift = 0;
  let cursor = Number(pos || 0);
  for (let count = 0; cursor < limit && count < 10; count += 1) {
    const byte = bytes[cursor] & 0xff;
    cursor += 1;
    const chunk = byte & 0x7f;
    value += chunk * (2 ** shift);
    if (bigValue !== null) {
      bigValue += BigInt(chunk) << BigInt(shift);
    }
    if ((byte & 0x80) === 0) {
      const valueText = bigValue !== null ? bigValue.toString(10) : String(value);
      const valueHexText = bigValue !== null ? `0x${bigValue.toString(16)}` : formatHexValue(value);
      return {
        ok: true,
        value,
        valueText,
        valueHexText,
        raw: bytes.slice(Number(pos || 0), cursor),
        next: cursor,
      };
    }
    shift += 7;
  }
  return { ok: false, value: 0, valueText: "0", valueHexText: "0x0", raw: [], next: Number(pos || 0) };
}

function gcloudVarintEncodedLength(value) {
  let current = Number(value);
  if (!Number.isFinite(current) || current < 0 || current > 0xffffffff) return 0;
  current = Math.floor(current);
  let length = 1;
  while (current >= 0x80) {
    current = Math.floor(current / 0x80);
    length += 1;
  }
  return length;
}

function scanUagameReportCodeCandidates(byteValues, maxHits = 32) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  const hits = [];
  for (let offset = 0; offset + 3 < bytes.length && hits.length < maxHits; offset += 1) {
    if (
      (bytes[offset] & 0xff) !== 0x01
      || (bytes[offset + 1] & 0xff) !== 0x0a
      || (bytes[offset + 2] & 0xff) !== 0x00
    ) continue;
    const code = (
      0x010a0000
      + (bytes[offset + 3] & 0xff)
    ) >>> 0;
    const recordStart = offset >= 6
      && (bytes[offset - 6] & 0xff) === 0x00
      && (bytes[offset - 5] & 0xff) === 0x00
      && (bytes[offset - 4] & 0xff) === 0x00
      && (bytes[offset - 3] & 0xff) === 0x01
      ? offset - 6
      : null;
    const declaredLength = recordStart === null
      ? null
      : readBe16(bytes, recordStart + 4);
    const structurallyBounded = recordStart !== null
      && Number.isFinite(declaredLength)
      && declaredLength >= 10
      && recordStart + declaredLength <= bytes.length;
    hits.push({
      offset,
      code,
      codeText: formatHexValue(code, 8),
      recordStart,
      declaredLength,
      structurallyBounded,
    });
  }
  return hits;
}

function scanUagameKnownMarkers(byteValues, maxHits = 24) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  const markers = [
    { key: "09 4e", bytes: [0x09, 0x4e] },
    { key: "0a 92", bytes: [0x0a, 0x92] },
    { key: "27 0f", bytes: [0x27, 0x0f] },
  ];
  const hits = [];
  for (const marker of markers) {
    for (let offset = 0; offset + marker.bytes.length <= bytes.length && hits.length < maxHits; offset += 1) {
      if (marker.bytes.every((byte, index) => (bytes[offset + index] & 0xff) === byte)) {
        hits.push({ marker: marker.key, offset });
      }
    }
  }
  return hits;
}

function parseUagamePackedUint32Root(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  if (bytes.length < 3) return null;
  const tag = readGcloudVarint(bytes, 0, bytes.length);
  if (!tag.ok || Number(tag.value) !== 0x12) return null;
  const length = readGcloudVarint(bytes, tag.next, bytes.length);
  if (!length.ok) return null;
  const payloadStart = Number(length.next || 0);
  const payloadLength = Number(length.value || 0);
  const payloadEnd = payloadStart + payloadLength;
  if (payloadLength <= 0 || payloadEnd !== bytes.length) return null;

  const values = [];
  let cursor = payloadStart;
  let canonical = true;
  while (cursor < payloadEnd && values.length < 8192) {
    const item = readGcloudVarint(bytes, cursor, payloadEnd);
    if (!item.ok || item.next <= cursor || item.value < 0 || item.value > 0xffffffff) return null;
    if (gcloudVarintEncodedLength(item.value) !== item.raw.length) canonical = false;
    values.push(Number(item.value));
    cursor = item.next;
  }
  if (cursor !== payloadEnd || values.length <= 0) return null;

  const counts = new Map();
  const prefixes = new Map();
  let idLikeCount = 0;
  for (const value of values) {
    counts.set(value, Number(counts.get(value) || 0) + 1);
    const decimal = String(value);
    if (/^\d{8,10}$/.test(decimal)) idLikeCount += 1;
    const prefix = decimal.slice(0, 3);
    prefixes.set(prefix, Number(prefixes.get(prefix) || 0) + 1);
  }
  const duplicates = Array.from(counts.entries())
    .filter((entry) => entry[1] > 1)
    .map((entry) => ({ value: entry[0], count: entry[1] }));
  const prefixCounts = Array.from(prefixes.entries())
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  const reportCodeValues = values.filter((value) => value >= 0x010a0000 && value <= 0x010a00ff);
  return {
    ok: true,
    field: 2,
    payloadStart,
    payloadLength,
    count: values.length,
    uniqueCount: counts.size,
    canonical,
    idLike: idLikeCount >= Math.ceil(values.length * 0.8),
    values,
    first: values.slice(0, 20),
    last: values.slice(-20),
    duplicates,
    prefixCounts,
    reportCodeValues,
  };
}

function analyzeUagameDecodedBodyProbe(byteValues, meta = null) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  if (bytes.length <= 0) return null;
  const reportHits = scanUagameReportCodeCandidates(bytes);
  const markerHits = scanUagameKnownMarkers(bytes);
  const packed = parseUagamePackedUint32Root(bytes);
  return {
    opcode: parseFlexibleInt(meta && meta.gcloudOpcode),
    opcodeText: String(meta && meta.gcloudOpcode || ""),
    length: bytes.length,
    packed,
    reportHits,
    structuredReportHits: reportHits.filter((hit) => hit.structurallyBounded),
    markerHits,
  };
}

function uagameReportProbeRows(probe, direction = "") {
  if (!probe) return [];
  const packed = probe.packed;
  const reportHits = Array.isArray(probe.reportHits) ? probe.reportHits : [];
  const structured = Array.isArray(probe.structuredReportHits) ? probe.structuredReportHits : [];
  const markerHits = Array.isArray(probe.markerHits) ? probe.markerHits : [];
  const rows = [];
  if (packed && packed.ok) {
    rows.push({
      label: "人话结论",
      value: `${direction === "inbound" ? "服务器下发" : direction === "outbound" ? "客户端上传" : "当前消息携带"} ${packed.count} 个数字 ID（${packed.uniqueCount} unique）；这是列表，不是 ZIP 文件，也没有未消费的尾部密文。`,
    });
    rows.push({
      label: "ID 样例",
      value: `前20=${packed.first.join(", ")} · 后20=${packed.last.join(", ")}`,
    });
    rows.push({
      label: "ID 分组",
      value: packed.prefixCounts.slice(0, 12).map((item) => `${item[0]}…×${item[1]}`).join(" · "),
    });
    rows.push({
      label: "Protobuf",
      value: `root field 2 · packed uint32 ×${packed.count} · payload=${packed.payloadLength}B · canonical=${packed.canonical ? "yes" : "no"} · byte boundary=complete`,
    });
  }

  const reportText = reportHits.length > 0
    ? reportHits.map((hit) => `${hit.codeText}@+${formatHexValue(hit.offset)}${hit.structurallyBounded ? `[record+${formatHexValue(hit.recordStart)} len=${hit.declaredLength}]` : "[raw候选]"}`).join(" · ")
    : "解密 body 全量扫描未发现 01 0a 00 xx";
  rows.push({ label: "01 0a 00 xx 扫描", value: reportText });
  rows.push({
    label: "TerSafe record",
    value: structured.length > 0
      ? `发现 ${structured.length} 个同时满足 00000001 + declared_len + reportCode 的结构候选，可继续交给 TerSafe decoder。`
      : "未发现完整 00000001 + declared_len + reportCode 记录；不会仅凭 4 字节巧合宣称 TerSafe 解密成功。",
  });
  rows.push({
    label: "Marker 独立扫描",
    value: markerHits.length > 0
      ? markerHits.map((hit) => `${hit.marker}@+${formatHexValue(hit.offset)}`).join(" · ")
      : "09 4e / 0a 92 / 27 0f 均未命中；reportCode 扫描不依赖这些 marker。",
  });
  if (packed && packed.reportCodeValues.length > 0) {
    rows.push({
      label: "ID值中的 reportCode",
      value: packed.reportCodeValues.map((value) => formatHexValue(value, 8)).join(", "),
    });
  }
  return rows;
}

function gcloudBytesToUtf8(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  try {
    if (typeof TextDecoder !== "undefined") {
      return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(byteValues));
    }
  } catch (_e) {
    return "";
  }
  if (byteValues.every((byte) => byte >= 32 && byte < 127)) {
    return byteValues.map((byte) => String.fromCharCode(byte)).join("");
  }
  return "";
}

function isGcloudVisibleString(text) {
  const raw = String(text || "");
  if (!raw) return false;
  for (const ch of raw) {
    const code = ch.charCodeAt(0);
    if (code < 32 || code === 127) return false;
  }
  return true;
}

function gcloudOpaqueBinaryCarrierKind(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  if (bytes.length >= 3 && bytes[0] === 0x5a && bytes[1] === 0x49 && bytes[2] === 0x50) return "ZIP carrier";
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) return "ZIP archive";
  if (bytes.length >= 2 && bytes[0] === 0x78 && (((bytes[0] << 8) | bytes[1]) % 31) === 0) return "zlib stream";
  return "";
}

function parseGcloudProtoNodes(bytes, start = 0, end = null, depth = 0, maxNodes = 120) {
  const limit = Math.min(Array.isArray(bytes) ? bytes.length : 0, end === null ? bytes.length : Number(end || 0));
  let pos = Math.max(0, Number(start || 0));
  const nodes = [];
  let reason = "";
  while (pos < limit && nodes.length < maxNodes) {
    const tagOffset = pos;
    const tag = readGcloudVarint(bytes, pos, limit);
    if (!tag.ok || tag.value === 0) {
      reason = "bad tag";
      return { nodes, ok: false, end: pos, reason };
    }
    const field = Math.floor(tag.value / 8);
    const wire = tag.value & 7;
    if (field <= 0 || field > 512) {
      reason = `field ${field} out of range`;
      return { nodes, ok: false, end: tagOffset, reason };
    }
    pos = tag.next;
    const node = {
      off: tagOffset,
      field,
      wire,
      depth,
      tagRaw: tag.raw || [],
      tagText: tag.valueText || String(tag.value),
      end: pos,
    };

    if (wire === 0) {
      const value = readGcloudVarint(bytes, pos, limit);
      if (!value.ok) {
        reason = `field[${field}] bad varint`;
        return { nodes, ok: false, end: pos, reason };
      }
      node.value = value.value;
      node.valueText = value.valueText;
      node.valueHexText = value.valueHexText;
      node.valueStart = pos;
      node.valueRaw = value.raw || [];
      node.end = value.next;
      pos = value.next;
    } else if (wire === 1) {
      if (pos + 8 > limit) {
        node.truncated = true;
        node.available = Math.max(0, limit - pos);
        node.end = limit;
        nodes.push(node);
        return { nodes, ok: false, end: limit, reason: `field[${field}] fixed64 truncated` };
      }
      node.valueStart = pos;
      node.valueHex = bytes.slice(pos, pos + 8).map(childHexByteText).join(" ");
      node.end = pos + 8;
      pos += 8;
    } else if (wire === 2) {
      const lengthInfo = readGcloudVarint(bytes, pos, limit);
      if (!lengthInfo.ok) {
        reason = `field[${field}] bad length`;
        return { nodes, ok: false, end: pos, reason };
      }
      const valueStart = lengthInfo.next;
      const valueEnd = valueStart + lengthInfo.value;
      node.len = lengthInfo.value;
      node.lenText = lengthInfo.valueText;
      node.lenRaw = lengthInfo.raw || [];
      node.valueStart = valueStart;
      node.valueEnd = valueEnd;
      if (valueEnd > limit) {
        node.truncated = true;
        node.available = Math.max(0, limit - valueStart);
        node.end = limit;
        nodes.push(node);
        return {
          nodes,
          ok: false,
          end: limit,
          reason: `field[${field}] len ${lengthInfo.value} > remain ${Math.max(0, limit - valueStart)}`,
        };
      }
      const valueBytes = bytes.slice(valueStart, valueEnd);
      const text = gcloudBytesToUtf8(valueBytes);
      const opaqueBinaryCarrier = gcloudOpaqueBinaryCarrierKind(valueBytes);
      if (text && isGcloudVisibleString(text)) {
        node.string = text;
      } else if (opaqueBinaryCarrier) {
        node.binaryCarrier = opaqueBinaryCarrier;
      } else if (depth < 6 && lengthInfo.value >= 2) {
        const child = parseGcloudProtoNodes(bytes, valueStart, valueEnd, depth + 1, maxNodes - nodes.length);
        if (child.nodes.length > 0) {
          node.children = child.nodes;
          node.childOk = child.ok;
          node.childReason = child.reason || "";
        }
      }
      node.end = valueEnd;
      pos = valueEnd;
    } else if (wire === 5) {
      if (pos + 4 > limit) {
        node.truncated = true;
        node.available = Math.max(0, limit - pos);
        node.end = limit;
        nodes.push(node);
        return { nodes, ok: false, end: limit, reason: `field[${field}] fixed32 truncated` };
      }
      node.valueStart = pos;
      node.valueHex = bytes.slice(pos, pos + 4).map(childHexByteText).join(" ");
      node.end = pos + 4;
      pos += 4;
    } else {
      reason = `wire ${wire} unsupported`;
      return { nodes, ok: false, end: pos, reason };
    }
    nodes.push(node);
  }
  if (nodes.length >= maxNodes && pos < limit) {
    return { nodes, ok: false, end: pos, reason: "node limit reached" };
  }
  return { nodes, ok: pos === limit, end: pos, reason };
}

function walkGcloudProtoNodes(nodes, path = [], topIndex = -1, out = []) {
  const list = Array.isArray(nodes) ? nodes : [];
  list.forEach((node, index) => {
    const nextTopIndex = path.length === 0 ? index : topIndex;
    const nextPath = path.concat(Number(node && node.field));
    out.push({ node, path: nextPath, topIndex: nextTopIndex });
    walkGcloudProtoNodes(node && node.children, nextPath, nextTopIndex, out);
  });
  return out;
}

function gcloudPathKey(path) {
  return (Array.isArray(path) ? path : []).join(".");
}

function gcloudRawPathText(path, topIndex = -1) {
  const parts = Array.isArray(path) ? path : [];
  if (parts.length <= 0) return "node";
  const fieldText = parts.map((field) => `field[${field}]`).join(".");
  if (parts.length === 1 && Number.isFinite(Number(topIndex))) {
    return `node[${Number(topIndex)}] ${fieldText}`;
  }
  return fieldText;
}

function gcloudPathText(path, topIndex = -1) {
  return gcloudRawPathText(path, topIndex);
}

function gcloudProtoPathLookup(proto) {
  if (!proto || !Array.isArray(proto.flat)) return new Map();
  if (proto._gcloudPathLookup instanceof Map) return proto._gcloudPathLookup;
  const lookup = new Map();
  for (const item of proto.flat) {
    const key = gcloudPathKey(item && item.path);
    if (key && !lookup.has(key)) lookup.set(key, item);
  }
  proto._gcloudPathLookup = lookup;
  return lookup;
}

function gcloudSemanticPathText(path, proto = null, topIndex = -1, node = null) {
  const parts = Array.isArray(path) ? path : [];
  if (parts.length <= 0) return "node";
  const lookup = gcloudProtoPathLookup(proto);
  const labels = parts.map((field, index) => {
    const prefix = parts.slice(0, index + 1);
    const exactNode = index === parts.length - 1 ? node : null;
    const found = lookup.get(gcloudPathKey(prefix));
    const alias = gcloudProtoFieldAlias(prefix, exactNode || (found && found.node), proto);
    return alias || `f${Number(field)}`;
  });
  if (parts.length === 1 && Number.isFinite(Number(topIndex))) {
    return `node[${Number(topIndex)}] ${labels[0]}`;
  }
  return labels.join(" > ");
}

function findGcloudCommandMatches(byteValues, maxBytes = 512) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
  const text = bytesToLatin1String(byteValues.slice(0, Math.min(maxBytes, byteValues.length)));
  const out = [];
  for (const match of text.matchAll(/CS[A-Za-z0-9_]{4,}/g)) {
    out.push({ off: Number(match.index || 0), text: String(match[0] || "") });
    if (out.length >= 12) break;
  }
  return out;
}

function chooseGcloudCommandDisplay(structuredName, roughName) {
  const structured = String(structuredName || "").trim();
  const rough = String(roughName || "").trim();
  if (!structured) return gcloudReadableTypeName(rough);
  // The raw ASCII scan historically swallowed the next protobuf tag byte.
  // For example field[7] "CSReportIDCReq" followed by tag 0x42 was shown as
  // "CSReportIDCReqB".  A parsed length-delimited command field is the exact
  // value and must always win over the rough substring scan.
  return gcloudReadableTypeName(structured);
}

function decodeGcloudLz4Block(byteValues, maxOutput = 4 * 1024 * 1024) {
  const input = Array.isArray(byteValues) ? byteValues : [];
  if (input.length < 4) return null;
  const output = [];
  let pos = 0;
  let sequences = 0;
  let matches = 0;
  try {
    while (pos < input.length) {
      const token = input[pos++] & 0xff;
      let literalLength = token >>> 4;
      if (literalLength === 15) {
        let extra = 255;
        while (extra === 255) {
          if (pos >= input.length) return null;
          extra = input[pos++] & 0xff;
          literalLength += extra;
        }
      }
      if (pos + literalLength > input.length || output.length + literalLength > maxOutput) return null;
      for (let index = 0; index < literalLength; index += 1) output.push(input[pos++] & 0xff);
      sequences += 1;
      if (pos >= input.length) break;
      if (pos + 2 > input.length) return null;
      const offset = (input[pos] & 0xff) | ((input[pos + 1] & 0xff) << 8);
      pos += 2;
      if (offset <= 0 || offset > output.length) return null;
      let matchLength = token & 0x0f;
      if (matchLength === 15) {
        let extra = 255;
        while (extra === 255) {
          if (pos >= input.length) return null;
          extra = input[pos++] & 0xff;
          matchLength += extra;
        }
      }
      matchLength += 4;
      if (output.length + matchLength > maxOutput) return null;
      for (let index = 0; index < matchLength; index += 1) {
        output.push(output[output.length - offset] & 0xff);
      }
      matches += 1;
    }
  } catch (_e) {
    return null;
  }
  if (pos !== input.length || output.length <= 0 || sequences <= 0) return null;
  return { bytes: output, sequences, matches };
}

function analyzeGcloudProtoCandidate(bytes, start, completeSource) {
  const parsed = parseGcloudProtoNodes(bytes, start, bytes.length, 0, 240);
  const flat = walkGcloudProtoNodes(parsed.nodes);
  const strings = flat.filter((item) => item.node && item.node.string);
  const commandField = strings.find((item) => /^CS[A-Za-z0-9_]{4,}$/.test(String(item.node.string || "")));
  const parentKey = commandField ? gcloudPathKey(commandField.path.slice(0, -1)) : "";
  const sibling = (field) => flat.find((item) => (
    gcloudPathKey(item.path.slice(0, -1)) === parentKey && Number(item.node && item.node.field) === Number(field)
  ));
  const roughMatch = findGcloudCommandMatches(bytes.slice(start), 160)[0] || null;
  const roughName = roughMatch ? roughMatch.text : "";
  const commandName = commandField ? String(commandField.node.string || "") : "";
  const commandDisplay = chooseGcloudCommandDisplay(commandName, roughName);
  const commandIdNode = sibling(3);
  const moduleNode = sibling(8);
  const languageNode = sibling(9);
  const topBody = flat.find((item) => item.path.length === 1 && Number(item.node && item.node.field) === 2);
  const covered = Math.max(0, Number(parsed.end || start) - Number(start || 0));
  const score = (parsed.ok ? 100000 : 0)
    + (commandDisplay ? 20000 : 0)
    + (flat.length > 0 ? 4000 : 0)
    + Math.min(covered, 20000)
    - Math.max(0, Number(start || 0)) * 40;
  const fragment = Boolean(!parsed.ok && commandDisplay);
  return {
    start,
    sourceComplete: !!completeSource,
    ok: parsed.ok,
    fragment,
    end: parsed.end,
    reason: parsed.reason || "",
    nodes: parsed.nodes,
    flat,
    strings,
    commandField,
    commandName,
    commandDisplay,
    roughName,
    commandId: commandIdNode && commandIdNode.node ? commandIdNode.node.value : null,
    module: moduleNode && moduleNode.node ? String(moduleNode.node.string || "") : "",
    language: languageNode && languageNode.node ? String(languageNode.node.string || "") : "",
    bodyNode: topBody ? topBody.node : null,
    covered,
    score,
  };
}

function analyzeGcloudBusinessProtoBytes(bytes, completeSource = true) {
  if (!Array.isArray(bytes) || bytes.length <= 0) return null;
  const starts = new Set();
  for (let i = 0; i < Math.min(8, bytes.length); i += 1) starts.add(i);
  for (const match of findGcloudCommandMatches(bytes, 192)) {
    const from = Math.max(0, Number(match.off || 0) - 10);
    for (let pos = from; pos <= Number(match.off || 0); pos += 1) {
      if (bytes[pos] === 0x0a) starts.add(pos);
    }
  }
  const candidates = Array.from(starts)
    .filter((start) => Number.isFinite(start) && start >= 0 && start < bytes.length)
    .map((start) => analyzeGcloudProtoCandidate(bytes, start, completeSource))
    .sort((left, right) => Number(right.score || 0) - Number(left.score || 0));
  return candidates[0] || null;
}

function analyzeGcloudBusinessProto(bytes, completeSource = true) {
  if (!Array.isArray(bytes) || bytes.length <= 0) return null;
  const direct = analyzeGcloudBusinessProtoBytes(bytes, completeSource);
  const lz4 = decodeGcloudLz4Block(bytes);
  if (lz4 && Array.isArray(lz4.bytes) && lz4.bytes.length > 0) {
    const unpacked = analyzeGcloudBusinessProtoBytes(lz4.bytes, completeSource);
    const directScore = Number(direct && direct.score ? direct.score : 0);
    const unpackedScore = Number(unpacked && unpacked.score ? unpacked.score : 0);
    if (
      unpacked
      && unpacked.commandDisplay
      && (unpacked.ok || unpacked.fragment)
      && Array.isArray(unpacked.flat)
      && unpacked.flat.length >= 4
      && unpackedScore > directScore + 1000
    ) {
      unpacked.viewBytes = lz4.bytes;
      unpacked.compression = {
        kind: "lz4-block",
        inputLength: bytes.length,
        outputLength: lz4.bytes.length,
        sequences: lz4.sequences,
        matches: lz4.matches,
      };
      return unpacked;
    }
  }
  if (direct) direct.viewBytes = bytes;
  return direct;
}

function gcloudProtoStatusText(proto) {
  if (!proto) return "payload 未加载";
  const prefix = proto.compression && proto.compression.kind === "lz4-block" ? "LZ4 解压 -> " : "";
  if (proto.ok && Number(proto.start || 0) === 0) return `${prefix}protobuf ok`;
  if (proto.ok && Number(proto.start || 0) > 0) return `${prefix}lead ${Number(proto.start)} + protobuf ok`;
  if (proto.commandDisplay) return `proto fragment${proto.reason ? ` (${proto.reason})` : ""}`;
  return proto.reason ? `protobuf 待证 (${proto.reason})` : "protobuf 待证";
}

function gcloudNodeValueText(node) {
  if (!node) return "-";
  if (node.truncated) {
    return `len=${Number(node.len || 0)} available=${Number(node.available || 0)} fragment`;
  }
  if (node.binaryCarrier) return `${node.binaryCarrier} · len=${Number(node.len || 0)}`;
  if (node.string) return `string "${shortenText(node.string, 120)}"`;
  if (Number(node.wire) === 0 && node.value !== undefined) {
    const valueText = String(node.valueText || node.value);
    const hexText = String(node.valueHexText || formatHexValue(node.value));
    return `varint ${valueText} (${hexText})`;
  }
  if (Number(node.wire) === 2) {
    const childStatus = node.childOk === false && node.childReason ? `; child ${node.childReason}` : "";
    return `len=${Number(node.len || 0)}${childStatus}`;
  }
  if (node.valueHex) return `wire${Number(node.wire)} ${node.valueHex}`;
  return `wire${Number(node.wire)}`;
}

function gcloudNodeChildStrings(node, maxItems = 16) {
  const out = [];
  const visit = (current) => {
    if (!current || out.length >= maxItems) return;
    if (current.string) out.push(String(current.string));
    for (const child of Array.isArray(current.children) ? current.children : []) visit(child);
  };
  visit(node);
  return out;
}

function gcloudStringContentAlias(text) {
  const value = String(text || "").trim();
  if (!value) return "";
  if (/^https?:\/\//i.test(value)) return /qlogo\.cn\//i.test(value) ? "avatar_url" : "url";
  if (/^tcp:\/\//i.test(value)) return "server_endpoint";
  if (/^(?:\/?(?:private|var|Library|Applications|System)\/)|(?:[A-Za-z]:\\)|.*\.(?:dylib|framework|data|json|plist)$/i.test(value)) return "path";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return "ip_address";
  if (/^com\.[A-Za-z0-9_.-]+$/.test(value)) return "bundle_id";
  if (/^IOS\d+(?:\.\d+)+$/i.test(value)) return "os_version";
  if (/^(?:Apple\|)?i(?:Phone|Pad)\d+,\d+$/i.test(value)) return "device_model";
  if (/^Mozilla\/\d/i.test(value)) return "user_agent";
  if (/^Apple$/i.test(value)) return "device_vendor";
  if (/GPU(?:Brand|Vendor|Model)/i.test(value)) return "gpu_brand";
  if (/^(?:WiFi|WLAN|Cellular|Ethernet|5G|4G|3G)$/i.test(value)) return "network_type";
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return "uuid";
  if (/^\[[0-9a-f:]+\]:\d+$/i.test(value) || /^(?:\d{1,3}\.){3}\d{1,3}:\d+$/.test(value)) return "network_address";
  if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(value)) return "host";
  if (/^[a-z]{2}(?:[-_][A-Za-z]{2,8})+$/i.test(value)) return "language";
  if (/^[A-Z]{2}$/.test(value)) return "region?";
  if (/^[A-Z]{3}$/.test(value)) return "currency?";
  if (/^\d+(?:\.\d+){2,}$/.test(value)) return "version?";
  if (/^[0-9]{10,20}$/.test(value)) return "id?";
  if (/^[0-9a-f]{32,64}$/i.test(value)) return "hash?";
  return "";
}

function gcloudProtoFieldAlias(path, node, proto) {
  const key = gcloudPathKey(path);
  // UAGame 20001 body has no DFM/Valorant CS-command header.  Preserve raw
  // f1/f2 paths until UAGame descriptors or registration tables prove names.
  if (proto && proto.uagameBody) return "";
  const generic = {
    "1": "header",
    "1.3": "call_id",
    "1.7": "command",
    "1.8": "module",
    "1.9": "language",
    "2": "body",
  };
  const commandName = String(proto && proto.commandDisplay ? proto.commandDisplay : "");
  const chatWorldLoad = /CSChatWorldLoad/i.test(commandName);
  const accountLogin = /CSAccountLogin/i.test(commandName);
  const onlineHeartbeatRes = /^CSOnlineHeartbeatRes/i.test(commandName);
  const prepareMapBoardRes = /^CSPrepareMapBoardRes/i.test(commandName);
  const prepareTdmMapBoardRes = /^CSPrepareTDMMapBoardRes/i.test(commandName);
  const switchUnlockInfoRes = /^CSSwitchLoadSystemUnlockInfoRes/i.test(commandName);
  const collectionRes = /^CSCollection/i.test(commandName);
  const gatewayKick = /^CSGatewayKickPlayerNtf$/i.test(commandName);
  const chatAliases = chatWorldLoad ? {
    "2.2": "items[]",
    "2.2.1": "message",
    "2.2.1.3": "text?",
    "2.2.2": "sender?",
    "2.2.2.2": "name?",
    "2.2.2.3": "id?",
    "2.5": "status?",
  } : {};
  const aceAliases = /CSAceSendLightFeatureDataNtf/i.test(commandName) ? {
    "2.1": "feature_hex_blob",
  } : (/CSAceSendAntiDataNtf/i.test(commandName) ? {
    "2.1": "anti_data_hex_blob",
  } : {});
  const gatewayKickAliases = gatewayKick ? {
    "2.1": "kick_code",
    "2.2": "notice",
  } : {};
  if (gatewayKickAliases[key]) return gatewayKickAliases[key];
  if (aceAliases[key]) return aceAliases[key];
  if (chatAliases[key]) return chatAliases[key];
  if (generic[key]) return generic[key];
  if (onlineHeartbeatRes && key === "2.2") return "server_time?";
  if (chatWorldLoad && key === "2.2.1.1") return "message_time?";
  if (prepareMapBoardRes) {
    if (key === "2.3.10") return "server_time?";
    if (key === "2.3.8.2") return "match_start?";
    if (key === "2.3.9.2") return "match_end?";
    if (/^2\.3\.(?:6|7|24)$/.test(key)) return "schedule_start?";
    if (/^2\.3\.(?:4|9|25)$/.test(key)) return "schedule_end?";
  }
  if (prepareTdmMapBoardRes) {
    if (/^2\.2\.(?:24|26)$/.test(key)) return "period_start?";
    if (/^2\.2\.(?:25|27)$/.test(key)) return "period_end?";
  }
  if (switchUnlockInfoRes) {
    if (key === "2.2.3") return "unlock_start?";
    if (key === "2.2.4") return "unlock_end?";
  }
  if (collectionRes && /^(?:2\.2\.25|2\.3\.25|2\.4\.25|2\.5\.2)$/.test(key)) return "time?";

  const text = String(node && node.string ? node.string : "");
  if (accountLogin) {
    if (/^IOS\d+(?:\.\d+)+$/i.test(text)) return "os_version";
    if (/^(?:Apple\|)?i(?:Phone|Pad)\d+,\d+$/i.test(text)) return "device_model";
    if (/^(?:WiFi|WLAN|Cellular|Ethernet|5G|4G|3G)$/i.test(text)) return "network_type";
    if (/^GenericGPUBrand$/i.test(text) || /GPU(?:Brand|Vendor|Model)/i.test(text)) return "gpu_brand";
    if (/^Mozilla\/\d/i.test(text)) return "user_agent";
    if (/^itopid$/i.test(text)) return "account_key";
    if (/^qq_qq-\d+-iap-\d+-/i.test(text)) return "iap_inc_id?";
    if (/^\d{10,20}$/.test(text)) return "account_id?";
  }
  const contentAlias = gcloudStringContentAlias(text);
  if (contentAlias) return contentAlias;
  if (Array.isArray(node && node.children) && node.children.length > 0) {
    const childText = gcloudNodeChildStrings(node).join(" | ");
    if (/IOS\d+(?:\.\d+)+/i.test(childText) && /i(?:Phone|Pad)\d+,\d+/i.test(childText)) return "device_profile";
    if (/\bitop(?:id)?\b/i.test(childText) && /\biap\b/i.test(childText)) return "account_context?";
  }
  if (/^CS[A-Za-z0-9_]{4,}$/.test(text)) return "command";
  if (/^(online|chat|mail|security|mall|role)$/i.test(text)) return "module?";
  if (/^zh[-_]/i.test(text)) return "language?";
  if (text.length >= 8 && /[\u4e00-\u9fff]/.test(text) && /[？?。！，,]/.test(text)) return "text?";
  if (gcloudAnalyzeBase64String(text)) return "base64_blob?";
  return "";
}

function gcloudProtoTypeText(node) {
  if (!node) return "-";
  if (node.truncated) return "fragment";
  if (node.string) {
    const hexInfo = gcloudAnalyzeHexString(node.string);
    if (hexInfo && hexInfo.kind === "ace-xor") return "ACE/xor";
    if (hexInfo && hexInfo.kind === "double-hex") return "hex->hex";
    if (hexInfo) return "hex-string";
    if (gcloudAnalyzeBase64String(node.string)) return "base64";
    return "string";
  }
  if (Number(node.wire) === 0) return "varint";
  if (Number(node.wire) === 1) return "fixed64";
  if (Number(node.wire) === 5) return "fixed32";
  if (Number(node.wire) === 2 && Array.isArray(node.children) && node.children.length > 0) return "message";
  if (Number(node.wire) === 2) return "bytes";
  return `wire${Number(node.wire)}`;
}

function gcloudOffsetText(value) {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) return "-";
  return `0x${Math.floor(num).toString(16).padStart(4, "0")}`;
}

function gcloudHexBytes(byteValues, maxBytes = 256) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  const safeMax = Math.max(8, Number(maxBytes || 256));
  const shown = bytes.slice(0, safeMax).map(childHexByteText).join(" ");
  if (bytes.length <= safeMax) return shown;
  return `${shown} ... (+${bytes.length - safeMax} bytes, total=${bytes.length})`;
}

function gcloudReadUint64(byteValues, offset = 0, little = false) {
  if (!Array.isArray(byteValues) || offset < 0 || offset + 7 >= byteValues.length || typeof BigInt !== "function") return null;
  let value = BigInt(0);
  for (let i = 0; i < 8; i += 1) {
    const idx = little ? offset + 7 - i : offset + i;
    value = (value << BigInt(8)) + BigInt(byteValues[idx] & 0xff);
  }
  return value;
}

function gcloudBigintText(value) {
  if (value === null || value === undefined) return "";
  try {
    const big = BigInt(value);
    return `${big.toString(10)} (0x${big.toString(16)})`;
  } catch (_e) {
    return "";
  }
}

function gcloudNodeValueBytes(node, bytes) {
  if (!node || !Array.isArray(bytes)) return [];
  const wire = Number(node.wire);
  if (wire === 0) return Array.isArray(node.valueRaw) ? node.valueRaw : bytes.slice(Number(node.valueStart || 0), Number(node.end || 0));
  if (wire === 1 || wire === 5 || wire === 2) {
    const start = Number(node.valueStart || node.end || 0);
    const end = wire === 2 && Number.isFinite(Number(node.valueEnd)) ? Number(node.valueEnd) : Number(node.end || start);
    return bytes.slice(Math.max(0, start), Math.max(0, end));
  }
  return [];
}

function gcloudNodeDecodedHexChildren(node) {
  if (!node || !Array.isArray(node.children)) return [];
  return node.children.filter((child) => child && child.string && gcloudAnalyzeHexString(child.string));
}

function gcloudNodeRawBytes(node, bytes) {
  if (!node || !Array.isArray(bytes)) return [];
  const start = Math.max(0, Number(node.off || 0));
  const end = Math.max(start, Number(node.end || start));
  return bytes.slice(start, end);
}

function gcloudPrintableAscii(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  if (bytes.length <= 0) return "";
  let text = "";
  for (const byte of bytes) {
    text += byte >= 32 && byte < 127 ? String.fromCharCode(byte) : ".";
  }
  return text.replace(/\.+$/g, "");
}

function gcloudIsHexText(text, minChars = 8) {
  const raw = String(text || "").trim();
  return raw.length >= Number(minChars || 8) && raw.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(raw);
}

function gcloudBytesFromHexText(text, maxBytes = 4096) {
  const raw = String(text || "").trim();
  if (!gcloudIsHexText(raw, 2)) return [];
  const byteCount = Math.min(Math.floor(raw.length / 2), Math.max(1, Number(maxBytes || 4096)));
  const out = [];
  for (let index = 0; index < byteCount; index += 1) {
    out.push(parseInt(raw.slice(index * 2, index * 2 + 2), 16) & 0xff);
  }
  return out;
}

function gcloudBytesAreAsciiHex(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  return bytes.length >= 8
    && bytes.length % 2 === 0
    && bytes.every((byte) => (
      (byte >= 0x30 && byte <= 0x39)
      || (byte >= 0x41 && byte <= 0x46)
      || (byte >= 0x61 && byte <= 0x66)
    ));
}

function gcloudBytesToAscii(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  return bytes.map((byte) => String.fromCharCode(byte & 0xff)).join("");
}

function gcloudReadableByteText(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  if (bytes.length <= 0) return "";
  const utf8 = gcloudBytesToUtf8(bytes);
  if (utf8 && isGcloudVisibleString(utf8)) return utf8;
  const printable = bytes.filter((byte) => byte >= 32 && byte < 127).length;
  if (printable < 4 || printable / bytes.length < 0.35) return "";
  return gcloudPrintableAscii(bytes);
}

function gcloudHexSlice(byteValues, offset = 0, length = null) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  const start = Math.max(0, Number(offset || 0));
  const end = length === null
    ? bytes.length
    : Math.min(bytes.length, start + Math.max(0, Number(length || 0)));
  return bytes.slice(start, end).map(childHexByteText).join(" ");
}

function gcloudByteEntropy(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  if (bytes.length <= 0) return 0;
  const counts = new Map();
  for (const byte of bytes) counts.set(byte & 0xff, Number(counts.get(byte & 0xff) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / bytes.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function gcloudEpochText(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 1577836800 || value > 2082758400) return "";
  try {
    return new Date(value * 1000).toISOString().replace(".000Z", "Z");
  } catch (_e) {
    return "";
  }
}

function gcloudEpochScalarInfo(value) {
  const raw = String(value ?? "").trim();
  if (!/^\d{10,13}$/.test(raw)) return null;
  const numberValue = Number(raw);
  if (!Number.isFinite(numberValue)) return null;
  let seconds = numberValue;
  let unit = "s";
  if (raw.length === 13) {
    seconds = Math.floor(numberValue / 1000);
    unit = "ms";
  } else if (raw.length !== 10) {
    return null;
  }
  const text = gcloudEpochText(seconds);
  if (!text) return null;
  return { seconds, unit, text };
}

function gcloudAnalyzeAcePayload(byteValues, meta = {}) {
  const payload = Array.isArray(byteValues) ? byteValues : [];
  const facts = [];
  const add = (label, value, className = "") => facts.push({ label, value, className });
  const signature = readBe16(payload, 0);
  const subtype = readBe16(payload, 2);
  const marker = String(meta.marker || "").toLowerCase().replace(/[^0-9a-f]/g, "");
  const profileResult = (profile, summary) => {
    facts.unshift({ label: "profile", value: profile, className: "gcloud-tree-fact-header" });
    return { profile, summary, facts };
  };

  if (signature !== 0x200f || subtype === null) {
    add("opaque_block", `${payload.length} bytes · entropy=${gcloudByteEntropy(payload).toFixed(2)} bits/byte · no verified inner format`, "gcloud-tree-fact-warning");
    return profileResult("ACE opaque payload", `opaque ${payload.length}-byte payload`);
  }

  add("signature", `@0x0000 BE16 ${formatHexValue(signature, 4)}`, "gcloud-tree-fact-header");
  add("subtype", `@0x0002 BE16 ${formatHexValue(subtype, 4)}`, "gcloud-tree-fact-header");

  const word4 = readBe32(payload, 4);
  const word8 = readBe32(payload, 8);
  const reportExpectedLen = subtype === 1
    && word4 !== null
    && word8 !== null
    && word4 === word8
    && word4 >= 16
    && word4 <= 4096
    ? 16 + word4
    : null;
  if (reportExpectedLen !== null && payload.length <= reportExpectedLen && reportExpectedLen - payload.length <= 4) {
    const missing = reportExpectedLen - payload.length;
    add("body_length", `@0x0004 BE32 ${word4}; expected payload ${reportExpectedLen} = header 16 + body ${word4}`, "gcloud-tree-fact-length");
    add("length_mirror", `@0x0008 BE32 ${word8} (matches body_length)`, "gcloud-tree-fact-length");
    add("flags", `@0x000c ${gcloudHexSlice(payload, 12, 4)}`, "gcloud-tree-fact-header");
    if (missing > 0) {
      add("available_body", `${Math.max(0, payload.length - 16)}/${word4} bytes · missing ${missing} byte${missing === 1 ? "" : "s"}`, "gcloud-tree-fact-warning");
      add("tail_status", "offset-sensitive tail fields hidden until full frame is present", "gcloud-tree-fact-warning");
      return profileResult("ACE report · truncated frame", "subtype 1 report with mirrored body length; frame truncated");
    }
    add("report_token?", `@0x0070 ${formatHexValue(readBe32(payload, 112), 8)}`, "gcloud-tree-fact-data");
    add("sequence?", `@0x0074 BE32 ${readBe32(payload, 116)} (same slot rises across samples)`, "gcloud-tree-fact-number");
    add("footer_constant", `@0x0078 ${formatHexValue(readBe32(payload, 120), 8)} (stable in this profile)`, "gcloud-tree-fact-data");
    return profileResult("ACE report · 16-byte header + 108-byte body", "subtype 1 report with mirrored body length");
  }

  if (subtype === 1 && payload.length === 124 && word8 === 0xe00000ff && readBe32(payload, 12) === 0x80808080) {
    add("counter", `@0x0004 BE32 ${word4}`, "gcloud-tree-fact-number");
    add("sentinel", `@0x0008 ${formatHexValue(word8, 8)}`, "gcloud-tree-fact-data");
    add("status_mask", "@0x000c 0x80808080 × 4", "gcloud-tree-fact-data");
    add("constant", `@0x0024 ${formatHexValue(readBe32(payload, 36), 8)}`, "gcloud-tree-fact-data");
    return profileResult("ACE status vector", "subtype 1 sentinel/status vector");
  }

  if (subtype === 1 && payload.length === 132 && marker === "b7b5") {
    const words = [];
    for (let offset = 8; offset <= 36; offset += 4) {
      const word = readBe32(payload, offset);
      words.push(`${gcloudOffsetText(offset)}:${word <= 0xffff ? word : formatHexValue(word, 8)}`);
    }
    add("counter", `@0x0004 BE32 ${word4}`, "gcloud-tree-fact-number");
    add("be32_vector", words.join(" · "), "gcloud-tree-fact-data gcloud-tree-fact-raw");
    add("layout_note", "these aligned words are stable across same-marker samples; meanings are not named yet", "gcloud-tree-fact-warning");
    return profileResult("ACE fixed numeric vector", "subtype 1 fixed numeric vector");
  }

  if (subtype === 1 && payload.length === 132 && marker === "b7b4") {
    const opaque = payload.slice(8);
    add("counter", `@0x0004 BE32 ${word4}`, "gcloud-tree-fact-number");
    add("opaque_block", `@0x0008 ${opaque.length} bytes · entropy=${gcloudByteEntropy(opaque).toFixed(2)} bits/byte`, "gcloud-tree-fact-data");
    add("decode_status", "packed/encrypted is possible, but no verified third-layer codec or key yet", "gcloud-tree-fact-warning");
    return profileResult("ACE opaque feature block", "subtype 1 high-entropy feature block");
  }

  if (subtype === 1 && payload.length === 12) {
    add("counter/status", `@0x0004 BE32 ${word4}`, "gcloud-tree-fact-number");
    add("token", `@0x0008 ${formatHexValue(word8, 8)}`, "gcloud-tree-fact-data");
    return profileResult("ACE short status frame", "subtype 1 short counter/status frame");
  }

  if (subtype === 7 && payload.length === 78) {
    add("payload_shape", `@0x0004 ${payload.length - 4} bytes · sparse/tagged layout candidate`, "gcloud-tree-fact-data");
    add("decode_status", "field boundaries need more same-subtype samples before naming", "gcloud-tree-fact-warning");
    return profileResult("ACE subtype 7 sparse vector", "subtype 7 sparse/tagged vector candidate");
  }

  add("payload_shape", `${payload.length} bytes · entropy=${gcloudByteEntropy(payload.slice(4)).toFixed(2)} bits/byte`, "gcloud-tree-fact-data");
  add("decode_status", `known ACE signature; subtype ${subtype} layout not classified`, "gcloud-tree-fact-warning");
  return profileResult(`ACE subtype ${subtype} · unclassified`, `subtype ${subtype} unclassified payload`);
}

function gcloudAnalyzeAceFixed64(byteValues) {
  const payload = Array.isArray(byteValues) ? byteValues : [];
  if (payload.length !== 64 || readBe32(payload, 0) !== 0x80dba23f) return null;
  const facts = [];
  const add = (label, value, className = "") => facts.push({ label, value, className });
  const sampleCounter = payload[9] & 0xff;
  const step3Counter = payload[10] & 0xff;
  const bucket = payload[11] & 0xff;
  const bucket16 = payload[13] & 0xff;

  add("profile", "ACE LightFeature 固定 64B 状态向量", "gcloud-tree-fact-header");
  add("signature", "@0x0000 0x80dba23f · 固定 magic/profile 候选", "gcloud-tree-fact-header");
  add("control", `@0x0004 ${gcloudHexSlice(payload, 4, 4)} · 当前序列固定`, "gcloud-tree-fact-header");
  add(
    "cadence",
    `@0x0009 sample=${sampleCounter} · @0x000a step3=${step3Counter} · @0x000b bucket=${bucket} · @0x000d bucket16=${bucket16}`,
    "gcloud-tree-fact-number",
  );
  add(
    "running_values",
    `@0x0010 BE16 ${readBe16(payload, 16)} · @0x0014 BE16 ${readBe16(payload, 20)} · @0x0016 BE16 ${readBe16(payload, 22)} · @0x0018 ${formatHexValue(readBe16(payload, 24), 4)}`,
    "gcloud-tree-fact-number",
  );
  add("stable_region_a", `@0x001a..0x0024 ${gcloudHexSlice(payload, 26, 11)}`, "gcloud-tree-fact-data gcloud-tree-fact-raw");
  add("pair_cadence", `@0x0025..0x0027 ${gcloudHexSlice(payload, 37, 3)}`, "gcloud-tree-fact-number");
  add("stable_region_b", `@0x0028..0x0037 ${gcloudHexSlice(payload, 40, 16)}`, "gcloud-tree-fact-data gcloud-tree-fact-raw");
  add("rolling_group", `@0x0038..0x003b ${gcloudHexSlice(payload, 56, 4)}`, "gcloud-tree-fact-number");
  add("rolling_token?", `@0x003c ${formatHexValue(readBe32(payload, 60), 8)} · 未证实为校验`, "gcloud-tree-fact-data");
  add(
    "样本矩阵",
    "62 包：固定 41/64 offset；相邻仅变 7-17B / 15-63bit",
    "gcloud-tree-fact-text",
  );
  add(
    "解码结论",
    "按明文状态向量展示；family0/1/2 共 990 个候选无闭合",
    "gcloud-tree-fact-warning",
  );
  add(
    "时序关系",
    "独立 30s 子序列；与 ACE/XOR 0x200f0001/0007 交错；不拼包",
    "gcloud-tree-fact-warning",
  );
  return {
    profile: "ACE LightFeature fixed64 state vector",
    summary: `fixed64 state vector · sample=${sampleCounter} · step3=${step3Counter}`,
    facts,
  };
}

function gcloudAnalyzeHexString(text) {
  const raw = String(text || "").trim();
  if (!gcloudIsHexText(raw, 16)) return null;
  const layer1 = gcloudBytesFromHexText(raw, 8192);
  if (layer1.length <= 0) return null;
  const facts = [
    { label: "source", value: `${raw.length} hex chars -> ${layer1.length} bytes`, className: "gcloud-tree-fact-source" },
  ];

  if (layer1.length >= 6 && (layer1[0] === 0x11 || layer1[0] === 0x12) && layer1[4] === 0x00 && layer1[5] === layer1.length - 6) {
    const key = layer1[1] & 0xff;
    const marker = layer1.slice(2, 4).map(childHexByteText).join("");
    const payload = layer1.slice(6).map((byte) => (byte ^ key) & 0xff);
    const kindText = `ACE XOR · ver=${formatHexValue(layer1[0], 2)} · key=${formatHexValue(key, 2)} · marker=${marker} · payload=${payload.length} bytes`;
    facts.push({ label: "envelope", value: kindText, className: "gcloud-tree-fact-envelope" });
    const inner = gcloudAnalyzeAcePayload(payload, { marker, version: layer1[0], key });
    facts.push(...inner.facts);
    const payloadText = gcloudReadableByteText(payload);
    if (payloadText) facts.push({ label: "payload_text", value: `"${shortenText(payloadText, 220)}"`, className: "gcloud-tree-fact-text gcloud-tree-fact-raw" });
    return {
      kind: "ace-xor",
      summary: `ACE/XOR · ${inner.summary} · ${payload.length} bytes`,
      facts,
      payload,
      profile: inner.profile,
    };
  }

  if (gcloudBytesAreAsciiHex(layer1)) {
    const innerText = gcloudBytesToAscii(layer1);
    const layer2 = gcloudBytesFromHexText(innerText, 8192);
    facts.push({ label: "envelope", value: `${layer1.length} ASCII-hex bytes -> ${layer2.length} payload bytes`, className: "gcloud-tree-fact-envelope" });
    const fixed64 = gcloudAnalyzeAceFixed64(layer2);
    if (fixed64) facts.push(...fixed64.facts);
    const payloadText = gcloudReadableByteText(layer2);
    if (payloadText) facts.push({ label: "payload_text", value: `"${shortenText(payloadText, 220)}"`, className: "gcloud-tree-fact-text gcloud-tree-fact-raw" });
    return {
      kind: "double-hex",
      summary: fixed64 ? `hex -> hex · ${fixed64.summary}` : `hex -> hex · ${layer2.length}-byte binary payload`,
      facts,
      payload: layer2,
      profile: fixed64 ? fixed64.profile : "",
    };
  }

  const epoch = layer1.length === 10 ? readBe32(layer1, 0) : null;
  const epochText = gcloudEpochText(epoch);
  const flags = layer1.length === 10 ? readBe16(layer1, 8) : null;
  if (epochText && flags !== null && (flags & 0xff00) === 0x0100) {
    facts.push({ label: "profile", value: "AntiData timestamp record", className: "gcloud-tree-fact-header" });
    facts.push({ label: "timestamp", value: `@0x0000 BE32 ${epoch} · ${epochText}`, className: "gcloud-tree-fact-time" });
    facts.push({ label: "token", value: `@0x0004 ${formatHexValue(readBe32(layer1, 4), 8)}`, className: "gcloud-tree-fact-data" });
    facts.push({ label: "flags", value: `@0x0008 ${formatHexValue(flags, 4)}`, className: "gcloud-tree-fact-number" });
    return {
      kind: "hex-bytes",
      summary: `timestamp ${epochText} · token · flags ${formatHexValue(flags, 4)}`,
      facts,
      payload: layer1,
    };
  }

  if (layer1.length >= 6) {
    const total = readBe16(layer1, 4);
    if (readBe32(layer1, 0) === 1 && total === layer1.length) {
      facts.push({
        label: "record_head",
        value: `v=${readBe32(layer1, 0)} total=${total} selector=${formatHexValue(readBe16(layer1, 6), 4)} sublen=${readBe16(layer1, 8) ?? "-"}`,
        className: "gcloud-tree-fact-header",
      });
    }
  }
  const utf8 = gcloudBytesToUtf8(layer1);
  if (utf8 && isGcloudVisibleString(utf8)) facts.push({ label: "decoded_text", value: `"${shortenText(utf8, 220)}"`, className: "gcloud-tree-fact-text gcloud-tree-fact-raw" });
  return {
    kind: "hex-bytes",
    summary: `hex string -> ${layer1.length} bytes`,
    facts,
    payload: layer1,
  };
}

function gcloudBase64DecodedLength(normalized) {
  const raw = String(normalized || "").replace(/\s+/g, "");
  if (!raw) return 0;
  const padded = raw.length + ((4 - (raw.length % 4)) % 4);
  const pad = raw.endsWith("==") ? 2 : (raw.endsWith("=") ? 1 : 0);
  return Math.max(0, Math.floor((padded * 3) / 4) - pad);
}

function gcloudBytesToBinaryString(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte & 0xff);
  return out;
}

function gcloudBase64RoundTripOk(normalized, decodedBytes) {
  if (typeof btoa !== "function") return true;
  try {
    const encoded = btoa(gcloudBytesToBinaryString(decodedBytes)).replace(/=+$/g, "");
    const source = String(normalized || "").replace(/=+$/g, "");
    return encoded === source;
  } catch (_e) {
    return false;
  }
}

function gcloudDecodedByteProfile(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  if (bytes.length <= 0) return "";
  const utf8 = normalizeVisibleText(decodeUtf8Strict(bytes));
  if (/^[\[{]/.test(utf8)) return "JSON/text";
  if (/^<\?xml|^<plist/i.test(utf8)) return "XML/plist";
  if (utf8 && isGcloudVisibleString(utf8) && looksMeaningfulText(utf8, 3, false)) return "text";
  if (bytes.length >= 4) {
    const head4 = gcloudHexSlice(bytes, 0, 4).replace(/\s+/g, "");
    if (head4 === "1f8b0800" || head4.startsWith("1f8b08")) return "gzip";
    if (head4 === "04224d18") return "LZ4 frame";
    if (head4 === "504b0304") return "ZIP";
    if (head4 === "89504e47") return "PNG";
    if (head4 === "25504446") return "PDF";
    if (head4 === "cafebabe" || head4 === "feedface" || head4 === "feedfacf" || head4 === "cefaedfe" || head4 === "cffaedfe") return "Mach-O";
    if (readBe32(bytes, 0) === 1 && readBe16(bytes, 4) !== null && readBe16(bytes, 4) <= bytes.length) return "binary record";
  }
  if (bytes.length >= 2 && bytes[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(bytes[1] & 0xff)) return "zlib";
  if (gcloudReadableByteText(bytes)) return "mixed text/binary";
  const parsed = parseGcloudProtoNodes(bytes, 0, bytes.length, 0, 20);
  if (parsed && parsed.ok && Array.isArray(parsed.nodes) && parsed.nodes.length > 0) return "protobuf?";
  const entropy = gcloudByteEntropy(bytes);
  if (entropy >= 7.2) return "high-entropy binary";
  return "binary";
}

function gcloudRememberBase64Analysis(key, value) {
  const cacheKey = String(key || "");
  if (!cacheKey) return value;
  if (GCLOUD_BASE64_ANALYSIS_CACHE.size >= GCLOUD_BASE64_ANALYSIS_CACHE_MAX) {
    const firstKey = GCLOUD_BASE64_ANALYSIS_CACHE.keys().next().value;
    if (firstKey) GCLOUD_BASE64_ANALYSIS_CACHE.delete(firstKey);
  }
  GCLOUD_BASE64_ANALYSIS_CACHE.set(cacheKey, value);
  return value;
}

function gcloudAnalyzeBase64String(text) {
  const compact = String(text || "").replace(/\s+/g, "");
  if (compact.length < 24 || compact.length > 16384) return null;
  if (GCLOUD_BASE64_ANALYSIS_CACHE.has(compact)) return GCLOUD_BASE64_ANALYSIS_CACHE.get(compact);
  if (gcloudIsHexText(compact, 16)) return null;
  const variety = [/[A-Z]/, /[a-z]/, /\d/, /[+/=_-]/].filter((re) => re.test(compact)).length;
  if (variety < 3) return null;
  const normalized = normalizeBase64Candidate(compact);
  if (!normalized) return gcloudRememberBase64Analysis(compact, null);
  const decodedLength = gcloudBase64DecodedLength(normalized);
  if (decodedLength < 12) return gcloudRememberBase64Analysis(compact, null);
  const decoded = b64ToBytes(normalized);
  if (!Array.isArray(decoded) || decoded.length < 12) return gcloudRememberBase64Analysis(compact, null);
  if (!gcloudBase64RoundTripOk(normalized, decoded)) return gcloudRememberBase64Analysis(compact, null);

  const profile = gcloudDecodedByteProfile(decoded);
  const facts = [
    { label: "source", value: `${compact.length} base64 chars -> ${decoded.length} bytes`, className: "gcloud-tree-fact-source" },
    { label: "profile", value: profile, className: "gcloud-tree-fact-header" },
    { label: "entropy", value: `${gcloudByteEntropy(decoded).toFixed(2)} bits/byte`, className: "gcloud-tree-fact-number" },
  ];

  const decodedText = describeDecodedBytes(decoded);
  if (decodedText && decodedText.text) {
    const textLabel = /^(?:JSON\/text|XML\/plist|text)$/.test(profile) ? "decoded_text" : "strings";
    facts.push({
      label: textLabel,
      value: `"${shortenText(decodedText.text, 180)}"`,
      className: "gcloud-tree-fact-text gcloud-tree-fact-raw",
    });
  }

  return gcloudRememberBase64Analysis(compact, {
    kind: "base64",
    summary: `base64 -> ${decoded.length}-byte ${profile}`,
    facts,
    payload: decoded,
    profile,
  });
}

function gcloudNodeInspectFacts(node, bytes, meaning = "", pathText = "") {
  if (!node) return [];
  const facts = [];
  const add = (label, value, className = "") => {
    const text = String(value ?? "").trim();
    if (!text) return;
    facts.push({ label, value: text, className });
  };
  const valueBytes = gcloudNodeValueBytes(node, bytes);
  if (node.binaryCarrier) {
    add("carrier", `${node.binaryCarrier} · ${valueBytes.length}B · protobuf recursion stopped`, "gcloud-tree-fact-source");
    return facts;
  }
  if (Number(node.wire) === 0 && node.value !== undefined) {
    const epoch = gcloudEpochScalarInfo(node.valueText || node.value);
    if (epoch) add("time?", `${epoch.text} (${epoch.unit})`, "gcloud-tree-fact-time");
  }
  const decodedHexChildren = gcloudNodeDecodedHexChildren(node);
  if (Number(node.wire) === 2 && decodedHexChildren.length > 0) {
    add("layer", `outer protobuf container; decoded hex shown in ${decodedHexChildren.length} child row${decodedHexChildren.length === 1 ? "" : "s"}`, "gcloud-tree-fact-source");
    return facts;
  }
  if (valueBytes.length > 0) {
    const utf8 = gcloudBytesToUtf8(valueBytes);
    if (utf8 && isGcloudVisibleString(utf8) && !node.string) add("utf8", `"${shortenText(utf8, 240)}"`, "gcloud-tree-fact-raw");
    const ascii = gcloudReadableByteText(valueBytes);
    if (ascii && ascii !== utf8 && !node.string) add("ascii", `"${shortenText(ascii, 240)}"`, "gcloud-tree-fact-raw");
    if (node.string) {
      const hexInfo = gcloudAnalyzeHexString(node.string);
      if (hexInfo && Array.isArray(hexInfo.facts)) {
        for (const fact of hexInfo.facts) {
          add(fact.label, fact.value, fact.className || "");
        }
      } else {
        const base64Info = gcloudAnalyzeBase64String(node.string);
        if (base64Info && Array.isArray(base64Info.facts)) {
          for (const fact of base64Info.facts) {
            add(fact.label, fact.value, fact.className || "");
          }
        }
      }
    }
  }
  return facts;
}

function gcloudProtoTreeValueText(node) {
  if (!node) return "";
  if (node.truncated) return `len=${Number(node.len || 0)} available=${Number(node.available || 0)}`;
  if (node.binaryCarrier) return `${node.binaryCarrier} · len=${Number(node.len || 0)}`;
  if (node.string) {
    const hexInfo = gcloudAnalyzeHexString(node.string);
    if (hexInfo) return hexInfo.summary;
    const base64Info = gcloudAnalyzeBase64String(node.string);
    if (base64Info) return base64Info.summary;
    return `"${node.string}"`;
  }
  if (Number(node.wire) === 0 && node.value !== undefined) {
    const valueText = String(node.valueText || node.value);
    const hexText = String(node.valueHexText || formatHexValue(node.value));
    return `${valueText} (${hexText})`;
  }
  if (Number(node.wire) === 2) {
    const childCount = Array.isArray(node.children) ? node.children.length : 0;
    const childStatus = node.childOk === false && node.childReason ? `; ${node.childReason}` : "";
    return childCount > 0 ? `len=${Number(node.len || 0)} children=${childCount}${childStatus}` : `len=${Number(node.len || 0)}`;
  }
  if (node.valueHex) return node.valueHex;
  return "";
}

function appendGcloudTreeValue(valueEl, node, bytes, meaning = "", pathText = "") {
  const primary = document.createElement("div");
  primary.className = "gcloud-tree-primary";
  const valueText = gcloudProtoTreeValueText(node);
  primary.textContent = valueText || "{...}";
  valueEl.appendChild(primary);
  if (!valueText) valueEl.classList.add("gcloud-tree-value-empty");

  const facts = gcloudNodeInspectFacts(node, bytes, meaning, pathText);
  if (facts.length > 0) {
    const factWrap = document.createElement("div");
    factWrap.className = "gcloud-tree-facts";
    for (const fact of facts) {
      const chip = document.createElement("span");
      chip.className = `gcloud-tree-fact${fact.className ? ` ${fact.className}` : ""}`;
      const label = document.createElement("span");
      label.className = "gcloud-tree-fact-label";
      label.textContent = fact.label;
      const value = document.createElement("span");
      value.className = "gcloud-tree-fact-value";
      value.textContent = fact.value;
      chip.appendChild(label);
      chip.appendChild(value);
      factWrap.appendChild(chip);
    }
    valueEl.appendChild(factWrap);
  }
}

function gcloudTreeRowTone(node, alias = "") {
  const meaning = String(alias || "").toLowerCase();
  if (node && node.binaryCarrier) return "gcloud-tree-tone-binary";
  if (node && node.string) {
    if (gcloudAnalyzeHexString(node.string)) return "gcloud-tree-tone-binary";
    if (gcloudAnalyzeBase64String(node.string)) return "gcloud-tree-tone-binary";
    return "gcloud-tree-tone-text";
  }
  if (/^(header|cmd_id|command|module|language)/.test(meaning)) return "gcloud-tree-tone-meta";
  if (/^(body|message|items|item|sender|device_profile|account_context)/.test(meaning)) return "gcloud-tree-tone-structure";
  if (node && [0, 1, 5].includes(Number(node.wire))) return "gcloud-tree-tone-number";
  if (node && Number(node.wire) === 2 && Array.isArray(node.children) && node.children.length > 0) return "gcloud-tree-tone-structure";
  return "gcloud-tree-tone-data";
}

function appendGcloudRawLayer(rawEl, className, text) {
  const line = document.createElement("div");
  line.className = className;
  line.textContent = text;
  rawEl.appendChild(line);
}

function appendGcloudTreeRaw(rawEl, node, bytes) {
  const decodedHexChildren = gcloudNodeDecodedHexChildren(node);
  if (Number(node && node.wire) === 2 && decodedHexChildren.length > 0) {
    const childCount = Array.isArray(node.children) ? node.children.length : 0;
    rawEl.textContent = `outer proto · ${Number(node.len || 0)}B -> decoded child`;
    rawEl.title = `Parent value contains ${childCount} protobuf child row${childCount === 1 ? "" : "s"}; decoded payload bytes are shown on the child row.`;
    rawEl.classList.add("gcloud-tree-raw-container");
    return;
  }
  if (node && node.binaryCarrier) {
    const valueBytes = gcloudNodeValueBytes(node, bytes);
    rawEl.textContent = `${node.binaryCarrier} · ${valueBytes.length}B · ${gcloudHexBytes(valueBytes, 64)}`;
    rawEl.title = `${node.binaryCarrier}; opaque payload is intentionally not decoded as protobuf`;
    rawEl.classList.add("gcloud-tree-raw-container");
    return;
  }
  if (node && node.string) {
    const valueBytes = gcloudNodeValueBytes(node, bytes);
    const hexInfo = gcloudAnalyzeHexString(node.string);
    if (hexInfo && Array.isArray(hexInfo.payload) && hexInfo.payload.length > 0) {
      const deepRoot = detectTssReport(hexInfo.payload);
      const hasAceDeepView = hexInfo.kind === "ace-xor"
        || Boolean(hexInfo.profile)
        || (deepRoot && isLikelyTssReportCode(deepRoot.value));
      const decodedPreviewLen = Math.min(160, hexInfo.payload.length);
      rawEl.classList.add("gcloud-tree-raw-layered");
      appendGcloudRawLayer(rawEl, "gcloud-tree-raw-source", `raw string ${valueBytes.length}B: ${gcloudHexBytes(valueBytes, 96)}`);
      appendGcloudRawLayer(
        rawEl,
        "gcloud-tree-raw-decoded",
        `decoded preview ${decodedPreviewLen}/${hexInfo.payload.length}B: ${gcloudHexBytes(hexInfo.payload, decodedPreviewLen)}${hasAceDeepView ? " · 完整字节见下方 ACE carrier 二次深度解析" : ""}`,
      );
      rawEl.title = `raw string bytes (${valueBytes.length}); decoded payload bytes (${hexInfo.payload.length})`;
      return;
    }
    const base64Info = gcloudAnalyzeBase64String(node.string);
    if (base64Info && Array.isArray(base64Info.payload) && base64Info.payload.length > 0) {
      rawEl.classList.add("gcloud-tree-raw-layered");
      appendGcloudRawLayer(rawEl, "gcloud-tree-raw-source", `raw string ${valueBytes.length}B: ${gcloudHexBytes(valueBytes, 96)}`);
      appendGcloudRawLayer(rawEl, "gcloud-tree-raw-decoded", `base64 decoded ${base64Info.payload.length}B: ${gcloudHexBytes(base64Info.payload, 160)}`);
      rawEl.title = `raw base64 string bytes (${valueBytes.length}); base64 decoded payload bytes (${base64Info.payload.length})`;
      return;
    }
  }
  const valueBytes = gcloudNodeValueBytes(node, bytes);
  rawEl.textContent = valueBytes.length > 0 ? gcloudHexBytes(valueBytes, 192) : "-";
  rawEl.title = valueBytes.length > 0 ? `raw value bytes (${valueBytes.length})` : "no raw value bytes";
  if (valueBytes.length <= 0) rawEl.classList.add("gcloud-tree-raw-empty");
}

function appendGcloudProtoTreeRows(container, nodes, proto, bytes, path = [], depth = 0, topIndex = -1, budget = null) {
  const list = Array.isArray(nodes) ? nodes : [];
  const countByField = new Map();
  const seenByField = new Map();
  for (const node of list) {
    const field = Number(node && node.field);
    if (!Number.isFinite(field)) continue;
    countByField.set(field, Number(countByField.get(field) || 0) + 1);
  }
  const state = budget || { count: 0, max: 90, truncated: false };
  list.forEach((node, index) => {
    if (!node || state.count >= state.max) {
      state.truncated = true;
      return;
    }
    state.count += 1;
    const nextTopIndex = path.length === 0 ? index : topIndex;
    const nextPath = path.concat(Number(node.field));
    const repeated = Number(countByField.get(Number(node.field)) || 0) > 1;
    const occurrence = Number(seenByField.get(Number(node.field)) || 0);
    seenByField.set(Number(node.field), occurrence + 1);
    const alias = gcloudProtoFieldAlias(nextPath, node, proto);
    const rawPathText = gcloudRawPathText(nextPath, nextTopIndex);
    const pathText = gcloudSemanticPathText(nextPath, proto, nextTopIndex, node);
    let keyText = alias || (repeated ? `item[${occurrence}]` : `value ${index + 1}`);
    if (alias && repeated) {
      keyText = alias.endsWith("[]")
        ? `${alias.slice(0, -2)}[${occurrence}]`
        : `${alias}[${occurrence}]`;
    }

    const row = document.createElement("div");
    row.className = `gcloud-tree-row ${gcloudTreeRowTone(node, alias)}`;
    row.style.setProperty("--depth", String(Math.min(depth, 8)));
    row.title = `${pathText} · ${rawPathText}`;

    const key = document.createElement("div");
    key.className = "gcloud-tree-key";
    key.textContent = keyText;

    const type = document.createElement("div");
    type.className = "gcloud-tree-type";
    type.textContent = gcloudProtoTypeText(node);

    const value = document.createElement("div");
    value.className = "gcloud-tree-value";
    appendGcloudTreeValue(value, node, bytes, alias || "", pathText);

    const raw = document.createElement("div");
    raw.className = "gcloud-tree-raw";
    appendGcloudTreeRaw(raw, node, bytes);

    row.appendChild(key);
    row.appendChild(type);
    row.appendChild(value);
    row.appendChild(raw);
    container.appendChild(row);

    if (Array.isArray(node.children) && node.children.length > 0) {
      appendGcloudProtoTreeRows(container, node.children, proto, bytes, nextPath, depth + 1, nextTopIndex, state);
    }
  });
  return state;
}

function buildGcloudProtoTree(proto, bytes = []) {
  if (!proto || !Array.isArray(proto.nodes) || proto.nodes.length <= 0) return null;
  const tree = document.createElement("div");
  tree.className = "gcloud-proto-tree";
  const state = appendGcloudProtoTreeRows(tree, proto.nodes, proto, bytes);
  if (state && state.truncated) {
    const row = document.createElement("div");
    row.className = "gcloud-tree-row";
    row.style.setProperty("--depth", "0");
    const key = document.createElement("div");
    key.className = "gcloud-tree-key";
    key.textContent = "more";
    const type = document.createElement("div");
    type.className = "gcloud-tree-type";
    type.textContent = "truncated";
    const value = document.createElement("div");
    value.className = "gcloud-tree-value gcloud-tree-value-empty";
    value.textContent = `tree display capped at ${state.max} nodes`;
    const raw = document.createElement("div");
    raw.className = "gcloud-tree-raw gcloud-tree-raw-empty";
    raw.textContent = "-";
    row.appendChild(key);
    row.appendChild(type);
    row.appendChild(value);
    row.appendChild(raw);
    tree.appendChild(row);
  }
  return tree;
}

function gcloudProtoNodeRows(proto, maxRows = 18) {
  if (!proto || !Array.isArray(proto.flat)) return [];
  const rows = [];
  const seen = new Set();
  const add = (item) => {
    if (!item || !item.node) return;
    const key = gcloudPathKey(item.path);
    if (seen.has(key)) return;
    seen.add(key);
    rows.push({
      path: gcloudSemanticPathText(item.path, proto, item.topIndex, item.node),
      rawPath: gcloudRawPathText(item.path, item.topIndex),
      value: gcloudNodeValueText(item.node),
    });
  };
  for (const item of proto.flat) {
    if (rows.length >= maxRows) break;
    if (item.path.length <= 2 || item.node.string || item.node.truncated) add(item);
  }
  return rows;
}

function gcloudCollectProtoStrings(proto, maxItems = 160) {
  const out = [];
  const walk = (nodes, path = [], topIndex = -1) => {
    if (!Array.isArray(nodes) || out.length >= maxItems) return;
    nodes.forEach((node, index) => {
      if (!node || out.length >= maxItems) return;
      const nextTopIndex = path.length === 0 ? index : topIndex;
      const nextPath = path.concat(Number(node.field));
      if (node.string) {
        const alias = gcloudProtoFieldAlias(nextPath, node, proto);
        out.push({
          text: String(node.string || ""),
          alias,
          path: nextPath,
          topIndex: nextTopIndex,
        });
      }
      if (Array.isArray(node.children) && node.children.length > 0) {
        walk(node.children, nextPath, nextTopIndex);
      }
    });
  };
  walk(proto && proto.nodes ? proto.nodes : []);
  return out;
}

function gcloudProducerPacket(ev) {
  const analysis = ev && ev.analysis && typeof ev.analysis === "object" ? ev.analysis : null;
  return analysis && analysis.packet && typeof analysis.packet === "object"
    ? analysis.packet
    : {};
}

function gcloudReadableStringsForEvent(ev, proto = null, maxItems = 24) {
  const out = [];
  const seen = new Set();
  const add = (value, path = "") => {
    const text = String(value ?? "").trim();
    if (!text || text.length < 2) return;
    if (/^(?:CS|UAGame)[A-Za-z0-9_]{4,}$/.test(text)) return;
    if (/^[a-z]{2}(?:[-_][A-Za-z]{2,8})+$/.test(text)) return;
    if (/^[0-9a-f]{64,}$/i.test(text) || /^[A-Za-z0-9+/]{96,}={0,2}$/.test(text)) return;
    const visible = /[\u3400-\u9fff]/u.test(text)
      || /^https?:\/\//i.test(text)
      || /[\s:/{\[]/.test(text)
      || (text.length >= 4 && isGcloudVisibleString(text));
    if (!visible) return;
    const key = text.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ text: shortenText(text, 320), path: String(path || "") });
  };

  const packet = gcloudProducerPacket(ev);
  const textSummary = packet.text_summary && typeof packet.text_summary === "object"
    ? packet.text_summary
    : {};
  for (const item of Array.isArray(textSummary.previews) ? textSummary.previews : []) {
    add(item && item.value, item && item.path);
  }
  for (const field of Array.isArray(packet.fields) ? packet.fields : []) {
    if (!field || field.value_type !== "string") continue;
    add(field.value, field.path);
  }
  for (const item of gcloudCollectProtoStrings(proto, Math.max(maxItems * 3, 96))) {
    add(item && item.text, item && item.path ? gcloudRawPathText(item.path, item.topIndex) : "");
  }
  out.sort((left, right) => {
    const leftCjk = /[\u3400-\u9fff]/u.test(left.text) ? 1 : 0;
    const rightCjk = /[\u3400-\u9fff]/u.test(right.text) ? 1 : 0;
    return rightCjk - leftCjk;
  });
  return out.slice(0, Math.max(1, Number(maxItems || 48)));
}

function gcloudPayloadChangeSummary(ev, summaryText = "") {
  const before = String(ev && ev.before_pay ? ev.before_pay : "");
  const current = String(ev && ev.pay ? ev.pay : "");
  const receivedWire = String(ev && ev.full_pay ? ev.full_pay : "");
  const forwardedWire = String(ev && ev.raw_pay ? ev.raw_pay : "");
  const summary = String(summaryText || (ev && ev.summary) || "");
  const declaredModified = /\bpayload_modified=1\b|\bwire_header_modified=1\b|\bwire_changed=1\b/i.test(summary)
    || gcloudSummaryHasBackendRebuild(summary);
  if (gcloudSummaryHasSentWireChange(summary) && receivedWire && forwardedWire) {
    const beforeWire = b64ToBytes(receivedWire);
    const afterWire = b64ToBytes(forwardedWire);
    const wireDiff = countChangedBytes(beforeWire, afterWire);
    return `修改前 wire ${beforeWire.length}B → 修改后 wire ${afterWire.length}B · 变化 ${wireDiff.changed}/${wireDiff.commonLen}${wireDiff.lenDelta ? ` · lenΔ=${wireDiff.lenDelta}` : ""}`;
  }
  const currentLen = current ? b64ToBytes(current).length : Number(ev && ev.len || 0);
  if (!before) {
    const currentStage = /\bcrypto=decrypted\b/i.test(summary) ? "当前解密 Payload" : "当前 Payload";
    return `${declaredModified ? "已修改" : "未修改"} · ${currentStage} ${currentLen}B`;
  }
  const beforeBytes = b64ToBytes(before);
  const currentBytes = current ? b64ToBytes(current) : [];
  const diff = countChangedBytes(beforeBytes, currentBytes);
  if (Number(diff.changed || 0) <= 0 && Number(diff.lenDelta || 0) === 0) {
    return `修改前 ${beforeBytes.length}B = 修改后 ${currentBytes.length}B · 内容相同`;
  }
  return `修改前 ${beforeBytes.length}B → 修改后 ${currentBytes.length}B · 变化 ${diff.changed}/${diff.commonLen}${diff.lenDelta ? ` · lenΔ=${diff.lenDelta}` : ""}`;
}

function eventPayloadDiff(leftText, rightText) {
  const left = String(leftText || "");
  const right = String(rightText || "");
  if (!left || !right || left === right) return null;
  const leftBytes = b64ToBytes(left);
  const rightBytes = b64ToBytes(right);
  if (leftBytes.length <= 0 && rightBytes.length <= 0) return null;
  const diff = countChangedBytes(leftBytes, rightBytes);
  if (Number(diff.changed || 0) <= 0 && Number(diff.lenDelta || 0) === 0) return null;
  const offsets = [];
  const commonLen = Math.min(leftBytes.length, rightBytes.length);
  for (let offset = 0; offset < commonLen && offsets.length < 12; offset += 1) {
    if (leftBytes[offset] === rightBytes[offset]) continue;
    offsets.push({
      offset,
      before: childHexByteText(leftBytes[offset]),
      after: childHexByteText(rightBytes[offset]),
    });
  }
  return { ...diff, offsets };
}

function eventModificationDiffText(ev) {
  const plaintext = eventPayloadDiff(ev && ev.before_pay, ev && ev.pay);
  const wire = eventPayloadDiff(ev && ev.full_pay, ev && ev.raw_pay);
  const selected = plaintext || wire;
  if (!selected) return { short: "", detail: "" };
  const stage = plaintext ? "明文" : "Wire";
  const delta = Number(selected.lenDelta || 0);
  const changed = Number(selected.changed || 0);
  const offsetText = (selected.offsets || []).map((item) => (
    `+${formatHexValue(item.offset)} ${item.before}->${item.after}`
  )).join("，");
  return {
    short: `${stage}${changed}B${delta ? `/lenΔ${delta > 0 ? "+" : ""}${delta}` : ""}`,
    detail: `${stage} before -> after：变化 ${changed}/${Number(selected.commonLen || 0)}`
      + (delta ? `，lenΔ=${delta > 0 ? "+" : ""}${delta}` : "")
      + (offsetText ? `；${offsetText}` : ""),
  };
}

function eventModificationEvidence(ev, summaryText = "") {
  const summary = String(summaryText || (ev && ev.summary) || "");
  const reasons = [];
  const addReason = (reason) => {
    const text = String(reason || "").trim();
    if (text && !reasons.includes(text)) reasons.push(text);
  };

  const backendEvidenceLabels = {
    analysis: "生产端 mutation.modified",
    payload_diff: "后端 Payload 前后不同",
    summary: "后端修改摘要",
  };
  if (ev && ev.modified === true) {
    const sources = Array.isArray(ev.modification_evidence) ? ev.modification_evidence : [];
    for (const source of sources) {
      const label = backendEvidenceLabels[String(source || "")];
      if (label) addReason(label);
    }
  }

  const summarySignals = [
    [/\[修改后:[^\]]+\]/, "Tersafe 修改标签"],
    [/\bpayload_modified=1\b/i, "Payload 已修改"],
    [/\bwire_rebuilt=1\b/i, "Wire 已重建"],
    [/\bwire_header_modified=1\b/i, "Wire 头已修改"],
    [/\bwire_changed=1\b/i, "发送 Wire 已变化"],
    [/\bbackend_rewrite_verified=1\b/i, "后端重建已验证"],
    [/\btcpview_focus=modified\b/i, "修改事件焦点"],
  ];
  for (const [pattern, reason] of summarySignals) {
    if (pattern.test(summary)) addReason(reason);
  }

  const plaintextDiff = eventPayloadDiff(ev && ev.before_pay, ev && ev.pay);
  if (plaintextDiff) {
    addReason("before_pay 与当前 Payload 不同");
  }
  const authoritativeModified = reasons.length > 0;
  if (authoritativeModified && eventPayloadDiff(ev && ev.full_pay, ev && ev.raw_pay)) {
    addReason("接收 Wire 与实际发送 Wire 不同");
  }

  if (reasons.length > 0) {
    return {
      state: "modified",
      modified: true,
      reasons,
      diff: eventModificationDiffText(ev),
    };
  }

  const analysis = ev && ev.analysis && typeof ev.analysis === "object" ? ev.analysis : null;
  const mutation = analysis && analysis.mutation && typeof analysis.mutation === "object"
    ? analysis.mutation
    : null;
  const transport = analysis && analysis.transport && typeof analysis.transport === "object"
    ? analysis.transport
    : null;
  const producerSaysUnchanged = Boolean(
    (mutation && mutation.modified === false)
    || (transport && transport.payload_modified === false)
  );
  if (producerSaysUnchanged && Number(ev && ev.dir) === 0) {
    return {
      state: "unchanged",
      modified: false,
      reasons: ["生产端 mutation.modified=false，未见 before/after 业务差异"],
      diff: { short: "", detail: "" },
    };
  }
  return null;
}

function syncEventModificationIndicator(wrap, summaryNode, ev, summaryText = "") {
  if (!wrap || !summaryNode || typeof summaryNode.querySelector !== "function") return;
  const evidence = eventModificationEvidence(ev, summaryText);
  let badge = summaryNode.querySelector(".summary-modification-badge");

  if (!evidence) {
    wrap.classList.remove("event-modified");
    wrap.classList.remove("event-unchanged");
    delete wrap.dataset.modified;
    delete wrap.dataset.modificationEvidence;
    if (badge) badge.remove();
    return;
  }

  const isModified = evidence.state === "modified";
  wrap.classList.toggle("event-modified", isModified);
  wrap.classList.toggle("event-unchanged", !isModified);
  wrap.dataset.modified = isModified ? "1" : "0";
  wrap.dataset.modificationEvidence = evidence.reasons.join(" | ");
  if (!badge) {
    badge = document.createElement("span");
    badge.className = "summary-modification-badge";
    const preview = summaryNode.querySelector(".summary-preview");
    if (preview) {
      summaryNode.insertBefore(badge, preview);
    } else {
      summaryNode.appendChild(badge);
    }
  }
  badge.className = `summary-modification-badge summary-modification-${evidence.state}`;
  badge.textContent = isModified
    ? `已修改${evidence.diff && evidence.diff.short ? ` · ${evidence.diff.short}` : ""}`
    : "未修改";
  const frame = `seq=${ev && ev.seq !== undefined ? ev.seq : "-"} m${ev && ev.msg_idx >= 0 ? ev.msg_idx : "-"}/c${ev && ev.chunk_idx >= 0 ? ev.chunk_idx : "-"}`;
  badge.title = `${isModified ? "该时间帧有真实修改证据" : "生产端明确未修改"} · ${frame}`
    + (evidence.diff && evidence.diff.detail ? ` · ${evidence.diff.detail}` : "")
    + ` · ${evidence.reasons.join(" · ")}`;
  badge.setAttribute("aria-label", badge.title);
}

function gcloudProtocolDisplayRows(info, ev, summaryText = "", readableStrings = []) {
  const sourceRows = Array.isArray(info && info.rows) ? info.rows : [];
  const meta = info && info.meta && typeof info.meta === "object" ? info.meta : {};
  const command = parseFlexibleInt(meta.command);
  const decrypted4013 = command === 0x4013 && String(meta.crypto || "").toLowerCase() === "decrypted";
  const direction = normalizeGcloudDirection(ev, meta) || meta.direction || "-";
  if (!decrypted4013) {
    const frame = info && info.frame ? info.frame : null;
    const commandText = command === 0x9001 ? "0x9001" : (meta.commandText || (Number.isFinite(command) ? formatHexValue(command, 4) : "?"));
    const payloadLength = frame && Number.isFinite(Number(frame.payloadLen))
      ? Number(frame.payloadLen)
      : Number(ev && ev.len || 0);
    return [{
      label: "Layout",
      value: command === 0x9001
        ? "TGCP 0x9001 header-only → echo / keepalive"
        : `TGCP ${commandText} → ${meta.crypto || "raw"} frame`,
    }, {
      label: "字段",
      value: [
        `command=${commandText}`,
        `direction=${direction}`,
        frame && Number.isFinite(Number(frame.headerLen)) ? `header=${Number(frame.headerLen)}B` : "",
        `payload=${payloadLength}B`,
      ].filter(Boolean).join(" · "),
    }, {
      label: "Payload",
      value: command === 0x9001 ? "0B · header-only" : `${payloadLength}B raw/encrypted`,
    }, {
      label: "修改",
      value: command === 0x9001 ? "未修改 · Payload 0B" : gcloudPayloadChangeSummary(ev, summaryText),
    }];
  }

  const proto = info && info.proto ? info.proto : null;
  const protoBytes = info && Array.isArray(info.protoBytes) ? info.protoBytes : [];
  const fieldCount = proto && Array.isArray(proto.flat) ? proto.flat.length : 0;
  const packet = gcloudProducerPacket(ev);
  const shape = packet.shape && typeof packet.shape === "object" ? packet.shape : {};
  const carrier = String(shape.application_carrier || "");
  const compression = info && info.proto && info.proto.compression ? info.proto.compression : null;
  const compressed = carrier === "lz4_raw" || !!compression;
  const rows = [];

  if (isUagameGcloudMeta(meta)) {
    const opcode = gcloudUagameOpcodeInfo(meta);
    const bodyKind = proto && proto.ok ? "Protobuf body" : "binary body";
    rows.push({
      label: "Layout",
      value: `TGCP 0x4013 → AES 明文${compressed ? " → raw-LZ4" : ""} → UAGame 40B header → ${bodyKind}`,
    });
    rows.push({
      label: "字段",
      value: [
        opcode ? `opcode=${opcode.opcodeText}` : "opcode=?",
        opcode && opcode.name ? `type=${opcode.name}` : "",
        `direction=${direction}`,
        `body=${protoBytes.length || Number(ev && ev.len || 0)}B`,
        fieldCount > 0 ? `fields=${fieldCount}` : "",
      ].filter(Boolean).join(" · "),
    });
  } else {
    const bodyKind = proto && proto.ok
      ? "Protobuf envelope { header=f1, body=f2 }"
      : "Protobuf fragment";
    const protoCommandName = proto && (proto.commandName || proto.commandDisplay)
      ? String(proto.commandName || proto.commandDisplay)
      : "";
    rows.push({
      label: "Layout",
      value: `TGCP 0x4013 → AES 明文${compressed ? " → LZ4" : ""} → ${bodyKind}`,
    });
    rows.push({
      label: "字段",
      value: [
        proto && proto.commandId !== null && proto.commandId !== undefined ? `cmd_id=${proto.commandId}` : "",
        protoCommandName ? `command=${gcloudCommandDisplay(protoCommandName)}` : "",
        proto && proto.module ? `module=${proto.module}` : "",
        proto && proto.language ? `language=${proto.language}` : "",
        fieldCount > 0 ? `fields=${fieldCount}` : "",
      ].filter(Boolean).join(" · ") || `direction=${direction}`,
    });
  }

  rows.push({
    label: "Payload",
    value: `解密后 ${protoBytes.length || Number(ev && ev.len || 0)}B${readableStrings.length > 0 ? ` · strings=${readableStrings.length}` : ""}`,
  });
  rows.push({ label: "修改", value: gcloudPayloadChangeSummary(ev, summaryText) });
  if (compressed) {
    const inputLength = Number(shape.application_carrier_len || (compression && compression.inputLength) || 0);
    const outputLength = Number(shape.application_envelope_len || (compression && compression.outputLength) || 0);
    rows.push({
      label: "压缩",
      value: `raw-LZ4${inputLength > 0 && outputLength > 0 ? ` ${inputLength}B → ${outputLength}B` : " 已解压"}`,
    });
  }

  const keepLabels = new Map([
    ["人话结论", "内容"],
    ["ID 样例", "ID 样例"],
    ["ID 分组", "ID 分组"],
    ["Protobuf", "Protobuf"],
    ["01 0a 00 xx 扫描", "ReportCode 扫描"],
    ["TerSafe record", "TerSafe record"],
    ["Marker 独立扫描", "Marker 独立扫描"],
    ["ID值中的 reportCode", "ID值中的 reportCode"],
    ["业务语义", "业务语义"],
    ["反作弊角色", "业务语义"],
    ["TSS 角色", "业务语义"],
    ["字段结构", "字段结构"],
    ["服务器提示", "服务器提示"],
    ["处罚状态", "处罚状态"],
    ["踢下线代码", "踢下线代码"],
    ["可读特征", "可读特征"],
    ["设备画像", "设备画像"],
    ["网络/资源", "网络/资源"],
    ["时间字段", "时间字段"],
  ]);
  for (const row of sourceRows) {
    const label = String(row && row.label || "");
    if (keepLabels.has(label)) rows.push({ ...row, label: keepLabels.get(label) });
  }
  return rows;
}

function gcloudFirstString(strings, predicate) {
  const list = Array.isArray(strings) ? strings : [];
  for (const item of list) {
    const text = String(item && item.text ? item.text : "");
    if (text && predicate(text, item)) return text;
  }
  return "";
}

function gcloudCompactUserAgent(text) {
  const value = String(text || "").trim();
  if (!value) return "";
  const os = value.match(/CPU OS ([0-9_]+)/i);
  const mobile = value.match(/Mobile\/([A-Za-z0-9]+)/i);
  const parts = [];
  if (os) parts.push(`iOS ${String(os[1]).replace(/_/g, ".")}`);
  if (mobile) parts.push(`Mobile/${mobile[1]}`);
  return parts.length > 0 ? parts.join(" ") : shortenText(value, 56);
}

function gcloudProfilePart(label, value, maxLen = 72) {
  const text = String(value || "").trim();
  if (!text) return "";
  return `${label}=${shortenText(text, maxLen)}`;
}

function gcloudJoinProfileParts(parts) {
  return (Array.isArray(parts) ? parts : []).filter(Boolean).join("  ");
}

function gcloudProtoProfileRows(proto, ev = null) {
  if (!proto || !Array.isArray(proto.nodes)) return [];
  const strings = gcloudCollectProtoStrings(proto);
  if (strings.length <= 0) return [];

  const os = gcloudFirstString(strings, (text) => /^IOS\d+(?:\.\d+)+$/i.test(text));
  const model = gcloudFirstString(strings, (text) => /^(?:Apple\|)?i(?:Phone|Pad)\d+,\d+$/i.test(text));
  const network = gcloudFirstString(strings, (text) => /^(?:WiFi|WLAN|Cellular|Ethernet|5G|4G|3G)$/i.test(text));
  const gpu = gcloudFirstString(strings, (text) => /^GenericGPUBrand$/i.test(text) || /GPU(?:Brand|Vendor|Model)/i.test(text));
  const userAgent = gcloudFirstString(strings, (text) => /^Mozilla\/\d/i.test(text));
  const clientVersion = gcloudFirstString(strings, (text) => /^\d+(?:\.\d+){2,}$/.test(text));
  const deviceUuid = gcloudFirstString(strings, (text) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text));
  const cidAccount = String(ev && ev.cid ? ev.cid : "").match(/\[acc:(\d{10,24})\]/);
  const accountId = cidAccount ? cidAccount[1] : gcloudFirstString(strings, (text) => /^\d{10,20}$/.test(text));
  const accountKeyIndex = strings.findIndex((item) => /^itopid$/i.test(String(item && item.text ? item.text : "")));
  const accountKey = accountKeyIndex >= 0 ? strings[accountKeyIndex].text : "";
  let iapIncId = gcloudFirstString(strings, (text) => /^qq_qq-\d+-iap-\d+-\d+-[A-Za-z0-9_-]+$/i.test(text));
  if (!iapIncId) {
    const iapIndex = strings.findIndex((item) => /^qq_qq-\d+-iap-\d+-/i.test(String(item && item.text ? item.text : "")));
    if (iapIndex >= 0) {
      const first = String(strings[iapIndex].text || "");
      const next = String(strings[iapIndex + 1] && strings[iapIndex + 1].text ? strings[iapIndex + 1].text : "");
      iapIncId = /^[A-Za-z0-9_-]{3,}$/i.test(next) ? `${first}${next}` : first;
    }
  }
  const endpoint = gcloudFirstString(strings, (text) => /^(?:\d{1,3}\.){3}\d{1,3}:\d+$/.test(text))
    || gcloudFirstString(strings, (text) => /^\[[0-9a-f:]+\]:(?!0$)\d+$/i.test(text));
  const avatar = gcloudFirstString(strings, (text) => /^https?:\/\//i.test(text) && /qlogo\.cn\//i.test(text));
  const region = gcloudFirstString(strings, (text) => /^[A-Z]{2}$/.test(text));
  const currency = gcloudFirstString(strings, (text) => /^[A-Z]{3}$/.test(text));

  const rows = [];
  const device = gcloudJoinProfileParts([
    gcloudProfilePart("model", model),
    gcloudProfilePart("os", os),
    gcloudProfilePart("net", network),
    gcloudProfilePart("gpu", gpu),
    gcloudProfilePart("ua", gcloudCompactUserAgent(userAgent)),
    gcloudProfilePart("client", clientVersion),
  ]);
  if (device) rows.push({ label: "设备画像", value: device });

  const account = gcloudJoinProfileParts([
    gcloudProfilePart("account", accountId),
    gcloudProfilePart("key", accountKey),
    gcloudProfilePart("iap_inc_id?", iapIncId, 96),
    gcloudProfilePart("uuid", deviceUuid),
  ]);
  if (account) rows.push({ label: "账号/标识", value: account });

  const networkRow = gcloudJoinProfileParts([
    gcloudProfilePart("endpoint", endpoint),
    gcloudProfilePart("avatar", avatar, 96),
    gcloudProfilePart("region", region),
    gcloudProfilePart("currency", currency),
  ]);
  if (networkRow) rows.push({ label: "网络/资源", value: networkRow });

  return rows;
}

function gcloudProtoTimeRows(proto, maxItems = 6) {
  if (!proto || !Array.isArray(proto.flat)) return [];
  const seen = new Set();
  const parts = [];
  for (const item of proto.flat) {
    if (!item || !item.node || Number(item.node.wire) !== 0 || item.node.value === undefined) continue;
    const epoch = gcloudEpochScalarInfo(item.node.valueText || item.node.value);
    if (!epoch) continue;
    const alias = gcloudProtoFieldAlias(item.path, item.node, proto) || gcloudSemanticPathText(item.path, proto, item.topIndex, item.node);
    const key = `${alias}|${epoch.text}|${epoch.unit}`;
    if (seen.has(key)) continue;
    seen.add(key);
    parts.push(`${alias}=${epoch.text}${epoch.unit === "ms" ? " ms" : ""}`);
    if (parts.length >= maxItems) break;
  }
  return parts.length > 0 ? [{ label: "时间字段", value: parts.join("  ") }] : [];
}

function getGcloudBusinessProtoCached(ev, bytes, completeSource = true) {
  const signature = [
    Array.isArray(bytes) ? bytes.length : 0,
    String(ev && ev.pay ? ev.pay : "").length,
    String(ev && ev.pfx ? ev.pfx : "").length,
    completeSource ? 1 : 0,
  ].join("|");
  if (ev && ev.__tcpvGcloudProtoCache && ev.__tcpvGcloudProtoCache.signature === signature) {
    return ev.__tcpvGcloudProtoCache.value;
  }
  const value = analyzeGcloudBusinessProto(bytes, completeSource);
  if (ev && typeof ev === "object") {
    ev.__tcpvGcloudProtoCache = { signature, value };
  }
  return value;
}

const GCLOUD_17500_NUMERIC_COMMANDS = new Map([
  [0x2208ec, { commandName: "CSAccountLoginReqB", focus: "login_req", confidence: "observed" }],
  [0x221015, { commandName: "CSAccountLoginRes", focus: "login_res", confidence: "observed" }],
  [0x35cb4e, { commandName: "CSAceSendAntiDataNtfB", focus: "ace_antidata", confidence: "correlated" }],
  [0x35d277, { commandName: "CSAceAntiDataAck", focus: "ace_antidata_ack", confidence: "correlated" }],
  [0x6b9bce, { commandName: "GCloudHeartbeatReq", focus: "heartbeat_req", confidence: "correlated" }],
  [0x6ba2f7, { commandName: "GCloudHeartbeatRes", focus: "heartbeat_res", confidence: "correlated" }],
  [0x0dd84c, { commandName: "GCloudNetworkStatusReq", focus: "network_status_req", confidence: "correlated" }],
  [0x0ddf75, { commandName: "GCloudNetworkStatusRes", focus: "network_status_res", confidence: "correlated" }],
]);

function gcloudNumericEnvelopeFromProto(proto) {
  const nodes = proto && Array.isArray(proto.nodes) ? proto.nodes : [];
  for (const node of nodes) {
    if (!node || Number(node.field) !== 1 || Number(node.wire) !== 2 || !Array.isArray(node.children)) continue;
    const messageIdNode = node.children.find((child) => child && Number(child.field) === 1 && Number(child.wire) === 0);
    if (!messageIdNode) continue;
    const messageId = parseFlexibleInt(messageIdNode.valueText ?? messageIdNode.value);
    if (!Number.isFinite(messageId)) continue;
    const sequenceNode = node.children.find((child) => child && Number(child.field) === 2 && Number(child.wire) === 0);
    const messageSeq = sequenceNode ? parseFlexibleInt(sequenceNode.valueText ?? sequenceNode.value) : null;
    return { messageId, messageSeq };
  }
  return null;
}

function gcloudNumericCommandInfo(ev, proto = null, summaryText = "") {
  const summary = String(summaryText || (ev && ev.summary) || "");
  const meta = parseGcloud65010Summary(summary, ev);
  const flow = getCurrentFlowMeta();
  const targetPort = gcloudTargetPortFromText(
    ev && ev.cid,
    flow && flow.last_cid,
    summary,
  );
  const schema = String(meta.gcloudSchema || "");
  if (targetPort !== "17500" && schema !== "pubgm_numeric_v1") return null;

  const summaryMessageId = parseFlexibleInt(meta.gcloudMessageId);
  const summaryMessageSeq = parseFlexibleInt(meta.gcloudMessageSeq);
  const envelope = Number.isFinite(summaryMessageId) ? null : gcloudNumericEnvelopeFromProto(proto);
  const messageId = Number.isFinite(summaryMessageId) ? summaryMessageId : Number(envelope && envelope.messageId);
  if (!Number.isFinite(messageId)) return null;
  const messageSeq = Number.isFinite(summaryMessageSeq)
    ? summaryMessageSeq
    : Number.isFinite(Number(envelope && envelope.messageSeq)) ? Number(envelope.messageSeq) : null;
  const mapped = GCLOUD_17500_NUMERIC_COMMANDS.get(messageId) || null;
  return {
    messageId,
    messageSeq,
    schema: schema || "pubgm_numeric_v1",
    commandName: mapped ? mapped.commandName : "",
    focus: mapped ? mapped.focus : "",
    confidence: String(meta.gcloudTypeConfidence || (mapped && mapped.confidence) || "unknown"),
    basis: String(meta.gcloudTypeBasis || "after"),
  };
}

function gcloudAceCommandKind(commandName) {
  const name = String(commandName || "");
  if (/^CSAceSendAntiDataNtf/i.test(name)) return "ace_antidata";
  if (/^CSAceAntiDataAck/i.test(name)) return "ace_ack";
  if (/^CSAceSendLightFeatureDataNtf/i.test(name)) return "ace_light";
  if (/^CSAceAntiDataTransferNtf/i.test(name)) return "ace_transfer";
  if (/^CSAce/i.test(name)) return "ace_other";
  return "";
}

function gcloudTssCommandKind(commandName) {
  return /^CSTss/i.test(String(commandName || "")) ? "cstss_all" : "";
}

function gcloudAceCommandLabel(kind) {
  if (kind === "ace_antidata") return "ACE 反作弊数据上报";
  if (kind === "ace_ack") return "ACE 反作弊数据确认";
  if (kind === "ace_light") return "ACE 轻量特征上报";
  if (kind === "ace_transfer") return "ACE 反作弊数据传输";
  return "ACE";
}

function gcloudAceReportMeaning(reportCode) {
  const report = Number(reportCode);
  if (!Number.isFinite(report)) return "";
  if (report === 0x010a0008) return "TSS 内层加密响应封套";
  if (report === 0x010a0009) return "TSS 内层加密控制封套";
  if (report === 0x010a0013) return "明文 TLV 文本记录";
  if (report === 0x010a0021) return "控制/反馈记录";
  if (report === 0x010a0056) return "同步文件保存请求";
  if ([0x0112235f, 0x01122362].includes(report)) return "设备型号/系统版本画像";
  if ((report & 0xffffff00) === 0x01122300) return `动态 metadata/state family · subtype=0x${(report & 0xff).toString(16).padStart(2, "0")}`;
  return reportBusinessLabel(report);
}

function gcloudAceReportTokens(payload, maxItems = 6) {
  const bytes = Array.isArray(payload) ? payload : [];
  const out = [];
  const seen = new Set();
  for (let offset = 0; offset + 4 <= Math.min(bytes.length, 192); offset += 1) {
    const value = readBe32(bytes, offset);
    if (!Number.isFinite(value)) continue;
    const isDynamic = (value & 0xffffff00) === 0x01122300;
    const isControl = (value & 0xffff0000) === 0x010a0000 || value === 0x0102000a;
    if (!isDynamic && !isControl) continue;
    const text = formatHexValue(value, 8);
    if (seen.has(text)) continue;
    seen.add(text);
    out.push({ value, text, offset });
    if (out.length >= maxItems) break;
  }
  return out;
}

function gcloudAceReadableSignals(payload, maxItems = 6) {
  const bytes = Array.isArray(payload) ? payload : [];
  const candidates = extractPrintableRuns(bytes, 4, 32)
    .map((item) => normalizeVisibleText(item && item.text ? item.text : ""))
    .filter((text) => (
      /(?:model|ver|inc_id|obf_id|state|status|cs|ob|account|hello|config|tersafe)[:=]/i.test(text)
      || /^\d{15,24}$/.test(text)
      || /hello, world/i.test(text)
    ));
  const out = [];
  const seen = new Set();
  for (const text of candidates) {
    const compact = shortenText(text, 150);
    if (!compact || seen.has(compact)) continue;
    seen.add(compact);
    out.push(compact);
    if (out.length >= maxItems) break;
  }
  return out;
}

function analyzeGcloudAceCarrier(proto, protoBytes) {
  const flat = proto && Array.isArray(proto.flat) ? proto.flat : [];
  const directTotal = Array.isArray(protoBytes) && protoBytes.length >= 10
    ? readBe16(protoBytes, 4)
    : null;
  const directTssRecord = Array.isArray(protoBytes)
    && protoBytes.length >= 10
    && readBe32(protoBytes, 0) === 1
    && Number.isFinite(directTotal)
    && Math.abs(Number(directTotal) - protoBytes.length) <= 4;
  const candidates = flat
    .filter((item) => (
      item && item.node && item.node.string
      && Array.isArray(item.path) && Number(item.path[0]) === 2
      && gcloudAnalyzeHexString(item.node.string)
    ))
    .sort((left, right) => String(right.node.string || "").length - String(left.node.string || "").length);
  let sourceNode = directTssRecord ? null : (candidates.length > 0 ? candidates[0].node : null);
  let hexInfo = sourceNode ? gcloudAnalyzeHexString(sourceNode.string) : null;
  let payload = directTssRecord
    ? protoBytes.slice(0, Number(directTotal))
    : (hexInfo && Array.isArray(hexInfo.payload) ? hexInfo.payload : []);

  if (payload.length <= 0) {
    const byteCandidates = flat
      .filter((item) => (
        item && item.node && Number(item.node.wire) === 2
        && Array.isArray(item.path) && Number(item.path[0]) === 2
        && !item.node.string && (!Array.isArray(item.node.children) || item.node.children.length === 0)
      ))
      .map((item) => ({ node: item.node, bytes: gcloudNodeValueBytes(item.node, protoBytes) }))
      .sort((left, right) => right.bytes.length - left.bytes.length);
    if (byteCandidates.length > 0) {
      sourceNode = byteCandidates[0].node;
      payload = byteCandidates[0].bytes;
    }
  }

  const carrierMode = directTssRecord
    ? "tss_record"
    : proto && proto.compression ? "binary_carrier" : (hexInfo ? "ascii_hex" : "binary_carrier");
  const total = payload.length >= 6 ? readBe16(payload, 4) : null;
  const rootReport = payload.length >= 10 && readBe32(payload, 0) === 1
    && Number.isFinite(total) && Math.abs(Number(total) - payload.length) <= 4
    ? readBe32(payload, 6)
    : null;
  const reportTokens = gcloudAceReportTokens(payload);
  const readable = gcloudAceReadableSignals(payload);
  const carrierChain = [
    directTssRecord ? `UAGame body -> TSS record ${payload.length}B` : "",
    proto && proto.compression ? `LZ4 解压 ${proto.compression.inputLength}->${proto.compression.outputLength}B` : "",
    directTssRecord ? "" : hexInfo ? `ASCII hex -> ${payload.length}B` : payload.length > 0 ? `${payload.length}B binary` : "payload unavailable",
  ].filter(Boolean).join(" · ");
  return {
    mode: carrierMode,
    sourceKind: hexInfo ? String(hexInfo.kind || "hex") : "binary",
    profile: hexInfo && hexInfo.profile ? String(hexInfo.profile) : "",
    chain: carrierChain,
    payload,
    rootReport,
    reportTokens,
    readable,
    entropy: payload.length > 0 ? gcloudByteEntropy(payload) : null,
    prefix: payload.length > 0 ? gcloudHexBytes(payload, 16) : "",
    confidence: rootReport !== null && ["ascii_hex", "tss_record"].includes(carrierMode)
      ? "decoded"
      : (hexInfo && hexInfo.profile) || reportTokens.length > 0
        ? "observed"
        : "inferred",
  };
}

function gcloudCommandNameForEvent(ev, summaryText = "") {
  if (!ev || typeof ev !== "object") return "";
  const summary = String(summaryText || ev.summary || "");
  const signature = `${summary.length}|${String(ev.pfx || "").length}|${String(ev.pay || "").length}`;
  if (ev.__tcpvGcloudCommandCache && ev.__tcpvGcloudCommandCache.signature === signature) {
    return ev.__tcpvGcloudCommandCache.value;
  }
  let value = "";
  if (isGcloud65010Summary(summary, ev)) {
    const meta = parseGcloud65010Summary(summary, ev);
    const uagameOpcode = gcloudUagameOpcodeInfo(meta);
    const preview = getGcloudPreviewBytes(ev);
    const frame = parseGcloudTgcpFrame(preview.bytes);
    const command = meta.command !== null ? meta.command : (frame ? frame.command : null);
    if (command === 0x4013 && String(meta.crypto || "").toLowerCase() === "decrypted") {
      const proto = getGcloudBusinessProtoCached(ev, preview.bytes, preview.complete);
      // Prefer the parsed length-delimited field over summary substring scans
      // so 65010 Req + protobuf tag 0x42 is never rendered as a fake ReqB.
      value = String(proto && (proto.commandName || proto.commandDisplay) ? (proto.commandName || proto.commandDisplay) : "");
      if (!value) {
        const numeric = gcloudNumericCommandInfo(ev, proto, summary);
        value = String(numeric && numeric.commandName ? numeric.commandName : "");
      }
    }
    if (!value && meta.gcloudType) value = gcloudReadableTypeName(meta.gcloudType);
    if (!value && meta.gcloudInferredType) {
      value = gcloudReadableTypeName(meta.gcloudInferredType);
    }
    if (uagameOpcode && uagameOpcode.name) value = uagameOpcode.name;
    if (!value) value = gcloudUagameOpcodeDisplay(meta);
  }
  ev.__tcpvGcloudCommandCache = { signature, value };
  return value;
}

function gcloudEventClass(ev) {
  if (!ev || typeof ev !== "object") return "other";
  const summary = String(ev.summary || "");
  if (!isGcloud65010Summary(summary, ev)) return "other";
  const name = gcloudCommandNameForEvent(ev, summary);
  if (/^CSAccountLogin(?:Req|Res)/i.test(name)) return "account_login";
  const aceKind = gcloudAceCommandKind(name);
  if (aceKind) return aceKind;
  const tssKind = gcloudTssCommandKind(name);
  if (tssKind) return tssKind;
  if (/^GCloudHeartbeat(?:Req|Res)/i.test(name)) return "gcloud_heartbeat";
  if (/^GCloudNetworkStatus(?:Req|Res)/i.test(name)) return "gcloud_network";
  const meta = parseGcloud65010Summary(summary, ev);
  if (meta.command === 0x4013) return "gcloud_4013";
  return "tgcp_control";
}

function gcloudAceNeighbourText(ev, commandName) {
  const events = Array.isArray(state.events) ? state.events : [];
  const index = events.indexOf(ev);
  if (index <= 0) return "当前窗口内无前序同类包";
  const kind = gcloudAceCommandKind(commandName);
  const wantedKind = kind === "ace_transfer" ? "ace_antidata" : kind;
  for (let cursor = index - 1; cursor >= Math.max(0, index - 800); cursor -= 1) {
    const candidate = events[cursor];
    if (gcloudEventClass(candidate) !== wantedKind) continue;
    const deltaMs = Number(gcloudEventTsMs(ev)) - Number(gcloudEventTsMs(candidate));
    if (!Number.isFinite(deltaMs) || deltaMs < 0) break;
    if (kind === "ace_transfer") return `紧跟前一 AntiData +${Math.round(deltaMs)}ms · 服务端下行关联候选`;
    const seconds = deltaMs / 1000;
    if (kind === "ace_light" && seconds >= 12 && seconds <= 18) return `距上一包 ${seconds.toFixed(1)}s · 约15s周期`;
    if (kind === "ace_antidata" && seconds <= 7) return `距上一包 ${seconds.toFixed(1)}s · 启动 burst`;
    if (kind === "ace_antidata" && seconds >= 30) return `距上一包 ${seconds.toFixed(1)}s · 低频/事件型刷新`;
    return `距上一同类 ${seconds.toFixed(1)}s`;
  }
  return kind === "ace_transfer" ? "当前窗口内未找到前序 AntiData" : "当前窗口内无前序同类包";
}

function analyzeGcloudAceCommand(ev, proto, protoBytes, commandName) {
  const kind = gcloudAceCommandKind(commandName);
  if (!kind) return null;
  const carrier = analyzeGcloudAceCarrier(proto, protoBytes);
  if (kind === "ace_transfer") {
    carrier.routeMode = "server_transfer";
    carrier.chain = ["server -> client", carrier.chain].filter(Boolean).join(" · ");
    carrier.confidence = carrier.payload.length > 0 ? carrier.confidence : "observed";
  }
  const hasRootReport = carrier.rootReport !== null
    && carrier.rootReport !== undefined
    && Number.isFinite(Number(carrier.rootReport));
  const rootText = hasRootReport ? formatHexValue(carrier.rootReport, 8) : "";
  const tokenText = carrier.reportTokens.map((item) => item.text).join(", ");
  const identity = rootText
    ? `root_report=${rootText}`
    : carrier.profile
      ? `profile=${carrier.profile}`
      : tokenText ? `reportish=${tokenText}` : "report=未识别";
  const meaning = hasRootReport
    ? gcloudAceReportMeaning(carrier.rootReport)
    : carrier.reportTokens.length > 0 ? gcloudAceReportMeaning(carrier.reportTokens[0].value) : "";
  const role = kind === "ace_antidata"
    ? "客户端主动重型/事件型反作弊上报；启动阶段密集，之后低频刷新。"
    : kind === "ace_light"
      ? "客户端轻量周期特征上报；当前样本以约15秒周期持续发送。"
      : kind === "ace_transfer"
        ? "服务端下行 transfer/回执/触发候选；只按近邻时序标注，不命名为已确认 ACK。"
        : "ACE security channel command。";
  return {
    kind,
    label: gcloudAceCommandLabel(kind),
    commandName,
    carrier,
    identity,
    meaning,
    role,
    cadence: gcloudAceNeighbourText(ev, commandName),
  };
}

function analyzeGcloudTssCommand(proto, protoBytes, commandName) {
  if (!gcloudTssCommandKind(commandName)) return null;
  const carrier = analyzeGcloudAceCarrier(proto, protoBytes);
  const rootReport = Number(carrier.rootReport);
  const hasRootReport = carrier.rootReport !== null
    && carrier.rootReport !== undefined
    && Number.isFinite(rootReport);
  const rootText = hasRootReport ? formatHexValue(rootReport, 8) : "";
  const tokenText = carrier.reportTokens.map((item) => item.text).join(", ");
  const identity = rootText
    ? `root_report=${rootText}`
    : carrier.profile
      ? `profile=${carrier.profile}`
      : tokenText ? `report=${tokenText}` : "report=未识别";
  return {
    kind: "cstss_all",
    label: "CSTss",
    commandName,
    carrier,
    identity,
    meaning: hasRootReport ? gcloudAceReportMeaning(rootReport) : "",
    role: /^CSTssHeartbeatNtf/i.test(commandName)
      ? "TSS 心跳/状态通知；按当前会话时序观察，不将字段提升为已确认处罚结论。"
      : "TSS 安全通道命令；carrier 继续按 TSS record 与加密信封分层解析。",
  };
}

function analyzeGcloudGatewayKickCommand(proto, commandName) {
  if (!/^CSGatewayKickPlayerNtf$/i.test(String(commandName || ""))) return null;
  const lookup = gcloudProtoPathLookup(proto);
  const codeItem = lookup.get("2.1");
  const noticeItem = lookup.get("2.2");
  const codeNode = codeItem && codeItem.node ? codeItem.node : null;
  const noticeNode = noticeItem && noticeItem.node ? noticeItem.node : null;
  const codeText = codeNode && Number(codeNode.wire) === 0
    ? String(codeNode.valueText ?? codeNode.value ?? "")
    : "";
  const codeValue = codeText !== "" && Number.isFinite(Number(codeText)) ? Number(codeText) : null;
  const protoBytes = proto && Array.isArray(proto.viewBytes) ? proto.viewBytes : [];
  const noticeBytes = noticeNode
    && Number(noticeNode.wire) === 2
    && Number.isFinite(Number(noticeNode.valueStart))
    && Number.isFinite(Number(noticeNode.valueEnd))
    ? protoBytes.slice(Number(noticeNode.valueStart), Number(noticeNode.valueEnd))
    : [];
  const notice = String(
    noticeNode && noticeNode.string
      ? noticeNode.string
      : gcloudBytesToUtf8(noticeBytes)
  ).trim();
  const freezeMatch = notice.match(/冻结\s*(\d+)\s*天/);
  const unlockMatch = notice.match(/解封时间(?:为|[:：]?)\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
  const freezeDays = freezeMatch ? Number(freezeMatch[1]) : null;
  const unlockTime = unlockMatch ? String(unlockMatch[1]) : "";
  const serverFreeze = /账号[^。\n]{0,24}冻结/.test(notice);
  const evidence = [];
  if (/游戏环境及行为数据异常/.test(notice)) evidence.push("游戏环境及行为数据异常");
  if (/异常或网络环境/.test(notice)) evidence.push("异常/网络环境");
  if (/第三方插件|第三方[^。\n]{0,8}应用/.test(notice)) evidence.push("第三方插件或同时运行应用");
  if (/常用设备/.test(notice)) evidence.push("常用设备");
  if (/共享账号/.test(notice)) evidence.push("共享账号");
  const penaltyText = [
    serverFreeze ? "服务器侧账号冻结" : "网关强制下线",
    Number.isFinite(freezeDays) ? `${freezeDays}天` : "",
    unlockTime ? `解封 ${unlockTime}` : "",
  ].filter(Boolean).join(" · ");
  const packetResultText = serverFreeze
    ? "本包 notice 同时明确包含账号冻结结果"
    : "本包 notice 未出现可确认的账号冻结措辞";
  const codeMeaning = codeValue === null
    ? "当前片段未解析到 field[2].field[1] varint"
    : `${codeValue} (${formatHexValue(codeValue)}) · ${packetResultText}；官方枚举名未知`;
  return {
    commandName: String(commandName || ""),
    codeValue,
    codeText,
    codeMeaning,
    notice,
    freezeDays,
    unlockTime,
    serverFreeze,
    penaltyText,
    evidence,
    fieldShape: `body.field1=varint${codeText ? `(${codeText})` : "(?)"} · body.field2=utf8${noticeNode ? `(len=${Number(noticeNode.len || 0)})` : "(?)"}`,
    role: serverFreeze
      ? "服务器主动下发；网关要求客户端立即退出，本包提示文本同时确认服务器侧账号冻结。"
      : "服务器主动下发的网关强制下线通知；具体处罚结果以本包提示文本为准。",
    boundary: "kick_code 仅按本包 varint 原值展示，不把任何数值硬编码成官方处罚枚举。冻结期限、解封时间和风险提示均从当前 notice 动态提取；提示文本不足以证明具体由哪条 ACE/TerSafe 上报触发。",
  };
}

function analyzeGcloudEvent(ev, summaryText = "") {
  if (!isGcloud65010Summary(summaryText || (ev && ev.summary), ev)) return null;
  const meta = parseGcloud65010Summary(summaryText || (ev && ev.summary), ev);
  const preview = getGcloudPreviewBytes(ev);
  const bytes = preview.bytes;
  const frame = parseGcloudTgcpFrame(bytes);
  const command = meta.command !== null ? meta.command : (frame ? frame.command : null);

  if (command === 0x9001) {
    const direction = normalizeGcloudDirection(ev, meta);
    const control = parseGcloud9001Control(bytes, frame);
    const pair = control && control.ok ? findGcloud9001Pair(ev, control, meta) : null;
    const roleText = direction === "outbound"
      ? "payload_len=0 的控制旁路帧；客户端主动探测/保活，等待服务端原样 echo。"
      : direction === "inbound"
        ? "payload_len=0 的控制旁路帧；服务端 echo 回包，扩展字段与客户端请求相同。"
        : "payload_len=0 的控制旁路帧；9001 控制帧，当前方向未知。";
    const rttText = pair && Number.isFinite(Number(pair.rttMs))
      ? `匹配到${pair.direction === "outbound" ? "出站请求" : "入站回包"} index=${pair.index} seq=${pair.seq ?? "-"}，RTT≈${Math.round(Number(pair.rttMs))}ms`
      : "当前事件窗口未找到另一半；可能未加载到相邻区间。";
    const controlText = control && control.ok
      ? `control_id=${control.controlId ?? "-"} tick_len=${control.tickLen ?? "-"} tick48=${control.tickHex} flag=${control.flag ?? "-"} reserved=${control.reservedZero ? "zero" : control.reservedHex}`
      : control && control.reason ? control.reason : "raw preview 未加载";
    return {
      kind: "control",
      meta,
      bytes,
      frame,
      control,
      pair,
      title: "TGCP 9001 控制帧 / echo",
      chips: [
        direction === "outbound" ? "9001 ping" : direction === "inbound" ? "9001 echo" : "TGCP 9001",
        meta.direction ? `dir=${meta.direction}` : "",
        meta.seq ? `seq=${meta.seq}` : "",
        control && control.ok && control.controlId !== null ? `ctrl=${control.controlId}` : "",
        pair && Number.isFinite(Number(pair.rttMs)) ? `RTT≈${Math.round(Number(pair.rttMs))}ms` : "",
      ].filter(Boolean),
      rows: [
        { label: "控制关系", value: roleText },
        { label: "配对", value: rttText },
        { label: "控制字段", value: controlText },
        { label: "Header", value: frame ? `header_len=${frame.headerLen ?? "-"} payload_len=${frame.payloadLen ?? "-"} total=${frame.totalLen}` : "raw preview 未加载" },
        { label: "Magic", value: frame ? `${frame.magic} command=${frame.commandText}` : meta.commandText || "-" },
        { label: "与4013", value: "常贴着 CSOnlineHeartbeatReq/Res 的节奏出现；4013 是 AES 后的业务 protobuf，9001 是 TGCP 传输层 echo，不进入 4013 解密。" },
      ],
      nodeRows: [],
    };
  }

  if (command === 0x4013 && String(meta.crypto || "").toLowerCase() === "decrypted") {
    if (isUagamePrivateFragmentMeta(meta)) {
      const fragment = analyzeUagamePrivateFragment(bytes);
      const markerText = fragment.markerOffset === null
        ? "marker 未加载"
        : `abab@+${formatHexValue(fragment.markerOffset, 2)}`;
      return {
        kind: "uagame_private_fragment",
        meta,
        bytes,
        fragment,
        title: `UAGame private fragment · ${fragment.family}`,
        chips: [
          `fragment ${fragment.family}`,
          markerText,
          normalizeGcloudDirection(ev, meta),
        ].filter(Boolean),
        rows: [
          { label: "分片族", value: `${fragment.family} · prefix=${fragment.prefix || "-"} · total=${fragment.totalLen}B` },
          { label: "Fragment anchor", value: `${markerText}${fragment.payloadStart === null ? "" : ` · payload@+${formatHexValue(fragment.payloadStart, 2)}`}` },
          { label: "片段前缀", value: fragment.payloadPrefix || "当前 preview 未包含 marker 后载荷" },
          { label: "识别边界", value: "这是 UAGame f4/f8 private/segmented frame；marker offset 动态，marker 后不是完整 protobuf。不得把 +0x04 当 opcode，也不生成伪 child tree。" },
        ],
        nodeRows: [],
      };
    }
    const proto = getGcloudBusinessProtoCached(ev, bytes, preview.complete);
    if (proto && isUagameGcloudMeta(meta)) {
      proto.uagameBody = true;
      // Command/header aliases belong to the 65010 CS envelope, not to the
      // already-extracted UAGame business body.
      if (!meta.gcloudType) proto.commandDisplay = "";
    }
    const protoBytes = proto && Array.isArray(proto.viewBytes) ? proto.viewBytes : bytes;
    const uagameProbe = isUagameGcloudMeta(meta)
      ? analyzeUagameDecodedBodyProbe(protoBytes, meta)
      : null;
    const compression = proto && proto.compression ? proto.compression : null;
    const numeric = gcloudNumericCommandInfo(ev, proto, summaryText || (ev && ev.summary));
    const uagameOpcode = gcloudUagameOpcodeInfo(meta);
    const effectiveCommandName = String(
      (!isUagameGcloudMeta(meta) && proto && (proto.commandName || proto.commandDisplay))
      || gcloudReadableTypeName(meta.gcloudType)
      || (numeric && numeric.commandName)
      || (uagameOpcode && uagameOpcode.name)
      || gcloudReadableTypeName(meta.gcloudInferredType)
      || ""
    );
    const effectiveCommandDisplay = String(
      (isUagameGcloudMeta(meta) && gcloudUagameOpcodeDisplay(meta))
      || gcloudCommandDisplay(effectiveCommandName)
      || ""
    );
    // 17500 的数字信封没有 CS* 明文命令名。把后端已验证或按端口
    // 映射出的名称挂到当前解析视图，确保详情、字段别名和筛选口径一致。
    if (proto && effectiveCommandName && !proto.commandDisplay) {
      proto.commandDisplay = effectiveCommandName;
      proto.commandNameSource = meta.gcloudType
        ? String(meta.gcloudTypeSource || "backend")
        : (numeric && numeric.commandName ? "numeric" : "inferred");
    }
    const title = effectiveCommandDisplay
      ? `GCloud 明文 ${effectiveCommandDisplay}`
      : "GCloud 4013 明文";
    const bodyNode = proto && !proto.uagameBody && proto.bodyNode ? proto.bodyNode : null;
    const profileRows = gcloudProtoProfileRows(proto, ev);
    const timeRows = gcloudProtoTimeRows(proto);
    const gatewayKick = effectiveCommandName
      ? analyzeGcloudGatewayKickCommand(proto, effectiveCommandName)
      : null;
    if (gatewayKick) {
      return {
        kind: "kick",
        meta,
        bytes,
        protoBytes,
        proto,
        kick: gatewayKick,
        title: `账号冻结 / 网关强制下线 · ${effectiveCommandDisplay}`,
        chips: [
          gatewayKick.serverFreeze ? "账号冻结" : "网关强制下线",
          normalizeGcloudDirection(ev, meta) === "inbound" ? "server → client" : normalizeGcloudDirection(ev, meta),
          gatewayKick.codeValue !== null ? `kick_code=${gatewayKick.codeValue}` : "kick_code=?",
          Number.isFinite(gatewayKick.freezeDays) ? `冻结${gatewayKick.freezeDays}天` : "",
          gatewayKick.unlockTime ? `解封 ${gatewayKick.unlockTime}` : "",
          proto ? gcloudProtoStatusText(proto) : "",
        ].filter(Boolean),
        rows: [
          { label: "命令", value: effectiveCommandDisplay },
          { label: "业务语义", value: gatewayKick.role },
          { label: "字段结构", value: gatewayKick.fieldShape },
          { label: "踢下线代码", value: gatewayKick.codeMeaning },
          { label: "处罚状态", value: gatewayKick.penaltyText || "当前提示未包含可提取的冻结期限。" },
          ...(gatewayKick.notice ? [{ label: "服务器提示", value: gatewayKick.notice }] : []),
          ...(gatewayKick.evidence.length > 0 ? [{ label: "文本线索", value: gatewayKick.evidence.join(" · ") }] : []),
          { label: "解析边界", value: gatewayKick.boundary },
          ...profileRows,
          { label: "4013", value: `plain_len=${meta.plainLen || bytes.length || "-"} padding=${meta.padding || "-"}` },
        ],
        nodeRows: gcloudProtoNodeRows(proto),
      };
    }
    const ace = effectiveCommandName
      ? analyzeGcloudAceCommand(ev, proto, protoBytes, effectiveCommandName)
      : null;
    if (ace) {
      const carrier = ace.carrier || {};
      const opaqueText = Array.isArray(carrier.payload) && carrier.payload.length > 0
        ? `len=${carrier.payload.length} entropy=${Number(carrier.entropy || 0).toFixed(2)} prefix=${carrier.prefix || "-"}`
        : "当前 command 无可独立解释的 carrier payload";
      return {
        kind: "ace",
        meta,
        bytes,
        protoBytes,
        proto,
        ace,
        title: `${ace.label} · ${effectiveCommandDisplay}`,
        chips: [
          ...(isUagameGcloudMeta(meta) ? ["4013 decrypted", gcloudUagameOpcodeDisplay(meta)] : []),
          ace.label,
          normalizeGcloudDirection(ev, meta),
          numeric ? `msg_id=${formatHexValue(numeric.messageId)}` : "",
          numeric ? `basis=${numeric.basis}` : "",
          proto.module ? `channel=${proto.module}` : "",
          carrier.mode ? `carrier=${carrier.mode}` : "",
          ace.identity,
          carrier.confidence ? `confidence=${carrier.confidence}` : "",
        ].filter(Boolean),
        rows: [
          { label: "命令", value: effectiveCommandDisplay },
          ...(numeric ? [{ label: "数字信封", value: `schema=${numeric.schema} msg_id=${formatHexValue(numeric.messageId)} seq=${numeric.messageSeq ?? "-"} basis=${numeric.basis} confidence=${numeric.confidence}` }] : []),
          { label: "反作弊角色", value: ace.role },
          { label: "承载链", value: carrier.chain || carrier.mode || "-" },
          { label: "报告标识", value: [ace.identity, ace.meaning].filter(Boolean).join(" · ") },
          ...(carrier.readable && carrier.readable.length > 0 ? [{ label: "可读特征", value: carrier.readable.join("  |  ") }] : []),
          { label: "节奏/关联", value: ace.cadence },
          { label: carrier.profile ? "载荷摘要" : "Opaque 摘要", value: opaqueText },
          { label: "解析边界", value: `confidence=${carrier.confidence || "inferred"}；observed/inferred 字段不提升为封禁码、白名单或确认 ACK。` },
          ...profileRows,
          { label: "4013", value: `plain_len=${meta.plainLen || bytes.length || "-"} padding=${meta.padding || "-"}` },
        ],
        nodeRows: gcloudProtoNodeRows(proto),
      };
    }
    const tss = effectiveCommandName
      ? analyzeGcloudTssCommand(proto, protoBytes, effectiveCommandName)
      : null;
    if (tss) {
      const carrier = tss.carrier || {};
      return {
        kind: "tss",
        meta,
        bytes,
        protoBytes,
        proto,
        tss,
        title: `CSTss · ${effectiveCommandDisplay}`,
        chips: [
          "CSTss*",
          normalizeGcloudDirection(ev, meta),
          proto.module ? `channel=${proto.module}` : "",
          carrier.mode ? `carrier=${carrier.mode}` : "",
          tss.identity,
        ].filter(Boolean),
        rows: [
          { label: "命令", value: effectiveCommandDisplay },
          ...(numeric ? [{ label: "数字信封", value: `schema=${numeric.schema} msg_id=${formatHexValue(numeric.messageId)} seq=${numeric.messageSeq ?? "-"} basis=${numeric.basis} confidence=${numeric.confidence}` }] : []),
          { label: "TSS 角色", value: tss.role },
          { label: "承载链", value: carrier.chain || carrier.mode || "-" },
          { label: "报告标识", value: [tss.identity, tss.meaning].filter(Boolean).join(" · ") },
          { label: "解析边界", value: "先识别 carrier 与 record framing；加密信封仅在算法支持且 CRC 校验通过后展示内层语义。" },
          ...profileRows,
          { label: "4013", value: `plain_len=${meta.plainLen || bytes.length || "-"} padding=${meta.padding || "-"}` },
        ],
        nodeRows: gcloudProtoNodeRows(proto),
      };
    }
    return {
      kind: proto && proto.ok ? "proto" : "fragment",
      meta,
      bytes,
      protoBytes,
      proto,
      uagameProbe,
      title: uagameProbe && uagameProbe.packed && uagameProbe.packed.ok
        ? `UAGame 数字 ID 列表 · ${gcloudUagameOpcodeDisplay(meta)}`
        : title,
      chips: [
        ...(isUagameGcloudMeta(meta)
          ? [effectiveCommandDisplay || gcloudUagameOpcodeDisplay(meta), proto ? gcloudEventPayloadStatusText(proto, meta) : "UAGame body"]
          : [effectiveCommandDisplay || "4013 decrypted"]),
        ...(uagameProbe && uagameProbe.packed && uagameProbe.packed.ok
          ? [`ID×${uagameProbe.packed.count}`, `unique=${uagameProbe.packed.uniqueCount}`]
          : []),
        ...(uagameProbe
          ? [uagameProbe.reportHits.length > 0 ? `01 0a report×${uagameProbe.reportHits.length}` : "01 0a report=0"]
          : []),
        numeric ? `msg_id=${formatHexValue(numeric.messageId)}` : "",
        numeric && Number.isFinite(numeric.messageSeq) ? `msg_seq=${numeric.messageSeq}` : "",
        numeric ? `confidence=${numeric.confidence}` : "",
        meta.gcloudTypeSource ? `type=${meta.gcloudTypeSource}` : "",
        meta.gcloudContext ? `ctx=${meta.gcloudContext}` : "",
        proto && proto.commandId !== null && proto.commandId !== undefined ? `call_id=${formatHexValue(proto.commandId)}` : "",
        proto && proto.module ? `module=${proto.module}` : "",
        proto && proto.language ? proto.language : "",
        compression && compression.kind === "lz4-block" ? "LZ4已解压" : "",
        !isUagameGcloudMeta(meta) && proto ? gcloudEventPayloadStatusText(proto, meta) : "",
      ].filter(Boolean),
      rows: [
        ...uagameReportProbeRows(uagameProbe, normalizeGcloudDirection(ev, meta)),
        ...(isUagameGcloudMeta(meta) ? [{
          label: "UAGame 4013",
          value: `${gcloudUagameOpcodeDisplay(meta)} · direction=${normalizeGcloudDirection(ev, meta)} · 40-byte header · body=${meta.plainLen ? Math.max(0, Number(meta.plainLen) - 40) : protoBytes.length}B`,
        }, {
          label: "Identity anchor",
          value: gcloudUagameEnvelopeAnchorText(),
        }, {
          label: "识别边界",
          value: "opcode 是 UAGame 消息类型；body 再按 protobuf tree / TSS record / private binary 分层识别，不套用 65010 的 CS* 名称。",
        }] : []),
        { label: "命令", value: effectiveCommandDisplay || "未从当前 payload/prefix 识别到 CS* 名称" },
        ...(!isUagameGcloudMeta(meta) && proto && proto.commandId !== null && proto.commandId !== undefined ? [{
          label: "消息关联 ID",
          value: `root.1.3=${formatHexValue(proto.commandId)} · 用于请求/响应配对，会随调用变化，不是固定消息类型 ID；类型由 root.1.7 command 确定。`,
        }] : []),
        ...(numeric ? [{ label: "数字信封", value: `schema=${numeric.schema} msg_id=${formatHexValue(numeric.messageId)} seq=${numeric.messageSeq ?? "-"} basis=${numeric.basis} confidence=${numeric.confidence}` }] : []),
        ...(meta.gcloudContext ? [{ label: "上下文", value: meta.gcloudContext }] : []),
        {
          label: isUagameGcloudMeta(meta) ? "Payload" : "Proto",
          value: proto
            ? (proto.ok ? gcloudProtoStatusText(proto) : gcloudEventPayloadStatusText(proto, meta))
            : (isUagameGcloudMeta(meta) ? "UAGame body" : "payload 未加载"),
        },
        { label: "Lead", value: proto && Number(proto.start || 0) > 0 ? `${Number(proto.start)} byte (${protoBytes.slice(0, proto.start).map(childHexByteText).join(" ")})` : "0 byte" },
        { label: isUagameGcloudMeta(meta) ? "Root" : "Body", value: isUagameGcloudMeta(meta) ? "UAGame business protobuf；字段按原始 fN 路径展示" : (bodyNode ? gcloudNodeValueText(bodyNode) : "当前片段未见顶层 body (field[2])") },
        ...timeRows,
        ...profileRows,
        ...(compression ? [{ label: "压缩", value: `LZ4 raw block 解压 ${compression.inputLength} -> ${compression.outputLength} byte` }] : []),
        { label: "4013", value: `plain_len=${meta.plainLen || bytes.length || "-"} padding=${meta.padding || "-"}` },
      ],
      nodeRows: gcloudProtoNodeRows(proto),
    };
  }

  const handshakeEvidence = gcloudWireHandshakeEvidence(ev);
  const handshakeRows = gcloudHandshakeDiagnosticRows(ev, handshakeEvidence);
  const currentHandshake = handshakeEvidence.find((item) => item.source === "forwarded")
    || handshakeEvidence.find((item) => item.source === "current")
    || handshakeEvidence[0]
    || null;
  return {
    kind: "raw",
    meta,
    bytes,
    frame,
    handshakeEvidence,
    title: command !== null ? `TGCP ${formatHexValue(command, 4)}` : `TGCP ${meta.targetPort || "GCloud"}`,
    chips: [
      command !== null ? formatHexValue(command, 4) : "",
      meta.direction ? `dir=${meta.direction}` : "",
      meta.crypto || "",
      currentHandshake && currentHandshake.method !== null ? `method=${currentHandshake.method}` : "",
      currentHandshake && currentHandshake.method === 3 ? `wire key_len=${currentHandshake.keyLength}` : "",
    ].filter(Boolean),
    rows: [
      { label: "说明", value: "当前帧不是已解密的 4013 业务明文，按 TGCP 原始帧观察。" },
      { label: "Header", value: frame ? `header_len=${frame.headerLen ?? "-"} payload_len=${frame.payloadLen ?? "-"}` : "raw preview 未加载" },
      ...handshakeRows,
    ],
    nodeRows: [],
  };
}

function getGcloudProducerValidation(ev) {
  const analysis = ev && ev.analysis && typeof ev.analysis === "object" ? ev.analysis : null;
  const validation = analysis && analysis.validation && typeof analysis.validation === "object"
    ? analysis.validation
    : null;
  return validation && validation.schema === "tcpv.gcloud.validation.v1" ? validation : null;
}

function gcloudValidationSummaryInsights(ev) {
  const validation = getGcloudProducerValidation(ev);
  if (!validation) return [];
  const out = [];
  const resource = validation.login_resource && validation.login_resource.present
    ? validation.login_resource
    : null;
  if (resource) {
    out.push({
      kind: "file",
      text: String(resource.resource_name || "LoginRes resource"),
      title: `field20 resource · field21 ZIP ${Number(resource.blob_len || 0)}B · ${resource.zip_entry || "entry?"}`,
    });
    out.push({
      kind: resource.crc_match === true ? "state" : "type",
      text: resource.crc_match === true ? "ZIP CRC32 ✓" : resource.crc_match === false ? "ZIP CRC32 ✗" : "ZIP CRC32 未带线值",
      title: `wire=${resource.wire_crc32 || "-"} actual=${resource.actual_crc32 || "-"} confidence=${resource.confidence || "observed"}`,
    });
  }
  const antidata = validation.ace_antidata && typeof validation.ace_antidata === "object"
    ? validation.ace_antidata
    : null;
  const records = antidata && Array.isArray(antidata.records) ? antidata.records : [];
  if (records.length > 0) {
    const first = records[0] || {};
    out.push({ kind: "file", text: String(first.resource_name || "MRPCS"), title: `confidence=${first.confidence || "observed"}` });
    out.push({ kind: "type", text: String(first.report_code || "report=?"), title: `${first.carrier_kind || "carrier"} · ${Number(first.record_len || 0)}B` });
  }
  const light = validation.ace_light_feature && typeof validation.ace_light_feature === "object"
    ? validation.ace_light_feature
    : null;
  const carrier = light && light.carrier && typeof light.carrier === "object" ? light.carrier : null;
  if (carrier) {
    out.push({ kind: "carrier", text: `LightFeature ${carrier.kind || "carrier"}`, title: `${carrier.source_encoding || "-"} · decoded=${Number(carrier.decoded_length || 0)}B` });
  }
  return out;
}

function buildGcloudSummaryInsights(ev, summaryText = "") {
  if (!isGcloud65010Summary(summaryText || (ev && ev.summary), ev)) return [];
  const info = analyzeGcloudEvent(ev, summaryText);
  if (!info) return [];
  const out = [];
  if (info.kind === "control") {
    const direction = normalizeGcloudDirection(ev, info.meta);
    const control = info.control || null;
    const pair = info.pair || null;
    out.push({
      kind: "control",
      text: `${direction === "inbound" ? "9001 echo" : "9001 ping"}${control && control.ok && control.controlId !== null ? ` #${control.controlId}` : ""}`,
      title: "payload_len=0；TGCP 传输层 echo/保活，不走 4013 AES 解密。",
    });
    if (info.meta && info.meta.seq) {
      out.push({ kind: "gcloud", text: `seq ${info.meta.seq}`, title: info.meta.raw });
    }
    if (pair && Number.isFinite(Number(pair.rttMs))) {
      out.push({
        kind: "type",
        text: `RTT ${Math.round(Number(pair.rttMs))}ms`,
        title: `当前窗口匹配到另一半 index=${pair.index}`,
      });
    }
    return out;
  }
  if (info.kind === "uagame_private_fragment" && info.fragment) {
    const fragment = info.fragment;
    const markerText = fragment.markerOffset === null
      ? "marker?"
      : `abab@+${formatHexValue(fragment.markerOffset, 2)}`;
    return [{
      kind: "proto",
      text: `fragment ${fragment.family} · ${markerText}`,
      title: "UAGame private/segmented frame；marker offset 动态，未把 +0x04 误认成 opcode，未对不完整片段生成 protobuf child tree。",
    }];
  }
  if (info.kind === "ace" && info.ace) {
    const ace = info.ace;
    const carrier = ace.carrier || {};
    out.push(...gcloudUagame4013Insights(info.meta, ace.commandName));
    if (isUagameGcloudMeta(info.meta)) {
      if (ace.identity) out.push({ kind: "type", text: ace.identity, title: ace.meaning || ace.identity });
      return out;
    }
    out.push({ kind: "ace", text: gcloudCommandDisplay(ace.commandName) || ace.label, title: ace.label });
    out.push({ kind: "carrier", text: carrier.mode || "ACE carrier", title: carrier.chain || carrier.mode || "" });
    if (ace.identity) out.push({ kind: "type", text: ace.identity, title: ace.meaning || ace.identity });
    return out;
  }
  if (info.kind === "kick" && info.kick) {
    const kick = info.kick;
    out.push({ kind: "ace", text: kick.serverFreeze ? "账号冻结 / 强制下线" : "网关强制下线", title: kick.commandName });
    if (kick.codeValue !== null) out.push({ kind: "type", text: `kick_code=${kick.codeValue}`, title: kick.codeMeaning });
    if (Number.isFinite(kick.freezeDays)) out.push({ kind: "carrier", text: `冻结${kick.freezeDays}天`, title: kick.penaltyText });
    if (kick.unlockTime) out.push({ kind: "time", text: `解封 ${kick.unlockTime}`, title: kick.notice });
    return out;
  }
  if (info.kind === "tss" && info.tss) {
    const tss = info.tss;
    const carrier = tss.carrier || {};
    out.push({ kind: "ace", text: gcloudCommandDisplay(tss.commandName) || "CSTss", title: "TSS 安全通道命令" });
    out.push({ kind: "carrier", text: carrier.mode || "TSS carrier", title: carrier.chain || carrier.mode || "" });
    if (tss.identity) out.push({ kind: "type", text: tss.identity, title: tss.meaning || tss.identity });
    return out;
  }
  const proto = info.proto || null;
  const name = String(
    (proto && proto.commandDisplay)
    || gcloudCommandNameForEvent(ev, summaryText)
    || gcloudUagameOpcodeDisplay(info.meta)
    || ""
  );
  const commandDisplay = isUagameGcloudMeta(info.meta)
    ? name
    : gcloudCommandDisplay(name);
  const flow = getCurrentFlowMeta();
  const gcloudPort = gcloudTargetPortFromText(
    ev && ev.cid,
    flow && flow.last_cid,
    summaryText,
  );
  const uagameInsights = gcloudUagame4013Insights(info.meta, name);
  if (uagameInsights.length > 0) {
    out.push(...uagameInsights);
  } else {
    out.push({
      kind: "gcloud",
      text: commandDisplay || (info.meta && info.meta.commandText ? `${info.meta.commandText} ${info.meta.crypto || ""}`.trim() : `GCloud ${gcloudPort || "TGCP"}`),
      title: info.meta ? info.meta.raw : "",
    });
  }
  if (info.uagameProbe && info.uagameProbe.packed && info.uagameProbe.packed.ok) {
    out.push({
      kind: "proto",
      text: `下发 ID×${info.uagameProbe.packed.count}`,
      title: `field2 packed uint32；unique=${info.uagameProbe.packed.uniqueCount}；已完整消费当前解密 body。`,
    });
  }
  if (info.uagameProbe) {
    out.push({
      kind: info.uagameProbe.reportHits.length > 0 ? "ace" : "type",
      text: info.uagameProbe.reportHits.length > 0
        ? `01 0a report×${info.uagameProbe.reportHits.length}`
        : "01 0a report 无命中",
      title: "直接扫描解密 body，不依赖 09 4e / 0a 92 / 27 0f marker；只有同时满足记录头和长度边界才提升为 TerSafe record。",
    });
  }
  if (proto) {
    out.push({
      kind: "proto",
      text: gcloudEventPayloadStatusText(proto, info.meta),
      title: gcloudProtoStatusText(proto),
    });
    if (proto.module) out.push({ kind: "type", text: proto.module, title: "protobuf field[8] module" });
  } else if (isUagameGcloudMeta(info.meta)) {
    out.push({
      kind: "proto",
      text: "UAGame body",
      title: "已按 UAGame 20001 的 40-byte envelope 提取 body；当前 body 不强制假设为 protobuf。",
    });
  }
  return out;
}

function appendGcloudKv(grid, label, value) {
  const text = String(value || "").trim();
  if (!text) return;
  const item = document.createElement("div");
  item.className = "gcloud-kv";
  const key = document.createElement("div");
  key.className = "gcloud-kv-label";
  key.textContent = label;
  const val = document.createElement("div");
  val.className = "gcloud-kv-value";
  val.textContent = text;
  item.appendChild(key);
  item.appendChild(val);
  grid.appendChild(item);
}

function appendGcloudFact(grid, row, wide = false) {
  const text = String(row && row.value ? row.value : "").trim();
  if (!text) return;
  const item = document.createElement("div");
  item.className = `gcloud-fact${wide ? " gcloud-fact-wide" : ""}`;
  const label = document.createElement("span");
  label.className = "gcloud-fact-label";
  label.textContent = String(row && row.label ? row.label : "-");
  const value = document.createElement("span");
  value.className = "gcloud-fact-value";
  value.textContent = text;
  item.appendChild(label);
  item.appendChild(value);
  grid.appendChild(item);
}

function compactGcloudContextRow(row) {
  const label = String(row && row.label ? row.label : "");
  const full = String(row && row.value ? row.value : "").trim();
  let shortLabel = label;
  let value = full;
  if (label === "载荷摘要" || label === "Opaque 摘要") {
    shortLabel = "payload";
    const len = full.match(/\blen=(\d+)/i);
    const entropy = full.match(/\bentropy=([0-9.]+)/i);
    value = [len ? `${len[1]}B` : "", entropy ? `H=${entropy[1]}` : ""].filter(Boolean).join(" · ") || full;
  } else if (label === "账号/标识") {
    shortLabel = "account";
    value = full.replace(/^account=/i, "");
  } else if (label === "4013") {
    value = full.replace(/plain_len=/i, "plain ").replace(/\bpadding=/i, "padding ");
  } else if (label === "压缩") {
    shortLabel = "LZ4";
  }
  return { label: shortLabel, value, full };
}

function appendGcloudContext(rail, row) {
  const compact = compactGcloudContextRow(row);
  if (!compact.value) return;
  const item = document.createElement("span");
  item.className = "gcloud-context-item";
  item.title = compact.full;
  const label = document.createElement("strong");
  label.className = "gcloud-context-label";
  label.textContent = compact.label;
  const value = document.createElement("span");
  value.className = "gcloud-context-value";
  value.textContent = compact.value;
  item.appendChild(label);
  item.appendChild(value);
  rail.appendChild(item);
}

function appendGcloudEvidenceDetails(panel, rows) {
  if (!Array.isArray(rows) || rows.length <= 0) return;
  const details = document.createElement("details");
  details.className = "gcloud-evidence-details";
  const summary = document.createElement("summary");
  summary.textContent = `证据边界 · ${rows.length}`;
  details.appendChild(summary);
  const list = document.createElement("div");
  list.className = "gcloud-evidence-list";
  for (const row of rows) {
    const line = document.createElement("div");
    line.className = "gcloud-evidence-row";
    const label = document.createElement("strong");
    label.textContent = String(row && row.label ? row.label : "-");
    const value = document.createElement("span");
    value.textContent = String(row && row.value ? row.value : "-");
    line.appendChild(label);
    line.appendChild(value);
    list.appendChild(line);
  }
  details.appendChild(list);
  panel.appendChild(details);
}

function appendGcloudSecuritySummary(panel, info) {
  const rows = Array.isArray(info && info.rows) ? info.rows.filter((row) => String(row && row.value || "").trim()) : [];
  const primaryLabels = info.kind === "tss"
    ? ["TSS 角色", "承载链", "报告标识", "可读特征"]
    : ["反作弊角色", "节奏/关联", "承载链", "报告标识", "可读特征"];
  const contextLabels = new Set(["载荷摘要", "Opaque 摘要", "账号/标识", "4013", "压缩"]);
  const consumed = new Set(["命令"]);
  const primary = document.createElement("div");
  primary.className = "gcloud-fact-grid";
  for (const label of primaryLabels) {
    const row = rows.find((candidate) => String(candidate && candidate.label || "") === label);
    if (!row) continue;
    consumed.add(label);
    appendGcloudFact(primary, row, label === "可读特征");
  }
  if (primary.childElementCount > 0) panel.appendChild(primary);

  const rail = document.createElement("div");
  rail.className = "gcloud-context-rail";
  for (const row of rows) {
    const label = String(row && row.label || "");
    if (!contextLabels.has(label)) continue;
    consumed.add(label);
    appendGcloudContext(rail, row);
  }
  if (rail.childElementCount > 0) panel.appendChild(rail);
}

function appendGcloudReadableStrings(panel, items) {
  const rows = Array.isArray(items) ? items : [];
  if (rows.length <= 0) return;
  const block = document.createElement("section");
  block.className = "gcloud-readable";
  const title = document.createElement("div");
  title.className = "gcloud-readable-title";
  title.textContent = `明文字符串 ×${rows.length}`;
  block.appendChild(title);
  const list = document.createElement("div");
  list.className = "gcloud-readable-list";
  for (const item of rows) {
    const row = document.createElement("div");
    row.className = "gcloud-readable-string";
    row.textContent = String(item && item.text ? item.text : "");
    if (item && item.path) row.title = String(item.path);
    list.appendChild(row);
  }
  block.appendChild(list);
  panel.appendChild(block);
}

function buildGcloudPacketPanel(ev, summaryText = "") {
  const info = analyzeGcloudEvent(ev, summaryText);
  if (!info) return null;
  const panel = document.createElement("section");
  panel.className = `gcloud-brief gcloud-brief-${info.kind || "raw"}`;

  const head = document.createElement("div");
  head.className = "gcloud-head";
  const title = document.createElement("div");
  title.className = "gcloud-title";
  title.textContent = info.title || "GCloud/TGCP";
  head.appendChild(title);
  const chips = document.createElement("div");
  chips.className = "gcloud-chip-list";
  const visibleChips = (Array.isArray(info.chips) ? info.chips : [])
    .filter((text) => !/^(?:seq|ctrl|msg_id|msg_seq|call_id|basis|confidence|type|ctx|method|wire key_len)=/i.test(String(text || "")))
    .slice(0, 5);
  for (const text of visibleChips) {
    const chip = document.createElement("span");
    chip.className = `gcloud-chip${info.kind === "control" ? " gcloud-chip-control" : ""}${info.kind === "proto" ? " gcloud-chip-proto" : ""}${info.kind === "ace" || info.kind === "tss" ? " gcloud-chip-ace" : ""}${info.kind === "kick" ? " gcloud-chip-kick" : ""}`;
    chip.textContent = text;
    chips.appendChild(chip);
  }
  head.appendChild(chips);
  panel.appendChild(head);

  const readableStrings = gcloudReadableStringsForEvent(ev, info.proto);

  const grid = document.createElement("div");
  grid.className = "gcloud-kv-grid";
  for (const row of gcloudProtocolDisplayRows(info, ev, summaryText, readableStrings)) {
    appendGcloudKv(grid, row.label, row.value);
  }
  if (grid.childElementCount > 0) panel.appendChild(grid);

  appendGcloudReadableStrings(panel, readableStrings);

  const protoTree = info.proto ? buildGcloudProtoTree(info.proto, info.protoBytes || info.bytes) : null;
  if (protoTree) {
    const details = document.createElement("details");
    details.className = "gcloud-tree-details";
    details.open = info.kind !== "ace" && info.kind !== "tss" && info.kind !== "kick";
    const summary = document.createElement("summary");
    const count = info.proto && Array.isArray(info.proto.flat) ? info.proto.flat.length : info.nodeRows.length;
    summary.textContent = `${info.kind === "ace" || info.kind === "tss" ? "Protobuf 外层" : "Layout / fields / value / hex"} ×${count}`;
    details.appendChild(summary);
    details.appendChild(protoTree);
    panel.appendChild(details);
  }

  if (!protoTree && Array.isArray(info.nodeRows) && info.nodeRows.length > 0) {
    const details = document.createElement("details");
    details.className = "gcloud-node-details";
    details.open = !protoTree;
    const summary = document.createElement("summary");
    summary.textContent = `字段 / value ×${info.nodeRows.length}`;
    details.appendChild(summary);
    const list = document.createElement("div");
    list.className = "gcloud-node-list";
    for (const row of info.nodeRows) {
      const nodeRow = document.createElement("div");
      nodeRow.className = "gcloud-node-row";
      if (row.rawPath) nodeRow.title = `${row.path} · ${row.rawPath}`;
      const path = document.createElement("div");
      path.className = "gcloud-node-path";
      path.textContent = row.path;
      if (row.rawPath) path.title = row.rawPath;
      const value = document.createElement("div");
      value.className = "gcloud-node-value";
      value.textContent = row.value;
      nodeRow.appendChild(path);
      nodeRow.appendChild(value);
      list.appendChild(nodeRow);
    }
    details.appendChild(list);
    panel.appendChild(details);
  } else if (info.kind === "control") {
    const note = document.createElement("div");
    note.className = "gcloud-note";
    note.textContent = "9001 是 45 字节 header-only echo/保活帧；当前抓包中由客户端主动发起，服务端用相同 24 字节扩展字段回声。";
    panel.appendChild(note);
  }

  return panel;
}

function buildGcloudValidationPanel(ev) {
  const validation = getGcloudProducerValidation(ev);
  if (!validation) return null;

  const panel = document.createElement("section");
  panel.className = "gcloud-brief gcloud-validation-panel";
  const head = document.createElement("div");
  head.className = "gcloud-head";
  const title = document.createElement("div");
  title.className = "gcloud-title";
  title.textContent = "GCloud 验证证据 · MRPCS / CSAce / CRC";
  head.appendChild(title);
  const chips = document.createElement("div");
  chips.className = "gcloud-chip-list";

  const command = validation.command && typeof validation.command === "object" ? validation.command : {};
  const resource = validation.login_resource && typeof validation.login_resource === "object"
    ? validation.login_resource
    : null;
  const antidata = validation.ace_antidata && typeof validation.ace_antidata === "object"
    ? validation.ace_antidata
    : null;
  const records = antidata && Array.isArray(antidata.records) ? antidata.records : [];
  const light = validation.ace_light_feature && typeof validation.ace_light_feature === "object"
    ? validation.ace_light_feature
    : null;
  const relation = validation.ace_relation && typeof validation.ace_relation === "object"
    ? validation.ace_relation
    : null;
  const chipTexts = [
    command.name || "GCloud",
    command.confidence ? `command:${command.confidence}` : "",
    resource && resource.present ? resource.resource_name : "",
    resource && resource.present ? `ZIP ${Number(resource.blob_len || 0)}B` : "",
    resource && resource.present && resource.crc_match === true ? "CRC32 MATCH" : "",
    records.length > 0 ? records[0].resource_name : "",
    records.length > 0 ? records[0].report_code : "",
    light && light.carrier ? `LightFeature ${light.carrier.kind || "carrier"}` : "",
  ].filter(Boolean);
  for (const text of chipTexts.slice(0, 8)) {
    const chip = document.createElement("span");
    chip.className = "gcloud-chip gcloud-chip-ace";
    chip.textContent = String(text);
    chips.appendChild(chip);
  }
  head.appendChild(chips);
  panel.appendChild(head);

  const grid = document.createElement("div");
  grid.className = "gcloud-kv-grid";
  appendGcloudKv(
    grid,
    "命令证据",
    `${command.name || "未识别"} · ${command.direction || "direction?"} · confidence=${command.confidence || "inferred"}`,
  );
  if (resource && resource.present) {
    const entries = Array.isArray(resource.zip_entries)
      ? resource.zip_entries.map((item) => `${item.name} (${Number(item.size || 0)}B, crc=${item.crc32 || "-"})`).join("  |  ")
      : String(resource.zip_entry || "");
    appendGcloudKv(grid, "LoginRes 资源", `field20=${resource.resource_name || "-"} · field21=${resource.blob_type || "zip"} ${Number(resource.blob_len || 0)}B · confidence=${resource.confidence || "observed"}`);
    appendGcloudKv(grid, "ZIP entry", entries || "中央目录为空");
    appendGcloudKv(grid, "ZIP blob CRC32", `field22 wire=${resource.wire_crc32 || "-"} · actual=${resource.actual_crc32 || "-"} · match=${resource.crc_match === true ? "true" : resource.crc_match === false ? "false" : "unknown"}`);
    appendGcloudKv(grid, "LoginRes flag", `field23=${resource.flag ?? "-"}`);
  } else if (resource) {
    appendGcloudKv(grid, "LoginRes 资源", `当前 payload 未形成完整 field20+field21 ZIP bundle · ${resource.reason || "not present"}`);
  }
  for (const [index, record] of records.entries()) {
    appendGcloudKv(
      grid,
      `AntiData MRPCS #${index + 1}`,
      `${record.resource_name || "MRPCS"} · report=${record.report_code || "-"} · carrier=${record.carrier_kind || "-"} · record=${Number(record.record_len || 0)}B · request_flag=${record.request_flag ?? "-"} · confidence=${record.confidence || "observed"}`,
    );
  }
  if (antidata && records.length <= 0) {
    appendGcloudKv(grid, "AntiData", `命令已观察，当前 payload 未见完整 MRPCS record · ${antidata.evidence || ""}`);
  }
  if (light) {
    const carrier = light.carrier && typeof light.carrier === "object" ? light.carrier : {};
    const envelope = carrier.envelope && typeof carrier.envelope === "object" ? carrier.envelope : null;
    appendGcloudKv(grid, "LightFeature carrier", `${carrier.kind || "unresolved"} · encoding=${carrier.source_encoding || "-"} · decoded=${Number(carrier.decoded_length || 0)}B · confidence=${light.confidence || "observed"}`);
    if (envelope) {
      appendGcloudKv(grid, "LightFeature envelope", `type=${envelope.type ?? "-"} · xor_key=${envelope.xor_key ?? "-"} · feature=0x${Number(envelope.raw_feature_id || 0).toString(16).padStart(4, "0")} · common=0x${Number(envelope.common_protocol_id || 0).toString(16).padStart(4, "0")} · schema=${envelope.schema_or_version ?? "-"} · payload=${Number(envelope.payload_length || 0)}B`);
    } else if (carrier.kind) {
      appendGcloudKv(grid, "LightFeature 字段边界", `fixed64_family=${carrier.fixed64_family || "-"} · field_semantics=${carrier.field_semantics || "unresolved"}`);
    }
  }
  if (relation) {
    appendGcloudKv(grid, "Transfer/Ack 边界", `${relation.role || "relation"} · confidence=${relation.confidence || "inferred"} · ${relation.boundary || ""}`);
  }
  appendGcloudKv(grid, "证据等级", validation.boundary || "confirmed / observed / inferred 分层展示");
  panel.appendChild(grid);
  return panel;
}

function buildWssJsonPanel(ev, summaryText = "") {
  if (!isWssJsonSummary(summaryText, ev)) return null;
  const analysis = getWssJsonAnalysis(ev);
  if (!analysis) return null;
  const transport = analysis.transport && typeof analysis.transport === "object" ? analysis.transport : {};
  const jsonInfo = analysis.json && typeof analysis.json === "object" ? analysis.json : {};
  const resource = analysis.feature_resource && typeof analysis.feature_resource === "object"
    ? analysis.feature_resource
    : null;
  const method = String(jsonInfo.method || readSummaryValue(summaryText, "method") || "unknown");

  const panel = document.createElement("section");
  panel.className = "gcloud-brief gcloud-validation-panel wss-json-panel";
  const head = document.createElement("div");
  head.className = "gcloud-head";
  const title = document.createElement("div");
  title.className = "gcloud-title";
  title.textContent = "Lobby WSS JSON · MRPCS / CRC";
  head.appendChild(title);
  const chips = document.createElement("div");
  chips.className = "gcloud-chip-list";
  const archive = resource && resource.archive && typeof resource.archive === "object" ? resource.archive : {};
  const chipTexts = [
    method,
    Number(ev && ev.dir) === 0 ? "C→S" : "S→C",
    jsonInfo.valid === true ? "JSON plaintext" : "JSON invalid",
    resource ? resource.feature_name : "",
    resource && resource.crc_match === true ? "blob CRC32 MATCH" : "",
    archive.valid === true ? `ZIP ${Number(archive.entry_count || 0)} entry` : "",
  ].filter(Boolean);
  for (const text of chipTexts) {
    const chip = document.createElement("span");
    chip.className = "gcloud-chip gcloud-chip-ace";
    chip.textContent = String(text);
    chips.appendChild(chip);
  }
  head.appendChild(chips);
  panel.appendChild(head);

  const grid = document.createElement("div");
  grid.className = "gcloud-kv-grid";
  appendGcloudKv(
    grid,
    "传输边界",
    `wss:// TLS 在线加密；当前为 mitmproxy 解密后的 payload · app=${transport.application_payload || "unknown"}`,
  );
  appendGcloudKv(
    grid,
    "WSS 路径",
    `${transport.host || "-"}${transport.path || "/"} · query_stored=${transport.query_stored === false ? "false" : "unknown"}`,
  );
  appendGcloudKv(
    grid,
    "JSON 方法",
    `${jsonInfo.method_key || "method"}=${method} · keys=${Array.isArray(jsonInfo.keys) ? jsonInfo.keys.join(", ") : "-"}`,
  );

  if (resource) {
    appendGcloudKv(
      grid,
      "ACE featureName",
      `${resource.feature_name || "-"} · kind=${resource.kind || "ace_feature_resource_push"} · confidence=${resource.confidence || "observed"}`,
    );
    appendGcloudKv(
      grid,
      "featureData",
      `Base64=${resource.base64_valid === true ? "valid" : "invalid"} · decoded=${Number(resource.blob_len || 0)}B · sha256=${resource.blob_sha256 || "-"}`,
    );
    appendGcloudKv(
      grid,
      "dataCRC",
      `wire=${resource.wire_crc32 || "-"} · actual=${resource.actual_crc32 || "-"} · match=${resource.crc_match === true ? "true" : resource.crc_match === false ? "false" : "unknown"} · scope=${resource.crc_scope || "unresolved"}`,
    );
    if (archive.valid === true) {
      const entries = Array.isArray(archive.entries) ? archive.entries : [];
      for (const [index, entry] of entries.entries()) {
        appendGcloudKv(
          grid,
          `ZIP entry #${index + 1}`,
          `${entry.name || "-"} · ${Number(entry.actual_size ?? entry.size ?? 0)}B · wire_crc=${entry.wire_crc32 || "-"} · actual_crc=${entry.actual_crc32 || "-"} · match=${entry.crc_match === true ? "true" : entry.crc_match === false ? "false" : "unknown"} · sha256=${entry.sha256 || "-"}`,
        );
      }
    } else {
      appendGcloudKv(grid, "ZIP", archive.reason || resource.reason || "not validated");
    }
    appendGcloudKv(
      grid,
      "跨 flow 边界",
      "只确认当前 WSS flow 的资源字段；与 65010 LightFeature/MRPCS 仅作同族命名参考，未证明直接关联，也不是解密密钥。",
    );
  }
  panel.appendChild(grid);
  return panel;
}

function eventPrefixText(ev) {
  const chunks = [];
  for (const key of ["pfx", "before_pfx", "full_pfx", "raw_pfx"]) {
    const bytes = bytesFromHexPrefix(ev && ev[key], 192);
    if (bytes.length <= 0) continue;
    const text = extractPrintableRuns(bytes, 3, 8)
      .map((item) => String(item && item.text ? item.text : "").trim())
      .filter(Boolean)
      .join(" ; ");
    if (text) chunks.push(text);
  }
  return chunks.join(" ; ");
}

function eventDecodedSignalText(ev) {
  const chunks = [];
  const seenPayloads = new Set();
  for (const key of ["before_pay", "pay", "full_pay"]) {
    const base64Text = String(ev && ev[key] ? ev[key] : "");
    if (!base64Text || seenPayloads.has(base64Text)) continue;
    seenPayloads.add(base64Text);
    const bytes = b64ToBytesLimited(base64Text, 512);
    if (bytes.length <= 0) continue;
    const text = extractPrintableRuns(bytes, 3, 14)
      .map((item) => String(item && item.text ? item.text : "").trim())
      .filter(Boolean)
      .join(" ; ");
    if (text) chunks.push(text);
  }
  return chunks.join(" ; ");
}

function extractSummarySection(summaryText, name) {
  const safeName = escapeRegexLiteral(name);
  const match = String(summaryText || "").match(new RegExp(`\\[${safeName}:([^\\]]+)\\]`));
  return match ? String(match[1] || "").trim() : "";
}

function shortClockFromDateText(value) {
  const text = String(value || "");
  const match = text.match(/\b\d{4}-\d{2}-\d{2}\s+(\d{2}:\d{2}:\d{2})\b/);
  return match ? match[1] : text;
}

function shortClockFromEpochSeconds(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds)) return "";
  try {
    const { hh, mi, ss } = displayTimeParts(seconds * 1000);
    return `${hh}:${mi}:${ss}`;
  } catch (_e) {
    return "";
  }
}

function timestampSecondsFromToken(rawText) {
  const raw = String(rawText || "").trim();
  if (!/^\d{10}(?:\d{3})?$/.test(raw)) return null;
  const value = Number(raw);
  if (!Number.isFinite(value)) return null;
  const seconds = raw.length === 13 ? Math.floor(value / 1000) : value;
  return isPlausibleTimestampSeconds(seconds) ? seconds : null;
}

function timestampCountLabel(count, triplet = false) {
  const n = Math.max(0, Math.floor(Number(count) || 0));
  if (triplet) return "三时间";
  if (n <= 1) return "时间";
  return `时间×${n}`;
}

function parseTimestampAnalysisItems(analysisText) {
  const items = [];
  for (const match of String(analysisText || "").matchAll(/(?:^|[;\s])([^;\s=]+?)=(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/g)) {
    const key = String(match[1] || "").trim();
    const dateText = String(match[2] || "").trim();
    if (!key || /^(now|flow_start)$/i.test(key)) continue;
    const clock = shortClockFromDateText(dateText);
    if (!clock) continue;
    const parsed = key.match(/^(.+?):([^:@\s]+)(?:@0x([0-9a-f]+))?$/i);
    items.push({
      key,
      label: parsed ? parsed[1] : key,
      kind: parsed ? parsed[2] : "",
      offset: parsed && parsed[3] ? Number.parseInt(parsed[3], 16) : NaN,
      dateText,
      clock,
    });
  }
  return items;
}

function timestampSecondsFromDateTimeText(dateText) {
  const text = String(dateText || "").trim();
  if (!text) return null;
  const parsed = new Date(text.replace(" ", "T"));
  const seconds = Math.floor(parsed.getTime() / 1000);
  return isPlausibleTimestampSeconds(seconds) ? seconds : null;
}

function parseSummaryChildTimestampHints(summaryText) {
  const analysis = extractSummarySection(summaryText, "时间分析");
  const out = new Map();
  for (const item of parseTimestampAnalysisItems(analysis)) {
    const label = String(item && item.label ? item.label : "").trim();
    const match = label.match(/^child(\d+)\/(0x[0-9a-f]+)$/i);
    const absoluteOffset = Number(item && item.offset);
    if (!match || !Number.isFinite(absoluteOffset)) continue;
    const childIndex = Number.parseInt(match[1], 10);
    const hint = {
      childIndex,
      report: String(match[2] || "").toLowerCase(),
      field: String(item && item.kind ? item.kind : "summary_time"),
      absoluteOffset,
      dateText: String(item && item.dateText ? item.dateText : ""),
      clock: String(item && item.clock ? item.clock : ""),
      seconds: timestampSecondsFromDateTimeText(item && item.dateText),
    };
    const list = out.get(childIndex) || [];
    list.push(hint);
    out.set(childIndex, list);
  }
  return out;
}

function findContinuousObTimestampTriplet(items) {
  const byLabel = new Map();
  for (const item of Array.isArray(items) ? items : []) {
    const kindMatch = String(item && item.kind ? item.kind : "").match(/^ob([567])_(?:s|ms)$/i);
    if (!kindMatch) continue;
    const label = String(item && item.label ? item.label : "").trim();
    if (!label) continue;
    const bucket = byLabel.get(label) || new Map();
    const index = Number(kindMatch[1]);
    if (!bucket.has(index)) bucket.set(index, item);
    byLabel.set(label, bucket);
  }

  for (const [label, bucket] of byLabel.entries()) {
    if (![5, 6, 7].every((index) => bucket.has(index))) continue;
    const triplet = [bucket.get(5), bucket.get(6), bucket.get(7)];
    const offsets = triplet.map((item) => Number(item && item.offset));
    const offsetsKnown = offsets.every((value) => Number.isFinite(value));
    if (offsetsKnown && !(offsets[0] < offsets[1] && offsets[1] < offsets[2])) continue;
    return { label, items: triplet };
  }
  return null;
}

function compactTimeInsight(summaryText) {
  const analysis = extractSummarySection(summaryText, "时间分析");
  const analysisItems = parseTimestampAnalysisItems(analysis);
  const triplet = findContinuousObTimestampTriplet(analysisItems);
  if (triplet) {
    const shown = triplet.items.map((item) => `${String(item.kind || "").replace(/_s$/i, "")} ${item.clock}`);
    const detail = triplet.items
      .map((item) => `${item.kind}@${Number.isFinite(Number(item.offset)) ? formatHexValue(item.offset) : "?"}=${item.dateText}`)
      .join(" / ");
    return {
      kind: "time",
      text: `${timestampCountLabel(3, true)} ${shown.join(" / ")}`,
      title: `${triplet.label} 连续 ob5/ob6/ob7：${detail}${analysis ? ` | ${analysis}` : ""}`,
    };
  }

  const explicit = [];
  for (const item of analysisItems) {
    if (!item.clock || explicit.includes(item.clock)) continue;
    explicit.push(item.clock);
  }
  if (explicit.length > 0) {
    const shown = explicit.slice(0, 3);
    return {
      kind: "time",
      text: `${timestampCountLabel(explicit.length)} ${shown.join(" / ")}`,
      title: analysis,
    };
  }

  const timePacket = extractSummarySection(summaryText, "时间包");
  const seconds = [];
  for (const match of timePacket.matchAll(/\b1[5-9]\d{8}\b/g)) {
    const clock = shortClockFromEpochSeconds(match[0]);
    if (clock && !seconds.includes(clock)) seconds.push(clock);
    if (seconds.length >= 3) break;
  }
  if (seconds.length > 0) {
    const shown = seconds.slice(0, 3);
    return {
      kind: "time",
      text: `${timestampCountLabel(seconds.length)} ${shown.join(" / ")}`,
      title: timePacket,
    };
  }
  return null;
}

function compactPacketSemanticInsight(ev) {
  const info = getEventPacketSemanticInfo(ev);
  if (!info) return null;
  return {
    kind: "semantic",
    text: info.text,
    title: info.title || info.text,
  };
}

function semanticTierLabel(value) {
  const labels = {
    confirmed: "确定",
    observed: "观察",
    approximate: "推测",
    unknown: "未知",
    high: "高置信",
  };
  const key = String(value || "unknown").toLowerCase();
  return labels[key] || String(value || "未知");
}

function summarizeStructuredChildSemantics(children) {
  // UAGAME_COMPACT_SUMMARY_V2: compact rows and human-readable child details.
  const items = Array.isArray(children) ? children.filter((item) => item && typeof item === "object") : [];
  if (items.length <= 0) return null;
  const distribution = new Map();
  const concrete = new Map();
  let confirmed = 0;
  let approximate = 0;
  let unknown = 0;
  for (const child of items) {
    const label = String(child.semantic_label_zh || child.semantic_role || "未解析记录").trim();
    distribution.set(label, (distribution.get(label) || 0) + 1);
    const tier = String(child.semantic_tier || child.semantic_role_confidence || "unknown").toLowerCase();
    const exact = child.semantic_exact_meaning === true || tier === "confirmed" || tier === "observed";
    if (exact) confirmed += 1;
    else if (tier === "approximate") approximate += 1;
    else unknown += 1;
    const generic = /(?:候选|待证|未解析|未知|unresolved|unknown|shape\s*未完整)/i.test(label);
    if (!generic) concrete.set(label, (concrete.get(label) || 0) + 1);
  }
  const countBits = [`子项${items.length}`];
  if (confirmed > 0) countBits.push(`确定${confirmed}`);
  if (approximate > 0) countBits.push(`推测${approximate}`);
  if (unknown > 0) countBits.push(`未知${unknown}`);
  const concreteBits = Array.from(concrete.entries())
    .sort((left, right) => Number(right[1]) - Number(left[1]))
    .slice(0, 2)
    .map(([label, count]) => `${label}${count > 1 ? `×${count}` : ""}`);
  const fullDistribution = Array.from(distribution.entries())
    .sort((left, right) => Number(right[1]) - Number(left[1]))
    .map(([label, count]) => `${label}×${count}`)
    .join(" / ");
  return {
    kind: "child",
    text: [...countBits, ...concreteBits].join(" · "),
    countText: countBits.join(" · "),
    title: `child 语义分布：${fullDistribution}`,
    total: items.length,
    confirmed,
    approximate,
    unknown,
    genericOnly: concreteBits.length <= 0,
  };
}

function compactStructuredSemanticInsights(ev) {
  const semantic = ev && ev.analysis && typeof ev.analysis === "object" ? ev.analysis : null;
  if (!semantic || semantic.schema !== "tersafe.semantic.v1") return [];
  const packet = semantic.packet && typeof semantic.packet === "object" ? semantic.packet : {};
  const semanticActions = Array.isArray(semantic.actions) ? semantic.actions : [];
  const firstAction = semanticActions.find((item) => (
    item && item.source_seq !== undefined && item.source_seq !== null
  )) || semanticActions[0] || {};
  const reportCode = String(packet.report_code || "").trim();
  const rawRole = String(
    packet.semantic_label_zh
      || packet.semantic_role
      || (packet.shape && packet.shape.semantic_role)
      || packet.role
      || "未知角色"
  ).trim();
  const isParent = /(?:^|0x)010a001b$/i.test(reportCode)
    || String(packet.semantic_role || packet.role || "") === "parent_container";
  const payloadRole = isParent ? "父容器" : rawRole;
  const tier = String(packet.semantic_tier || packet.semantic_role_confidence || "unknown").toLowerCase();
  const tierText = tier === "confirmed" || tier === "observed" ? "" : semanticTierLabel(tier);
  const childSummary = summarizeStructuredChildSemantics(packet.children);
  const stateBits = [reportCode, payloadRole, tierText].filter(Boolean);
  if (isParent && childSummary) stateBits.push(childSummary.countText);
  const out = [{
    kind: "state",
    text: stateBits.join(" · "),
    title: [
      `report=${reportCode || "-"}`,
      `family=${packet.report_family || "-"}`,
      childSummary ? childSummary.title : "",
    ].filter(Boolean).join(" | "),
  }];
  if (childSummary && !isParent && !childSummary.genericOnly) out.push(childSummary);

  const actionText = String(semantic.action || "").trim();
  const boringAction = /^(?:只读解析|观察动作|observe_only|read_only|原包透传)$/i.test(actionText);
  if (semanticActions.length > 0 || (actionText && !boringAction)) {
    const sourceBits = [];
    if (firstAction.source_seq !== undefined && firstAction.source_seq !== null) {
      sourceBits.push(`8091#${firstAction.source_seq}`);
    }
    if (Number.isFinite(Number(semantic.source_age_ms))) {
      sourceBits.push(`${Number(semantic.source_age_ms)}ms`);
    }
    if (firstAction.shape_match) sourceBits.push(String(firstAction.shape_match));
    sourceBits.push(actionText || "动作");
    out.push({ kind: "semantic", text: sourceBits.join(" → "), title: String(semantic.reason || "") });
  }

  const correlation = semantic.response_correlation && typeof semantic.response_correlation === "object"
    ? semantic.response_correlation
    : null;
  if (correlation && correlation.status && !["request_anchor", "unresolved"].includes(String(correlation.status))) {
    const responseText = [
      correlation.response_report_code || packet.report_code || "response",
      correlation.request_seq ? `← req#${correlation.request_seq}` : correlation.status,
      Number.isFinite(Number(correlation.delta_ms)) ? `${Number(correlation.delta_ms)}ms` : "",
      Number(correlation.burst_index || 0) > 1 ? `burst×${Number(correlation.burst_index)}` : "",
    ].filter(Boolean).join(" ");
    out.push({ kind: "type", text: responseText, title: correlation.status });
  }
  return out;
}

function compactSynthesisInsight(summaryText) {
  const raw = String(summaryText || "").trim();
  if (!raw || !/(?:\[SYNTH\]|\blocal_semantic_synthesis\b|\bchild_synth=[1-9]\d*)/.test(raw)) {
    return null;
  }
  const synthCount = readSummaryValue(raw, "child_synth") || "1";
  const detailMatch = raw.match(/\b(pubgm_outer_type_[^\]\s]+)/);
  const detail = detailMatch ? detailMatch[1] : "";
  return {
    kind: "synth",
    text: [
      "SYNTH",
      `child_synth=${synthCount}`,
      "local_semantic_synthesis",
      detail,
    ].filter(Boolean).join(" · "),
    title: raw,
  };
}

function isOpaqueUndecryptedSummary(summaryText) {
  return /(?:\[OPAQUE\]|\bundecrypted_outer_control(?:_passthrough)?\b|\bopaque_value_preserved\b)/.test(
    String(summaryText || "")
  );
}

function compactOpaqueInsight(summaryText) {
  const raw = String(summaryText || "").trim();
  if (!isOpaqueUndecryptedSummary(raw)) return null;
  const shapeMatch = raw.match(/\b(pubgm_outer_type_[^\]\s]+)/);
  return {
    kind: "opaque",
    text: [
      "OPAQUE",
      "未解密外层",
      "value保持",
      shapeMatch ? shapeMatch[1] : "",
    ].filter(Boolean).join(" · "),
    title: raw,
  };
}

function collectPacketSignalMatches(sourceText, regex, maxItems = 2) {
  const out = [];
  const seen = new Set();
  regex.lastIndex = 0;
  for (const match of String(sourceText || "").matchAll(regex)) {
    const raw = String(match && match[0] ? match[0] : "")
      .replace(/^[,;|\s]+|[,;|\s]+$/g, "")
      .trim();
    if (!raw) continue;
    const key = raw.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(raw);
    if (out.length >= maxItems) break;
  }
  return out;
}

function compactPacketTextInsights(ev, summaryText) {
  const sourceText = `${String(summaryText || "")} ; ${eventPrefixText(ev)} ; ${eventDecodedSignalText(ev)}`;
  const items = [];
  const seen = new Set();
  const add = (kind, prefix, value, maxLen = 58) => {
    const text = String(value || "").trim();
    if (!text) return;
    const key = `${kind}:${text.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    const displayText = Number.isFinite(Number(maxLen)) && Number(maxLen) > 0
      ? compactText(text, Number(maxLen))
      : text;
    items.push({
      kind,
      text: `${prefix} ${displayText}`,
      title: text,
    });
  };

  for (const value of collectPacketSignalMatches(sourceText, PACKET_FILE_REFERENCE_REGEX, 2)) {
    add("file", "文件", value, 48);
  }
  for (const value of collectPacketSignalMatches(sourceText, PACKET_STATE_REFERENCE_REGEX, 1)) {
    add("state", "状态", value, 58);
  }
  const deviceMatch = sourceText.match(/model:[^;\s|]+(?:;ver:[^;\s|]+)?(?:;inc_id:[^;\s|]+)?(?:;obf_id:[^;\s|]+)?/i);
  if (deviceMatch) {
    add("device", "设备", deviceMatch[0], 0);
  }
  return items;
}

function compactChildInsight(summaryText) {
  const counts = parseChildSummaryCounts(summaryText);
  const total = Number.parseInt(counts.total, 10);
  if (!Number.isFinite(total) || total <= 0) return null;
  const changed = Number.parseInt(counts.changed, 10);
  const kept = Number.parseInt(counts.kept, 10);
  const clean = Number.parseInt(counts.clean, 10);
  const nodeCounts = innerNodeIdCounts(readSummaryValue(summaryText, "node_id"));
  const actionCounts = childActionSummaryCounts(summaryText);
  const useActionCounts = actionCounts.total === total;
  const bits = [`child ${total}`];
  if (Number.isFinite(changed) && changed > 0) bits.push(`改${changed}`);
  if (useActionCounts) {
    if (actionCounts.replace > 0) bits.push(`替换${actionCounts.replace}`);
    if (actionCounts.keep > 0) bits.push(`保留${actionCounts.keep}`);
    if (actionCounts.clean > 0) bits.push(`清理${actionCounts.clean}`);
    if (actionCounts.drop > 0) bits.push(`删除${actionCounts.drop}`);
  } else {
    if (Number.isFinite(nodeCounts.replace)) bits.push(`替换${nodeCounts.replace}`);
    if (Number.isFinite(nodeCounts.keep)) bits.push(`保留${nodeCounts.keep}`);
    if (Number.isFinite(nodeCounts.clean)) bits.push(`清理${nodeCounts.clean}`);
    if (Number.isFinite(nodeCounts.drop) && nodeCounts.drop > 0) bits.push(`删除${nodeCounts.drop}`);
    if (!Number.isFinite(nodeCounts.keep) && Number.isFinite(kept) && kept > 0) bits.push(`保留${kept}`);
    if (!Number.isFinite(nodeCounts.clean) && Number.isFinite(clean) && clean > 0) bits.push(`清理${clean}`);
  }
  return {
    kind: "child",
    text: bits.join(" "),
    title: String(summaryText || ""),
  };
}

function compactFlowRoleText(reportText, role) {
  const parsed = parseReportCodeNumber(reportText);
  const raw = String(role || "").trim();
  if (parsed === 0x010a001b) return "父容器";
  return raw
    .replace(/\/批量上报骨架/g, "")
    .replace(/批量上报骨架/g, "")
    .trim();
}

function compactTypeInsight(summaryText) {
  const kv = parseSummaryKeyValues(summaryText);
  const reportText = formatReportCodeText(kv.report || kv.code);
  const role = compactFlowRoleText(reportText, decodeSummaryToken(kv.role));
  if (reportText === "-" && !role) return null;
  return {
    kind: "type",
    text: [reportText !== "-" ? reportText : "", role || reportBusinessLabel(reportText)].filter(Boolean).join(" "),
    title: [reportText, role, decodeSummaryToken(kv.hint)].filter(Boolean).join(" | "),
  };
}

function buildSummaryInsightStrip(ev, summaryText) {
  const hasStructuredSemantic = !!(
    ev && ev.analysis && typeof ev.analysis === "object" && ev.analysis.schema === "tersafe.semantic.v1"
  );
  const isGcloud = isGcloud65010Summary(summaryText, ev);
  const isWssJson = isWssJsonSummary(summaryText, ev);
  if (!isDecodedFlowEvent(ev, summaryText) && !hasStructuredSemantic && !isGcloud && !isWssJson) return null;
  const candidates = isGcloud
    ? buildGcloudSummaryInsights(ev, summaryText).filter(Boolean)
    : isWssJson
      ? buildWssSummaryInsights(ev, summaryText).filter(Boolean)
      : hasStructuredSemantic
        ? [
          compactOpaqueInsight(summaryText),
          compactSynthesisInsight(summaryText),
          ...compactStructuredSemanticInsights(ev),
          compactPacketSemanticInsight(ev),
          ...compactPacketTextInsights(ev, summaryText),
          compactTimeInsight(summaryText),
        ].filter(Boolean)
        : [
          compactOpaqueInsight(summaryText),
          compactSynthesisInsight(summaryText),
          compactPacketSemanticInsight(ev),
          ...compactPacketTextInsights(ev, summaryText),
          compactChildInsight(summaryText),
          compactTypeInsight(summaryText),
          compactTimeInsight(summaryText),
        ].filter(Boolean);
  if (candidates.length <= 0) return null;
  const strip = document.createElement("span");
  strip.className = "summary-insights";
  const seen = new Set();
  const maxItems = hasStructuredSemantic ? 4 : 5;
  for (const item of candidates) {
    const text = String(item && item.text || "").trim();
    const key = text.toLowerCase();
    if (!text || seen.has(key)) continue;
    seen.add(key);
    const chip = document.createElement("span");
    chip.className = `summary-insight-chip${item.kind ? ` summary-insight-${item.kind}` : ""}`;
    chip.textContent = text;
    chip.title = item.title || text;
    strip.appendChild(chip);
    if (seen.size >= maxItems) break;
  }
  return strip.childElementCount > 0 ? strip : null;
}

function syncSummaryInsightStrip(summaryNode, ev, summaryText = "") {
  if (!summaryNode || typeof summaryNode.querySelectorAll !== "function") return;
  for (const node of summaryNode.querySelectorAll(".summary-insights")) {
    node.remove();
  }
  const strip = buildSummaryInsightStrip(ev, summaryText);
  if (!strip) return;
  const extra = summaryNode.querySelector(".summary-extra");
  const tail = summaryNode.querySelector(".summary-tail");
  if (extra) {
    summaryNode.insertBefore(strip, extra);
  } else if (tail) {
    summaryNode.insertBefore(strip, tail);
  } else {
    summaryNode.appendChild(strip);
  }
}

function shouldHydrateSummaryBadges(ev, summaryText = "") {
  if (!ev || typeof ev !== "object") return false;
  if (Number(ev.dir) !== 0) return false;
  if (!isDecodedFlowEvent(ev, summaryText)) return false;
  if (ev.__tcpvSummaryHydrated || ev.__tcpvSummaryHydrateStarted) return false;
  if (String(ev.pay || "") || String(ev.before_pay || "")) return false;
  return true;
}

function hydrateSummaryBadges(summaryNode, ev, summaryText = "", eventId = "") {
  const accountText = String(state.flowId || "").trim();
  const idText = String(eventId || getEventId(ev) || "").trim();
  if (!accountText || !idText || !shouldHydrateSummaryBadges(ev, summaryText)) return false;

  ev.__tcpvSummaryHydrateStarted = true;
  fetchEventPayload(accountText, idText)
    .then((detail) => {
      if (state.flowId !== accountText) return;
      if (!applyEventPayloadDetail(ev, detail)) return;
      ev.__tcpvPayloadDetailFetched = true;
      ev.__tcpvSummaryHydrated = true;
      if (gcloudAceCommandKind(gcloudCommandNameForEvent(ev, summaryText))) {
        refreshAceOverviewUi();
      }
      if (summaryNode && summaryNode.isConnected) {
        syncSummaryInsightStrip(summaryNode, ev, summaryText);
        syncSummaryHiBadge(summaryNode, ev);
        syncSummaryTimestampBadge(summaryNode, ev);
        syncSummaryIdfvBadge(summaryNode, ev, summaryText);
        syncSummaryHistoryOpenidBadge(summaryNode, ev, summaryText);
        syncEventModificationIndicator(
          summaryNode.closest("details"),
          summaryNode,
          ev,
          String(ev && ev.summary ? ev.summary : summaryText)
        );
      } else {
        schedulePreviewOffsetRender();
      }
    })
    .catch((_e) => {
      ev.__tcpvSummaryHydrateStarted = false;
    });
  return true;
}

function printableStats(byteValues) {
  const printable = [];
  let alpha = 0;
  let digit = 0;
  let slashCount = 0;
  let dotCount = 0;
  let spaceCount = 0;
  for (const byte of byteValues) {
    if (byte < 32 || byte >= 127) continue;
    printable.push(byte);
    const ch = String.fromCharCode(byte);
    if ((byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)) alpha += 1;
    if (byte >= 48 && byte <= 57) digit += 1;
    if (ch === "/") slashCount += 1;
    if (ch === ".") dotCount += 1;
    if (ch === " ") spaceCount += 1;
  }
  let maxRun = 0;
  let curRun = 0;
  let prev = -1;
  for (const byte of printable) {
    if (byte === prev) {
      curRun += 1;
    } else {
      curRun = 1;
      prev = byte;
    }
    if (curRun > maxRun) maxRun = curRun;
  }
  return {
    printable: printable.length,
    alpha,
    digit,
    slashCount,
    dotCount,
    spaceCount,
    uniquePrintables: new Set(printable).size,
    maxRun,
  };
}

function buildAsciiPreview(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  let out = "";
  for (const byte of byteValues) {
    out += byte >= 32 && byte < 127 ? String.fromCharCode(byte) : ".";
  }
  return out;
}

function formatHexBytePreview(byteValues, limit = 16) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  const max = Math.max(1, Number(limit || 16));
  return byteValues
    .slice(0, max)
    .map((byte) => (byte & 0xff).toString(16).padStart(2, "0"))
    .join(" ");
}

function formatHexBytesCompact(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  return byteValues.map((byte) => (byte & 0xff).toString(16).padStart(2, "0")).join("");
}

function formatHexSignature(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  const headLimit = 32;
  const tailLimit = 16;
  if (byteValues.length <= headLimit + tailLimit + 8) {
    return `all=${formatHexBytePreview(byteValues, byteValues.length)}`;
  }
  const head = formatHexBytePreview(byteValues, headLimit);
  const tail = formatHexBytePreview(byteValues.slice(-tailLimit), tailLimit);
  return `head=${head} tail=${tail}`;
}

function xorByteValues(byteValues, key) {
  const xorKey = Number(key || 0) & 0xff;
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
  return byteValues.map((byte) => (byte ^ xorKey) & 0xff);
}

function summarizeFixedXorSegment(byteValues, key = 0xb6, baseOff = 0, label = "") {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  const decoded = xorByteValues(byteValues, key);
  const extracted = extractPrintableRuns(decoded, 3, 5);
  const runs = extracted
    .map((item) => `${formatHexValue(Number(baseOff || 0) + Number(item.off || 0))}:${shortenText(item.text, 48)}`)
    .filter(Boolean);
  if (runs.length <= 0) return "";
  const score = extracted.reduce((total, item) => total + String(item.text || "").length, 0);
  return JSON.stringify({
    label,
    key,
    score,
    text: `key=${formatHexValue(key, 2)}${label ? ` base=${label}` : ""} ${runs.join(" | ")}`,
  });
}

function summarizeFixedXor(record, reportCode, key = 0xb6) {
  if (!Array.isArray(record) || record.length <= 0) return "";
  const candidates = [];
  if (Number(reportCode) === 0x0102000a && record.length > 36) {
    candidates.push(summarizeFixedXorSegment(record.slice(36), key, 36, "body16"));
    candidates.push(summarizeFixedXorSegment(record.slice(32), key, 32, "body12"));
    candidates.push(summarizeFixedXorSegment(record.slice(20), key, 20, "payload"));
  }
  candidates.push(summarizeFixedXorSegment(record, key, 0, "record"));
  let best = null;
  for (const raw of candidates) {
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw);
      if (!best || Number(parsed.score || 0) > Number(best.score || 0)) {
        best = parsed;
      }
    } catch {
      continue;
    }
  }
  return best ? String(best.text || "") : "";
}

function summarizeCommonFixedXor(record, reportCode) {
  const previews = [];
  const seen = new Set();
  for (const key of XOR_COMMON_KEYS) {
    const preview = summarizeFixedXor(record, reportCode, key);
    if (!preview) continue;
    const dedupeKey = `${key}:${preview}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    previews.push(preview);
  }
  return previews.join(" ; ");
}

function buildCommonXorPreviewItems(payload, bodyRelOffCandidates = [12, 16]) {
  if (!Array.isArray(payload) || payload.length <= 0) return [];
  const items = [];
  const seen = new Set();
  for (const bodyRelOff of bodyRelOffCandidates) {
    if (payload.length <= bodyRelOff) continue;
    const body = payload.slice(bodyRelOff);
    const bodyOff = 20 + bodyRelOff;
    for (const key of XOR_COMMON_KEYS) {
      const decoded = xorByteValues(body, key);
      const runs = extractPrintableRuns(decoded, 3, 4);
      if (!runs.length) continue;
      const score = runs.reduce((total, item) => total + String(item.text || "").length, 0);
      if (score < 6) continue;
      const preview = runs
        .slice(0, 3)
        .map((item) => `${formatHexValue(bodyOff + Number(item.off || 0))}:${shortenText(item.text, 48)}`)
        .join(" | ");
      const dedupeKey = `${key}:${bodyRelOff}:${preview}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      items.push({
        off: bodyOff,
        text: `key=${formatHexValue(key, 2)} base=body${bodyRelOff} ${preview}`,
        kind: "common-xor",
        score,
      });
    }
  }
  items.sort((a, b) => Number(b.score || 0) - Number(a.score || 0));
  return items.slice(0, 8);
}

function scoreXorCandidate(decodedBytes, runs) {
  const stats = printableStats(decodedBytes);
  const lowerText = buildAsciiPreview(decodedBytes).toLowerCase();
  const keywordHits = XOR_TEXT_KEYWORDS.filter((token) => lowerText.includes(token));

  let score = stats.printable;
  score += stats.alpha * 2;
  score += stats.digit;
  score += stats.slashCount;
  score += stats.dotCount * 2;
  score += stats.spaceCount;
  score += stats.uniquePrintables * 2;
  score += keywordHits.length * 30;
  if (stats.alpha < 8) {
    score -= stats.slashCount * 4;
    score -= stats.dotCount * 2;
    score -= stats.spaceCount;
  }
  if (stats.maxRun > 8) {
    score -= (stats.maxRun - 8) * 6;
  }
  if (stats.uniquePrintables < 6) {
    score -= (6 - stats.uniquePrintables) * 10;
  }
  if (stats.alpha === 0 && keywordHits.length === 0) {
    score -= 80;
  }
  const longestRunLen = runs.reduce((maxLen, item) => Math.max(maxLen, String(item.text || "").length), 0);
  const bestRunUnique = runs.reduce((maxLen, item) => Math.max(maxLen, new Set(String(item.text || "")).size), 0);
  return {
    score,
    keywordHits,
    stats,
    longestRunLen,
    bestRunUnique,
  };
}

function pickBestSingleByteXor(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return null;
  let best = null;
  const isBetterRank = (left, right) => {
    for (let i = 0; i < left.length; i++) {
      const a = Number(left[i] || 0);
      const b = Number(right[i] || 0);
      if (a > b) return true;
      if (a < b) return false;
    }
    return false;
  };
  for (let key = 0; key < 256; key++) {
    const decoded = byteValues.map((byte) => byte ^ key);
    const runs = extractPrintableRuns(decoded, 3, 6);
    if (runs.length <= 0) continue;
    const scored = scoreXorCandidate(decoded, runs);
    const candidate = {
      key,
      runs,
      decoded,
      ...scored,
    };
    if (!best) {
      best = candidate;
      continue;
    }
    const rank = [
      candidate.score,
      candidate.keywordHits.length,
      candidate.longestRunLen,
      candidate.bestRunUnique,
      candidate.stats.alpha,
      candidate.stats.uniquePrintables,
    ];
    const bestRank = [
      best.score,
      best.keywordHits.length,
      best.longestRunLen,
      best.bestRunUnique,
      best.stats.alpha,
      best.stats.uniquePrintables,
    ];
    if (isBetterRank(rank, bestRank)) {
      best = candidate;
    }
  }
  return best;
}

function analyzeDecodedSliceXor(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length < 36) return null;
  const recType = readBe16(byteValues, 6);
  const subcode = readBe16(byteValues, 8);
  if (recType !== 0x0102 || subcode !== 0x000a) {
    return null;
  }

  const payload = byteValues.slice(20, 20 + ANALYSIS_XOR_SCAN_MAX_BYTES);
  if (payload.length < 16) return null;

  const baseInfo = {
    recType,
    subcode,
    innerLen: readBe16(payload, 0),
    innerType: readBe16(payload, 2),
    innerConst1: readBe32(payload, 4),
    innerConst2: readBe32(payload, 8),
    innerField: readBe32(payload, 12),
  };

  let bestChoice = null;
  for (const bodyRelOff of [12, 16]) {
    if (payload.length <= bodyRelOff) continue;
    const best = pickBestSingleByteXor(payload.slice(bodyRelOff));
    if (!best) continue;
    let adjustedScore = best.score;
    if (best.keywordHits.length > 0) adjustedScore += 40;
    if (best.stats.alpha >= 12 && best.stats.uniquePrintables >= 10) adjustedScore += 20;
    if (best.stats.maxRun > 8) adjustedScore -= 20;
    const candidate = {
      bodyRelOff,
      adjustedScore,
      best,
    };
    if (!bestChoice) {
      bestChoice = candidate;
      continue;
    }
    if (
      candidate.adjustedScore > bestChoice.adjustedScore ||
      (candidate.adjustedScore === bestChoice.adjustedScore && candidate.bodyRelOff > bestChoice.bodyRelOff)
    ) {
      bestChoice = candidate;
    }
  }
  if (!bestChoice) return null;

  const bodyOff = 20 + bestChoice.bodyRelOff;
  const commonPreviews = buildCommonXorPreviewItems(payload, [12, 16]);
  const runs = bestChoice.best.runs
    .map((item) => ({
      off: bodyOff + Number(item.off || 0),
      text: shortenText(item.text, 96),
      kind: inferStringKind(item.text),
    }))
    .filter((item) => isDisplayableDecodedRun(item.text, item.kind));
  return {
    ...baseInfo,
    bodyOff,
    key: bestChoice.best.key,
    score: bestChoice.best.score,
    preview: shortenText(runs.map((item) => item.text).join(" | "), 120),
    keywordHits: bestChoice.best.keywordHits,
    runs,
    commonPreviews,
  };
}

function isLikelyTssReportCode(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return false;
  const family = (num >>> 16) & 0xffff;
  return family === 0x010a || family === 0x0102 || family === 0x0112;
}

function detectTssReport(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length < 4) return null;
  for (const offset of [6, 0, 3]) {
    const value = readBe32(byteValues, offset);
    if (isLikelyTssReportCode(value)) {
      return { value, offset };
    }
  }
  return null;
}

const TSS_CRYPTO_KEY_LABELS = [
  "CHAGQX",
  "Q_VA[\\R",
  "SYSZZ",
  "]P@XQA",
  "CE]AQ",
  "[TK",
  "QDF\\",
  "D^GP\\",
  "CA@Z@P",
  "WIX_83qpt",
];
const TSS_FAMILY1_SBOX = [
  0x09d0c479, 0x28c8ffe0, 0x84aa6c39, 0x9dad7287, 0x7dff9be3, 0xd4268361, 0xc96da1d4, 0x7974cc93,
  0x85d0582e, 0x2a4b5705, 0x1ca16a62, 0xc3bd279d, 0x0f1f25e5, 0x5160372f, 0xc695c1fb, 0x4d7ff1e4,
  0xae5f6bf4, 0x0d72ee46, 0xff23de8a, 0xb1cf8e83, 0xf14902e2, 0x3e981e42, 0x8bf53eb6, 0x7f4bf8ac,
  0x83631f83, 0x25970205, 0x76afe784, 0x3a7931d4, 0x4f846450, 0x5c64c3f6, 0x210a5f18, 0xc6986a26,
  0x28f4e826, 0x3a60a81c, 0xd340a664, 0x7ea820c4, 0x526687c5, 0x7eddd12b, 0x32a11d1d, 0x9c9ef086,
  0x80f6e831, 0xab6f04ad, 0x56fb9b53, 0x8b2e095c, 0xb68556ae, 0xd2250b0d, 0x294a7721, 0xe21fb253,
  0xae136749, 0xe82aae86, 0x93365104, 0x99404a66, 0x78a784dc, 0xb69ba84b, 0x04046793, 0x23db5c1e,
  0x46cae1d6, 0x2fe28134, 0x5a223942, 0x1863cd5b, 0xc190c6e3, 0x07dfb846, 0x6eb88816, 0x2d0dcc4a,
  0xa4ccae59, 0x3798670d, 0xcbfa9493, 0x4f481d45, 0xeafc8ca8, 0xdb1129d6, 0xb0449e20, 0x0f5407fb,
  0x6167d9a8, 0xd1f45763, 0x4daa96c3, 0x3bec5958, 0xababa014, 0xb6ccd201, 0x38d6279f, 0x02682215,
  0x8f376cd5, 0x092c237e, 0xbfc56593, 0x32889d2c, 0x854b3e95, 0x05bb9b43, 0x7dcd5dcd, 0xa02e926c,
  0xfae527e5, 0x36a1c330, 0x3412e1ae, 0xf257f462, 0x3c4f1d71, 0x30a2e809, 0x68e5f551, 0x9c61ba44,
  0x5ded0ab8, 0x75ce09c8, 0x9654f93e, 0x698c0cca, 0x243cb3e4, 0x2b062b97, 0x0f3b8d9e, 0x00e050df,
  0xfc5d6166, 0xe35f9288, 0xc079550d, 0x0591aee8, 0x8e531e74, 0x75fe3578, 0x2f6d829a, 0xf60b21ae,
  0x95e8eb8d, 0x6699486b, 0x901d7d9b, 0xfd6d6e31, 0x1090acef, 0xe0670dd8, 0xdab2e692, 0xcd6d4365,
  0xe5393514, 0x3af345f0, 0x6241fc4d, 0x460da3a3, 0x7bcf3729, 0x8bf1d1e0, 0x14aac070, 0x1587ed55,
  0x3afd7d3e, 0xd2f29e01, 0x29a9d1f6, 0xefb10c53, 0xcf3b870f, 0xb414935c, 0x664465ed, 0x024acac7,
  0x59a744c1, 0x1d2936a7, 0xdc580aa6, 0xcf574ca8, 0x040a7a10, 0x6cd81807, 0x8a98be4c, 0xaccea063,
  0xc33e92b5, 0xd1e0e03d, 0xb322517e, 0x2092bd13, 0x386b2c4a, 0x52e8dd58, 0x58656dfb, 0x50820371,
  0x41811896, 0xe337ef7e, 0xd39fb119, 0xc97f0df6, 0x68fea01b, 0xa150a6e5, 0x55258962, 0xeb6ff41b,
  0xd7c9cd7a, 0xa619cd9e, 0xbcf09576, 0x2672c073, 0xf003fb3c, 0x4ab7a50b, 0x1484126a, 0x487ba9b1,
  0xa64fc9c6, 0xf6957d49, 0x38b06a75, 0xdd805fcd, 0x63d094cf, 0xf51c999e, 0x1aa4d343, 0xb8495294,
  0xce9f8e99, 0xbffcd770, 0xc7c275cc, 0x378453a7, 0x7b21be33, 0x397f41bd, 0x4e94d131, 0x92cc1f98,
  0x5915ea51, 0x99f861b7, 0xc9980a88, 0x1d74fd5f, 0xb0a495f8, 0x614deed0, 0xb5778eea, 0x5941792d,
  0xfa90c1f8, 0x33f824b4, 0xc4965372, 0x3ff6d550, 0x4ca5fec0, 0x8630e964, 0x5b3fbbd6, 0x7da26a48,
  0xb203231a, 0x04297514, 0x2d639306, 0x2eb13149, 0x16a45272, 0x532459a0, 0x8e5f4872, 0xf966c7d9,
  0x07128dc0, 0x0d44db62, 0xafc8d52d, 0x06316131, 0xd838e7ce, 0x1bc41d00, 0x3a2e8c0f, 0xea83837e,
  0xb984737d, 0x13ba4891, 0xc4f8b949, 0xa6d6acb3, 0xa215cdce, 0x8359838b, 0x6bd1aa31, 0xf579dd52,
  0x21b93f93, 0xf5176781, 0x187dfdde, 0xe94aeb76, 0x2b38fd54, 0x431de1da, 0xab394825, 0x9ad3048f,
  0xdfea32aa, 0x659473e3, 0x623f7863, 0xf3346c59, 0xab3ab685, 0x3346a90b, 0x6b56443e, 0xc6de01f8,
  0x8d421fc0, 0x9b0ed10c, 0x88f1a1e9, 0x54c1f029, 0x7dead57b, 0x8d7ba426, 0x4cf5178a, 0x551a7cca,
  0x1a9a5f08, 0xfcd651b9, 0x25605182, 0xe11fc6c3, 0xb6fd9676, 0x337b3027, 0xb7c8eb14, 0x9e5fd030,
  0x6b57e354, 0xad913cf7, 0x7e16688d, 0x58872a69, 0x2c2fc7df, 0xe389ccc6, 0x30738df1, 0x0824a734,
  0xe1797a8b, 0xa4a8d57b, 0x5b5d193b, 0xc8a8309b, 0x73f9a978, 0x73398d32, 0x0f59573e, 0xe9df2b03,
  0xe8a5b6c8, 0x848d0704, 0x98df93c2, 0x720a1dc3, 0x684f259a, 0x943ba848, 0xa6370152, 0x863b5ea3,
  0xd17b978b, 0x6d9b58ef, 0x0a700dd4, 0xa73d36bf, 0x8e6a0829, 0x8695bc14, 0xe35b3447, 0x933ac568,
  0x8894b022, 0x2f511c27, 0xddfbcc3c, 0x006662b6, 0x117c83fe, 0x4e12b414, 0xc2bca766, 0x3a2fec10,
  0xf4562420, 0x55792e2a, 0x46f5d857, 0xceda25ce, 0xc3601d3b, 0x6c00ab46, 0xefac9c28, 0xb3c35047,
  0x611dfee3, 0x257c3207, 0xfdd58482, 0x3b14d84f, 0x23becb64, 0xa075f3a3, 0x088f8ead, 0x07adf158,
  0x7796943c, 0xfacabf3d, 0xc09730cd, 0xf7679969, 0xda44e9ed, 0x2c854c12, 0x35935fa3, 0x2f057d9f,
  0x690624f8, 0x1cb0bafd, 0x7b0dbdc6, 0x810f23bb, 0xfa929a1a, 0x6d969a17, 0x6742979b, 0x74ac7d05,
  0x010e65c4, 0x86a3d963, 0xf907b5a0, 0xd0042bd3, 0x158d7d03, 0x287a8255, 0xbba8366f, 0x096edc33,
  0x21916a7b, 0x77b56b86, 0x951622f9, 0xa6c5e650, 0x8cea17d1, 0xcd8c62bc, 0xa3d63433, 0x358a68fd,
  0x0f9b9d3c, 0xd6aa295b, 0xfe33384a, 0xc000738e, 0xcd67eb2f, 0xe2eb6dc2, 0x97338b02, 0x06c9f246,
  0x419cf1ad, 0x2b83c045, 0x3723f18a, 0xcb5b3089, 0x160bead7, 0x5d494656, 0x35f8a74b, 0x1e4e6c9e,
  0x000399bd, 0x67466880, 0xb4174831, 0xacf423b2, 0xca815ab3, 0x5a6395e7, 0x302a67c5, 0x8bdb446b,
  0x108f8fa4, 0x10223eda, 0x92b8b48b, 0x7f38d0ee, 0xab2701d4, 0x0262d415, 0xaf224a30, 0xb3d88aba,
  0xf8b2c3af, 0xdaf7ef70, 0xcc97d3b7, 0xe9614b6c, 0x2baebff4, 0x70f687cf, 0x386c9156, 0xce092ee5,
  0x01e87da6, 0x6ce91e6a, 0xbb7bcc84, 0xc7922c20, 0x9d3b71fd, 0x060e41c6, 0xd7590f15, 0x4e03bb47,
  0x183c198e, 0x63eeb240, 0x2ddbf49a, 0x6d5cba54, 0x923750af, 0xf9e14236, 0x7838162b, 0x59726c72,
  0x81b66760, 0xbb2926c1, 0x48a0ce0d, 0xa6c0496d, 0xad43507b, 0x718d496a, 0x9df057af, 0x44b1bde6,
  0x054356dc, 0xde7ced35, 0xd51a138b, 0x62088cc9, 0x35830311, 0xc96efca2, 0x686f86ec, 0x8e77cb68,
  0x63e1d6b8, 0xc80f9778, 0x79c491fd, 0x1b4c67f2, 0x72698d7d, 0x5e368c31, 0xf7d95e2e, 0xa1d3493f,
  0xdcd9433e, 0x896f1552, 0x4bc4ca7a, 0xa6d1baf4, 0xa5a96dcc, 0x0bef8b46, 0xa169fda7, 0x74df40b7,
  0x4e208804, 0x9a756607, 0x038e87c8, 0x20211e44, 0x8b7ad4bf, 0xc6403f35, 0x1848e36d, 0x80bdb038,
  0x1e62891c, 0x643d2107, 0xbf04d6f8, 0x21092c8c, 0xf644f389, 0x0778404e, 0x7b78adb8, 0xa2c52d53,
  0x42157abe, 0xa2253e2e, 0x7bf3f4ae, 0x80f594f9, 0x953194e7, 0x77eb92ed, 0xb3816930, 0xda8d9336,
  0xbf447469, 0xf26d9483, 0xee6faed5, 0x71371235, 0xde425f73, 0xb4e59f43, 0x7dbe2d4e, 0x2d37b185,
  0x49dc9a63, 0x98c39d98, 0x1301c9a2, 0x389b1bbf, 0x0c18588d, 0xa421c1ba, 0x7aa3865c, 0x71e08558,
  0x3c5cfcaa, 0x7d239ca4, 0x0297d9dd, 0xd7dc2830, 0x4b37802b, 0x7428ab54, 0xaeee0347, 0x4b3fbb85,
  0x692f2f08, 0x134e578e, 0x36d9e0bf, 0xae8b5fcf, 0xedb93ecf, 0x2b27248e, 0x170eb1ef, 0x7dc57fd6,
  0x1e760f16, 0xb1136601, 0x864e1b9b, 0xd7ea7319, 0x3ab871bd, 0xcfa4d76f, 0xe31bd782, 0x0dbeb469,
  0xabb96061, 0x5370f85d, 0xffb07e37, 0xda30d0fb, 0xebc977b6, 0x0b98b40f, 0x3a4d0fe6, 0xdf4fc26b,
  0x159cf22a, 0xc298d6e2, 0x2b78ef6a, 0x61a94ac0, 0xab561187, 0x14eea0f0, 0xdf0d4164, 0x19af70ee
];
const TSS_FAMILY1_WEAK_KEY_B = [0xa4a8d57b, 0x5b5d193b, 0xc8a8309b, 0x73f9a978];
const TSS_FAMILY2_TAIL_CONST = [0x37, 0x92, 0x44, 0x68, 0xa5, 0x3d, 0xcc, 0x7f, 0xbb, 0x0f, 0xd9, 0x88, 0xee, 0x9a, 0xe9, 0x5a];
const TSS_FAMILY0_KEY_XOR = [0x8a, 0xe6, 0x9b, 0xf3, 0xc1, 0x7d, 0x40, 0x25];
let tssCrc32TableCache = null;
const tssFamily1ScheduleCache = new Map();
const tssFamily2ScheduleCache = new Map();
const tssFamily0TableCache = new Map();

function tssRol32(value, count) {
  const shift = Number(count) & 31;
  const word = Number(value) >>> 0;
  if (shift === 0) return word;
  return ((word << shift) | (word >>> (32 - shift))) >>> 0;
}

function tssRor32(value, count) {
  const shift = Number(count) & 31;
  const word = Number(value) >>> 0;
  if (shift === 0) return word;
  return ((word >>> shift) | (word << (32 - shift))) >>> 0;
}

function tssSlotRaw(slot, width = 8) {
  const label = String(TSS_CRYPTO_KEY_LABELS[Number(slot)] || "");
  const out = [];
  for (let index = 0; index < width; index += 1) {
    out.push(index < label.length ? label.charCodeAt(index) & 0xff : 0);
  }
  return out;
}

function tssWriteLe32(out, offset, value) {
  const word = Number(value) >>> 0;
  out[offset] = word & 0xff;
  out[offset + 1] = (word >>> 8) & 0xff;
  out[offset + 2] = (word >>> 16) & 0xff;
  out[offset + 3] = (word >>> 24) & 0xff;
}

function tssFamily1Schedule(slot) {
  const slotIndex = Number(slot);
  if (tssFamily1ScheduleCache.has(slotIndex)) return tssFamily1ScheduleCache.get(slotIndex);
  const raw = tssSlotRaw(slotIndex, 16);
  const t = [
    readLe32(raw, 0),
    readLe32(raw, 4),
    readLe32(raw, 8),
    readLe32(raw, 12),
    4,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ];
  const k = new Array(40).fill(0);
  const prev2 = [13, 14, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
  const prev7 = [8, 9, 10, 11, 12, 13, 14, 0, 1, 2, 3, 4, 5, 6, 7];
  const stirIdx = [14, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
  const outIdx = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6];

  for (let pass = 0; pass < 4; pass += 1) {
    for (let index = 0; index < 15; index += 1) {
      t[index] = (t[index] ^ (pass + 4 * index) ^ tssRor32((t[prev2[index]] ^ t[prev7[index]]) >>> 0, 29)) >>> 0;
    }
    for (let round = 0; round < 4; round += 1) {
      for (let index = 0; index < 15; index += 1) {
        t[index] = tssRol32((t[index] + TSS_FAMILY1_SBOX[t[stirIdx[index]] & 0x1ff]) >>> 0, 9);
      }
    }
    for (let index = 0; index < outIdx.length; index += 1) {
      k[pass * 10 + index] = t[outIdx[index]] >>> 0;
    }
  }

  for (let index = 5; index < 36; index += 2) {
    let word = (k[index] | 3) >>> 0;
    const x = (((k[index] & 0x7ffffffc) ^ (word >>> 1) ^ 0x7ffffffc) >>> 0);
    const y = (x & (x >>> 1) & (x >>> 2)) >>> 0;
    const z = (y & (y >>> 3) & (y >>> 6)) >>> 0;
    if (z) {
      let mask = ((z << 1) | (z << 2)) >>> 0;
      mask = (mask | (mask << 2)) >>> 0;
      mask = ((mask & 0xfffffffc) | ((mask << 4) >>> 0)) >>> 0;
      const rotated = tssRol32(TSS_FAMILY1_WEAK_KEY_B[k[index] & 3], k[index - 1] & 0x1f);
      word = (word ^ (rotated & mask)) >>> 0;
    }
    k[index] = word >>> 0;
  }

  tssFamily1ScheduleCache.set(slotIndex, k);
  return k;
}

function tssFamily1MarsE(input, k1, k2) {
  let m = (Number(input) + Number(k1)) >>> 0;
  let r = Math.imul(tssRol32(input, 13), Number(k2)) >>> 0;
  let l = TSS_FAMILY1_SBOX[m & 0x1ff] >>> 0;
  r = tssRol32(r, 5);
  m = tssRol32(m, r & 0x1f);
  l = (l ^ r) >>> 0;
  r = tssRol32(r, 5);
  l = (l ^ r) >>> 0;
  l = tssRol32(l, r & 0x1f);
  return { l, m, r };
}

function tssFamily1RotWordsLeft(words) {
  return [words[3], words[0], words[1], words[2]];
}

function tssFamily1DecryptBlock(block, schedule) {
  let d = [
    readLe32(block, 0),
    readLe32(block, 4),
    readLe32(block, 8),
    readLe32(block, 12),
  ];

  for (let index = 0; index < 4; index += 1) {
    d[index] = (d[index] + schedule[36 + index]) >>> 0;
  }

  for (let round = 7; round >= 0; round -= 1) {
    d = tssFamily1RotWordsLeft(d);
    d[0] = tssRor32(d[0], 24);
    d[3] = (d[3] ^ TSS_FAMILY1_SBOX[(d[0] >>> 8) & 0xff]) >>> 0;
    d[3] = (d[3] + TSS_FAMILY1_SBOX[256 + ((d[0] >>> 16) & 0xff)]) >>> 0;
    d[2] = (d[2] + TSS_FAMILY1_SBOX[(d[0] >>> 24) & 0xff]) >>> 0;
    d[1] = (d[1] ^ TSS_FAMILY1_SBOX[256 + (d[0] & 0xff)]) >>> 0;
    if (round === 2 || round === 6) d[0] = (d[0] + d[3]) >>> 0;
    if (round === 3 || round === 7) d[0] = (d[0] + d[1]) >>> 0;
  }

  for (let round = 15; round >= 0; round -= 1) {
    d = tssFamily1RotWordsLeft(d);
    d[0] = tssRor32(d[0], 13);
    const transform = tssFamily1MarsE(d[0], schedule[2 * round + 4], schedule[2 * round + 5]);
    d[2] = (d[2] - transform.m) >>> 0;
    if (round < 8) {
      d[1] = (d[1] - transform.l) >>> 0;
      d[3] = (d[3] ^ transform.r) >>> 0;
    } else {
      d[3] = (d[3] - transform.l) >>> 0;
      d[1] = (d[1] ^ transform.r) >>> 0;
    }
  }

  for (let round = 7; round >= 0; round -= 1) {
    d = tssFamily1RotWordsLeft(d);
    if (round === 0 || round === 4) d[0] = (d[0] - d[3]) >>> 0;
    if (round === 1 || round === 5) d[0] = (d[0] - d[1]) >>> 0;
    d[0] = tssRol32(d[0], 24);
    d[3] = (d[3] ^ TSS_FAMILY1_SBOX[256 + ((d[0] >>> 24) & 0xff)]) >>> 0;
    d[2] = (d[2] - TSS_FAMILY1_SBOX[(d[0] >>> 16) & 0xff]) >>> 0;
    d[1] = (d[1] - TSS_FAMILY1_SBOX[256 + ((d[0] >>> 8) & 0xff)]) >>> 0;
    d[1] = (d[1] ^ TSS_FAMILY1_SBOX[d[0] & 0xff]) >>> 0;
  }

  for (let index = 0; index < 4; index += 1) {
    d[index] = (d[index] - schedule[index]) >>> 0;
  }

  const out = new Array(16).fill(0);
  tssWriteLe32(out, 0, d[0]);
  tssWriteLe32(out, 4, d[1]);
  tssWriteLe32(out, 8, d[2]);
  tssWriteLe32(out, 12, d[3]);
  return out;
}

function tssFamily1TailTransform(data, slot) {
  const input = Array.isArray(data) ? data : [];
  const key = tssSlotRaw(slot, 8);
  return input.map((value, index) => {
    const constant = TSS_FAMILY2_TAIL_CONST[index & 15];
    const keyByte = key[index & 7];
    const delta = ((-constant) & 0xff) >>> 0;
    const mixed = ((((constant ^ Number(value) ^ keyByte) + delta) & 0xff) ^ constant) & 0xff;
    return mixed ^ keyByte;
  });
}

function tssFamily1Decrypt(cipher, slot) {
  const input = Array.isArray(cipher) ? cipher : [];
  const schedule = tssFamily1Schedule(slot);
  const out = [];
  const fullLength = input.length & ~0x0f;
  for (let offset = 0; offset < fullLength; offset += 16) {
    out.push(...tssFamily1DecryptBlock(input.slice(offset, offset + 16), schedule));
  }
  if (fullLength < input.length) {
    out.push(...tssFamily1TailTransform(input.slice(fullLength), slot));
  }
  return out;
}

function tssFamily2Schedule(slot) {
  const slotIndex = Number(slot);
  if (tssFamily2ScheduleCache.has(slotIndex)) return tssFamily2ScheduleCache.get(slotIndex);
  const schedule = new Array(44).fill(0);
  schedule[0] = 0xb7e15163;
  for (let index = 1; index < schedule.length; index += 1) {
    schedule[index] = (schedule[index - 1] + 0x9e3779b9) >>> 0;
  }
  const words = tssSlotRaw(slotIndex, 8);
  let a = 0;
  let b = 0;
  for (let round = 0; round < 132; round += 1) {
    const scheduleIndex = round % 44;
    a = schedule[scheduleIndex] = tssRol32((schedule[scheduleIndex] + a + b) >>> 0, 3);
    const wordIndex = round & 7;
    b = words[wordIndex] = tssRol32((words[wordIndex] + a + b) >>> 0, (a + b) & 31);
  }
  tssFamily2ScheduleCache.set(slotIndex, schedule);
  return schedule;
}

function tssFamily2Decrypt(cipher, slot) {
  const input = Array.isArray(cipher) ? cipher : [];
  const schedule = tssFamily2Schedule(slot);
  const out = new Array(input.length).fill(0);
  const fullLength = input.length & ~0x0f;
  for (let offset = 0; offset < fullLength; offset += 16) {
    let a = readLe32(input, offset);
    let b = readLe32(input, offset + 4);
    let c = readLe32(input, offset + 8);
    let d = readLe32(input, offset + 12);
    c = (c - schedule[43]) >>> 0;
    a = (a - schedule[42]) >>> 0;
    for (let round = 20; round > 0; round -= 1) {
      const oldA = a;
      a = d;
      d = c;
      c = b;
      b = oldA;
      const u = tssRol32(Math.imul(d, (Math.imul(2, d) + 1) >>> 0), 5);
      const t = tssRol32(Math.imul(b, (Math.imul(2, b) + 1) >>> 0), 5);
      c = (tssRor32((c - schedule[2 * round + 1]) >>> 0, t) ^ u) >>> 0;
      a = (tssRor32((a - schedule[2 * round]) >>> 0, u) ^ t) >>> 0;
    }
    d = (d - schedule[1]) >>> 0;
    b = (b - schedule[0]) >>> 0;
    tssWriteLe32(out, offset, a);
    tssWriteLe32(out, offset + 4, b);
    tssWriteLe32(out, offset + 8, c);
    tssWriteLe32(out, offset + 12, d);
  }
  const key = tssSlotRaw(slot, 8);
  for (let index = fullLength; index < input.length; index += 1) {
    const tailIndex = index - fullLength;
    const constant = TSS_FAMILY2_TAIL_CONST[tailIndex & 15];
    const keyByte = key[tailIndex & 7];
    const value = ((((constant ^ input[index] ^ keyByte) + ((-constant) & 0xff)) & 0xff) ^ constant) & 0xff;
    out[index] = value ^ keyByte;
  }
  return out;
}

function tssFamily0Decrypt(cipher, slot) {
  const slotIndex = Number(slot);
  let cached = tssFamily0TableCache.get(slotIndex);
  if (!cached) {
    const raw = tssSlotRaw(slotIndex, 8);
    const key = raw.map((value, index) => (value ^ TSS_FAMILY0_KEY_XOR[index]) & 0xff);
    const table = Array.from({ length: 256 }, (_value, index) => index);
    let seed = ((((key[5] << 16) | (key[6] << 8) | key[7]) ^ ((key[1] << 16) | (key[2] << 8) | key[3])) >>> 0);
    for (let index = 0; index < 256; index += 1) {
      seed = (Math.imul(214013, seed) + 2531011) >>> 0;
      const swapIndex = (seed >>> 16) & 0xff;
      const previous = table[index];
      table[index] = table[swapIndex];
      table[swapIndex] = previous;
    }
    const inverse = new Array(256).fill(0);
    table.forEach((value, index) => { inverse[value] = index; });
    cached = { key, table: inverse };
    tssFamily0TableCache.set(slotIndex, cached);
  }
  return (Array.isArray(cipher) ? cipher : []).map((value, index) => {
    const keyByte = cached.key[index & 7];
    return (keyByte ^ (index & 0xff) ^ cached.table[(Number(value) ^ keyByte) & 0xff]) & 0xff;
  });
}

function tssCrc32(byteValues) {
  if (!tssCrc32TableCache) {
    tssCrc32TableCache = Array.from({ length: 256 }, (_value, index) => {
      let crc = index;
      for (let bit = 0; bit < 8; bit += 1) crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1);
      return crc >>> 0;
    });
  }
  let crc = 0xffffffff;
  for (const byte of Array.isArray(byteValues) ? byteValues : []) {
    crc = (tssCrc32TableCache[(crc ^ Number(byte)) & 0xff] ^ (crc >>> 8)) >>> 0;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function parseTssEncryptedEnvelope(record) {
  if (!Array.isArray(record) || record.length < 28) return null;
  const report = detectTssReport(record);
  if (!report || report.offset !== 6 || ![0x010a0008, 0x010a0009].includes(Number(report.value))) return null;
  const version = readBe32(record, 0);
  const total = readBe16(record, 4);
  if (version !== 1 || !Number.isFinite(total) || Math.abs(Number(total) - record.length) > 4) return null;
  const family = Number(record[20]);
  const slot = Number(record[21]);
  const expectedCrc = readBe32(record, 22);
  const cipherLength = readBe16(record, 26);
  const availableLength = Math.max(0, record.length - 28);
  const validFamily = family >= 0 && family <= 2;
  const validSlot = slot >= 0 && slot < TSS_CRYPTO_KEY_LABELS.length;
  const validLength = Number.isFinite(cipherLength) && cipherLength >= 0 && cipherLength <= availableLength;
  return {
    report: report.value,
    family,
    familyName: family === 0 ? "family0_gene" : family === 1 ? "family1_mars" : family === 2 ? "family2_rc6" : `family${family}`,
    slot,
    keyLabel: validSlot ? TSS_CRYPTO_KEY_LABELS[slot] : "",
    expectedCrc,
    cipherLength,
    availableLength,
    cipher: validLength ? record.slice(28, 28 + cipherLength) : [],
    trailingLength: validLength ? Math.max(0, availableLength - cipherLength) : availableLength,
    valid: validFamily && validSlot && validLength,
    reason: !validFamily ? `不支持的 family=${family}` : !validSlot ? `slot=${slot} 越界` : !validLength ? `cipher_len=${cipherLength}，可用=${availableLength}` : "",
  };
}

function decryptTssEncryptedEnvelope(record) {
  const envelope = parseTssEncryptedEnvelope(record);
  if (!envelope) return null;
  if (!envelope.valid) return { ...envelope, supported: false, plain: [], reason: envelope.reason || "加密信封头无效" };
  const plain = envelope.family === 0
    ? tssFamily0Decrypt(envelope.cipher, envelope.slot)
    : envelope.family === 1
      ? tssFamily1Decrypt(envelope.cipher, envelope.slot)
      : tssFamily2Decrypt(envelope.cipher, envelope.slot);
  const actualCrc = tssCrc32(plain);
  const crcMatch = actualCrc === envelope.expectedCrc;
  const innerRoot = crcMatch ? detectTssReport(plain) : null;
  return {
    ...envelope,
    supported: true,
    plain,
    actualCrc,
    crcMatch,
    innerRoot,
    reason: crcMatch ? "" : `CRC mismatch: expected ${formatHexValue(envelope.expectedCrc, 8)} actual ${formatHexValue(actualCrc, 8)}`,
  };
}

function parseTssTlvRecord0013(record) {
  if (!Array.isArray(record) || record.length < 22) return null;
  const report = detectTssReport(record);
  if (!report || report.offset !== 6 || Number(report.value) !== 0x010a0013) return null;
  const version = readBe32(record, 0);
  const total = readBe16(record, 4);
  if (version !== 1 || !Number.isFinite(total) || Number(total) !== record.length) return null;
  const items = [];
  let offset = 20;
  while (offset < record.length) {
    if (offset + 2 > record.length) return { valid: false, reason: `TLV header truncated @${hexOffsetText(offset)}`, items };
    const type = Number(record[offset]);
    const length = Number(record[offset + 1]);
    const valueOffset = offset + 2;
    const end = valueOffset + length;
    if (end > record.length) return { valid: false, reason: `TLV len=${length} exceeds record @${hexOffsetText(offset)}`, items };
    const value = record.slice(valueOffset, end);
    const printable = value.every((byte) => Number(byte) >= 32 && Number(byte) < 127);
    items.push({ index: items.length, offset, type, length, valueOffset, end, value, text: printable ? String.fromCharCode(...value) : "" });
    offset = end;
  }
  return {
    valid: offset === record.length,
    reason: offset === record.length ? "" : `record tail ${record.length - offset}B`,
    version,
    total,
    headerIdHex: `0x${formatHexBytesCompact(record.slice(10, 18))}`,
    flags: readBe16(record, 18),
    items,
  };
}

function tssRecordIdentity(record, report) {
  if (report && Number(report.value) === 0x010a0013 && Array.isArray(record) && record.length >= 18) {
    return { idValue: null, idText: `0x${formatHexBytesCompact(record.slice(10, 18))}` };
  }
  return { idValue: readBe32(record, childRecordIdOffset(record, report)), idText: "" };
}

function reportName(reportCode) {
  const value = Number(reportCode);
  const names = {
    0x010a0008: "nested-encrypted-response-envelope",
    0x010a0009: "nested-encrypted-control-envelope",
    0x010a0013: "plaintext-tlv-record",
    0x010a001b: "container",
    0x010a0011: "server-acknowledged-request",
    0x010a0010: "0011-ack",
    0x0102000a: "leaf",
  };
  if (names[value]) return names[value];
  const family = (value >>> 16) & 0xffff;
  if (family === 0x0112) return "metadata";
  if (family === 0x010a) return "container/meta";
  if (family === 0x0102) return "leaf";
  return "record";
}

function classifyRecordBytes(byteValues, reportCode) {
  const report = Number(reportCode);
  if (report === 0x010a0011) return "required-server-acknowledged-request";
  if (report === 0x010a0010) return "010a0011-ack-response";
  if (report === 0x010a001b) return "container";
  if (report === 0x0102000a) {
    const runs = extractPrintableRuns(byteValues, 4, 2);
    return runs.length > 0 ? "text/binary-leaf" : "binary-like-leaf";
  }
  if (((report >>> 16) & 0xffff) === 0x0112) return "structured-metadata";
  return reportName(report);
}

function formatRecordValuePreview(byteValues, reportCode) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  const encrypted = parseTssEncryptedEnvelope(byteValues);
  if (encrypted) {
    return `${encrypted.familyName} · slot[${encrypted.slot}]${encrypted.keyLabel ? `=${encrypted.keyLabel}` : ""} · cipher ${encrypted.cipherLength}B · CRC32 ${formatHexValue(encrypted.expectedCrc, 8)}`;
  }
  const tlvRecord = parseTssTlvRecord0013(byteValues);
  if (tlvRecord && tlvRecord.valid) {
    return tlvRecord.items.map((item) => (
      `TLV[${item.index}] type=${item.type} len=${item.length}${item.text ? ` text="${item.text}"` : ""}`
    )).join(" · ");
  }
  if (Number(reportCode) === 0x0102000a) {
    const report = detectTssReport(byteValues);
    const layout = read0102000aLayout(byteValues, report);
    const bodyLayout = parseTypedBodyStructure(byteValues, layout);
    if (bodyLayout && bodyLayout.kind === "periodicProbeTable") {
      return `结构:tick=${Number(bodyLayout.tick)} entries=${bodyLayout.entries.length} ${bodyLayout.algebra}`;
    }
    if (bodyLayout && ["fixedWordBlock", "bitmapWordBlock"].includes(bodyLayout.kind)) {
      return `结构:${bodyLayout.label} words=${bodyLayout.words.length} ${bodyLayout.algebra}`;
    }
  }
  const runs = extractPrintableRuns(byteValues, 3, 4);
  const text = runs
    .map((item) => String(item.text || "").trim())
    .filter(Boolean)
    .join(" | ");
  if (text) return shortenText(text, 180);
  if (Number(reportCode) === 0x0102000a) {
    const report = detectTssReport(byteValues);
    if (report && report.offset !== 6) {
      const padded = [0, 0, 0, 1, 0, byteValues.length & 0xff, ...byteValues];
      const xor = analyzeDecodedSliceXor(padded);
      if (xor && xor.preview) return `xor:${xor.preview}`;
    }
    const xor = analyzeDecodedSliceXor(byteValues);
    if (xor && xor.preview) return `xor:${xor.preview}`;
  }
  return "";
}

function semanticProfileValue(role, category, label, tier, evidence = []) {
  return {
    role: String(role || "unresolved_payload"),
    category: String(category || "unknown"),
    label: String(label || "未解析记录"),
    tier: String(tier || "unknown"),
    evidence: Array.isArray(evidence) ? evidence.map(String) : [],
  };
}

function semanticAsciiView(byteValues) {
  if (!Array.isArray(byteValues)) return "";
  return byteValues
    .map((byte) => (Number(byte) >= 32 && Number(byte) < 127 ? String.fromCharCode(Number(byte)) : " "))
    .join("");
}

function localChildSemanticProfile(record, reportCode) {
  const report = Number(reportCode);
  const rawLower = semanticAsciiView(record).toLowerCase();
  if (parseTssEncryptedEnvelope(record)) {
    return report === 0x010a0008
      ? semanticProfileValue("nested_encrypted_tss_response", "response.crypto_envelope", "TSS 内层加密响应封套", "observed", ["report_010a0008", "family_slot_crc_cipher_len"])
      : semanticProfileValue("nested_encrypted_tss_control", "control.crypto_envelope", "TSS 内层加密控制封套", "observed", ["report_010a0009", "family_slot_crc_cipher_len"]);
  }
  const tlvRecord = parseTssTlvRecord0013(record);
  if (tlvRecord && tlvRecord.valid) {
    return semanticProfileValue("plaintext_tlv_text_record", "control.tlv_text", "明文 TLV 文本记录", "observed", ["report_010a0013", "20_byte_header", "u8_type_u8_length", "length_closes_record"]);
  }
  if (report === 0x010a001b) return semanticProfileValue("parent_container", "report.container", "批量上报父容器", "confirmed", ["report_code"]);
  if (report === 0x010a0011) return semanticProfileValue("server_acknowledged_child_request", "control.acknowledged_child_request", "服务器确认型子请求（保活/握手候选）", "confirmed", ["paired_leaf_id", "010a0010_ack"]);
  if (report === 0x010a0010) return semanticProfileValue("010a0011_ack_response", "response.ack", "010a0011 子请求回执（leaf_id 回显）", "confirmed", ["paired_leaf_id", "status_0324"]);
  if (report === 0x010a0036) return semanticProfileValue("sync_file_marker", "control.resource_sync", "配置/规则文件同步标记", "observed", ["report_code", "resource_name"]);
  if (report === 0x010a0056) return semanticProfileValue("sync_file_save_request", "control.resource_sync", "同步文件保存请求", "observed", ["report_code"]);
  if ([0x010a0024, 0x010a0027, 0x010a0044, 0x010a0057].includes(report)) {
    return semanticProfileValue("response_feedback_fields", "response.feedback", "响应反馈/状态字段", "observed", ["fixed_response_offsets", "timeline_required"]);
  }

  if (report === 0x0102000a) {
    const reportInfo = detectTssReport(record);
    const layout = read0102000aLayout(record, reportInfo);
    if (!layout) return semanticProfileValue("typed_leaf_unresolved_shape", "telemetry.typed_leaf", "探测遥测叶子（shape 未完整）", "approximate", ["report_family"]);
    const body = record.slice(Math.min(record.length, Number(layout.bodyStart || 0)));
    const bodyLayout = parseTypedBodyStructure(record, layout);
    if (bodyLayout && bodyLayout.kind === "periodicProbeTable") {
      return semanticProfileValue(
        "periodic_probe_schedule_table",
        "telemetry.probe_scheduler",
        "周期探测调度与结果表（probe_id 含义待证）",
        "observed",
        ["body_len_4_plus_n_times_6", "u16_probe_id_raw32_value", "historical_monotonic_tick", "relative_to_probe_0x8000"],
      );
    }
    if (bodyLayout && bodyLayout.kind === "fixedWordBlock") {
      return semanticProfileValue(
        "fixed_probe_word_block",
        "telemetry.binary_probe.words",
        "固定字状态探测块（字段含义待证）",
        "observed",
        ["body_u32_slots", "inner_type_0x2001", "full_shape"],
      );
    }
    if (bodyLayout && bodyLayout.kind === "bitmapWordBlock") {
      return semanticProfileValue(
        "probe_bitmap_or_capability_mask",
        "telemetry.binary_probe.bitmap",
        "位图/能力掩码探测块（bit 含义待证）",
        "observed",
        ["body_u32_slots", "zero_and_ffffffff_masks", "inner_type_0x2011", "full_shape"],
      );
    }
    const xorLower = semanticAsciiView(xorByteValues(body, 0xb6)).toLowerCase();
    const combined = `${rawLower} ${xorLower}`;
    const knownTime = KNOWN_0102000A_TIMESTAMP_LAYOUTS.find((shape) => layoutMatchesKnownTimestampShape(layout, shape));
    if (knownTime && String(knownTime.label || "").includes("current")) {
      return semanticProfileValue("typed_timestamp_current", "telemetry.time.current", "当前采样时间", "confirmed", ["full_shape", knownTime.label]);
    }
    if (knownTime && String(knownTime.label || "").includes("session")) {
      return semanticProfileValue("typed_timestamp_session_baseline", "telemetry.time.session_baseline", "会话/缓存基准时间", "observed", ["full_shape", knownTime.label]);
    }
    if (/uiwindow|uitransitionview|uidropshadowview|\buiview\b/.test(combined)) {
      return semanticProfileValue("ui_hierarchy_probe", "environment.ui_hierarchy", "UI 层级/前台窗口探测", "observed", ["xor_text", "ui_tokens", "full_shape"]);
    }
    const hasModule = /\.dylib|\.framework|\/usr\/lib|frameworks\/|\.so\b/.test(combined);
    const hasProcess = /backboardd|backboardservices|springboard|mediaserverd|chronod|duetexpertd|thermalmonitord|locationd|\blogd\b|com\.apple|coremotion|corebrightness|corefoundation/.test(combined);
    if (hasModule && hasProcess) return semanticProfileValue("module_process_integrity_probe", "environment.module_process", "动态库/进程组合探测", "observed", ["xor_text", "module_token", "process_token"]);
    if (hasModule) return semanticProfileValue("module_or_dylib_path_probe", "environment.module_integrity", "动态库/Framework 路径探测", "observed", ["xor_text", "module_token"]);
    if (hasProcess) return semanticProfileValue("process_or_callstack_probe", "environment.process_stack", "系统进程/调用栈探测", "observed", ["xor_text", "process_token"]);
    if (Number(layout.innerType) === 0x100b) return semanticProfileValue("ui_hierarchy_probe_candidate", "environment.ui_hierarchy", "UI 层级探测（近似）", "approximate", ["inner_type_0x100b", "historical_shape_family"]);
    if ([0x1105, 0x2000, 0xfff2].includes(Number(layout.innerType))) return semanticProfileValue("module_path_probe_candidate", "environment.module_integrity", "模块/动态库路径探测（近似）", "approximate", [`inner_type_${formatHexValue(layout.innerType, 4)}`, "historical_shape_family"]);
    if ([0x8027, 0x8029].includes(Number(layout.innerType))) return semanticProfileValue("process_stack_probe_candidate", "environment.process_stack", "进程/调用栈探测（近似）", "approximate", [`inner_type_${formatHexValue(layout.innerType, 4)}`, "historical_shape_family"]);
    return semanticProfileValue("typed_leaf_binary_probe", "telemetry.binary_probe", "稳定二进制探测/遥测（字段待证）", "approximate", ["full_shape", `inner_type_${formatHexValue(layout.innerType, 4)}`]);
  }

  if (((report >>> 16) & 0xffff) === 0x0112) {
    const hasCsob = ["cs:", ",ob:", "state:", ",r:", ",p:"].every((token) => rawLower.includes(token));
    const hasCsobCandidate = ["cs:", "state:", ",r:", ",p:"].every((token) => rawLower.includes(token));
    const hasDevice = /model:|ver:/.test(rawLower);
    const hasFile = /config2\.dat|config3\.dat|comm\.zip|mrpcs_i|\.data/.test(rawLower);
    if (hasCsob) return semanticProfileValue("csob_state_snapshot", "metadata.state.csob", "CSOB 状态快照", "confirmed", ["cs", "ob", "state", "r", "p"]);
    if (hasCsobCandidate) return semanticProfileValue(
      "csob_state_candidate_missing_ob",
      "metadata.state.csob_candidate",
      `CSOB 状态候选（缺少 ob）${hasDevice ? " + 设备画像" : ""}`,
      "observed",
      ["cs", "state", "r", "p", "missing_ob"],
    );
    if (hasDevice && hasFile) return semanticProfileValue("device_profile_with_file_reference", "metadata.device_profile", "设备画像 + 配置文件引用", "observed", ["model_ver", "file_name"]);
    if (hasDevice) return semanticProfileValue("device_profile_metadata", "metadata.device_profile", "设备型号/系统版本画像", "observed", ["model_ver"]);
    if (hasFile || /\bdl:/.test(rawLower)) return semanticProfileValue("configuration_file_observation", "metadata.file_reference", "配置/规则文件引用", "observed", ["file_name"]);
    if (/state:|cnt:|counter/.test(rawLower)) return semanticProfileValue("state_or_counter_metadata", "metadata.state", "状态/计数元数据", "observed", ["state_counter_key"]);
    if (/idevidfv:|itsssdkuuid:|iappmachuuid:/.test(rawLower)) return semanticProfileValue("device_identity_metadata", "metadata.device_identity", "设备身份标识元数据", "observed", ["device_identifier_key"]);
    if (/vpn:|language:|iscreencaptured:|ios_tp_api/.test(rawLower)) return semanticProfileValue("device_environment_metadata", "metadata.device_environment", "设备环境/开关标签", "observed", ["environment_label"]);
    if (/historyopenid:|openid|account/.test(rawLower)) return semanticProfileValue("account_history_metadata", "metadata.account", "账号/OpenID 历史元数据", "observed", ["account_key"]);
    if (/apple root ca|certification authority/.test(rawLower)) return semanticProfileValue("certificate_or_trust_observation", "metadata.trust", "证书/信任材料观察", "observed", ["certificate_text"]);
    if (/iteamid:|teamid:/.test(rawLower)) return semanticProfileValue("signing_team_metadata", "metadata.signing", "签名 TeamID 元数据", "observed", ["team_id_key"]);
    if (/iappversion:|iappinfo:/.test(rawLower)) return semanticProfileValue("application_version_metadata", "metadata.application", "应用版本/组件元数据", "observed", ["app_version_key"]);
    if (/framework|\.dylib/.test(rawLower)) return semanticProfileValue("module_or_framework_observation", "metadata.module", "模块/Framework 元数据", "observed", ["module_text"]);
    if (/addlistener|hdmioutput/.test(rawLower)) return semanticProfileValue("runtime_api_or_output_route_observation", "metadata.runtime", "运行时 API/输出路由元数据", "observed", ["runtime_api_text"]);
    if (/error/.test(rawLower)) return semanticProfileValue("error_observation", "metadata.error", "错误/异常元数据", "observed", ["error_text"]);
    return semanticProfileValue("dynamic_metadata_context", "metadata.context", "结构化元数据（具体子项待证）", "approximate", ["metadata_family"]);
  }

  const family = (report >>> 16) & 0xffff;
  if (family === 0x010a) return semanticProfileValue("control_or_feedback_record", "control.protocol", "控制/反馈记录（具体字段待证）", "approximate", ["report_family_0x010a"]);
  if (family === 0x0102) return semanticProfileValue("telemetry_leaf", "telemetry.leaf", "探测遥测叶子（具体字段待证）", "approximate", ["report_family_0x0102"]);
  return semanticProfileValue("unresolved_payload", "unknown", "未解析记录", "unknown", []);
}

function attachLocalChildSemantic(child, record) {
  if (!child || child.truncated) return child;
  const profile = localChildSemanticProfile(record, child.reportCode);
  child.semanticRole = profile.role;
  child.semanticCategory = profile.category;
  child.semanticLabel = profile.label;
  child.semanticTier = profile.tier;
  child.semanticEvidence = profile.evidence;
  const reportInfo = Number(child.reportCode) === 0x0102000a ? detectTssReport(record) : null;
  child.typedLayout = reportInfo ? read0102000aLayout(record, reportInfo) : null;
  child.bodyLayout = child.typedLayout ? parseTypedBodyStructure(record, child.typedLayout) : null;
  if (child.bodyLayout) {
    child.xorCommonPreview = "";
  }
  return child;
}

function isBinaryLikeLeafRecord(record, reportCode) {
  return Number(reportCode) === 0x0102000a && classifyRecordBytes(record, reportCode) === "binary-like-leaf";
}

function summarizeBinaryLikeChildren(children) {
  const binaryChildren = (Array.isArray(children) ? children : []).filter(
    (child) => !child.truncated && child.className === "binary-like-leaf"
  );
  if (binaryChildren.length <= 0) return "";
  const byLen = new Map();
  const byReport = new Map();
  const signatures = [];
  for (const child of binaryChildren) {
    const len = Number(child.len || 0);
    byLen.set(len, (byLen.get(len) || 0) + 1);
    const reportText = child.reportCode !== null ? formatHexValue(child.reportCode, 8) : "-";
    byReport.set(reportText, (byReport.get(reportText) || 0) + 1);
    const sig = String(child.hexSignature || "").replace(/^head=/, "");
    if (sig && signatures.length < 4) {
      signatures.push(`child[${child.index}]:${sig}`);
    }
  }
  const lenText = Array.from(byLen.entries())
    .sort((a, b) => Number(a[0]) - Number(b[0]))
    .map(([len, count]) => `${len}x${count}`)
    .join(",");
  const reportText = Array.from(byReport.entries())
    .sort((a, b) => String(a[0]).localeCompare(String(b[0])))
    .map(([report, count]) => `${report}x${count}`)
    .join(",");
  const sigText = signatures.length > 0 ? ` sig=${signatures.join(" ; ")}` : "";
  return `binary_like_stats count=${binaryChildren.length} lengths=${lenText} reports=${reportText}${sigText}`;
}

function childRecordIdOffset(record, report) {
  if (!report || !Array.isArray(record)) return 10;
  return Number(report.offset || 0) + 4;
}

function extractTimestampCandidatesFromText(text) {
  const matches = String(text || "").match(/\b1[5-9]\d{8}(?:\d{3})?\b/g) || [];
  const unique = [];
  const seen = new Set();
  for (const raw of matches) {
    if (seen.has(raw)) continue;
    seen.add(raw);
    unique.push(raw);
    if (unique.length >= 6) break;
  }
  return unique;
}

function extractTimestampCandidatesFromRecord(record) {
  if (!Array.isArray(record) || record.length === 0) return [];
  const text = extractPrintableRuns(record, 3, 64)
    .map((run) => String(run && run.text ? run.text : ""))
    .join(" ");
  return extractTimestampCandidatesFromText(text);
}

function parseTssChildrenAt(byteValues, startOffset, maxChildren = 256) {
  const children = [];
  let offset = Number(startOffset || 0);
  for (let index = 0; index < maxChildren && offset < byteValues.length; index += 1) {
    if (offset + 4 > byteValues.length) {
      break;
    }
    let childLen = readLe32(byteValues, offset);
    let lengthEndian = "le";
    if (!Number.isFinite(childLen) || childLen <= 0 || offset + 4 + childLen > byteValues.length) {
      const beLen = readBe32(byteValues, offset);
      if (Number.isFinite(beLen) && beLen > 0 && offset + 4 + beLen <= byteValues.length) {
        childLen = beLen;
        lengthEndian = "be";
      }
    }
    if (!Number.isFinite(childLen) || childLen <= 0 || offset + 4 + childLen > byteValues.length) {
      break;
    }
    const record = byteValues.slice(offset + 4, offset + 4 + childLen);
    const report = detectTssReport(record);
    if (!report || !isLikelyTssReportCode(report.value)) {
      break;
    }
    const reportCode = report.value;
    const identity = tssRecordIdentity(record, report);
    const valuePreview = formatRecordValuePreview(record, reportCode);
    const className = classifyRecordBytes(record, reportCode);
    const timestampCandidates = extractTimestampCandidatesFromRecord(record);
    children.push({
      index,
      offset,
      len: childLen,
      lengthEndian,
      reportCode,
      reportOffset: report ? report.offset : -1,
      idValue: identity.idValue,
      idText: identity.idText,
      className,
      valuePreview,
      timestampCandidates,
      hexSignature: className === "binary-like-leaf" ? formatHexSignature(record) : "",
      xorCommonPreview: className === "binary-like-leaf" ? summarizeCommonFixedXor(record, reportCode) : "",
    });
    attachLocalChildSemantic(children[children.length - 1], record);
    offset += 4 + childLen;
  }
  return {
    children,
    consumed: offset - Number(startOffset || 0),
    endOffset: offset,
    complete: children.length > 0 && offset === byteValues.length,
  };
}

function buildParentContainerInfo(byteValues, parsedChildren, options = {}) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return null;
  const childStartOffset = Math.max(0, Math.floor(Number(options.childStartOffset || 0)));
  const countOffset = Math.max(0, Math.floor(Number(options.countOffset || 0)));
  const declaredCount = Math.max(0, Math.floor(Number(options.declaredCount || 0)));
  const parsed = parsedChildren && typeof parsedChildren === "object" ? parsedChildren : {};
  const rawChildrenEndOffset = Number(parsed.endOffset);
  const childrenEndOffset = Number.isFinite(rawChildrenEndOffset)
    ? Math.max(0, Math.min(byteValues.length, Math.floor(rawChildrenEndOffset)))
    : childStartOffset;
  const tailBytes = byteValues.slice(childrenEndOffset);
  const tailHex = formatHexBytesCompact(tailBytes);
  return {
    layout: String(options.layout || ""),
    countOffset,
    childCount: declaredCount,
    headerLen: childStartOffset,
    childStartOffset,
    childrenEndOffset,
    childBytesLen: Math.max(0, childrenEndOffset - childStartOffset),
    tailOffset: childrenEndOffset,
    tailLen: tailBytes.length,
    tailHex,
    tailMagicOk: tailHex === TSS_PARENT_TRAILER_MAGIC_HEX,
    tailRole: tailBytes.length === 0
      ? "empty"
      : tailHex === TSS_PARENT_TRAILER_MAGIC_HEX
        ? "fixed-parent-trailer"
        : "unknown-trailer",
  };
}

function parseTssChildRecords(byteValues) {
  const root = detectTssReport(byteValues);
  if (!root || root.value !== 0x010a001b || byteValues.length < 28) {
    return { root, children: [] };
  }
  const childCount = readLe32(byteValues, 20);
  const legacy = parseTssChildrenAt(byteValues, 16);
  const compactCount = Number(byteValues[20]);
  const compactCounted =
    Number.isFinite(compactCount) && compactCount > 0 && compactCount <= 256
      ? parseTssChildrenAt(byteValues, 21, compactCount)
      : { children: [], complete: false };
  if (compactCounted.children.length === compactCount) {
    const layout = "compact-count-u8";
    return {
      root,
      children: compactCounted.children,
      layout,
      parent: buildParentContainerInfo(byteValues, compactCounted, {
        layout,
        countOffset: 20,
        childStartOffset: 21,
        declaredCount: compactCount,
      }),
    };
  }
  if (!Number.isFinite(childCount) || childCount < 0 || childCount > 256) {
    if (compactCounted.children.length > 0) {
      const layout = "compact-count-u8-partial";
      return {
        root,
        children: compactCounted.children,
        layout,
        parent: buildParentContainerInfo(byteValues, compactCounted, {
          layout,
          countOffset: 20,
          childStartOffset: 21,
          declaredCount: compactCount,
        }),
      };
    }
    return legacy.children.length > 0 ? { root, children: legacy.children, layout: "legacy-no-count" } : { root, children: [] };
  }
  if (childCount === 0 && legacy.children.length > 0) {
    return { root, children: legacy.children, layout: "legacy-no-count" };
  }

  const children = [];
  let offset = 24;
  for (let index = 0; index < childCount; index += 1) {
    if (offset + 4 > byteValues.length) {
      children.push({ index, offset, truncated: true, reason: "missing child length" });
      break;
    }
    let childLen = readLe32(byteValues, offset);
    let lengthEndian = "le";
    if (!Number.isFinite(childLen) || childLen < 0 || offset + 4 + childLen > byteValues.length) {
      const beLen = readBe32(byteValues, offset);
      if (Number.isFinite(beLen) && beLen >= 0 && offset + 4 + beLen <= byteValues.length) {
        childLen = beLen;
        lengthEndian = "be";
      }
    }
    if (!Number.isFinite(childLen) || childLen < 0 || offset + 4 + childLen > byteValues.length) {
      children.push({ index, offset, truncated: true, reason: `bad child length ${childLen}` });
      break;
    }
    const record = byteValues.slice(offset + 4, offset + 4 + childLen);
    const report = detectTssReport(record);
    const reportCode = report ? report.value : null;
    const identity = tssRecordIdentity(record, report);
    const valuePreview = formatRecordValuePreview(record, reportCode);
    const className = classifyRecordBytes(record, reportCode);
    const timestampCandidates = extractTimestampCandidatesFromRecord(record);
    children.push({
      index,
      offset,
      len: childLen,
      lengthEndian,
      reportCode,
      reportOffset: report ? report.offset : -1,
      idValue: identity.idValue,
      idText: identity.idText,
      className,
      valuePreview,
      timestampCandidates,
      hexSignature: className === "binary-like-leaf" ? formatHexSignature(record) : "",
      xorCommonPreview: className === "binary-like-leaf" ? summarizeCommonFixedXor(record, reportCode) : "",
    });
    attachLocalChildSemantic(children[children.length - 1], record);
    offset += 4 + childLen;
  }
  if (children.length === 0 && legacy.children.length > 0) {
    return { root, children: legacy.children, layout: "legacy-no-count" };
  }
  const countedParsed = { children, endOffset: offset, consumed: offset - 24 };
  return {
    root,
    children,
    layout: "counted",
    parent: buildParentContainerInfo(byteValues, countedParsed, {
      layout: "counted",
      countOffset: 20,
      childStartOffset: 24,
      declaredCount: childCount,
    }),
  };
}

// === TerSafe recursive decode tree (portable DFM-style recursion) ===

const TSS_RECURSE_MAX_DEPTH = 6;
const TSS_RECURSE_MAX_NODES = 128;
const TSS_RECURSE_MAX_CHILDREN = 64;
const TSS_RECURSE_MAX_HEX_BYTES = 64;
const TSS_RECURSE_MAX_STRING_LEN = 96;

const TSS_RECURSE_REPORT_NAMES = {
  0x010a0008: "nested-unwrap-envelope",
  0x010a0009: "nested-control-envelope",
  0x010a001b: "parent-container",
  0x010a0023: "control-wrapper",
  0x0102000a: "typed-leaf",
  0x010a0011: "request-child",
  0x010a0010: "ack-response",
  0x010a0027: "ack",
  0x010a0044: "short-response",
  0x010a0037: "report-0037",
  0x010a0056: "report-0056",
  0x010a0057: "file-config-sync",
  0x010a005f: "sync-status",
  0x010a0053: "control-status",
};

const TSS_RECURSE_KEY_SOURCE = "recovered-template-slot-derivation";
const TSS_RECURSE_KEY_CONFIDENCE = "crc32_structure_validated";

function tssRecurseBoundedHex(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  const capped = byteValues.slice(0, TSS_RECURSE_MAX_HEX_BYTES);
  return capped.map((byte) => (Number(byte) & 0xff).toString(16).padStart(2, "0")).join("");
}

function tssRecurseStrings(byteValues, baseOffset) {
  const runs = extractPrintableRuns(byteValues, 4, TSS_RECURSE_MAX_CHILDREN, { fullText: true });
  return (runs || []).slice(0, TSS_RECURSE_MAX_CHILDREN).map((item) => ({
    offset: Number(baseOffset || 0) + Number(item.off || 0),
    length: Number(item.len || String(item.text || "").length),
    text: shortenText(String(item.text || ""), TSS_RECURSE_MAX_STRING_LEN),
    truncated: String(item.text || "").length > TSS_RECURSE_MAX_STRING_LEN,
    confidence: "candidate",
    reason: "printable-ascii-run;not-schema-verified",
  }));
}

function tssRecurseReportCode(byteValues) {
  const report = detectTssReport(byteValues);
  return report ? Number(report.value) : null;
}

function tssRecurseNode(node) {
  return Object.assign({
    kind: "candidate",
    name: "unknown",
    path: "$",
    depth: 0,
    carrier: "direct",
    sourceOffset: null,
    declaredLen: 0,
    actualLen: 0,
    stage: "raw",
    reportCode: null,
    status: "candidate",
    truncated: false,
    hex: "",
    strings: [],
    stringStatus: "no_trusted_text",
    failure: null,
    children: [],
  }, node || {});
}

function tssRecurseEffectiveSlice(byteValues, declaredTotal) {
  if (Number.isFinite(declaredTotal) && declaredTotal > 0 && declaredTotal < byteValues.length) {
    return byteValues.slice(0, declaredTotal);
  }
  return byteValues;
}

function tssRecurseHexReport(code) {
  return code === null || code === undefined ? "unknown" : "0x" + formatHexValue(code, 8);
}

function tssRecurseWalk(byteValues, state) {
  const path = state.path || "$";
  const depth = Number(state.depth || 0);
  if (state.nodeBudget.value <= 0) {
    return tssRecurseNode({
      kind: "budget_stop", name: "recursion-budget-exhausted", path, depth,
      carrier: "direct", status: "candidate",
      failure: "recursive budget exhausted",
    });
  }
  state.nodeBudget.value -= 1;

  if (!Array.isArray(byteValues) || byteValues.length <= 0) {
    return tssRecurseNode({ kind: "candidate", name: "empty", path, depth, failure: "empty record" });
  }

  const report = detectTssReport(byteValues);
  const reportCode = report ? Number(report.value) : null;
  const declined = !report || !isLikelyTssReportCode(reportCode);
  const declaredTotal = readBe16(byteValues, 4);

  if (declined) {
    return tssRecurseNode({
      kind: "candidate", name: "candidate-non-tss-record", path, depth,
      carrier: "direct", sourceOffset: 0, declaredLen: declaredTotal,
      actualLen: byteValues.length, stage: "raw", reportCode, status: "candidate",
      truncated: Number.isFinite(declaredTotal) && declaredTotal > byteValues.length,
      hex: tssRecurseBoundedHex(byteValues),
      strings: tssRecurseStrings(byteValues),
      failure: "not a trusted TSS report family",
    });
  }

  if ((reportCode === 0x010a0008 || reportCode === 0x010a0009) && depth < TSS_RECURSE_MAX_DEPTH) {
    return tssRecurseEnvelope(byteValues, reportCode, declaredTotal, path, depth, state);
  }
  if (reportCode === 0x010a0023 && depth < TSS_RECURSE_MAX_DEPTH) {
    return tssRecurse0023Wrapper(byteValues, declaredTotal, path, depth, state);
  }
  if (reportCode === 0x010a001b && depth < TSS_RECURSE_MAX_DEPTH) {
    return tssRecurse001bContainer(byteValues, path, depth, state);
  }

  return tssRecurseNode({
    kind: "direct-compact-record",
    name: TSS_RECURSE_REPORT_NAMES[reportCode] || tssRecurseHexReport(reportCode),
    path, depth, carrier: "direct", sourceOffset: 0,
    declaredLen: declaredTotal, actualLen: byteValues.length, stage: "raw",
    reportCode, status: "verified",
    truncated: Number.isFinite(declaredTotal) && declaredTotal > 0 && declaredTotal < byteValues.length,
    hex: tssRecurseBoundedHex(byteValues),
    strings: tssRecurseStrings(byteValues),
  });
}

function tssRecurseEnvelope(byteValues, reportCode, declaredTotal, path, depth, state) {
  const effective = tssRecurseEffectiveSlice(byteValues, declaredTotal);
  const encrypted = decryptTssEncryptedEnvelope(effective);
  const headerValid = encrypted !== null && encrypted.supported;

  if (!headerValid) {
    return tssRecurseNode({
      kind: "candidate",
      name: tssRecurseHexReport(reportCode),
      path, depth, carrier: "family-decrypted", sourceOffset: 0,
      declaredLen: declaredTotal, actualLen: byteValues.length, stage: "raw", reportCode,
      status: "candidate",
      hex: tssRecurseBoundedHex(byteValues),
      strings: tssRecurseStrings(byteValues),
      failure: encrypted ? encrypted.reason : "envelope header/family invalid",
    });
  }

  const family = Number(encrypted.family);
  const slot = Number(encrypted.slot);
  const keyLabel = String(encrypted.keyLabel || "");
  const xor = {
    family,
    familyName: String(encrypted.familyName || ("family" + family)),
    slot,
    slotLabel: keyLabel,
    keySource: TSS_RECURSE_KEY_SOURCE,
    keyConfidence: encrypted.crcMatch ? "crc32_validated" : "crc32_structure_validated",
    keyDerivation: "slot-label xor fixed-constants -> 8-byte key -> permutation/block transform",
  };
  const crc = {
    algorithm: "crc32",
    expected: formatHexValue(encrypted.expectedCrc, 8),
    actual: encrypted.crcMatch ? formatHexValue(encrypted.actualCrc, 8) : "",
    match: Boolean(encrypted.crcMatch),
  };

  if (!encrypted.crcMatch) {
    return tssRecurseNode({
      kind: "candidate",
      name: TSS_RECURSE_REPORT_NAMES[reportCode] || tssRecurseHexReport(reportCode),
      path, depth, carrier: "family-decrypted", sourceOffset: 0,
      declaredLen: declaredTotal, actualLen: byteValues.length, stage: "decrypted", reportCode,
      status: "candidate", hex: tssRecurseBoundedHex(byteValues),
      plainHex: tssRecurseBoundedHex(encrypted.plain),
      plainLen: Array.isArray(encrypted.plain) ? encrypted.plain.length : 0,
      strings: tssRecurseStrings(encrypted.plain || []),
      stringStatus: "candidate-text-only",
      xor, crc,
      failure: "CRC32 mismatch: expected " + crc.expected + " got " + crc.actual,
    });
  }

  const inner = Array.isArray(encrypted.plain) ? encrypted.plain : [];
  const innerReport = detectTssReport(inner);
  const innerTrusted = Boolean(innerReport && isLikelyTssReportCode(innerReport.value));

  const node = tssRecurseNode({
    kind: "nested-unwrap-envelope",
    name: TSS_RECURSE_REPORT_NAMES[reportCode] || tssRecurseHexReport(reportCode),
    path, depth, carrier: "family-decrypted", sourceOffset: 0,
    declaredLen: declaredTotal, actualLen: byteValues.length,
    stage: innerTrusted ? "decrypted" : "xor-decoded", reportCode,
    status: innerTrusted ? "verified" : "candidate",
    hex: tssRecurseBoundedHex(byteValues),
    plainHex: tssRecurseBoundedHex(inner),
    plainLen: inner.length,
    strings: tssRecurseStrings(inner),
    stringStatus: innerTrusted ? "xor-validated-plaintext" : "candidate-text-only",
    xor, crc,
  });

  if (innerTrusted && depth + 1 < TSS_RECURSE_MAX_DEPTH && inner.length >= 10) {
    const child = tssRecurseWalk(inner, {
      nodeBudget: state.nodeBudget,
      path: path + ".inner",
      depth: depth + 1,
    });
    node.children = [child];
  }
  return node;
}

function tssRecurse0023Wrapper(byteValues, declaredTotal, path, depth, state) {
  const effective = tssRecurseEffectiveSlice(byteValues, declaredTotal);
  const payload = effective.slice(20);
  if (payload.length < 4) {
    return tssRecurseNode({
      kind: "candidate", name: "0x010a0023", path, depth, carrier: "0023-wrapper",
      declaredLen: declaredTotal, actualLen: byteValues.length, stage: "raw", reportCode: 0x010a0023,
      status: "candidate", hex: tssRecurseBoundedHex(byteValues),
      failure: "0023 wrapper shorter than cstr_len header",
    });
  }
  const cstrLen = readBe32(payload, 0);
  if (!Number.isFinite(cstrLen) || cstrLen < 1 || cstrLen > 0x40 || 4 + cstrLen + 2 > payload.length) {
    return tssRecurseNode({
      kind: "candidate", name: "0x010a0023", path, depth, carrier: "0023-wrapper",
      declaredLen: declaredTotal, actualLen: byteValues.length, stage: "raw", reportCode: 0x010a0023,
      status: "candidate", hex: tssRecurseBoundedHex(byteValues),
      failure: "0023 cstr_len out of range: " + formatHexValue(cstrLen, 8),
    });
  }
  const labelRaw = payload.slice(4, 4 + cstrLen);
  const label = labelRaw.length > 0 && labelRaw[labelRaw.length - 1] === 0
    ? String.fromCharCode.apply(null, labelRaw.slice(0, -1))
    : String.fromCharCode.apply(null, labelRaw);
  const nestedLen = readBe16(payload, 4 + cstrLen);
  const nested = (Number.isFinite(nestedLen) && nestedLen >= 0 && 6 + cstrLen + nestedLen <= payload.length)
    ? payload.slice(6 + cstrLen, 6 + cstrLen + nestedLen)
    : [];

  const node = tssRecurseNode({
    kind: "nested-wrapper-0023",
    name: "control-wrapper-0023", path, depth, carrier: "0023-wrapper", sourceOffset: 0,
    declaredLen: declaredTotal, actualLen: byteValues.length, stage: "raw", reportCode: 0x010a0023,
    status: "verified", hex: tssRecurseBoundedHex(byteValues),
    strings: tssRecurseStrings(byteValues),
  });
  node.labelText = label;
  node.nestedPayloadLen = nestedLen;

  const nestedReport = nested.length >= 10 ? detectTssReport(nested) : null;
  if (nestedReport && isLikelyTssReportCode(nestedReport.value) && depth + 1 < TSS_RECURSE_MAX_DEPTH) {
    const child = tssRecurseWalk(nested, { nodeBudget: state.nodeBudget, path: path + ".nested", depth: depth + 1 });
    node.children = [child];
  }
  return node;
}

function tssRecurse001bContainer(byteValues, path, depth, state) {
  const parsed = parseTssChildRecords(byteValues);
  const children = (Array.isArray(parsed.children) ? parsed.children : []).slice(0, TSS_RECURSE_MAX_CHILDREN);
  const node = tssRecurseNode({
    kind: "parent-container-010a001b",
    name: "parent-container", path, depth, carrier: "001b-container", sourceOffset: 0,
    declaredLen: readBe16(byteValues, 4), actualLen: byteValues.length, stage: "raw",
    reportCode: 0x010a001b, status: "verified",
    hex: tssRecurseBoundedHex(byteValues),
    strings: tssRecurseStrings(byteValues),
  });
  node.children = [];
  for (let index = 0; index < children.length && state.nodeBudget.value > 0; index += 1) {
    const child = children[index];
    const childBytes = childBytesFromParsed(byteValues, child);
    if (childBytes.length <= 0) continue;
    const childTree = tssRecurseWalk(childBytes, {
      nodeBudget: state.nodeBudget,
      path: path + ".children[" + index + "]",
      depth: depth + 1,
    });
    node.children.push(childTree);
  }
  return node;
}

function buildTssRecursiveDecodeTree(byteValues, options) {
  const opts = options || {};
  const maxNodes = Math.max(1, Math.min(Number(opts.maxNodes || TSS_RECURSE_MAX_NODES), 512));
  const state = { nodeBudget: { value: maxNodes }, path: "$", depth: 0 };
  const root = tssRecurseWalk(Array.isArray(byteValues) ? byteValues : [], state);
  const consumed = maxNodes - state.nodeBudget.value;
  return {
    schema: "tersafe.recursive_decode_tree.v1",
    reported: String(opts.kind || "tss"),
    ok: Boolean(root && root.status === "verified"),
    status: root && root.status === "verified" ? "verified" : "candidate",
    root,
    stats: {
      depth: 0,
      nodes: consumed,
      maxDepth: TSS_RECURSE_MAX_DEPTH,
      maxNodes,
    },
  };
}

function tssRecurseCountNodes(node) {
  if (!node || typeof node !== "object") return 0;
  let count = 1;
  if (Array.isArray(node.children)) {
    for (const child of node.children) count += tssRecurseCountNodes(child);
  }
  return count;
}

function tssRecurseNodeDisplayName(node) {
  const name = String(node && node.name || "");
  if (name.indexOf("0x") === 0 && node && node.reportCode !== null && node.reportCode !== undefined) {
    return name + " (" + String(node.carrier || "direct") + ")";
  }
  return name;
}

function renderTssRecursiveTree(tree, container) {
  if (!container || !tree || typeof tree !== "object") return null;
  const wrap = document.createElement("div");
  wrap.className = "tss-recursive-tree";
  const head = document.createElement("div");
  head.className = "tss-recursive-tree-head";
  const title = document.createElement("span");
  title.textContent = "TerSafe 递归解码树";
  const badge = document.createElement("span");
  badge.className = "tss-recursive-status tss-recursive-status-" + (tree.status === "verified" ? "ok" : "candidate");
  badge.textContent = tree.status === "verified" ? "结构校验通过" : "候选/未验证";
  head.appendChild(title);
  head.appendChild(badge);
  wrap.appendChild(head);
  const list = document.createElement("div");
  list.className = "tss-recursive-tree-nodes";
  if (tree.root) {
    list.appendChild(renderTssRecursiveNode(tree.root, 0));
  }
  wrap.appendChild(list);
  container.appendChild(wrap);
  return wrap;
}

function renderTssRecursiveNode(node, level) {
  const row = document.createElement("details");
  row.className = "tss-recursive-node";
  row.open = level === 0;
  const summary = document.createElement("summary");
  summary.className = "tss-recursive-node-summary";
  const depthPad = "  ".repeat(Math.min(level, 8));
  const statusChip = document.createElement("span");
  statusChip.className = "tss-recursive-node-status tss-recursive-node-status-" + (
    node.status === "verified" ? "ok" : node.status === "candidate" ? "candidate" : "error"
  );
  statusChip.textContent = node.status === "verified" ? "✓" : node.status === "candidate" ? "?" : "✗";
  summary.appendChild(statusChip);
  const nameSpan = document.createElement("span");
  nameSpan.className = "tss-recursive-node-name";
  nameSpan.textContent = depthPad + tssRecurseNodeDisplayName(node);
  summary.appendChild(nameSpan);
  const metaSpan = document.createElement("span");
  metaSpan.className = "tss-recursive-node-meta";
  const metaParts = [];
  if (node.reportCode !== null && node.reportCode !== undefined) metaParts.push("report=" + formatHexValue(node.reportCode, 8));
  if (node.carrier && node.carrier !== "direct") metaParts.push("carrier=" + node.carrier);
  if (node.stage && node.stage !== "raw") metaParts.push("stage=" + node.stage);
  metaParts.push("len=" + node.actualLen);
  if (node.depth !== undefined) metaParts.push("depth=" + node.depth);
  metaSpan.textContent = metaParts.join(" · ");
  summary.appendChild(metaSpan);
  row.appendChild(summary);

  const body = document.createElement("div");
  body.className = "tss-recursive-node-body";

  if (node.xor) {
    const xor = node.xor;
    const line = document.createElement("div");
    line.className = "tss-recursive-line";
    line.textContent = "XOR 算法 " + xor.familyName + " slot[" + xor.slot + "]" + (xor.slotLabel ? "=" + xor.slotLabel : "") +
      " · 密钥来源 " + xor.keySource + " · 置信 " + xor.keyConfidence;
    body.appendChild(line);
  }
  if (node.crc) {
    const line = document.createElement("div");
    line.className = "tss-recursive-line" + (node.crc.match ? " tss-recursive-line-ok" : " tss-recursive-line-error");
    line.textContent = "CRC32 " + (node.crc.match ? "匹配" : "不匹配") + " expected=" + node.crc.expected + " actual=" + node.crc.actual;
    body.appendChild(line);
  }
  if (node.sourceOffset !== null && node.sourceOffset !== undefined) {
    const line = document.createElement("div");
    line.className = "tss-recursive-line";
    line.textContent = "源偏移 " + hexOffsetText(node.sourceOffset) + " 声明长度 " + node.declaredLen + " 实际长度 " + node.actualLen + " stage=" + node.stage;
    body.appendChild(line);
  }
  if (Array.isArray(node.strings) && node.strings.length > 0) {
    const line = document.createElement("div");
    line.className = "tss-recursive-line tss-recursive-line-xor";
    line.textContent = "字符串(候选) " + node.stringStatus + ":";
    body.appendChild(line);
    for (const item of node.strings.slice(0, 12)) {
      const sub = document.createElement("div");
      sub.className = "tss-recursive-line tss-recursive-line-string";
      sub.textContent = "  @" + hexOffsetText(item.offset) + String.fromCharCode(34) + item.text + String.fromCharCode(34) + (item.truncated ? "…" : "") + " (候选，非校验字段)";
      body.appendChild(sub);
    }
  }
  if (node.plainHex) {
    const line = document.createElement("div");
    line.className = "tss-recursive-line tss-recursive-line-hex";
    line.textContent = "解密明文 (" + node.plainLen + "B): " + node.plainHex;
    body.appendChild(line);
  }
  if (node.hex) {
    const line = document.createElement("div");
    line.className = "tss-recursive-line tss-recursive-line-hex";
    line.textContent = "原始字节: " + node.hex;
    body.appendChild(line);
  }
  if (node.failure) {
    const line = document.createElement("div");
    line.className = "tss-recursive-line tss-recursive-line-error";
    line.textContent = "解析失败: " + node.failure;
    body.appendChild(line);
  }
  if (Array.isArray(node.children) && node.children.length > 0) {
    const childWrap = document.createElement("div");
    childWrap.className = "tss-recursive-node-children";
    for (const child of node.children) {
      if (child) childWrap.appendChild(renderTssRecursiveNode(child, level + 1));
    }
    body.appendChild(childWrap);
  }
  row.appendChild(body);
  return row;
}


function makeRootComparableNode(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return null;
  const root = detectTssReport(byteValues);
  if (!root || !isLikelyTssReportCode(root.value)) return null;
  const reportCode = root.value;
  const className = classifyRecordBytes(byteValues, reportCode);
  const valuePreview = formatRecordValuePreview(byteValues, reportCode);
  const timestampCandidates = extractTimestampCandidatesFromRecord(byteValues);
  const identity = tssRecordIdentity(byteValues, root);
  return attachLocalChildSemantic({
    index: 0,
    nodeLabel: "node[0]",
    offset: 0,
    recordStart: 0,
    recordEnd: byteValues.length,
    len: byteValues.length,
    lengthEndian: "",
    reportCode,
    reportOffset: root.offset,
    idValue: identity.idValue,
    idText: identity.idText,
    className,
    valuePreview,
    timestampCandidates,
    hexSignature: className === "binary-like-leaf" ? formatHexSignature(byteValues) : "",
    xorCommonPreview: className === "binary-like-leaf" || Number(reportCode) === 0x0102000a
      ? summarizeCommonFixedXor(byteValues, reportCode)
      : "",
  }, byteValues);
}

function parseLibrarySameLengthExamples(summaryText) {
  const raw = String(summaryText || "");
  const match = raw.match(/\bex=([^\s]+)/);
  if (!match) return new Map();
  const out = new Map();
  for (const item of String(match[1] || "").split("|")) {
    const parts = item.split(":");
    if (parts.length < 5) continue;
    const nodePath = `${parts[0]}:${parts[1]}`;
    const countText = parts[4] || "";
    const countMatch = countText.match(/^n(\d+)$/i);
    if (!countMatch) continue;
    out.set(nodePath, Number(countMatch[1]));
  }
  return out;
}

function buildTssTreeText(base64Text, options = {}) {
  const byteValues = b64ToBytes(base64Text);
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  const sameLenExamples =
    options && options.sameLenExamples instanceof Map ? options.sameLenExamples : new Map();
  const parsed = parseTssChildRecords(byteValues);
  const root = parsed.root || detectTssReport(byteValues);
  if (!root) return "";

  const lines = [];
  lines.push(`root report=${formatHexValue(root.value, 8)} type=${reportName(root.value)} len=${byteValues.length}`);
  if (root.value !== 0x010a001b) {
    const identity = tssRecordIdentity(byteValues, root);
    const preview = formatRecordValuePreview(byteValues, root.value);
    const timestampCandidates = extractTimestampCandidatesFromRecord(byteValues);
    lines.push(
      `  node[0] report=${formatHexValue(root.value, 8)} type=${localChildSemanticProfile(byteValues, root.value).label.replace(/\s+/g, "_")} len=${byteValues.length}` +
        (identity.idText ? ` id=${identity.idText}` : Number.isFinite(identity.idValue) ? ` id=${formatHexValue(identity.idValue, 4)}` : "") +
        (timestampCandidates.length > 0 ? ` timestamps=${timestampCandidates.join(",")}` : "")
    );
    if (preview) lines.push(`    value=${preview}`);
    return lines.join("\n");
  }

  lines.push(`child_count=${parsed.children.length}${parsed.layout ? ` layout=${parsed.layout}` : ""}`);
  if (parsed.parent) {
    const parent = parsed.parent;
    lines.push(
      `  parent:header len=${Number(parent.headerLen || 0)} count=${Number(parent.childCount || 0)} count_off=${formatHexValue(parent.countOffset)} child_start=${formatHexValue(parent.childStartOffset)} layout=${parent.layout || "-"}`
    );
    lines.push(
      `  parent:tail off=${formatHexValue(parent.tailOffset)} len=${Number(parent.tailLen || 0)} magic=${parent.tailHex || "-"} magic_ok=${parent.tailMagicOk ? 1 : 0} role=${parent.tailRole || "-"}`
    );
  }
  const binaryStats = summarizeBinaryLikeChildren(parsed.children);
  if (binaryStats) {
    lines.push(binaryStats);
  }
  for (const child of parsed.children) {
    if (child.truncated) {
      lines.push(`  child[${child.index}] off=${formatHexValue(child.offset)} truncated reason=${child.reason || "-"}`);
      continue;
    }
    const reportText = child.reportCode !== null ? formatHexValue(child.reportCode, 8) : "-";
    const childIdentityText = childIdText(child);
    const idText = childIdentityText !== "-" ? ` id=${childIdentityText}` : "";
    const keepText = child.reportCode === 0x010a0011 ? " keep=required ack=010a0010" : "";
    const tsText = Array.isArray(child.timestampCandidates) && child.timestampCandidates.length > 0
      ? ` timestamps=${child.timestampCandidates.join(",")}`
      : "";
    const sameLenCount = sameLenExamples.get(`child:${child.index}`);
    const sameLenText = Number.isFinite(sameLenCount) ? ` lib_same_len=${sameLenCount}` : "";
    lines.push(
      `  child[${child.index}] off=${formatHexValue(child.offset)} report=${reportText} type=${String(child.semanticLabel || child.className).replace(/\s+/g, "_")} tier=${child.semanticTier || "unknown"} len=${child.len}${idText}${keepText}${tsText}${sameLenText}`
    );
    if (child.valuePreview) {
      lines.push(`    value=${child.valuePreview}`);
    }
    if (child.hexSignature) {
      lines.push(`    hex_sig=${child.hexSignature}`);
    }
    if (child.xorCommonPreview) {
      lines.push(`    xor_common=${child.xorCommonPreview}`);
    }
  }
  return lines.join("\n");
}

function renderTssTreeHtml(treeText) {
  return String(treeText || "")
    .split("\n")
    .map((line) => {
      const escaped = escapeHtml(line);
      return escaped.replace(
        /(root|child_count|parent:header|parent:tail|binary_like_stats|child\[\d+\]|report=0x[0-9a-f]+|type=[^\s]+|len=\d+|id=0x[0-9a-f]+|count=\d+|count_off=0x[0-9a-f]+|child_start=0x[0-9a-f]+|off=0x[0-9a-f]+|magic=[0-9a-f-]+|magic_ok=[01]|role=[^\s]+|keep=target|timestamps=[^\s]+|lib_same_len=\d+|value=.+|hex_sig=.+|xor_common=.+)/gi,
        (token) => {
          let cls = "tree-token";
          if (/^(child\[|parent:)/i.test(token) || token === "root" || token === "binary_like_stats") cls += " tree-node";
          else if (/^report=/i.test(token)) cls += " tree-report";
          else if (/^type=/i.test(token)) cls += " tree-type";
          else if (/^id=/i.test(token)) cls += " tree-id";
          else if (/^value=/i.test(token)) cls += " tree-value";
          else if (/^(hex_sig|xor_common|timestamps|magic|role)=/i.test(token)) cls += " tree-value";
          else if (/^lib_same_len=/i.test(token)) cls += " tree-keep";
          else if (/^(keep=|magic_ok=1)/i.test(token)) cls += " tree-keep";
          return `<span class="${cls}">${token}</span>`;
        }
      );
    })
    .join("\n");
}

function createTssTreeSummary(title, base64Text, extraClass = "", options = {}) {
  const treeText = buildTssTreeText(base64Text, options);
  if (!treeText) return null;
  const shell = document.createElement("div");
  shell.className = `tree-shell ${extraClass || ""}`.trim();
  const head = document.createElement("div");
  head.className = "tree-head";
  head.textContent = title;
  const pre = document.createElement("pre");
  pre.className = "tree-body";
  pre.innerHTML = renderTssTreeHtml(treeText);
  shell.appendChild(head);
  shell.appendChild(pre);
  return shell;
}

function appendTssTreeSummary(panel, title, base64Text, options = {}) {
  const shell = createTssTreeSummary(title, base64Text, "", options);
  if (!shell) return;
  panel.appendChild(shell);
}

function childBytesFromParsed(byteValues, child) {
  if (!Array.isArray(byteValues) || !child || child.truncated) return [];
  const recordStart = Number(child.recordStart);
  const recordEnd = Number(child.recordEnd);
  if (Number.isFinite(recordStart)) {
    const end = Number.isFinite(recordEnd) ? recordEnd : recordStart + Number(child.len || 0);
    if (recordStart < 0 || end > byteValues.length || end < recordStart) return [];
    return byteValues.slice(recordStart, end);
  }
  const offset = Number(child.offset);
  const len = Number(child.len);
  if (!Number.isFinite(offset) || !Number.isFinite(len) || len < 0) return [];
  const start = offset + 4;
  const end = start + len;
  if (start < 0 || end > byteValues.length || end < start) return [];
  return byteValues.slice(start, end);
}

function countChangedBytes(left, right) {
  const leftBytes = Array.isArray(left) ? left : [];
  const rightBytes = Array.isArray(right) ? right : [];
  const commonLen = Math.min(leftBytes.length, rightBytes.length);
  let changed = 0;
  for (let i = 0; i < commonLen; i += 1) {
    if (leftBytes[i] !== rightBytes[i]) changed += 1;
  }
  return {
    commonLen,
    changed,
    lenDelta: rightBytes.length - leftBytes.length,
    leftLen: leftBytes.length,
    rightLen: rightBytes.length,
  };
}

function buildChangedIndexSet(left, right) {
  const leftBytes = Array.isArray(left) ? left : [];
  const rightBytes = Array.isArray(right) ? right : [];
  if (leftBytes.length <= 0 || rightBytes.length <= 0) return null;
  const maxLen = Math.max(leftBytes.length, rightBytes.length);
  const changed = new Set();
  for (let i = 0; i < maxLen; i += 1) {
    if (leftBytes[i] !== rightBytes[i]) changed.add(i);
  }
  return changed.size > 0 ? changed : null;
}

function parseChildActionDetails(summaryText) {
  const raw = String(summaryText || "");
  const out = new Map();
  const match = raw.match(/\bchild_detail=([^\s]+)/);
  if (match) {
    for (const item of String(match[1] || "").split(";")) {
      const parts = item.split(":");
      if (parts.length < 3) continue;
      const index = Number.parseInt(parts[0], 10);
      if (!Number.isFinite(index)) continue;
      out.set(index, {
        index,
        action: parts[1] || "",
        report: parts[2] || "",
        len: parts[3] || "",
        source: parts[4] || "",
        reason: "",
      });
    }
  }
  const reasonMatch = raw.match(/\bchild_reason=([^\s]+)/);
  if (reasonMatch) {
    for (const item of String(reasonMatch[1] || "").split(";")) {
      const sep = item.indexOf(":");
      if (sep <= 0) continue;
      const index = Number.parseInt(item.slice(0, sep), 10);
      if (!Number.isFinite(index)) continue;
      const encoded = item.slice(sep + 1);
      let reason = encoded;
      try {
        reason = decodeURIComponent(encoded);
      } catch (_e) {
        reason = encoded;
      }
      const previous = out.get(index) || { index, action: "", report: "", len: "", source: "" };
      previous.reason = reason;
      out.set(index, previous);
    }
  }
  return out;
}

function childActionSummaryCounts(summaryText) {
  const actions = parseChildActionDetails(summaryText);
  const counts = {
    total: actions instanceof Map ? actions.size : 0,
    replace: 0,
    keep: 0,
    clean: 0,
    drop: 0,
  };
  for (const action of actions.values()) {
    const code = String(action && action.action ? action.action : "").trim().toUpperCase();
    if (!code) continue;
    if (code === "KEEP") counts.keep += 1;
    else if (code === "CLEAN") counts.clean += 1;
    else if (code === "DROP") counts.drop += 1;
    else if (["SL", "FS", "VL", "F11", "CR", "BLK", "ND", "R11", "REQ11"].includes(code)) counts.replace += 1;
  }
  return counts;
}

function parseChildSummaryCounts(summaryText) {
  const raw = String(summaryText || "");
  const read = (key) => {
    const match = raw.match(new RegExp(`\\b${key}=([^\\s]+)`));
    return match ? match[1] : "";
  };
  return {
    total: read("child_total"),
    changed: read("child_changed"),
    sameLength: read("child_same_len"),
    forced: read("child_forced"),
    fallback: read("child_fb11"),
    kept: read("child_keep"),
    noop: read("child_noop"),
    clean: read("child_clean"),
  };
}

function childActionLabel(action, result = null) {
  const value = String(action || "").trim();
  const diff = result && result.diff ? result.diff : null;
  const labels = {
    SL: "同长替换",
    FS: "同类替换",
    VL: diff && Number(diff.lenDelta || 0) === 0 ? "同长替换" : "替换（长度有变化）",
    F11: "使用备用样本",
    CR: "跨类型替换",
    BLK: "替换风险项",
    ND: "替换普通项",
    R11: "替换少见项",
    REQ11: "修正请求标志",
    KEEP: "保持原样",
    CLEAN: "清理风险内容",
    DROP: "删除",
  };
  return labels[value] || value || "-";
}

function humanChildSemanticLabel(value) {
  let text = String(value || "").trim()
    .replace(/\s*\[(?:近似|推测|确定|观察|未知)\]\s*/g, " ")
    .replace(/\s+category=[^\s]+/g, "")
    .trim();
  const mappings = [
    [/动态库\/Framework 路径探测(?:\s*\[观察\])?/i, "可能包含动态库/Framework 路径"],
    [/模块\/动态库路径探测（近似）/i, "可能包含模块/动态库路径"],
    [/稳定二进制探测\/遥测（字段待证）/i, "固定格式的二进制数据"],
    [/能力掩码\/运行时状态候选/i, "可能是运行状态"],
    [/运行时指标\/完整性向量候选/i, "可能是运行指标"],
    [/定型二进制环境探测候选/i, "固定格式的环境数据"],
    [/内存区间\/进程布局候选/i, "可能是内存/进程信息"],
    [/结构化元数据（具体子项待证）/i, "结构化数据"],
    [/探测遥测叶子（具体字段待证）/i, "遥测数据"],
  ];
  for (const [pattern, replacement] of mappings) {
    if (pattern.test(text)) return replacement;
  }
  return text
    .replace(/（(?:字段|具体字段|具体子项)待证）/g, "")
    .replace(/候选/g, "可能是")
    .replace(/\s+/g, " ")
    .trim();
}

function compactChildShapeText(value) {
  const text = String(value || "");
  const inner = text.match(/\binner_type=(0x[0-9a-f]+)/i);
  const len = text.match(/\blen=(\d+)/i);
  return [
    inner ? `类型 ${inner[1]}` : "",
    len ? `长度 ${len[1]}` : "",
  ].filter(Boolean).join(" · ");
}

function isUsefulChildDecodedText(value) {
  const text = String(value || "").trim();
  if (!text || text.length < 6) return false;
  if (compactSemanticSignal(text)) return true;
  if (/\s/.test(text) && /[a-z\u4e00-\u9fff]{3}/i.test(text)) return true;
  const compact = text.replace(/[^a-z0-9]/gi, "");
  const unique = new Set(compact.toLowerCase()).size;
  return compact.length >= 10 && unique >= 5 && /[aeiou]/i.test(compact);
}

function humanChildRuleSummary(action, result) {
  const kind = childActionKind(action && action.action, action && action.reason);
  if (kind === "replace") {
    const source = action && action.source && action.source !== "-" ? compactReportToDisplay(action.source) : "";
    return source ? `已用录制样本 ${source} 替换` : "已用录制样本替换";
  }
  if (kind === "patch") return "已修正请求标志";
  if (kind === "clean") return "没有匹配样本，已清理风险内容";
  if (kind === "keep") return "命中保护规则，保持原样";
  if (kind === "drop") return "规则要求删除该项";
  if (kind === "neutral") return "已经是清理后的内容，无需修改";
  return result && result.label ? result.label : "仅查看，未修改";
}

function compactReportToDisplay(value) {
  const text = String(value || "").trim();
  if (!text || text === "-") return "-";
  return formatReportCodeText(text);
}

function bodyLayoutSemanticLines(bodyLayout) {
  if (!bodyLayout || typeof bodyLayout !== "object") return [];
  if (bodyLayout.kind === "periodicProbeTable") {
    const counts = bodyLayout.cadenceCounts || {};
    const typed = (Array.isArray(bodyLayout.entries) ? bodyLayout.entries : [])
      .filter((item) => item && item.valueKind === "typedValue")
      .slice(0, 6)
      .map((item) => `${formatHexValue(item.probeId, 4)}=${item.value.rawHex || "-"}`)
      .join("，");
    const lines = [
      `body=布局 ${bodyLayout.algebra}；u32单调tick + N×(u16 probe_id + raw32 value)`,
      `clock=tick=${Number(bodyLayout.tick || 0)} ${formatHexValue(bodyLayout.tick, 8)}；selector高16匹配=${bodyLayout.selectorTickMatch ? "是" : "否"}；旧样本换算运行约${compactDurationSeconds(bodyLayout.elapsedSecondsHistoricalEstimate)}（仅参考）`,
      `probes=相对0x8000轮次 每轮候选 ${Number(counts.perRound || 0)}项；隔轮候选 ${Number(counts.halfRound || 0)}项；低频/条件 ${Number(counts.sparse || 0)}项；多次/次轮待证 ${Number(counts.multiPerRound || 0) + Number(counts.subRound || 0)}项；typed ${Number(counts.typedValue || 0)}项`,
      "probe_ids=probe_id是稀疏枚举键，不是连续数组下标；缺号不等于丢包",
      `history=旧连续样本415包/约10时21分：0x8000轮次增量中位约30.031秒；这是历史基线，不是当前单包的协议常量`,
    ];
    if (typed) lines.push(`typed_values=typed raw32 ${typed}`);
    return lines;
  }
  if (["fixedWordBlock", "bitmapWordBlock"].includes(bodyLayout.kind)) {
    const words = (Array.isArray(bodyLayout.words) ? bodyLayout.words : [])
      .map((word) => {
        const suffix = word.allZero ? "全0" : word.allOne ? "全1" : `置位bit=${word.setBits.join("/") || "无"}`;
        return `w${word.index}=${word.value.be32Hex || formatHexValue(word.value.be32, 8)}(${suffix})`;
      })
      .join("，");
    return [
      `body=布局 ${bodyLayout.algebra}；${bodyLayout.label} [${bodyLayout.confidence}]`,
      `words=${words}`,
    ];
  }
  return [];
}

function childSemanticLines(child) {
  if (!child || child.truncated) return [];
  const lines = [];
  if (child.semanticLabel) {
    lines.push(`semantic=${child.semanticLabel} [${semanticTierLabel(child.semanticTier)}] category=${child.semanticCategory || "unknown"}`);
  }
  if (child.typedLayout) {
    const layout = child.typedLayout;
    lines.push(
      `shape=inner_type=${formatHexValue(layout.innerType, 4)} selector0=${formatHexValue(layout.selector0, 8)} selector1=${formatHexValue(layout.selector1, 8)} inner_field=${formatHexValue(layout.innerField, 8)} len=${Number(child.len || layout.len || 0)}`
    );
  }
  lines.push(...bodyLayoutSemanticLines(child.bodyLayout));
  if (child.valuePreview) lines.push(`value=${child.valuePreview}`);
  if (Array.isArray(child.timestampCandidates) && child.timestampCandidates.length > 0) {
    lines.push(`timestamps=${child.timestampCandidates.join(",")}`);
  }
  if (child.xorCommonPreview) lines.push(`xor=${child.xorCommonPreview}`);
  if (child.hexSignature) lines.push(`hex_sig=${child.hexSignature}`);
  return lines;
}

function semanticValueText(line, prefix) {
  const text = String(line || "");
  return text.startsWith(prefix) ? text.slice(prefix.length).trim() : "";
}

function compactSemanticSignal(text) {
  const raw = String(text || "");
  const matches = [];
  const add = (label) => {
    if (label && !matches.includes(label)) matches.push(label);
  };
  for (const match of raw.matchAll(/(?:\/(?:usr|private|system|var|applications|library)[^\s|;]{3,}|[\w.+-]+\.(?:dylib|framework|so)\b|(?:framework|privateframework)[^\s|;]*)/gi)) {
    add(match[0]);
  }
  if (/dylib|framework|usr\/lib|privateframework|\.so\b/i.test(raw) && matches.length <= 0) {
    const idx = raw.search(/dylib|framework|usr\/lib|privateframework|\.so\b/i);
    if (idx >= 0) add(shortenText(raw.slice(Math.max(0, idx - 36), idx + 84), 120));
  }
  for (const match of raw.matchAll(/(?:mrpcs?|mrcp|mrp)[\w.-]*(?:\.(?:data|dat|cfg|zip|bin))?|tersafe|config2\.dat|config3\.dat|comm\.zip/gi)) {
    add(match[0]);
  }
  if (matches.length > 0) return matches.slice(0, 6).join(" | ");
  return "";
}

function splitChildSemanticRows(child) {
  const primaryRows = [];
  const debugLines = [];
  const xorSignal = compactSemanticSignal(child && child.xorCommonPreview ? child.xorCommonPreview : "");
  for (const line of childSemanticLines(child)) {
    if (line.startsWith("semantic=")) {
      const raw = semanticValueText(line, "semantic=");
      primaryRows.push(["用途", humanChildSemanticLabel(raw), "child-card-line-long child-card-semantic"]);
      debugLines.push(line);
      continue;
    }
    if (line.startsWith("shape=")) {
      const raw = semanticValueText(line, "shape=");
      const compact = compactChildShapeText(raw);
      if (compact) primaryRows.push(["结构", compact, "child-card-line-long child-card-shape"]);
      debugLines.push(line);
      continue;
    }
    if (line.startsWith("body=")) {
      debugLines.push(line);
      continue;
    }
    if (line.startsWith("clock=")) {
      primaryRows.push(["运行时间", semanticValueText(line, "clock="), "child-card-line-long child-card-layout"]);
      continue;
    }
    if (line.startsWith("probes=") || line.startsWith("typed_values=") || line.startsWith("words=")) {
      debugLines.push(line);
      continue;
    }
    if (line.startsWith("value=")) {
      const value = semanticValueText(line, "value=").replace(/^xor:/i, "");
      const signal = compactSemanticSignal(value);
      if (signal) primaryRows.push(["发现", signal, "child-card-line-long child-card-parse"]);
      else if (isUsefulChildDecodedText(value)) primaryRows.push(["文本", compactText(value, 80), "child-card-line-long child-card-parse"]);
      else debugLines.push(line);
      continue;
    }
    if (line.startsWith("timestamps=")) {
      primaryRows.push(["时间", semanticValueText(line, "timestamps="), "child-card-line-long child-card-parse"]);
      continue;
    }
    if (line.startsWith("xor=")) {
      const signal = compactSemanticSignal(semanticValueText(line, "xor="));
      if (signal) primaryRows.push(["发现", signal, "child-card-line-long child-card-parse"]);
      debugLines.push(line);
      continue;
    }
    debugLines.push(line);
  }
  return { primaryRows, debugLines };
}

function childOffsetText(child) {
  if (!child || child.truncated || !Number.isFinite(Number(child.offset))) return "-";
  return formatHexValue(Number(child.offset));
}

function childTypeText(child) {
  if (!child || child.truncated) return "-";
  return String(child.className || reportBusinessLabel(child.reportCode) || "-");
}

function childNodeName(child) {
  if (!child || child.truncated) return "node[-]";
  if (child.nodeLabel) return String(child.nodeLabel);
  return `child[${child.index}]`;
}

function mergedChildSemanticText(beforeChild, afterChild) {
  const seen = new Set();
  const lines = [];
  for (const child of [afterChild, beforeChild]) {
    for (const line of childSemanticLines(child)) {
      if (seen.has(line)) continue;
      seen.add(line);
      lines.push(line);
      if (lines.length >= 4) break;
    }
    if (lines.length >= 4) break;
  }
  return lines.join("\n");
}

function childRuleAnnotations(beforeChild, afterChild, action) {
  const rules = [];
  const add = (text) => {
    if (text && !rules.includes(text)) rules.push(text);
  };
  const candidates = [afterChild, beforeChild].filter(Boolean);
  for (const child of candidates) {
    const report = parseReportCodeNumber(child.reportCode);
    if (!Number.isFinite(report)) continue;
    if (Math.floor(report / 0x100) === 0x011223) add(`011223xx：动态 metadata family；subtype=0x${(report & 0xff).toString(16).padStart(2, "0")}，含义由 payload 判定`);
    if (report === 0x010a0011) add("010a0011：服务器确认型子请求，必须原样保留；leaf_id 与 010a0010 精确配对，保活/握手仍为候选含义");
    if (report === 0x010a0010) add("010a0010：010a0011 回执；leaf_id 原样回显，现场尾状态为 0324");
    if (report === 0x0102000a) add("0102000a：typed leaf shell；必须按 inner_type/selector0/selector1/inner_field/len 分类");
  }
  const actionReport = compactReportToDisplay(action && action.report);
  const sourceReport = compactReportToDisplay(action && action.source);
  if (actionReport.startsWith("0x011223") || sourceReport.startsWith("0x011223")) add("011223xx：动态 metadata family，低字节只作 subtype");
  if (actionReport === "0x010a0011" || sourceReport === "0x010a0011") add("010a0011：不可删除、不可作为其他 child 的通用替代；等待 010a0010 回执");

  const semanticText = [mergedChildSemanticText(beforeChild, afterChild), action && action.reason]
    .join(" ")
    .toLowerCase();
  if (/\bmrp\b|\bmrpcs\b|\bmrcp\b|mrpcs_i|mrpcs_i_vv\.data/.test(semanticText)) add("mrp/mrpcs/mrcp：高级白名单规则");
  if (/tersafe|config2\.dat|config3\.dat|comm\.zip/.test(semanticText)) {
    add("tersafe/config2.dat/config3.dat/comm.zip：高级白名单规则");
  }
  if (/account_patch_neutral_timestamp/.test(semanticText)) {
    add("三时间戳 / account_patch_neutral_timestamp：时间戳保护规则");
  } else if (/timestamps=|timestamp|时间戳/.test(semanticText)) {
    add("时间戳候选：按连续三字段复核");
  }
  if (/strict_preserve_whitelist/.test(semanticText)) add("strict_preserve_whitelist：严格白名单保护");
  if (/no_library_match/.test(semanticText)) add("未命中录制源");
  const actionCode = String(action && action.action ? action.action : "");
  const alreadyNeutral = isAlreadyNeutralReason(action && action.reason);
  if (alreadyNeutral) add("已是中和/清理形态，不重复修改");
  if (actionCode === "KEEP" && !alreadyNeutral) add("保护目标，不替换");
  if (actionCode === "BLK") add("命中黑名单风险，但已找到 source，执行安全替换");
  if (actionCode === "ND") add("非设备风险 leaf，已找到 source，执行安全替换");
  if (actionCode === "CLEAN") add("无可用安全 source，执行兜底清理");
  return rules.join("\n");
}

function appendChildCardLine(card, label, value, className = "") {
  const text = String(value || "").trim();
  if (!text) return;
  const line = document.createElement("div");
  line.className = `child-card-line ${className}`.trim();
  line.title = `${label} ${text}`;
  const strong = document.createElement("strong");
  strong.textContent = label;
  line.appendChild(strong);
  line.appendChild(document.createTextNode(` ${text}`));
  card.appendChild(line);
}

function appendChildSideLine(side, label, value, className = "") {
  appendChildCardLine(side, label, value, className);
}

function appendChildDebugDetails(side, lines) {
  const cleanLines = (Array.isArray(lines) ? lines : [])
    .map((line) => String(line || "").trim())
    .filter(Boolean);
  if (!cleanLines.length) return;
  const details = document.createElement("details");
  details.className = "child-debug-details";
  const summary = document.createElement("summary");
  summary.className = "child-debug-title";
  summary.textContent = `调试细节 ${cleanLines.length}`;
  const pre = document.createElement("pre");
  pre.textContent = cleanLines.join("\n");
  details.appendChild(summary);
  details.appendChild(pre);
  side.appendChild(details);
}

function compactText(text, maxLen = 90) {
  const raw = String(text || "").replace(/\s+/g, " ").trim();
  if (raw.length <= maxLen) return raw;
  return `${raw.slice(0, Math.max(0, maxLen - 1))}…`;
}

function childDecisionText(kind, result) {
  if (kind === "replace") return "已用录制样本替换";
  if (kind === "patch") return "已修正请求标志";
  if (kind === "clean") return "没有匹配样本，已清理";
  if (kind === "keep") return "保持原样";
  if (kind === "drop") return "已删除";
  if (kind === "neutral") return "无需修改";
  return result && result.label ? result.label : "仅查看";
}

function compactRuleText(ruleText) {
  return String(ruleText || "")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .join("；");
}

function childActionKind(actionCode, reason = "") {
  if (isAlreadyNeutralReason(reason)) return "neutral";
  const value = String(actionCode || "").trim();
  if (value === "KEEP") return "keep";
  if (value === "CLEAN") return "clean";
  if (value === "DROP") return "drop";
  if (value === "REQ11") return "patch";
  if (
    value === "SL"
    || value === "FS"
    || value === "VL"
    || value === "F11"
    || value === "CR"
    || value === "R11"
    || value === "BLK"
    || value === "ND"
  ) {
    return "replace";
  }
  return "";
}

function childActionObservation(action, result) {
  return humanChildRuleSummary(action, result);
}

function childActionBadgeText(action, result) {
  const kind = childActionKind(action && action.action, action && action.reason);
  if (kind === "neutral") return "已清理形态";
  if (kind === "keep") return "保护保留";
  if (kind === "patch") return "标志修补";
  if (kind === "clean") return "兜底清理";
  if (kind === "drop") return "删除";
  if (kind === "replace") return "替换";
  return result && result.label ? result.label : "观察";
}

function ensureChildCommonStyles() {
  if (document.getElementById("tcpv-child-common-style")) return;
  const style = document.createElement("style");
  style.id = "tcpv-child-common-style";
  style.textContent = `
    .child-common-strip {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 6px 8px;
      margin: 5px 6px 0;
      background: color-mix(in srgb, var(--panel) 82%, var(--chip-bg));
      font-size: 12px;
      line-height: 1.35;
    }
    .parent-structure-strip {
      border: 1px solid color-mix(in srgb, #38bdf8 56%, var(--line));
      border-radius: 6px;
      padding: 7px 8px;
      margin: 6px 6px 0;
      background: color-mix(in srgb, #38bdf8 7%, var(--dump-bg));
      display: grid;
      gap: 5px;
      font-size: 12px;
      line-height: 1.35;
    }
    .parent-structure-title {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      color: color-mix(in srgb, #38bdf8 78%, var(--text));
      font-weight: 900;
    }
    .parent-structure-title small {
      color: var(--muted);
      font-weight: 700;
      text-align: right;
    }
    .parent-structure-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 6px;
    }
    .parent-structure-side {
      min-width: 0;
      border: 1px solid color-mix(in srgb, var(--line) 72%, transparent);
      border-radius: 5px;
      padding: 5px 6px;
      background: color-mix(in srgb, var(--panel) 72%, var(--dump-bg));
      color: color-mix(in srgb, var(--text) 86%, var(--muted));
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow-wrap: anywhere;
    }
    .parent-structure-side strong {
      color: var(--text);
      display: block;
      margin-bottom: 2px;
    }
    .parent-structure-magic-ok {
      color: color-mix(in srgb, #22c55e 82%, var(--text));
      font-weight: 850;
    }
    .parent-structure-magic-bad {
      color: color-mix(in srgb, #ef4444 86%, var(--text));
      font-weight: 900;
    }
	    .event-time-strip {
	      border: 1px solid color-mix(in srgb, #f59e0b 52%, var(--line));
	      border-radius: 6px;
	      padding: 6px 8px;
	      margin: 7px 6px 0;
	      background: color-mix(in srgb, #f59e0b 7%, var(--dump-bg));
	      display: flex;
	      flex-wrap: wrap;
	      align-items: center;
	      gap: 5px;
	      font-size: 12px;
	      line-height: 1.35;
	    }
	    .event-time-title {
	      color: color-mix(in srgb, #f59e0b 86%, var(--text));
	      font-weight: 900;
	      margin-right: 2px;
	    }
	    .event-time-chip {
	      min-width: 0;
	      max-width: 100%;
	      border: 1px solid color-mix(in srgb, #f59e0b 42%, var(--line));
	      border-radius: 999px;
	      padding: 2px 7px;
	      background: color-mix(in srgb, #f59e0b 7%, var(--panel));
	      color: color-mix(in srgb, #f59e0b 84%, var(--text));
	      white-space: nowrap;
	      overflow: hidden;
	      text-overflow: ellipsis;
	    }
	    .event-time-chip-summary {
	      border-color: color-mix(in srgb, #38bdf8 42%, var(--line));
	      background: color-mix(in srgb, #38bdf8 7%, var(--panel));
	      color: color-mix(in srgb, #38bdf8 82%, var(--text));
	      white-space: normal;
	      overflow: visible;
	      text-overflow: clip;
	    }
	    .child-compare-grid {
	      grid-template-columns: minmax(0, 1fr);
	      gap: 8px;
	      align-items: stretch;
	    }
	    .child-pair-card {
	      display: grid;
	      grid-template-columns: minmax(0, 1fr);
	      min-height: 0;
	      padding: 0;
	      gap: 0;
	      overflow: hidden;
	    }
	    .child-card-same-merged {
	      min-height: 0;
	    }
	    .child-pair-title {
	      min-width: 0;
	      border-bottom: 1px solid color-mix(in srgb, var(--line) 78%, transparent);
	      border-right: 0;
	      padding: 6px 8px;
	      display: flex;
	      flex-direction: row;
	      flex-wrap: wrap;
	      align-items: center;
	      justify-content: space-between;
	      gap: 4px 8px;
	      background: linear-gradient(
	        180deg,
	        color-mix(in srgb, var(--chip-bg) 66%, transparent),
        color-mix(in srgb, var(--dump-bg) 72%, var(--panel))
      );
    }
    .child-rail-name {
      display: block;
	      color: var(--text);
	      font-weight: 850;
	      font-size: 12px;
	      line-height: 1.2;
	      text-align: left;
	      overflow-wrap: anywhere;
	      display: inline-flex;
	      align-items: center;
	      gap: 6px;
	      flex: 1 1 130px;
	    }
	    .child-rail-label {
	      display: inline-block;
	      margin-top: 0;
	      color: var(--muted);
	      font-size: 10px;
	      font-weight: 750;
	      text-align: left;
	    }
	    .child-title-badges {
	      justify-content: flex-end;
	      gap: 4px;
	      flex: 0 0 auto;
	    }
	    .child-semantic-tier {
	      display: inline-flex;
	      align-items: center;
	      border: 1px solid color-mix(in srgb, #38bdf8 42%, var(--line));
	      border-radius: 999px;
	      padding: 1px 6px;
	      color: color-mix(in srgb, #7dd3fc 82%, var(--text));
	      background: color-mix(in srgb, #0ea5e9 9%, transparent);
	      font-size: 10px;
	      font-weight: 850;
	    }
	    .child-semantic-tier-approximate {
	      border-color: color-mix(in srgb, #f59e0b 48%, var(--line));
	      color: color-mix(in srgb, #fbbf24 86%, var(--text));
	      background: color-mix(in srgb, #f59e0b 9%, transparent);
	    }
	    .child-semantic-tier-confirmed {
	      border-color: color-mix(in srgb, #22c55e 48%, var(--line));
	      color: color-mix(in srgb, #4ade80 86%, var(--text));
	      background: color-mix(in srgb, #22c55e 9%, transparent);
	    }
    .child-rail-action {
      border: 1px solid var(--chip-line);
      border-radius: 999px;
      padding: 2px 6px;
      max-width: 100%;
      font-size: 11px;
      font-weight: 850;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      background: color-mix(in srgb, var(--chip-bg) 82%, transparent);
    }
    .child-rail-copy {
	      color: color-mix(in srgb, var(--text) 88%, var(--muted));
	      font-size: 11px;
	      line-height: 1.3;
	      text-align: left;
	      overflow-wrap: anywhere;
	      display: -webkit-box;
	      -webkit-line-clamp: 1;
	      -webkit-box-orient: vertical;
	      overflow: hidden;
	      flex: 1 1 100%;
	    }
    .child-risk-badge {
      border: 1px solid color-mix(in srgb, #ef4444 72%, var(--line));
      border-radius: 999px;
      padding: 2px 6px;
      max-width: 100%;
      color: color-mix(in srgb, #ef4444 86%, var(--text));
      background: color-mix(in srgb, #ef4444 10%, var(--dump-bg));
      font-size: 11px;
      font-weight: 900;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
	    .child-rail-meta-grid {
	      display: grid;
	      grid-template-columns: repeat(6, minmax(0, 1fr));
	      gap: 3px;
	      flex: 1 1 100%;
	    }
    .child-rail-meta {
      min-width: 0;
      border: 1px solid color-mix(in srgb, var(--line) 70%, transparent);
      border-radius: 4px;
      padding: 2px 4px;
	      background: color-mix(in srgb, var(--dump-bg) 74%, var(--panel));
	      color: color-mix(in srgb, var(--muted) 82%, var(--text));
	      font-size: 9.5px;
	      line-height: 1.2;
	      overflow: hidden;
	      text-overflow: ellipsis;
	      white-space: nowrap;
    }
    .child-rail-meta strong {
      color: var(--text);
      margin-right: 3px;
      font-weight: 800;
    }
    .child-decision-row {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
      margin-bottom: 5px;
    }
    .child-decision-pill {
      border: 1px solid var(--chip-line);
      border-radius: 999px;
      padding: 2px 8px;
      font-weight: 800;
      white-space: nowrap;
      background: color-mix(in srgb, var(--chip-bg) 82%, transparent);
    }
    .child-decision-replace {
      border-color: color-mix(in srgb, #22c55e 62%, var(--line));
      color: color-mix(in srgb, #22c55e 82%, var(--text));
    }
    .child-decision-patch {
      border-color: color-mix(in srgb, #38bdf8 62%, var(--line));
      color: color-mix(in srgb, #38bdf8 82%, var(--text));
    }
    .child-decision-clean,
    .child-decision-drop,
    .child-decision-neutral {
      border-color: color-mix(in srgb, #f97316 64%, var(--line));
      color: color-mix(in srgb, #f97316 86%, var(--text));
    }
    .child-decision-keep {
      border-color: color-mix(in srgb, var(--accent) 62%, var(--line));
      color: color-mix(in srgb, var(--accent) 82%, var(--text));
    }
    .child-decision-copy {
      min-width: 0;
      flex: 1 1 220px;
      color: var(--text);
      font-weight: 700;
      overflow-wrap: anywhere;
    }
    .child-metric-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(118px, 1fr));
      gap: 4px;
    }
    .child-common-chip {
      border: 1px solid color-mix(in srgb, var(--line) 82%, transparent);
      border-radius: 5px;
      background: color-mix(in srgb, var(--dump-bg) 78%, var(--panel));
      padding: 3px 5px;
      color: var(--text);
      min-width: 0;
      overflow-wrap: anywhere;
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
      gap: 4px;
      align-items: baseline;
    }
    .child-common-chip strong {
      color: var(--muted);
      font-weight: 700;
      white-space: nowrap;
      font-size: 11px;
    }
    .child-common-chip code {
      color: color-mix(in srgb, var(--text) 88%, var(--accent));
      font: inherit;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      overflow-wrap: anywhere;
    }
    .child-context-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 4px;
      margin-top: 4px;
      padding-top: 4px;
      border-top: 1px dashed color-mix(in srgb, var(--line) 72%, transparent);
    }
    .child-context-chip {
      min-width: 0;
      border: 1px solid color-mix(in srgb, var(--line) 70%, transparent);
      border-radius: 5px;
      padding: 3px 5px;
      background: color-mix(in srgb, var(--dump-bg) 76%, var(--panel));
      color: color-mix(in srgb, var(--muted) 80%, var(--text));
      overflow: visible;
      text-overflow: clip;
      white-space: normal;
      overflow-wrap: anywhere;
    }
	    .child-rail-meta-changed {
	      border-color: color-mix(in srgb, #ffd36a 56%, var(--line));
	      background: color-mix(in srgb, #ffd36a 10%, var(--dump-bg));
	      color: color-mix(in srgb, #ffd36a 82%, var(--text));
	    }
    .child-context-chip strong {
      color: var(--text);
      margin-right: 4px;
    }
    .child-side-compact .child-side-title {
      margin-bottom: 4px;
    }
    .child-side-compact .child-card-parse {
      white-space: pre-wrap;
      overflow: visible;
      text-overflow: clip;
      overflow-wrap: anywhere;
      max-width: 100%;
    }
    .child-side-compact .child-debug-details {
      margin-top: 2px;
      padding-top: 2px;
    }
	    .child-preview-row {
	      margin: 0;
	      display: grid;
	      grid-template-columns: repeat(2, minmax(360px, 1fr));
	      grid-template-rows: auto auto;
	      gap: 0;
	      min-width: 0;
	      min-height: 0;
	      overflow-x: auto;
	      scrollbar-gutter: stable;
    }
	    .child-preview-row-single {
	      grid-template-columns: minmax(0, 1fr);
	    }
    .ace-compare-status {
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
      gap: 6px 8px;
      align-items: baseline;
      padding: 7px 8px;
      border-bottom: 1px solid color-mix(in srgb, #fb7185 24%, var(--line));
      background: color-mix(in srgb, var(--dump-bg) 90%, #e11d48 10%);
      font-size: 12px;
      line-height: 1.35;
    }
    .ace-compare-status strong {
      color: var(--text);
      font-weight: 900;
      white-space: nowrap;
    }
    .ace-compare-status span {
      min-width: 0;
      color: color-mix(in srgb, var(--text) 86%, var(--muted));
      overflow-wrap: anywhere;
    }
    .ace-compare-status-missing {
      border-color: color-mix(in srgb, #f59e0b 42%, var(--line));
      background: color-mix(in srgb, #f59e0b 8%, var(--dump-bg));
    }
    .ace-compare-status-changed {
      border-color: color-mix(in srgb, #22c55e 42%, var(--line));
      background: color-mix(in srgb, #22c55e 7%, var(--dump-bg));
    }
    .ace-compare-status-same {
      border-color: color-mix(in srgb, #38bdf8 38%, var(--line));
      background: color-mix(in srgb, #38bdf8 6%, var(--dump-bg));
    }
    .ace-compare-status-unparsed {
      border-color: color-mix(in srgb, #f97316 42%, var(--line));
      background: color-mix(in srgb, #f97316 7%, var(--dump-bg));
    }
    .child-preview-box {
      min-width: 0;
	      border: 0;
	      border-radius: 0;
	      padding: 7px 9px;
	      background: color-mix(in srgb, var(--dump-bg) 88%, var(--panel));
	      display: grid;
	      grid-template-rows: subgrid;
	      grid-row: span 2;
      justify-content: flex-start;
      min-height: 0;
    }
	    .child-preview-info {
	      min-width: 0;
	      display: grid;
	      gap: 1px;
	      align-content: start;
	      padding-bottom: 6px;
	    }
	    .child-preview-before {
	      border-bottom: 0;
	      border-right: 1px solid color-mix(in srgb, var(--line) 78%, transparent);
	      background: color-mix(in srgb, #f59e0b 4%, var(--dump-bg));
	    }
    .child-preview-after {
      background: color-mix(in srgb, var(--resp) 4%, var(--dump-bg));
    }
    .child-preview-same {
      background: color-mix(in srgb, #f59e0b 3%, var(--dump-bg));
    }
    .child-preview-label {
      display: inline-block;
      margin-bottom: 5px;
	      color: var(--text);
	      font-weight: 800;
	      font-size: 13px;
	    }
    .child-preview-line {
      color: color-mix(in srgb, var(--muted) 80%, var(--text));
      overflow-wrap: anywhere;
      white-space: normal;
	      font-size: 13px;
	      line-height: 1.32;
	      margin-top: 1px;
    }
	    .child-preview-line-rich {
	      display: flex;
	      flex-wrap: wrap;
	      gap: 4px;
	      align-items: center;
	      margin-top: 3px;
	    }
	    .child-preview-token {
	      min-width: 0;
	      display: inline-flex;
	      align-items: baseline;
	      gap: 4px;
	      max-width: 100%;
	      border: 1px solid color-mix(in srgb, var(--line) 72%, transparent);
	      border-radius: 5px;
	      padding: 2px 6px;
	      background: color-mix(in srgb, var(--dump-bg) 74%, var(--panel));
	      color: color-mix(in srgb, var(--text) 86%, var(--muted));
	      overflow-wrap: anywhere;
	    }
	    .child-preview-token strong {
	      flex: 0 0 auto;
	      color: var(--muted);
	      font-weight: 850;
	    }
	    .child-preview-token span {
	      min-width: 0;
	    }
	    .child-preview-token code {
	      font: inherit;
	      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
	      color: color-mix(in srgb, var(--text) 92%, var(--accent));
	      overflow-wrap: anywhere;
	    }
	    .child-preview-token-action {
	      border-color: color-mix(in srgb, #22c55e 48%, var(--line));
	      background: color-mix(in srgb, #22c55e 7%, var(--dump-bg));
	    }
	    .child-preview-token-action strong,
	    .child-preview-token-action span {
	      color: color-mix(in srgb, #22c55e 76%, var(--text));
	    }
	    .child-preview-token-reason {
	      border-color: color-mix(in srgb, #f59e0b 50%, var(--line));
	      background: color-mix(in srgb, #f59e0b 8%, var(--dump-bg));
	    }
	    .child-preview-token-reason strong,
	    .child-preview-token-reason span {
	      color: color-mix(in srgb, #f59e0b 80%, var(--text));
	    }
	    .child-preview-token-source,
	    .child-preview-token-parse {
	      border-color: color-mix(in srgb, #38bdf8 48%, var(--line));
	      background: color-mix(in srgb, #38bdf8 7%, var(--dump-bg));
	    }
	    .child-preview-token-source strong,
	    .child-preview-token-source code,
	    .child-preview-token-parse strong {
	      color: color-mix(in srgb, #38bdf8 82%, var(--text));
	    }
	    .child-preview-token-rule {
	      flex: 1 1 100%;
	      align-items: flex-start;
	      border-color: color-mix(in srgb, #a78bfa 48%, var(--line));
	      background: color-mix(in srgb, #a78bfa 7%, var(--dump-bg));
	    }
	    .child-preview-token-rule strong {
	      color: color-mix(in srgb, #c4b5fd 84%, var(--text));
	    }
	    .child-preview-token-risk {
	      border-color: color-mix(in srgb, #ef4444 56%, var(--line));
	      background: color-mix(in srgb, #ef4444 8%, var(--dump-bg));
	    }
	    .child-preview-token-risk strong,
	    .child-preview-token-risk span {
	      color: color-mix(in srgb, #ef4444 86%, var(--text));
	    }
	    .child-preview-token-xor {
	      border-color: color-mix(in srgb, #67e8f9 46%, var(--line));
	      background: color-mix(in srgb, #67e8f9 6%, var(--dump-bg));
	    }
	    .child-preview-token-xor strong,
	    .child-preview-token-xor code {
	      color: color-mix(in srgb, #67e8f9 84%, var(--text));
	    }
	    .child-preview-token-time {
	      border-color: color-mix(in srgb, #f59e0b 54%, var(--line));
	      background: color-mix(in srgb, #f59e0b 9%, var(--dump-bg));
	    }
	    .child-preview-token-time strong,
	    .child-preview-token-time span,
	    .child-preview-token-time code {
	      color: color-mix(in srgb, #f59e0b 86%, var(--text));
	    }
    .child-preview-line-meta {
      color: color-mix(in srgb, var(--text) 88%, var(--muted));
      font-weight: 650;
    }
    .child-preview-line-hex {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      color: color-mix(in srgb, var(--accent) 72%, var(--muted));
    }
    .child-preview-line-risk {
      color: color-mix(in srgb, #ef4444 86%, var(--text));
      font-weight: 800;
    }
	    .child-hex-table {
	      margin-top: 7px;
	      border: 1px solid color-mix(in srgb, var(--line) 78%, transparent);
	      border-radius: 5px;
	      overflow-x: auto;
	      overflow-y: visible;
	      scrollbar-gutter: stable;
	      background: color-mix(in srgb, var(--dump-bg) 84%, #000);
	    }
	    .child-hex-table::-webkit-scrollbar {
	      width: 8px;
	      height: 8px;
	    }
	    .child-hex-table::-webkit-scrollbar-track {
	      background: color-mix(in srgb, var(--dump-bg) 82%, var(--panel));
	    }
	    .child-hex-table::-webkit-scrollbar-thumb {
	      border: 2px solid color-mix(in srgb, var(--dump-bg) 82%, var(--panel));
	      border-radius: 999px;
	      background: color-mix(in srgb, var(--accent) 48%, var(--muted));
	    }
	    .child-hex-details > summary.child-hex-title {
	      list-style: none;
	      cursor: pointer;
	      border-left: 0;
	      min-height: 0;
	      user-select: none;
	      display: flex;
	      align-items: center;
	      gap: 8px;
	    }
	    .child-hex-details > summary.child-hex-title::-webkit-details-marker {
	      display: none;
	    }
	    .child-hex-details > summary.child-hex-title::after {
	      content: "展开";
	      margin-left: auto;
	      color: var(--muted);
	      font-size: 10px;
	      font-weight: 800;
	    }
	    .child-hex-details[open] > summary.child-hex-title::after {
	      content: "收起";
	    }
    .child-hex-title {
      padding: 5px 7px;
      border-bottom: 1px solid color-mix(in srgb, var(--line) 68%, transparent);
      color: color-mix(in srgb, var(--text) 88%, var(--muted));
      font-size: 12px;
      font-weight: 850;
    }
    .child-body-layout-panel {
      padding: 7px;
      border-bottom: 1px solid color-mix(in srgb, var(--line) 72%, transparent);
      background: linear-gradient(135deg, color-mix(in srgb, #22c55e 7%, var(--dump-bg)), color-mix(in srgb, #38bdf8 5%, var(--dump-bg)));
    }
    .child-body-layout-title {
      color: color-mix(in srgb, #86efac 82%, var(--text));
      font-size: 12px;
      font-weight: 900;
      margin-bottom: 5px;
    }
    .child-body-layout-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 4px;
    }
    .child-body-layout-item {
      display: grid;
      gap: 1px;
      min-width: 0;
      padding: 4px 6px;
      border: 1px solid color-mix(in srgb, var(--line) 76%, transparent);
      border-radius: 4px;
      background: color-mix(in srgb, var(--dump-bg) 84%, transparent);
      font-size: 11px;
    }
    .child-body-layout-item strong {
      color: color-mix(in srgb, #7dd3fc 82%, var(--text));
      font-size: 10px;
    }
    .child-body-layout-item span {
      color: var(--text);
      overflow-wrap: anywhere;
    }
    .child-hex-body {
      display: grid;
      gap: 0;
      padding: 3px 0;
    }
	    .child-hex-row {
	      display: grid;
	      grid-template-columns: 54px minmax(104px, max-content) minmax(80px, 16ch) minmax(0, 1fr);
      gap: 8px;
      align-items: baseline;
      padding: 2px 7px;
      font-size: 12px;
      line-height: 1.38;
    }
    .child-hex-row-tlvType,
    .child-hex-row-tlvLen,
    .child-hex-row-tlvValue {
      border-left: 2px solid color-mix(in srgb, #38bdf8 38%, transparent);
    }
    .child-hex-row-bodyHeader {
      border-left: 2px solid color-mix(in srgb, #f59e0b 64%, transparent);
    }
    .child-hex-row-probeEntry {
      border-left: 2px solid color-mix(in srgb, #22c55e 34%, transparent);
    }
    .child-hex-row-bodyWord {
      border-left: 2px solid color-mix(in srgb, #38bdf8 42%, transparent);
    }
    .child-hex-row-report .child-hex-note,
    .child-hex-row-id .child-hex-note {
      color: color-mix(in srgb, #38bdf8 84%, var(--text));
      font-weight: 800;
    }
    .child-hex-row-version .child-hex-note,
    .child-hex-row-total .child-hex-note,
    .child-hex-row-len .child-hex-note,
    .child-hex-row-innerLen .child-hex-note,
    .child-hex-row-innerType .child-hex-note,
    .child-hex-row-selector .child-hex-note,
    .child-hex-row-innerField .child-hex-note,
    .child-hex-row-headerId .child-hex-note,
    .child-hex-row-flags .child-hex-note {
      color: color-mix(in srgb, #c4b5fd 80%, var(--text));
      font-weight: 800;
    }
    .child-hex-row-tlvType .child-hex-note,
    .child-hex-row-tlvLen .child-hex-note,
    .child-hex-row-tlvValue .child-hex-note {
      color: color-mix(in srgb, #7dd3fc 84%, var(--text));
      font-weight: 800;
    }
    .child-hex-row-bodyHeader .child-hex-note {
      color: color-mix(in srgb, #fbbf24 86%, var(--text));
      font-weight: 850;
    }
    .child-hex-row-probeEntry .child-hex-note {
      color: color-mix(in srgb, #86efac 78%, var(--text));
    }
    .child-hex-row-bodyWord .child-hex-note {
      color: color-mix(in srgb, #7dd3fc 82%, var(--text));
    }
    .child-hex-offset,
    .child-hex-bytes,
    .child-hex-ascii {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      white-space: pre;
    }
    .child-hex-offset {
      color: color-mix(in srgb, var(--muted) 82%, var(--text));
    }
    .child-hex-bytes,
    .child-hex-byte-grid {
      color: color-mix(in srgb, var(--accent) 80%, var(--text));
    }
    .child-hex-byte-grid,
    .child-hex-char-grid {
      display: inline-grid;
      grid-auto-flow: column;
      grid-auto-columns: 2ch;
      column-gap: 1ch;
      align-items: baseline;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      white-space: pre;
    }
	    .child-hex-byte-cell,
	    .child-hex-ascii-cell {
	      text-align: center;
	    }
	    .child-hex-byte-cell-changed {
	      color: #ffd36a;
	      background: rgba(255, 179, 46, 0.22);
	      border-radius: 3px;
	      box-shadow: 0 0 0 1px rgba(255, 179, 46, 0.18);
	    }
	    .child-hex-byte-cell-time {
	      color: color-mix(in srgb, #f59e0b 84%, var(--text));
	      background: rgba(245, 158, 11, 0.10);
	      border-radius: 3px;
	      box-shadow: 0 0 0 1px rgba(245, 158, 11, 0.12);
	    }
	    .child-hex-ascii {
	      display: inline-grid;
	      grid-auto-flow: column;
	      grid-auto-columns: 1ch;
	      color: color-mix(in srgb, var(--muted) 80%, var(--text));
	      opacity: 0.84;
	    }
	    .child-hex-ascii-cell-string {
	      color: color-mix(in srgb, #4ade80 82%, var(--text));
	      background: rgba(34, 197, 94, 0.10);
	      border-radius: 2px;
	      font-weight: 800;
	    }
	    .child-hex-ascii-cell-changed {
	      color: #ffd36a;
	      background: rgba(255, 179, 46, 0.18);
	      border-radius: 2px;
	      font-weight: 850;
	    }
	    .child-hex-time-row {
	      display: grid;
	      grid-template-columns: 54px minmax(104px, max-content) minmax(0, 1fr);
	      gap: 8px;
	      align-items: baseline;
	      padding: 0 7px 2px;
	      font-size: 12px;
	      line-height: 1.22;
	      background: color-mix(in srgb, #f59e0b 5%, transparent);
	      border-left: 2px solid color-mix(in srgb, #f59e0b 56%, transparent);
	    }
	    .child-hex-time-label,
	    .child-hex-time-value {
	      color: color-mix(in srgb, #f59e0b 86%, var(--text));
	      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
	      white-space: pre;
	    }
	    .child-hex-time-note {
	      color: color-mix(in srgb, #f59e0b 74%, var(--muted));
	      white-space: normal;
	      overflow: visible;
	      text-overflow: clip;
	      overflow-wrap: anywhere;
	    }
    .child-hex-note {
      min-width: 0;
      color: color-mix(in srgb, var(--text) 78%, var(--muted));
      overflow-wrap: anywhere;
      word-break: break-word;
      white-space: normal;
    }
    .child-hex-row-time {
      background: color-mix(in srgb, #f59e0b 10%, transparent);
      border-left: 2px solid color-mix(in srgb, #f59e0b 72%, transparent);
    }
	    .child-hex-row-string {
	      background: color-mix(in srgb, #22c55e 3%, transparent);
	      border-left: 2px solid color-mix(in srgb, #22c55e 42%, transparent);
	    }
	    .child-hex-row-string .child-hex-note {
	      color: color-mix(in srgb, #22c55e 78%, var(--text));
	      font-weight: 800;
	    }
	    .child-hex-byte-cell-string {
	      color: color-mix(in srgb, #22c55e 72%, var(--text));
	      font-weight: 750;
	    }
    .child-hex-row-time .child-hex-note {
      color: color-mix(in srgb, #f59e0b 82%, var(--text));
      font-weight: 800;
    }
    .child-hex-insights {
      border-top: 1px solid color-mix(in srgb, var(--line) 68%, transparent);
      padding: 5px 6px 6px;
      display: grid;
      gap: 3px;
      font-size: 11px;
      line-height: 1.35;
    }
    .child-hex-insight {
      display: grid;
      grid-template-columns: 86px minmax(0, 1fr);
      gap: 8px;
      color: color-mix(in srgb, var(--text) 82%, var(--muted));
    }
    .child-hex-insight strong {
      color: var(--text);
      font-weight: 850;
    }
    .child-hex-insight-string strong,
    .child-hex-insight-string span {
      color: color-mix(in srgb, #22c55e 78%, var(--text));
    }
    .child-hex-insight-time strong,
    .child-hex-insight-time span {
      color: color-mix(in srgb, #f59e0b 82%, var(--text));
    }
    .child-hex-insight span {
      min-width: 0;
      overflow: visible;
      text-overflow: clip;
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .child-preview-empty {
      color: var(--muted);
      font-size: 12px;
    }
    @media (max-width: 900px) {
      .dump-grid,
      .dump-grid-request.dump-grid-decrypted {
        grid-template-columns: minmax(0, 1fr) !important;
        overflow-x: hidden;
      }
      .dump-grid > * {
        min-width: 0;
      }
      .dump-grid > .child-compare-inline {
        grid-column: 1 / -1;
        width: 100%;
      }
      .child-compare-grid {
        grid-template-columns: minmax(0, 1fr);
      }
      .parent-structure-grid {
        grid-template-columns: 1fr;
      }
      .child-preview-row {
        grid-template-columns: minmax(0, 1fr);
        grid-template-rows: auto;
        overflow-x: hidden;
      }
      .child-preview-row > .child-preview-box {
        grid-row: auto;
      }
      .child-preview-row > .child-preview-before {
        border-right: 0;
        border-bottom: 1px solid color-mix(in srgb, var(--line) 78%, transparent);
      }
    }
	    @media (max-width: 520px) {
	      .child-compare-grid {
	        grid-template-columns: minmax(0, 1fr);
	        gap: 6px;
	      }
	      .child-pair-title {
	        padding: 5px 6px;
	        gap: 3px 5px;
	      }
	      .child-rail-name {
	        flex-basis: 72px;
	        font-size: 11px;
	      }
	      .child-rail-label {
	        display: none;
	      }
	      .child-title-badges {
	        max-width: 100%;
	      }
	      .child-status,
	      .child-rail-action,
	      .child-risk-badge {
	        padding: 1px 5px;
	        font-size: 10px;
	      }
	      .child-rail-copy {
	        font-size: 10px;
	      }
	      .child-rail-meta-grid {
	        grid-template-columns: repeat(2, minmax(0, 1fr));
	        gap: 2px;
	      }
	      .child-rail-meta {
	        padding: 1px 3px;
	        font-size: 9px;
	      }
	      .child-preview-box {
	        padding: 6px;
	      }
	      .child-preview-label,
	      .child-preview-line {
	        font-size: 11px;
	      }
	      .child-hex-title,
	      .child-hex-insights {
	        font-size: 10px;
	      }
	      .child-hex-insight {
	        grid-template-columns: minmax(0, 1fr);
	        gap: 1px;
	      }
	      .child-hex-insight strong {
	        overflow: hidden;
	        text-overflow: ellipsis;
	        white-space: nowrap;
	      }
	    }
	    @media (max-width: 330px) {
	      .child-compare-grid {
	        grid-template-columns: minmax(0, 1fr);
	      }
	    }
	    @media (max-width: 720px) {
	      .child-pair-card {
	        grid-template-columns: minmax(0, 1fr);
	      }
	      .child-preview-before {
	        border-right: 1px solid color-mix(in srgb, var(--line) 78%, transparent);
	        border-bottom: 0;
	      }
      .child-pair-title {
        padding: 8px 6px;
      }
      .child-rail-name {
        font-size: 13px;
      }
    }
  `;
  document.head.appendChild(style);
}

function sameTextValue(left, right) {
  return String(left || "") === String(right || "");
}

function pairText(label, beforeValue, afterValue) {
  const beforeText = String(beforeValue || "-");
  const afterText = String(afterValue || "-");
  if (beforeText === "-" && afterText === "-") return "";
  if (sameTextValue(beforeText, afterText)) return `${label} ${beforeText}`;
  return `${label} ${beforeText} -> ${afterText}`;
}

function appendChildCommonChip(strip, label, value, className = "") {
  const text = String(value || "").trim();
  if (!text) return;
  const chip = document.createElement("span");
  chip.className = `child-common-chip ${className}`.trim();
  const strong = document.createElement("strong");
  strong.textContent = label;
  chip.appendChild(strong);
  const code = document.createElement("code");
  code.textContent = text;
  chip.appendChild(code);
  strip.appendChild(chip);
}

function appendChildRailMeta(container, label, value) {
  const text = String(value || "").trim();
  if (!text || text === "-") return;
  const row = document.createElement("div");
  row.className = "child-rail-meta";
  if (text.includes("->")) row.classList.add("child-rail-meta-changed");
  row.title = `${label} ${text}`;
  const strong = document.createElement("strong");
  strong.textContent = label;
  row.appendChild(strong);
  row.appendChild(document.createTextNode(text));
  container.appendChild(row);
}

function childUiTerm(term) {
  const labels = {
    idx: "idx(索引)",
    report: "report(报告码)",
    type: "type(类型)",
    ID: "leaf_id?(候选ID/序号)",
    len: "len(长度)",
    diff: "diff(差异)",
    offset: "offset(偏移)",
    source: "source(来源)",
    hex: "hex(十六进制)",
    head: "head(头)",
    tail: "tail(尾)",
    all: "all(全部)",
  };
  return labels[term] || term;
}

function childUiShortTerm(term) {
  const labels = {
    idx: "序号",
    report: "消息",
    type: "用途",
    ID: "ID",
    len: "长度",
    diff: "变化",
    offset: "位置",
  };
  return labels[term] || term;
}

function annotateHexSignature(signature) {
  return String(signature || "")
    .replace(/\ball=/g, `${childUiTerm("all")}=`)
    .replace(/\bhead=/g, `${childUiTerm("head")}=`)
    .replace(/\btail=/g, `${childUiTerm("tail")}=`);
}

function hexOffsetText(offset) {
  const value = Number(offset);
  if (!Number.isFinite(value)) return "+0x?";
  return `+0x${Math.max(0, value).toString(16).padStart(2, "0")}`;
}

function childHexByteText(byte) {
  return (Number(byte || 0) & 0xff).toString(16).padStart(2, "0");
}

function childDecodedChar(byte) {
  const value = Number(byte || 0) & 0xff;
  if (value === 32) return "␠";
  if (value >= 33 && value < 127) return String.fromCharCode(value);
  return "·";
}

function formatTimestampDateTime(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value)) return "";
  try {
    const { yyyy, mm, dd, hh, mi, ss } = displayTimeParts(value * 1000);
    return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
  } catch (_e) {
    return "";
  }
}

function addChildHexAnnotation(map, offset, text) {
  const pos = Number(offset);
  const value = String(text || "").trim();
  if (!Number.isFinite(pos) || pos < 0 || !value) return;
  const existing = map.get(pos) || [];
  if (!existing.includes(value)) existing.push(value);
  map.set(pos, existing);
}

function addChildHexField(fields, offset, length, note, kind = "field") {
  const start = Number(offset);
  const size = Number(length);
  const text = String(note || "").trim();
  if (!Number.isFinite(start) || start < 0 || !Number.isFinite(size) || size <= 0) return;
  fields.push({
    offset: Math.floor(start),
    length: Math.floor(size),
    note: text,
    kind,
  });
}

function isDisplayableDecodedRun(text, kind = "") {
  const raw = String(text || "");
  const normalized = normalizeVisibleText(raw);
  if (normalized.length < 4) return false;
  const lower = normalized.toLowerCase();
  if (compactSemanticSignal(normalized)) return true;
  if (/\d{10,24}/.test(normalized)) return true;
  if (/(model:|ver:|inc_id:|obf_id:|appid:|uuid:|client:|bundle:)/i.test(normalized)) return true;
  if (/[/:;=_]/.test(normalized) && /[A-Za-z0-9]{3,}/.test(normalized)) return true;
  if (String(kind || "") !== "ascii") return true;
  if (normalized.length >= 12 && /^[A-Za-z0-9 .:_/-]+$/.test(normalized)) return true;
  return false;
}

function buildPlainDecodedOverlay(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return null;
  const runs = extractPrintableRuns(byteValues, 4, 48, { fullText: true }).map((item) => {
    const start = Number(item.off || 0);
    const text = String(item.text || "");
    return {
      start,
      end: start + text.length,
      text,
      kind: inferStringKind(text),
    };
  }).filter((run) => isDisplayableDecodedRun(run.text, run.kind));
  if (runs.length <= 0 || runs.every((run) => String(run.text || "").length < 8)) return null;
  return {
    mode: "ascii",
    key: null,
    label: "ascii",
    start: 0,
    decoded: byteValues.slice(),
    runs,
  };
}

function plainOverlayHasSemanticSignal(overlay) {
  const runs = Array.isArray(overlay && overlay.runs) ? overlay.runs : [];
  if (runs.length <= 0) return false;
  let hasAccountLike = false;
  let hasFileLike = false;
  for (const run of runs) {
    const text = normalizeVisibleText(run && run.text);
    if (!text) continue;
    const lower = text.toLowerCase();
    if (compactSemanticSignal(text)) return true;
    if (/(?:^|[^a-z0-9])mrp(?:c|cs)?[a-z0-9_.-]*|mrcp|\.data\b/.test(lower)) return true;
    if (/(model:|ver:|inc_id:|obf_id:|state:|appid:|uuid:|bundle:)/i.test(text)) return true;
    if (/\d{10,24}/.test(text)) hasAccountLike = true;
    if (/[a-z0-9_./-]+\.(?:data|dylib|framework|plist|txt)\b/i.test(text)) hasFileLike = true;
  }
  return hasAccountLike && hasFileLike;
}

function shouldPreferPlainDecodedOverlay(byteValues, reportCode, plainOverlay) {
  if (!plainOverlay || !Array.isArray(byteValues) || byteValues.length <= 0) return false;
  const report = Number(reportCode);
  if (Number(report) === 0x0102000a && isBinaryLikeLeafRecord(byteValues, report)) return false;
  return plainOverlayHasSemanticSignal(plainOverlay);
}

function childBestDecodedOverlay(childBytes) {
  if (!Array.isArray(childBytes) || childBytes.length <= 0) return null;
  if (parseTssEncryptedEnvelope(childBytes)) return null;
  const detected = detectTssReport(childBytes);
  const plainOverlay = buildPlainDecodedOverlay(childBytes);
  if (shouldPreferPlainDecodedOverlay(childBytes, detected ? Number(detected.value) : NaN, plainOverlay)) {
    return plainOverlay;
  }

  const makeXorCandidate = (start, key, source = "common") => {
    const safeStart = Math.max(0, Math.floor(Number(start)));
    const xorKey = Number(key) & 0xff;
    if (!Number.isFinite(safeStart) || safeStart >= childBytes.length) return null;
    const decoded = xorByteValues(childBytes.slice(safeStart), xorKey);
    const runsRaw = extractPrintableRuns(decoded, 3, 48, { fullText: true });
    if (runsRaw.length <= 0) return null;
    const scored = scoreXorCandidate(decoded, runsRaw);
    const meaningfulRunLen = runsRaw.reduce((maxLen, item) => Math.max(maxLen, String(item.text || "").length), 0);
    const totalTextLen = runsRaw.reduce((total, item) => total + String(item.text || "").length, 0);
    const strongWithoutKeyword =
      meaningfulRunLen >= 8
      && Number(scored.stats && scored.stats.alpha) >= 6
      && Number(scored.stats && scored.stats.uniquePrintables) >= 8
      && Number(scored.bestRunUnique || 0) >= 6
      && Number(scored.stats && scored.stats.maxRun) <= 8;
    if (scored.keywordHits.length <= 0 && !strongWithoutKeyword) return null;
    const runs = runsRaw.map((item) => {
        const runStart = safeStart + Number(item.off || 0);
        const text = String(item.text || "");
        return {
          start: runStart,
          end: runStart + text.length,
          text,
          kind: inferStringKind(text),
        };
      })
      .filter((run) => isDisplayableDecodedRun(run.text, run.kind));
    if (runs.length <= 0) return null;
    return {
      mode: "xor",
      key: xorKey,
      label: `xor ${formatHexValue(xorKey, 2)}`,
      source,
      start: safeStart,
      decoded,
      runs,
      score: Number(scored.score || 0),
      keywordHits: scored.keywordHits,
      longestRunLen: meaningfulRunLen,
      totalTextLen,
    };
  };

  const candidates = [];
  const layout = detected && Number(detected.value) === 0x0102000a ? read0102000aLayout(childBytes, detected) : null;
  const layoutValueStart = layout ? Number(layout.shift) + 0x24 : NaN;
  const starts = [
    layoutValueStart,
    Number.isFinite(layoutValueStart) ? layoutValueStart + 4 : NaN,
    Number.isFinite(layoutValueStart) ? layoutValueStart + 8 : NaN,
    36,
    32,
    20,
  ].filter((value, index, all) => Number.isFinite(value) && value >= 0 && value < childBytes.length && all.indexOf(value) === index);

  for (const start of starts) {
    for (const key of XOR_COMMON_KEYS) {
      const candidate = makeXorCandidate(start, key, "common-key");
      if (candidate) candidates.push(candidate);
    }
  }

  const analysis = analyzeDecodedSliceXor(childBytes);
  if (
    analysis
    && Number.isFinite(Number(analysis.key))
    && Number.isFinite(Number(analysis.bodyOff))
    && Array.isArray(analysis.keywordHits)
    && analysis.keywordHits.length > 0
  ) {
    const candidate = makeXorCandidate(Number(analysis.bodyOff), Number(analysis.key), "keyword-scan");
    if (candidate) candidates.push(candidate);
  }

  const keyPriority = (item) => Number(XOR_KEY_PRIORITY.get(Number(item && item.key) & 0xff) || 0);
  candidates.sort((a, b) => (
    (Number(b.keywordHits && b.keywordHits.length) - Number(a.keywordHits && a.keywordHits.length))
    || (Number(b.longestRunLen || 0) - Number(a.longestRunLen || 0))
    || (Number(b.totalTextLen || 0) - Number(a.totalTextLen || 0))
    || (keyPriority(b) - keyPriority(a))
    || (Number(b.score || 0) - Number(a.score || 0))
  ));
  if (candidates.length > 0) {
    return candidates[0];
  }

  return plainOverlay;
}

function childDecodedCellsForRange(overlay, offset, end) {
  if (!overlay || !Array.isArray(overlay.decoded)) return null;
  const start = Number(offset);
  const stop = Number(end);
  if (!Number.isFinite(start) || !Number.isFinite(stop) || stop <= start) return null;
  const runs = (Array.isArray(overlay.runs) ? overlay.runs : []).filter((run) => (
    Number(run.start) < stop && Number(run.end) > start
  ));
  if (runs.length <= 0) return null;
  const cells = [];
  for (let pos = start; pos < stop; pos += 1) {
    const decodedIndex = pos - Number(overlay.start || 0);
    const inRun = runs.some((run) => pos >= Number(run.start) && pos < Number(run.end));
    if (decodedIndex < 0 || decodedIndex >= overlay.decoded.length || !inRun) {
      cells.push(" ");
    } else {
      cells.push(childDecodedChar(overlay.decoded[decodedIndex]));
    }
  }
  const notes = [];
  for (const run of runs) {
    const runStart = Number(run.start);
    const runEnd = Number(run.end);
    if (runStart >= start && runStart < stop) {
      notes.push(`${run.kind || "string"} ${hexOffsetText(runStart)}-${hexOffsetText(Math.max(runStart, runEnd - 1))}`);
    }
  }
  return {
    cells,
    note: notes.join("；"),
  };
}

function collectChildTimestampItems(childBytes, valueStart, timestampHints = []) {
  if (!Array.isArray(childBytes) || childBytes.length < 4) return [];
  const out = [];
  const seen = new Set();
  const add = (start, value, source, label = "", options = {}) => {
    const offset = Number(start);
    const seconds = Number(value);
    const rawEnd = Number(options && options.end);
    const end = Number.isFinite(rawEnd) && rawEnd > offset ? rawEnd : offset + 4;
    if (!Number.isFinite(offset) || offset < 0 || end > childBytes.length) return;
    if (!isPlausibleTimestampSeconds(seconds) || seen.has(offset)) return;
    seen.add(offset);
    const clock = formatTimestampDateTime(seconds) || formatTimestampClock(seconds) || String(seconds);
    const display = timestampShapeDisplay(label);
    const labelText = source === "known" && display ? `[${display}] ` : "";
    const sourceText = source === "known" || source === "summary" ? "时间戳" : source === "ob-triplet" ? "三时间戳" : "候选时间戳";
    out.push({
      start: offset,
      end,
      value: seconds,
      source,
      label,
      triplet: !!(options && options.triplet),
      text: String(options && options.text ? options.text : `${sourceText} ${labelText}${clock} @${hexOffsetText(offset)} BE秒=${seconds}`),
    });
  };

  for (const hint of Array.isArray(timestampHints) ? timestampHints : []) {
    const offset = Number(hint && hint.start);
    if (!Number.isFinite(offset) || offset < 0 || offset + 3 >= childBytes.length) continue;
    const actual = readBe32(childBytes, offset);
    if (!isPlausibleTimestampSeconds(actual)) continue;
    const field = String(hint && hint.field ? hint.field : "summary_time");
    const clock = formatTimestampDateTime(actual) || formatTimestampClock(actual) || String(actual);
    add(offset, actual, "summary", field, {
      text: `时间戳 [${field}] ${clock} @${hexOffsetText(offset)} BE秒=${actual}`,
    });
  }

  for (const item of collectRecordTimestampRanges(childBytes, 0)) {
    if (item && item.triplet) {
      add(Number(item.start), Number(item.value), "ob-triplet", item.kind, {
        triplet: true,
        end: Number(item.end),
        text: item.text,
      });
    } else {
      add(Number(item && item.start), Number(item && item.value), "known", item && item.kind);
    }
  }

  // Generic aligned BE32 values are not timestamps by default. In particular,
  // ASCII/hash bytes such as child +0x44 "dd3b" can numerically resemble an
  // epoch. The server-side tersafe.semantic.v1 analysis records such values as
  // rejected candidates with a reason; only ob:T1/T2/T3, known typed-leaf
  // shapes, and explicit schema hints are highlighted here.
  return out.sort((a, b) => Number(a.start) - Number(b.start));
}

function childHexStructure(child, childBytes, options = {}) {
  const annotations = new Map();
  const fields = [];
  let valueStart = null;
  if (!Array.isArray(childBytes) || childBytes.length <= 0) return { annotations, fields, valueStart };
  addChildHexAnnotation(annotations, 0, "record start(记录起点)");

  const detected = detectTssReport(childBytes);
  const fallbackReport = parseReportCodeNumber(child && child.reportCode);
  const fallbackOffset = Number(child && child.reportOffset);
  const report = detected || (
    Number.isFinite(fallbackReport) && Number.isFinite(fallbackOffset) && fallbackOffset >= 0
      ? { value: fallbackReport, offset: fallbackOffset }
      : null
  );

  if (report && Number.isFinite(Number(report.offset))) {
    const reportOffset = Number(report.offset);
    const framedVersion = childBytes.length >= 10 ? readBe32(childBytes, 0) : null;
    const framedTotal = childBytes.length >= 10 ? readBe16(childBytes, 4) : null;
    const hasTssLikeFrame = reportOffset === 6
      && framedVersion === 1
      && Number.isFinite(framedTotal)
      && Math.abs(Number(framedTotal) - childBytes.length) <= 4;
    if (hasTssLikeFrame) {
      addChildHexField(fields, 0, 4, `record version ${framedVersion} · TSS-like framing observed`, "version");
      addChildHexField(fields, 4, 2, `record total ${framedTotal} byte · actual ${childBytes.length}`, "total");
      valueStart = 14;
    }
    addChildHexField(
      fields,
      reportOffset,
      4,
      `${childUiTerm("report")} @${hexOffsetText(reportOffset)} ${formatHexValue(report.value, 8)}${Number(report.value) === 0x010a0013 ? " · byte split candidate 01 | 0a | 0013(19)" : ""}`,
      "report",
    );
    const idOffset = childRecordIdOffset(childBytes, report);
    if (Number(report.value) === 0x010a0013 && childBytes.length >= 20) {
      const tlvHeader = parseTssTlvRecord0013(childBytes);
      addChildHexField(fields, 10, 8, `header ID/sequence candidate · BE64 raw ${tlvHeader ? tlvHeader.headerIdHex : `0x${formatHexBytesCompact(childBytes.slice(10, 18))}`}`, "headerId");
      addChildHexField(fields, 18, 2, `flags/reserved candidate ${formatHexValue(readBe16(childBytes, 18), 4)}`, "flags");
    } else if (Number.isFinite(idOffset) && idOffset >= 0 && idOffset + 3 < childBytes.length) {
      addChildHexField(
        fields,
        idOffset,
        4,
        `${childUiTerm("ID")} @${hexOffsetText(idOffset)} ${formatHexValue(readBe32(childBytes, idOffset), 4)}`,
        "id",
      );
    }

    const encrypted = parseTssEncryptedEnvelope(childBytes);
    if (encrypted) {
      valueStart = 28;
      addChildHexField(fields, 20, 1, `crypto family ${encrypted.family} · ${encrypted.familyName}`, "cryptoFamily");
      addChildHexField(fields, 21, 1, `key slot[${encrypted.slot}]${encrypted.keyLabel ? ` · ${encrypted.keyLabel}` : ""}`, "cryptoSlot");
      addChildHexField(fields, 22, 4, `plaintext CRC32 ${formatHexValue(encrypted.expectedCrc, 8)}`, "crc");
      addChildHexField(fields, 26, 2, `cipher len ${encrypted.cipherLength} byte · available ${encrypted.availableLength}`, "cipherLen");
      addChildHexAnnotation(annotations, 28, `ciphertext start · ${encrypted.cipherLength} byte；此区不做 ASCII/XOR 语义猜测`);
    }

    const tlvRecord = parseTssTlvRecord0013(childBytes);
    if (tlvRecord && tlvRecord.valid) {
      valueStart = 20;
      for (const item of tlvRecord.items) {
        addChildHexField(fields, item.offset, 1, `TLV[${item.index}] type ${item.type}`, "tlvType");
        addChildHexField(fields, item.offset + 1, 1, `TLV[${item.index}] len ${item.length} byte`, "tlvLen");
        addChildHexField(
          fields,
          item.valueOffset,
          item.length,
          `TLV[${item.index}] value${item.text ? ` · text "${item.text}"` : ""} · ${hexOffsetText(item.valueOffset)} + ${item.length} = ${hexOffsetText(item.end)} (record end)`,
          "tlvValue",
        );
      }
    }

    if (Number(report.value) === 0x0102000a) {
      const layout = read0102000aLayout(childBytes, report);
      if (layout) {
        const lenOffset = Number(layout.shift) + 4;
        const innerLenOffset = Number(layout.shift) + 0x14;
        const innerTypeOffset = Number(layout.shift) + 0x16;
        const selector0Offset = Number(layout.shift) + 0x18;
        const selector1Offset = Number(layout.shift) + 0x1c;
        const innerFieldOffset = Number(layout.shift) + 0x20;
        valueStart = Number(layout.shift) + 0x24;
        const bodyLayout = child && child.bodyLayout ? child.bodyLayout : parseTypedBodyStructure(childBytes, layout);
        addChildHexField(fields, lenOffset, 2, `total len(总长度) ${Number(layout.len)}，confirmed`, "len");
        addChildHexField(fields, innerLenOffset, 2, `inner len(内部结构长度) ${Number(layout.innerLen || 0)}；从inner_type起覆盖到record末尾`, "innerLen");
        addChildHexField(fields, innerTypeOffset, 2, `inner type(shape字段) ${formatHexValue(layout.innerType, 4)}`, "innerType");
        addChildHexField(fields, selector0Offset, 4, `selector0(shape选择字0) ${formatHexValue(layout.selector0, 8)}`, "selector");
        const selector1Note = bodyLayout && bodyLayout.kind === "periodicProbeTable"
          ? `selector1 ${formatHexValue(layout.selector1, 8)}；高16=${formatHexValue((Number(layout.selector1) >>> 16) & 0xffff, 4)}对应单调tick，低16=${Number(bodyLayout.selectorRevisionOrFlags)} revision/flags候选`
          : `selector1(shape选择字1) ${formatHexValue(layout.selector1, 8)}`;
        addChildHexField(fields, selector1Offset, 4, selector1Note, "selector");
        if (innerFieldOffset >= 0 && innerFieldOffset + 3 < childBytes.length) {
          const pairNote = bodyLayout && bodyLayout.kind === "periodicProbeTable"
            ? `；u16 pair候选=${Number(bodyLayout.innerPair.left)}/${Number(bodyLayout.innerPair.right)}`
            : "";
          addChildHexField(fields, innerFieldOffset, 4, `inner field(shape字段) ${formatHexValue(readBe32(childBytes, innerFieldOffset), 8)}${pairNote}；它不是body[0]`, "innerField");
        }
        if (bodyLayout && bodyLayout.kind === "periodicProbeTable") {
          addChildHexField(
            fields,
            Number(bodyLayout.bodyStart),
            4,
            `单调运行tick ${formatHexValue(bodyLayout.tick, 8)} = ${Number(bodyLayout.tick)}；旧415包中位约0.987682 tick/秒，换算约${compactDurationSeconds(bodyLayout.elapsedSecondsHistoricalEstimate)}（仅历史参考）；selector匹配=${bodyLayout.selectorTickMatch ? "是" : "否"}`,
            "bodyHeader",
          );
          for (const item of bodyLayout.entries) {
            const value = item.value || {};
            const counterText = item.valueKind === "typedValue"
              ? `BE=${Number(value.be32)} LE=${Number(value.le32)}${Number.isFinite(value.floatBe) ? ` floatBE=${Number(value.floatBe).toPrecision(7)}` : ""}`
              : `计数候选=${Number(value.be32)}${Number.isFinite(item.roundRatio) ? `，相对全局轮次≈${Number(item.roundRatio).toFixed(3)}×` : ""}`;
            addChildHexField(
              fields,
              Number(item.offset),
              6,
              `探测项[${item.index}] probe_id=${formatHexValue(item.probeId, 4)}；raw32=${value.rawHex || "-"}；${counterText}；${item.valueKindLabel}`,
              "probeEntry",
            );
          }
          addChildHexAnnotation(annotations, valueStart, `body已闭合：${bodyLayout.algebra}；u32 tick + ${bodyLayout.entries.length}×(u16 probe_id + raw32 value)`);
        } else if (bodyLayout && ["fixedWordBlock", "bitmapWordBlock"].includes(bodyLayout.kind)) {
          for (const word of bodyLayout.words) {
            const value = word.value || {};
            const flags = word.allZero ? "全0" : word.allOne ? "全1/FFFF掩码" : `BE置位bit=${word.setBits.join("/") || "无"}`;
            addChildHexField(
              fields,
              Number(word.offset),
              4,
              `body word[${word.index}] raw=${value.rawHex || "-"}；BE=${formatHexValue(value.be32, 8)}(${Number(value.be32)})；LE=${formatHexValue(value.le32, 8)}；${flags}${Number.isFinite(value.floatBe) ? `；floatBE=${Number(value.floatBe).toPrecision(7)}` : ""}`,
              "bodyWord",
            );
          }
          addChildHexAnnotation(annotations, valueStart, `body已闭合：${bodyLayout.algebra}；${bodyLayout.label}，具体字段/bit含义待证`);
        } else if (valueStart >= 0 && valueStart < childBytes.length) {
          addChildHexAnnotation(annotations, valueStart, `body candidate(值区候选) @${hexOffsetText(valueStart)}；未命中已确认布局，以下按16字节分行`);
        }
      }
    }
  }

  const timestamps = collectChildTimestampItems(childBytes, valueStart, options.timestampHints);
  for (const item of timestamps) {
    const start = Number(item && item.start);
    const end = Number(item && item.end);
    if (!Number.isFinite(start) || start < 0 || !Number.isFinite(end) || end <= start || end > childBytes.length) continue;
    addChildHexField(fields, start, end - start, item.text || "时间戳", "timestamp");
  }

  return { annotations, fields, valueStart, timestamps };
}

function buildChildHexModel(child, childBytes, options = {}) {
  if (!Array.isArray(childBytes) || childBytes.length <= 0) return { rows: [], overlay: null, timestamps: [] };
  const { annotations, fields, valueStart, timestamps } = childHexStructure(child, childBytes, options);
  const overlay = child && child.bodyLayout ? null : childBestDecodedOverlay(childBytes);
  const changedOffsets = options && options.changedOffsets instanceof Set ? options.changedOffsets : null;
  const bodyStart = Number.isFinite(Number(valueStart)) ? Number(valueStart) : Math.min(16, childBytes.length);
  const normalizedFields = (Array.isArray(fields) ? fields : [])
    .map((field) => {
      const offset = Math.max(0, Math.floor(Number(field && field.offset)));
      const length = Math.max(0, Math.floor(Number(field && field.length)));
      return {
        offset,
        length: Math.min(length, Math.max(0, childBytes.length - offset)),
        note: String(field && field.note ? field.note : "").trim(),
        kind: String(field && field.kind ? field.kind : "field"),
      };
    })
    .filter((field) => Number.isFinite(field.offset) && field.length > 0 && field.offset < childBytes.length)
    .sort((a, b) => (
      (a.offset - b.offset)
      || (a.kind === "timestamp" ? -1 : 0)
      || (b.kind === "timestamp" ? 1 : 0)
      || (b.length - a.length)
    ));

  const rows = [];
  const appendRow = (offset, length, notes = [], kind = "") => {
    const safeOffset = Math.max(0, Math.floor(Number(offset)));
    const safeLength = Math.max(0, Math.floor(Number(length)));
    if (!Number.isFinite(safeOffset) || !Number.isFinite(safeLength) || safeLength <= 0) return;
    if (safeOffset >= childBytes.length) return;
    const end = Math.min(childBytes.length, safeOffset + safeLength);
    const chunk = childBytes.slice(safeOffset, end);
    const mergedNotes = [
      ...(annotations.get(safeOffset) || []),
      ...notes,
    ].map((note) => String(note || "").trim()).filter(Boolean);
    const uniqueNotes = [];
    for (const note of mergedNotes) {
      if (!uniqueNotes.includes(note)) uniqueNotes.push(note);
    }
	    rows.push({
	      offset: safeOffset,
	      bytes: chunk.map(childHexByteText).join(" "),
	      byteValues: chunk,
	      changedIndexes: changedOffsets
	        ? chunk.map((_byte, index) => changedOffsets.has(safeOffset + index))
	        : [],
	      decoded: childDecodedCellsForRange(overlay, safeOffset, end),
	      note: uniqueNotes.join("；"),
	      kind: uniqueNotes.some((note) => /时间戳/.test(note)) ? "timestamp" : String(kind || ""),
	    });
  };
  const emitGapRows = (start, end) => {
    let cursor = Math.max(0, Math.floor(Number(start)));
    const stop = Math.min(childBytes.length, Math.max(cursor, Math.floor(Number(end))));
    while (cursor < stop) {
      const width = cursor >= bodyStart ? 16 : 4;
      const length = Math.min(width, stop - cursor);
      appendRow(cursor, length);
      cursor += length;
    }
  };

  let cursor = 0;
  for (const field of normalizedFields) {
    if (field.offset < cursor) {
      addChildHexAnnotation(annotations, field.offset, field.note);
      continue;
    }
    emitGapRows(cursor, field.offset);
    appendRow(field.offset, field.length, [field.note], field.kind);
    cursor = field.offset + field.length;
  }
  emitGapRows(cursor, childBytes.length);
  return { rows, overlay, timestamps };
}

function childHexRowKindClass(kind) {
  const value = String(kind || "").trim();
  if (!value) return "";
  if (!["version", "total", "report", "id", "headerId", "flags", "tlvType", "tlvLen", "tlvValue", "len", "innerLen", "innerType", "selector", "innerField", "bodyHeader", "probeEntry", "bodyWord", "timestamp", "cryptoFamily", "cryptoSlot", "crc", "cipherLen"].includes(value)) return "";
  return ` child-hex-row-${value}`;
}

function childTimestampDisplayFromNote(note) {
  const text = String(note || "").trim();
  if (!text) return null;
  const first = text.split("；").find((part) => /时间戳/.test(part)) || text;
  const match = first.match(/^(候选时间戳|时间戳)\s*(\[[^\]]+\]\s*)?(.+?)\s*@(\+0x[0-9a-f]+)\s*BE秒=(\d+)/i);
  if (!match) {
    return {
      label: /候选/.test(first) ? "候选时间" : "时间戳",
      value: first,
      note: "",
    };
  }
  const kind = match[1] || "时间戳";
  const shape = String(match[2] || "").trim();
  return {
    label: kind === "候选时间戳" ? "候选时间" : "时间戳",
    value: String(match[3] || "").trim(),
    note: [shape, match[4], `BE=${match[5]}`].filter(Boolean).join(" "),
  };
}

function appendChildBodyLayoutPanel(wrap, bodyLayout) {
  if (!wrap || !bodyLayout) return;
  const panel = document.createElement("div");
  panel.className = "child-body-layout-panel";
  const title = document.createElement("div");
  title.className = "child-body-layout-title";
  title.textContent = `${bodyLayout.label || "Body结构"} · ${bodyLayout.confidence || "字段待证"}`;
  panel.appendChild(title);
  const grid = document.createElement("div");
  grid.className = "child-body-layout-grid";
  const add = (label, value) => {
    const item = document.createElement("div");
    item.className = "child-body-layout-item";
    const strong = document.createElement("strong");
    strong.textContent = label;
    const text = document.createElement("span");
    text.textContent = String(value || "-");
    item.appendChild(strong);
    item.appendChild(text);
    grid.appendChild(item);
  };
  add("布局", bodyLayout.algebra);
  if (bodyLayout.kind === "periodicProbeTable") {
    const counts = bodyLayout.cadenceCounts || {};
    const global = (bodyLayout.entries || []).find((entry) => Number(entry.probeId) === 0x8000);
    add("运行tick", `${Number(bodyLayout.tick)}；旧样本换算约${compactDurationSeconds(bodyLayout.elapsedSecondsHistoricalEstimate)}（仅参考）`);
    add("探测项", `${bodyLayout.entries.length} 项`);
    add("probe_id", "稀疏枚举键；中间缺号不代表丢包");
    add("轮次关系", `每轮候选 ${Number(counts.perRound || 0)} · 隔轮候选 ${Number(counts.halfRound || 0)} · 低频/条件 ${Number(counts.sparse || 0)}`);
    add("全局轮次", global ? Number(global.value && global.value.be32) : "未见0x8000");
    add("历史基线", "旧415包：0x8000轮次中位约30.031秒；当前集合待复核");
    add("边界校验", `selector tick ${bodyLayout.selectorTickMatch ? "匹配" : "不匹配"} · inner pair ${bodyLayout.innerPair.left}/${bodyLayout.innerPair.right}`);
  } else {
    add("字段槽", `${bodyLayout.words.length} × u32`);
    add("全0槽", bodyLayout.words.filter((word) => word.allZero).length);
    add("全1槽", bodyLayout.words.filter((word) => word.allOne).length);
    add("解释边界", "仅确认槽位/位图结构，具体字段与bit含义待证");
  }
  panel.appendChild(grid);
  wrap.appendChild(panel);
}

function appendChildFullHexTable(box, child, childBytes, options = {}) {
  const model = buildChildHexModel(child, childBytes, options);
  const rows = model.rows;
  if (!rows.length) return;
  const encryptedEnvelope = parseTssEncryptedEnvelope(childBytes);

	  const wrap = document.createElement("div");
	  wrap.className = "child-hex-table";
	  const title = document.createElement("div");
	  title.className = "child-hex-title";
	  const len = Array.isArray(childBytes) ? childBytes.length : 0;
	  title.textContent = `${childUiTerm("hex")} 完整 child bytes / ${childUiTerm("len")} ${len}`;
	  wrap.appendChild(title);
	  appendChildBodyLayoutPanel(wrap, child && child.bodyLayout);

	  const body = document.createElement("div");
	  body.className = "child-hex-body";
  for (const row of rows) {
    const decoded = row && row.decoded && Array.isArray(row.decoded.cells) ? row.decoded : null;
    const isTimestamp = row && row.kind === "timestamp";
    const line = document.createElement("div");
    line.className = `child-hex-row${row.note ? " child-hex-row-marked" : ""}${row.kind === "timestamp" ? " child-hex-row-time" : ""}${childHexRowKindClass(row.kind)}`;

    const offset = document.createElement("code");
    offset.className = "child-hex-offset";
    offset.textContent = hexOffsetText(row.offset);

    const bytes = document.createElement("code");
    bytes.className = "child-hex-bytes child-hex-byte-grid";
    const byteValues = Array.isArray(row.byteValues) ? row.byteValues : [];
	    const changedIndexes = Array.isArray(row.changedIndexes) ? row.changedIndexes : [];
	    for (let index = 0; index < byteValues.length; index += 1) {
	      const byte = byteValues[index];
	      const span = document.createElement("span");
	      const decodedChar = decoded && decoded.cells[index] && String(decoded.cells[index]).trim()
	        ? String(decoded.cells[index])
	        : "";
	      span.className = `child-hex-byte-cell${changedIndexes[index] ? " child-hex-byte-cell-changed" : ""}${decodedChar ? " child-hex-byte-cell-string" : ""}${isTimestamp ? " child-hex-byte-cell-time" : ""}`;
	      span.textContent = childHexByteText(byte);
	      if (decodedChar) span.title = `string char "${decodedChar}"`;
	      if (isTimestamp) span.title = [span.title, row.note].filter(Boolean).join("；");
	      bytes.appendChild(span);
	    }

    const note = document.createElement("span");
    note.className = "child-hex-note";
    const noteParts = [isTimestamp ? "时间戳" : (row.note || "")];
    if (decoded && decoded.note) noteParts.push(decoded.note);
    note.textContent = noteParts.filter(Boolean).join("；");

    const ascii = document.createElement("code");
    ascii.className = "child-hex-ascii";
    for (let index = 0; index < byteValues.length; index += 1) {
      const decodedChar = decoded && decoded.cells[index] && String(decoded.cells[index]).trim()
        ? String(decoded.cells[index])
        : "";
      const rawByte = Number(byteValues[index]);
      const absoluteOffset = Number(row.offset) + index;
      const encryptedCipherByte = encryptedEnvelope
        && absoluteOffset >= 28
        && absoluteOffset < 28 + Number(encryptedEnvelope.cipherLength || 0);
      const rawChar = !encryptedCipherByte && rawByte >= 32 && rawByte < 127 ? String.fromCharCode(rawByte) : ".";
      const span = document.createElement("span");
      span.className = `child-hex-ascii-cell${decodedChar ? " child-hex-ascii-cell-string" : ""}${changedIndexes[index] ? " child-hex-ascii-cell-changed" : ""}`;
      span.textContent = decodedChar || rawChar;
      if (decodedChar) span.title = `${decoded.note || "decoded string"} · ${hexOffsetText(Number(row.offset) + index)}`;
      ascii.appendChild(span);
    }

    line.appendChild(offset);
    line.appendChild(bytes);
    line.appendChild(ascii);
    line.appendChild(note);
	    body.appendChild(line);

	    if (isTimestamp) {
	      const time = childTimestampDisplayFromNote(row.note);
	      if (time) {
	        const timeLine = document.createElement("div");
	        timeLine.className = "child-hex-time-row";

	        const timeLabel = document.createElement("code");
	        timeLabel.className = "child-hex-time-label";
	        timeLabel.textContent = time.label || "时间戳";

	        const timeValue = document.createElement("code");
	        timeValue.className = "child-hex-time-value";
	        timeValue.textContent = time.value || "";

	        const timeNote = document.createElement("span");
	        timeNote.className = "child-hex-time-note";
	        timeNote.textContent = time.note || "";

	        timeLine.appendChild(timeLabel);
	        timeLine.appendChild(timeValue);
	        timeLine.appendChild(timeNote);
	        body.appendChild(timeLine);
	      }
	    }

	  }
	  wrap.appendChild(body);

  const insights = [];
  if (model.overlay && Array.isArray(model.overlay.runs) && model.overlay.runs.length > 0) {
    for (const run of model.overlay.runs.slice(0, 8)) {
      insights.push({
        kind: "string",
        label: model.overlay.label || "string",
        value: `${hexOffsetText(run.start)}-${hexOffsetText(Math.max(Number(run.start), Number(run.end) - 1))} ${run.kind ? `${run.kind} ` : ""}"${normalizeVisibleText(run.text)}"`,
      });
    }
  }
  if (Array.isArray(model.timestamps) && model.timestamps.length > 0) {
    for (const ts of model.timestamps.slice(0, 8)) {
      insights.push({
        kind: "time",
        label: ts.source === "known" ? "时间戳" : "候选时间戳",
        value: ts.text,
      });
    }
  }
  if (options.showInsights !== false && insights.length > 0) {
    const insightBox = document.createElement("div");
    insightBox.className = "child-hex-insights";
    for (const insight of insights) {
      const item = document.createElement("div");
      item.className = `child-hex-insight child-hex-insight-${insight.kind || "field"}`;
      item.title = `${insight.label || ""} ${insight.value || ""}`.trim();
      const label = document.createElement("strong");
      label.textContent = insight.label || "";
      const value = document.createElement("span");
      value.textContent = insight.value || "";
      item.appendChild(label);
      item.appendChild(value);
      insightBox.appendChild(item);
    }
    wrap.appendChild(insightBox);
  }

  box.appendChild(wrap);
}

function makeChildCommonStrip(beforeChild, afterChild, action, result, ruleCompact, observation) {
  ensureChildCommonStyles();
  const strip = document.createElement("div");
  strip.className = "child-common-strip";
  const kind = childActionKind(action && action.action, action && action.reason) || "observe";

  const decision = document.createElement("div");
  decision.className = "child-decision-row";
  const pill = document.createElement("span");
  pill.className = `child-decision-pill child-decision-${kind}`;
  pill.textContent = childActionBadgeText(action, result);
  const copy = document.createElement("span");
  copy.className = "child-decision-copy";
  copy.textContent = childDecisionText(kind, result);
  decision.appendChild(pill);
  decision.appendChild(copy);
  strip.appendChild(decision);

  const primary = document.createElement("div");
  primary.className = "child-metric-grid";

  appendChildCommonChip(primary, "report", pairText("", childReportText(beforeChild), childReportText(afterChild)).trim());
  appendChildCommonChip(primary, "类型", pairText("", childTypeText(beforeChild), childTypeText(afterChild)).trim());
  appendChildCommonChip(
    primary,
    "长度",
    pairText(
      "",
      beforeChild && Number.isFinite(beforeChild.len) ? String(beforeChild.len) : "-",
      afterChild && Number.isFinite(afterChild.len) ? String(afterChild.len) : "-",
    ).trim(),
  );
  appendChildCommonChip(primary, "ID", pairText("", childIdText(beforeChild), childIdText(afterChild)).trim());
  appendChildCommonChip(primary, "差异", childDiffText(result && result.diff));
  appendChildCommonChip(primary, "动作", childActionLabel(action && action.action, result));
  if (action && action.source && action.source !== "-") {
    appendChildCommonChip(primary, "来源", compactReportToDisplay(action.source));
  }
  strip.appendChild(primary);

  const detailRows = [];
  if (action && action.reason) {
    detailRows.push(["原因", translatedReasonText(action.reason) || action.reason]);
  }
  if (ruleCompact) {
    detailRows.push(["规则", ruleCompact]);
  }
  if (observation) {
    detailRows.push(["观察", observation]);
  }
  if (detailRows.length) {
    const rowWrap = document.createElement("div");
    rowWrap.className = "child-context-row";
    for (const [label, value] of detailRows) {
      const row = document.createElement("div");
      row.className = "child-context-chip";
      row.title = `${label} ${value}`;
      const strong = document.createElement("strong");
      strong.textContent = `${label} `;
      row.appendChild(strong);
      row.appendChild(document.createTextNode(normalizeVisibleText(value)));
      rowWrap.appendChild(row);
    }
    strip.appendChild(rowWrap);
  }

  return strip.childNodes.length ? strip : null;
}

function makeChildSide(child, sideLabel, sideClass, extraRows = [], options = {}) {
  const side = document.createElement("div");
  side.className = `child-side child-side-${sideClass}${options.compactMeta ? " child-side-compact" : ""}`.trim();

  const title = document.createElement("div");
  title.className = "child-side-title";
  const name = document.createElement("span");
  name.textContent = childNodeName(child);
  const label = document.createElement("span");
  label.className = "child-side-label";
  label.textContent = sideLabel;
  title.appendChild(name);
  title.appendChild(label);
  side.appendChild(title);

  if (!options.compactMeta) {
    appendChildSideLine(side, "report", childReportText(child));
    appendChildSideLine(side, "类型", childTypeText(child));
    appendChildSideLine(side, "长度", child && Number.isFinite(child.len) ? String(child.len) : "-");
    appendChildSideLine(side, "ID", childIdText(child));
  }

  const semanticRows = splitChildSemanticRows(child);
  for (const [rowLabel, value, className] of semanticRows.primaryRows) {
    appendChildSideLine(side, rowLabel, value, className || "");
  }

  for (const [rowLabel, value, className] of extraRows) {
    appendChildSideLine(side, rowLabel, value, className || "");
  }

  const debugLines = [];
  const offsetText = childOffsetText(child);
  if (offsetText && offsetText !== "-") debugLines.push(`offset=${offsetText}`);
  debugLines.push(...semanticRows.debugLines);
  appendChildDebugDetails(side, debugLines);

  return side;
}

function childPreviewLines(child, maxLines = 2) {
  if (!child || child.truncated) return [];
  const semanticRows = splitChildSemanticRows(child);
  const lines = [];
  for (const [label, value] of semanticRows.primaryRows) {
    const text = normalizeVisibleText(value);
    if (text) lines.push(`${label} ${text}`);
    if (lines.length >= maxLines) break;
  }
  if (lines.length < maxLines) {
    const offsetText = childOffsetText(child);
    if (offsetText && offsetText !== "-") lines.push(`offset=${offsetText}`);
  }
  return lines.slice(0, maxLines);
}

function childIndexText(child) {
  if (!child || child.truncated || !Number.isFinite(Number(child.index))) return "-";
  return String(Number(child.index));
}

function childSemanticRoleText(child) {
  if (!child || child.truncated) return "";
  if (child.semanticLabel) {
    return `${child.semanticLabel} [${semanticTierLabel(child.semanticTier)}]`;
  }
  const report = parseReportCodeNumber(child.reportCode);
  const text = [
    child.valuePreview,
    child.xorCommonPreview,
    child.hexSignature,
    childTypeText(child),
  ].join(" ").toLowerCase();
  if (/uiwindow|uiview|uicontroller|uitransition|backboard|spotlight/.test(text)) {
    return "ui-hierarchy / UI层级与前台服务链";
  }
  if (/dylib|framework|usr\/lib|privateframework|\.so\b/.test(text)) {
    return "dylib-path? / 动态库路径候选";
  }
  if (/process|backboardservices|springboard|spotlight|com\.apple/.test(text)) {
    return "process-chain / 系统进程链";
  }
  if (/mrpcs|mrcp|mrp|\.data|documents-dir|files-dir|main_module_path|\/var\/|\/documents|\/library/.test(text)) {
    return "file_reference / 路径或同步文件引用";
  }
  if (/model|ver|iphone|ipad|ios|language|screen|vpn/.test(text)) {
    return "device_profile / 设备与运行环境画像";
  }
  if (/inc_id|obf_id|account|open_id|openid|uin/.test(text)) {
    return "account_metadata / 账号与会话索引";
  }
  if (/\bstate\b|<state:|cnt:|counter|status/.test(text)) {
    return "state_snapshot / 状态快照";
  }
  if (Number(report) === 0x0102000a) return "typed leaf shell / 按完整 shape 分类";
  if (Math.floor(Number(report || 0) / 0x10000) === 0x0112) return "structured-metadata / 结构化元数据";
  return "";
}

function childRichTypeText(child) {
  if (!child || child.truncated) return "-";
  const report = parseReportCodeNumber(child.reportCode);
  const rawType = String(child.className || "").trim();
  if (child.semanticLabel) return humanChildSemanticLabel(child.semanticLabel);
  if (Number(report) === 0x0102000a) return "分类数据项";
  if (Number(report) === 0x010a0011) return "需保留的子请求";
  if (Number(report) === 0x010a0010) return "子请求回执";
  if (Number(report) === 0x010a001b) return "父容器";
  if (Math.floor(Number(report || 0) / 0x10000) === 0x0112) return "结构化数据";
  if (rawType === "text/binary-leaf") return "文本和二进制混合数据";
  if (rawType === "binary-like-leaf" || rawType === "binary-like") return "二进制数据";
  if (rawType === "structured" || rawType === "structured-metadata") return "结构化数据";
  return rawType || reportBusinessLabel(report) || "-";
}

function childFullMetaLine(child) {
  if (!child || child.truncated) return "";
  const parts = [
    `索引 ${childIndexText(child)}`,
    `${childUiTerm("report")} ${childReportText(child)}`,
    `${childUiTerm("type")} ${childRichTypeText(child)}`,
    `${childUiTerm("ID")} ${childIdText(child)}`,
    Number.isFinite(child.len) ? `${childUiTerm("len")} ${child.len}` : "",
    `${childUiTerm("offset")} ${childOffsetText(child)}`,
  ].filter((part) => part && !part.endsWith(" -"));
  return parts.join(" | ");
}

function childCompactMetaLine(child) {
  if (!child || child.truncated) return "";
  const parts = [
    Number.isFinite(child.len) ? `长度 ${child.len}` : "",
    childOffsetText(child) && childOffsetText(child) !== "-" ? `位置 ${childOffsetText(child)}` : "",
  ].filter(Boolean);
  return parts.join(" | ");
}

function childHexLine(child, childBytes) {
  if (child && child.hexSignature) return `${childUiTerm("hex")} ${annotateHexSignature(child.hexSignature)}`;
  if (Array.isArray(childBytes) && childBytes.length > 0) {
    const head = formatHexBytePreview(childBytes, Math.min(32, childBytes.length));
    return `${childUiTerm("hex")} ${childUiTerm("head")}=${head}${childBytes.length > 32 ? " ..." : ""}`;
  }
  return "";
}

function childPreviewRichLines(child, childBytes, options = {}) {
  if (!child || child.truncated) return [];
  const lines = [];
  const meta = childCompactMetaLine(child);
  if (meta) lines.push({ text: meta, className: "child-preview-line-meta" });
  const semanticRows = splitChildSemanticRows(child);
  const semanticLimit = options.merged ? 4 : 3;
  for (const [label, value] of semanticRows.primaryRows) {
    const text = String(value || "").trim();
    if (text) lines.push({ text: `${label} ${text}`, className: "" });
    if (lines.length >= semanticLimit + 1) break;
  }
  for (const extra of Array.isArray(options.extraLines) ? options.extraLines : []) {
    const text = typeof extra === "object" ? String(extra.text || "").trim() : String(extra || "").trim();
    const className = typeof extra === "object" && extra.className ? String(extra.className) : "child-preview-line-meta";
    if (text) lines.push({ text, className });
  }
  return lines;
}

function childPreviewSegmentKind(label, fallbackClass = "") {
  const value = String(label || "").trim().toLowerCase();
  if (value === "动作" || value === "处理") return "action";
  if (value === "原因") return "reason";
  if (value === "source(来源)" || value === "source" || value === "来源") return "source";
  if (value === "规则") return "rule";
  if (value === "风险" || value === "注意") return "risk";
  if (["解析", "用途", "结构", "发现", "文本"].includes(value)) return "parse";
  if (["body布局", "运行时钟", "探测分组", "typed值", "字段槽"].includes(value)) return "parse";
  if (value === "可打印xor") return "xor";
  if (value === "时间戳" || value === "候选时间戳") return "time";
  if (value === "len" || value === "off") return "meta";
  if (String(fallbackClass || "").includes("risk")) return "risk";
  return "plain";
}

function childPreviewSegmentParts(rawSegment, fallbackClass = "") {
  const raw = String(rawSegment || "").trim();
  if (!raw) return null;
  const labels = [
    "处理",
    "注意",
    "用途",
    "结构",
    "发现",
    "文本",
    "source(来源)",
    "可打印XOR",
    "Body布局",
    "运行时钟",
    "探测分组",
    "Typed值",
    "字段槽",
    "候选时间戳",
    "时间戳",
    "动作",
    "原因",
    "规则",
    "风险",
    "解析",
    "长度",
    "位置",
    "len",
    "off",
  ];
  for (const label of labels) {
    if (raw === label) {
      return { label, value: "", kind: childPreviewSegmentKind(label, fallbackClass) };
    }
    if (raw.startsWith(`${label} `) || raw.startsWith(`${label}:`) || raw.startsWith(`${label}：`)) {
      const value = raw.slice(label.length).replace(/^[\s:：]+/, "");
      return { label, value, kind: childPreviewSegmentKind(label, fallbackClass) };
    }
  }
  return { label: "", value: raw, kind: childPreviewSegmentKind("", fallbackClass) };
}

function formatTimestampPreviewValue(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  const parts = text.split(/[,\s/]+/).map((item) => item.trim()).filter(Boolean);
  if (parts.length <= 0) return text;
  const clocks = [];
  for (const part of parts) {
    if (!/^\d{10}$/.test(part)) return text;
    const seconds = Number(part);
    if (!isPlausibleTimestampSeconds(seconds)) return text;
    const clock = formatTimestampDateTime(seconds) || formatTimestampClock(seconds) || part;
    clocks.push(clock);
  }
  return clocks.join(" / ");
}

function appendChildPreviewToken(container, segment, fallbackClass = "") {
  const parts = childPreviewSegmentParts(segment, fallbackClass);
  if (!parts) return;
  const chip = document.createElement("span");
  chip.className = `child-preview-token child-preview-token-${parts.kind}`.trim();
  chip.title = String(segment || "").trim();
  if (parts.label) {
    const label = document.createElement("strong");
    label.textContent = parts.label;
    chip.appendChild(label);
  }
  if (parts.value) {
    const displayValue = parts.kind === "time" ? formatTimestampPreviewValue(parts.value) : parts.value;
    const valueNode = /^(0x[0-9a-f]+|[a-z0-9_./:-]+)$/i.test(parts.value) && parts.value.length <= 80
      ? document.createElement("code")
      : document.createElement("span");
    valueNode.textContent = displayValue;
    chip.appendChild(valueNode);
  }
  container.appendChild(chip);
}

function appendChildPreviewLine(container, entry) {
  const text = String(entry && entry.text ? entry.text : "").trim();
  if (!text) return;
  const className = String(entry && entry.className ? entry.className : "");
  const line = document.createElement("div");
  line.className = `child-preview-line child-preview-line-rich ${className}`.trim();
  line.title = text;
  const segments = text.split(/\s+\|\s+/).map((segment) => segment.trim()).filter(Boolean);
  for (const segment of segments.length ? segments : [text]) {
    appendChildPreviewToken(line, segment, className);
  }
  container.appendChild(line);
}

function makeChildPreviewBox(child, label, sideClass, childBytes = [], options = {}) {
  const box = document.createElement("div");
  box.className = `child-preview-box child-preview-${sideClass}`;
  const info = document.createElement("div");
  info.className = "child-preview-info";
  const title = document.createElement("div");
  title.className = "child-preview-label";
  title.textContent = label;
  info.appendChild(title);
  const lines = childPreviewRichLines(child, childBytes, options);
  if (!lines.length) {
    const empty = document.createElement("div");
    empty.className = "child-preview-empty";
    empty.textContent = "-";
    info.appendChild(empty);
  } else {
    for (const entry of lines) {
      appendChildPreviewLine(info, entry);
    }
  }
  box.appendChild(info);
	  appendChildFullHexTable(box, child, childBytes, {
	    changedOffsets: options.changedOffsets || null,
	    showInsights: options.showInsights !== false,
	    timestampHints: options.timestampHints || [],
	  });
	  return box;
	}

function childRecordAbsoluteStart(child) {
  if (!child || child.truncated) return null;
  const recordStart = Number(child.recordStart);
  if (Number.isFinite(recordStart)) return recordStart;
  const offset = Number(child.offset);
  if (Number.isFinite(offset)) return offset + 4;
  return null;
}

function normalizeChildTimestampHints(child, childBytes, timestampHintMap) {
  if (!child || child.truncated || !(timestampHintMap instanceof Map)) return [];
  const index = Number(child.index);
  const hints = timestampHintMap.get(index) || [];
  if (!Array.isArray(hints) || hints.length <= 0) return [];
  const reportText = childReportText(child).toLowerCase();
  const recordStart = childRecordAbsoluteStart(child);
  const out = [];
  const seen = new Set();
  for (const hint of hints) {
    if (!hint) continue;
    const report = String(hint.report || "").toLowerCase();
    if (report && reportText !== "-" && report !== reportText) continue;
    const absoluteOffset = Number(hint.absoluteOffset);
    const candidates = [];
    if (Number.isFinite(absoluteOffset) && Number.isFinite(recordStart)) {
      candidates.push(absoluteOffset - recordStart);
    }
    if (Number.isFinite(absoluteOffset)) candidates.push(absoluteOffset);
    for (const start of candidates) {
      const local = Math.floor(Number(start));
      if (!Number.isFinite(local) || local < 0 || local + 3 >= childBytes.length) continue;
      const actual = readBe32(childBytes, local);
      if (!isPlausibleTimestampSeconds(actual)) continue;
      const key = `${local}:${actual}:${hint.field || ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        ...hint,
        start: local,
        seconds: actual,
      });
      break;
    }
  }
  return out;
}

function makeChildPreviewRow(beforeChild, afterChild, labelBase = "child", beforeBytes = [], afterBytes = [], result = null, action = null, ruleCompact = "", risk = null, timestampHintMap = null, rowOptions = {}) {
  const row = document.createElement("div");
  row.className = "child-preview-row";
  const changedOffsets = buildChangedIndexSet(beforeBytes, afterBytes);
  const beforeTimestampHints = normalizeChildTimestampHints(beforeChild, beforeBytes, timestampHintMap);
  const afterTimestampHints = normalizeChildTimestampHints(afterChild, afterBytes, timestampHintMap);
  const forceSideBySideSame = Boolean(rowOptions && rowOptions.forceSideBySideSame);
  if (result && result.kind === "same" && !forceSideBySideSame) {
    row.classList.add("child-preview-row-single");
    const singleLabel = result.originalOnly
      ? `${labelBase} 原包 / 当前`
      : result.currentOnly
        ? `${labelBase} 当前结构`
        : `${labelBase} 未修改`;
    row.appendChild(makeChildPreviewBox(afterChild || beforeChild, singleLabel, "same", afterBytes.length ? afterBytes : beforeBytes, {
      merged: true,
      showInsights: true,
      timestampHints: afterTimestampHints.length ? afterTimestampHints : beforeTimestampHints,
    }));
    return row;
  }
  row.appendChild(makeChildPreviewBox(beforeChild, `${labelBase} 修改前`, "before", beforeBytes, {
    changedOffsets,
    showInsights: true,
    timestampHints: beforeTimestampHints,
  }));
  const afterExtra = [];
  if (action && (action.action || action.reason || action.source)) {
    afterExtra.push(`处理 ${humanChildRuleSummary(action, result)}`);
  }
  if (risk && risk.text) afterExtra.push({ text: `注意 ${risk.text}`, className: "child-preview-line-risk" });
  row.appendChild(makeChildPreviewBox(afterChild, `${labelBase} 修改后`, "after", afterBytes, {
    extraLines: afterExtra,
    changedOffsets,
    showInsights: true,
    timestampHints: afterTimestampHints,
  }));
  return row;
}

function inferChildActionFromSummary(summaryKv, result, beforeChild, afterChild) {
  const kv = summaryKv && typeof summaryKv === "object" ? summaryKv : {};
  const sim = String(kv.sim || "").trim();
  const mode = String(kv.mode || "").trim();
  const match = String(kv.match || "").trim();
  const reason = String(kv.reason || "").trim();
  if (sim === "preserved_target_allowed" || match === "target_preserve") {
    return {
      action: "KEEP",
      reason: reason || "target_preserve",
      source: "",
      report: "",
    };
  }
  if (sim === "neutralized_fallback" || mode === "target_neutralize") {
    const same = result && result.kind === "same";
    const ruleText = childRuleAnnotations(beforeChild, afterChild, { reason });
    const protectedSame = same && /白名单|保护/.test(ruleText);
    return {
      action: protectedSame ? "KEEP" : "CLEAN",
      reason: reason || "neutralized_fallback",
      source: "",
      report: "",
    };
  }
  if (sim === "no_library_match") {
    const same = result && result.kind === "same";
    const ruleText = childRuleAnnotations(beforeChild, afterChild, { reason: reason || "no_library_match" });
    const protectedSame = same && /白名单|保护/.test(ruleText);
    return {
      action: protectedSame ? "KEEP" : "CLEAN",
      reason: reason || "no_library_match",
      source: "",
      report: "",
    };
  }
  return null;
}

function childResultInfo(beforeChild, afterChild, beforeBytes, afterBytes) {
  if (!beforeChild && !afterChild) {
    return { label: "无解析", kind: "struct" };
  }
  if (beforeChild && !afterChild) {
    return { label: "已删除", kind: "struct" };
  }
  if (!beforeChild && afterChild) {
    return { label: "新增", kind: "struct" };
  }

  const beforeReport = beforeChild.reportCode;
  const afterReport = afterChild.reportCode;
  const beforeId = beforeChild.idValue;
  const afterId = afterChild.idValue;
  const diff = countChangedBytes(beforeBytes, afterBytes);
  if (Number(beforeReport) !== Number(afterReport)) {
    return { label: "类型变化", kind: "struct", diff };
  }
  if (diff.lenDelta !== 0) {
    return { label: "长度变化", kind: "struct", diff };
  }
  if (diff.changed > 0) {
    return { label: "已变化", kind: "changed", diff };
  }
  if (Number.isFinite(beforeId) && Number.isFinite(afterId) && Number(beforeId) !== Number(afterId)) {
    return { label: "ID变化", kind: "changed", diff };
  }
  return { label: "结果一样", kind: "same", diff };
}

function isRequestFlagPatchDiff(beforeChild, afterChild, beforeBytes, afterBytes, result, summaryKv = null) {
  const beforeReport = parseReportCodeNumber(beforeChild && beforeChild.reportCode);
  const afterReport = parseReportCodeNumber(afterChild && afterChild.reportCode);
  if (beforeReport !== 0x0102000a || afterReport !== 0x0102000a) return false;
  const left = Array.isArray(beforeBytes) ? beforeBytes : [];
  const right = Array.isArray(afterBytes) ? afterBytes : [];
  if (left.length <= 0 || left.length !== right.length) return false;
  const diff = result && result.diff ? result.diff : countChangedBytes(left, right);
  if (Number(diff.lenDelta || 0) !== 0 || Number(diff.changed || 0) <= 0 || Number(diff.changed || 0) > 2) {
    return false;
  }
  const changedOffsets = [];
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) changedOffsets.push(i);
  }
  if (!changedOffsets.length || !changedOffsets.every((offset) => left[offset] === 0x00 && right[offset] === 0x01)) {
    return false;
  }
  const mode = String(summaryKv && summaryKv.mode ? summaryKv.mode : "").trim();
  if (mode === "child_request_flag_0x11_patch") return true;
  return changedOffsets.some((offset) => offset === 0x11);
}

function requestFlagPatchAction(beforeChild, afterChild) {
  return {
    action: "REQ11",
    reason: "child_request_flag_0x11_patch",
    source: "",
    report: childReportText(afterChild || beforeChild),
  };
}

function childReportText(child) {
  if (!child || child.truncated || child.reportCode === null || child.reportCode === undefined) return "-";
  return formatHexValue(child.reportCode, 8);
}

function childIdText(child) {
  if (!child || child.truncated) return "-";
  if (child.idText) return String(child.idText);
  if (!Number.isFinite(child.idValue)) return "-";
  return formatHexValue(child.idValue, 4);
}

function childDiffText(diff) {
  if (!diff) return "-";
  const changed = Number(diff.changed || 0);
  const delta = Number(diff.lenDelta || 0);
  if (delta === 0) return `改了 ${changed} 字节`;
  return `改了 ${changed} 字节，${delta > 0 ? "增加" : "减少"} ${Math.abs(delta)} 字节`;
}

function childReplacementRisk(beforeChild, afterChild, beforeBytes, afterBytes, action, result) {
  const kind = childActionKind(action && action.action, action && action.reason);
  if (kind !== "replace") return null;
  const diff = result && result.diff ? result.diff : countChangedBytes(beforeBytes, afterBytes);
  const beforeType = childRichTypeText(beforeChild);
  const afterType = childRichTypeText(afterChild);
  const lengthChanged = Number(diff && diff.lenDelta || 0) !== 0;
  const typeChanged = beforeType && afterType && beforeType !== "-" && afterType !== "-" && beforeType !== afterType;
  if (!lengthChanged && !typeChanged) return null;
  const parts = [];
  if (lengthChanged) parts.push(`长度 ${diff.leftLen} → ${diff.rightLen}`);
  if (typeChanged) parts.push("用途不同");
  return {
    level: "review",
    text: `${parts.join("，")}，请确认录制样本是否匹配`,
  };
}

function makeChildCard(beforeChildren, afterChildren, beforeBytesAll, afterBytesAll, index, actionMap, summaryKv = null, timestampHintMap = null, options = {}) {
  ensureChildCommonStyles();
  const beforeChild = beforeChildren[index] || null;
  const afterChild = afterChildren[index] || null;
  const beforeBytes = childBytesFromParsed(beforeBytesAll, beforeChild);
  const afterBytes = childBytesFromParsed(afterBytesAll, afterChild);
  const originalOnly = Boolean(options && options.originalOnly && !beforeChild && afterChild);
  const currentOnly = Boolean(options && options.currentOnly && !beforeChild && afterChild);
  const comparedResult = childResultInfo(beforeChild, afterChild, beforeBytes, afterBytes);
  const result = originalOnly || currentOnly
    ? {
      label: originalOnly ? "原包观察" : "当前结构",
      kind: "same",
      diff: null,
      originalOnly,
      currentOnly,
    }
    : comparedResult;
  const mappedAction = actionMap instanceof Map ? actionMap.get(index) : null;
  let action = mappedAction || (originalOnly || currentOnly ? null : inferChildActionFromSummary(summaryKv, result, beforeChild, afterChild));
  if (isRequestFlagPatchDiff(beforeChild, afterChild, beforeBytes, afterBytes, result, summaryKv)) {
    action = requestFlagPatchAction(beforeChild, afterChild);
  }
  const nodeLabel = childNodeName(afterChild || beforeChild || { index });
  const ruleText = childRuleAnnotations(beforeChild, afterChild, action);
  const ruleCompact = compactRuleText(ruleText);
  const observation = childActionObservation(action, result);
  const kind = childActionKind(action && action.action, action && action.reason) || "observe";
  const risk = childReplacementRisk(beforeChild, afterChild, beforeBytes, afterBytes, action, result);
  const hasExplicitAction = Boolean(action && (action.action || action.reason || action.source || action.report));
  const sameNoAction = result.kind === "same" && !hasExplicitAction;

  const card = document.createElement("div");
  card.className = `child-pair-card child-card-result-${result.kind}`;
  if (result.kind === "same" && !(options && options.forceSideBySideSame)) {
    card.classList.add("child-card-same-merged");
  }

  const title = document.createElement("div");
  title.className = "child-pair-title";
  const name = document.createElement("span");
  name.className = "child-rail-name";
  name.textContent = nodeLabel;
  const label = document.createElement("span");
  label.className = "child-rail-label";
  label.textContent = "预览";
  name.appendChild(label);
  const badges = document.createElement("span");
  badges.className = "child-title-badges";
  const status = document.createElement("span");
  status.className = `child-status child-status-${result.kind}`;
  status.textContent = originalOnly ? "原包观察" : (currentOnly ? "当前结构" : (sameNoAction ? "未修改" : result.label));
  badges.appendChild(status);
  const semanticChild = afterChild || beforeChild;
  if (semanticChild && semanticChild.semanticLabel) {
    const semanticBadge = document.createElement("span");
    const semanticTier = String(semanticChild.semanticTier || "unknown").toLowerCase();
    semanticBadge.className = `child-semantic-tier child-semantic-tier-${semanticTier}`;
    semanticBadge.textContent = semanticTierLabel(semanticTier);
    semanticBadge.title = [
      semanticChild.semanticLabel,
      semanticChild.semanticCategory,
      ...(Array.isArray(semanticChild.semanticEvidence) ? semanticChild.semanticEvidence : []),
    ].filter(Boolean).join(" | ");
    badges.appendChild(semanticBadge);
  }
  if (!sameNoAction) {
    const actionBadge = document.createElement("span");
    actionBadge.className = `child-rail-action child-decision-${kind}`;
    actionBadge.textContent = childActionBadgeText(action, result);
    badges.appendChild(actionBadge);
  }
  if (risk) {
    const riskBadge = document.createElement("span");
    riskBadge.className = "child-risk-badge";
    riskBadge.textContent = "变化较大";
    riskBadge.title = risk.text;
    badges.appendChild(riskBadge);
  }
  title.appendChild(name);
  title.appendChild(badges);

  if (!sameNoAction) {
    const copy = document.createElement("div");
    copy.className = "child-rail-copy";
    copy.title = [childDecisionText(kind, result), risk && risk.text, ruleCompact, observation].filter(Boolean).join("；");
    copy.textContent = risk ? `${childDecisionText(kind, result)}；${risk.text}` : childDecisionText(kind, result);
    title.appendChild(copy);
  }

  const meta = document.createElement("div");
  meta.className = "child-rail-meta-grid";
  if (originalOnly || currentOnly) {
    appendChildRailMeta(meta, childUiShortTerm("idx"), childIndexText(afterChild));
    appendChildRailMeta(meta, childUiShortTerm("report"), childReportText(afterChild));
    appendChildRailMeta(meta, childUiShortTerm("type"), childRichTypeText(afterChild));
    appendChildRailMeta(meta, childUiShortTerm("ID"), childIdText(afterChild));
    appendChildRailMeta(meta, childUiShortTerm("len"), afterChild && Number.isFinite(afterChild.len) ? String(afterChild.len) : "-");
  } else {
    appendChildRailMeta(meta, childUiShortTerm("idx"), pairText("", childIndexText(beforeChild), childIndexText(afterChild)).trim());
    appendChildRailMeta(meta, childUiShortTerm("report"), pairText("", childReportText(beforeChild), childReportText(afterChild)).trim());
    appendChildRailMeta(meta, childUiShortTerm("type"), pairText("", childRichTypeText(beforeChild), childRichTypeText(afterChild)).trim());
    appendChildRailMeta(meta, childUiShortTerm("ID"), pairText("", childIdText(beforeChild), childIdText(afterChild)).trim());
    appendChildRailMeta(
      meta,
      childUiShortTerm("len"),
      pairText(
        "",
        beforeChild && Number.isFinite(beforeChild.len) ? String(beforeChild.len) : "-",
        afterChild && Number.isFinite(afterChild.len) ? String(afterChild.len) : "-",
      ).trim(),
    );
    appendChildRailMeta(meta, childUiShortTerm("diff"), childDiffText(result && result.diff));
  }
  if (meta.childNodes.length) title.appendChild(meta);

  card.appendChild(title);
  card.appendChild(makeChildPreviewRow(beforeChild, afterChild, nodeLabel, beforeBytes, afterBytes, result, action, ruleCompact, risk, timestampHintMap, {
    forceSideBySideSame: Boolean(options && options.forceSideBySideSame),
  }));

  return card;
}

function parentStructureText(parent) {
  if (!parent) return "无 0x010A001B 父容器结构信息";
  const tailHex = parent.tailHex || "-";
  const magicText = parent.tailLen === 0
    ? "tail=empty"
    : parent.tailMagicOk
      ? `tail=fixed-trailer ${tailHex}`
      : `tail=${tailHex} unexpected`;
  return [
    `count=${Number(parent.childCount || 0)}`,
    `layout=${parent.layout || "-"}`,
    `header_len=${Number(parent.headerLen || 0)}`,
    `child_start=${formatHexValue(parent.childStartOffset)}`,
    `children_end=${formatHexValue(parent.childrenEndOffset)}`,
    `tail_len=${Number(parent.tailLen || 0)}`,
    magicText,
  ].join("  ");
}

function appendParentStructureSide(container, label, parent) {
  const side = document.createElement("div");
  side.className = "parent-structure-side";
  const title = document.createElement("strong");
  title.textContent = label;
  side.appendChild(title);
  const text = document.createElement("span");
  text.textContent = parentStructureText(parent);
  side.appendChild(text);
  if (parent && Number(parent.tailLen || 0) > 0 && !parent.tailMagicOk) {
    const status = document.createElement("div");
    status.className = "parent-structure-magic-bad";
    status.textContent = "tail 不是已知固定 trailer，需要复核";
    side.appendChild(status);
  }
  container.appendChild(side);
}

function makeParentStructureStrip(beforeParent, afterParent, options = {}) {
  if (!beforeParent && !afterParent) return null;
  const strip = document.createElement("div");
  strip.className = "parent-structure-strip";
  const title = document.createElement("div");
  title.className = "parent-structure-title";
  const left = document.createElement("span");
  left.textContent = "父容器结构证据";
	  const right = document.createElement("small");
	  right.textContent = "header / fixed trailer 只作结构边界参考";
  title.appendChild(left);
  title.appendChild(right);
  strip.appendChild(title);

  const grid = document.createElement("div");
  grid.className = "parent-structure-grid";
  if (options && (options.originalOnly || options.currentOnly)) {
    appendParentStructureSide(
      grid,
      options.originalOnly ? "原包 / 当前 parent" : "当前 parent",
      afterParent || beforeParent,
    );
  } else {
    appendParentStructureSide(grid, "before parent", beforeParent);
    appendParentStructureSide(grid, "after parent", afterParent);
  }
  strip.appendChild(grid);
  return strip;
}

function buildEventTimestampStrip(summaryText, beforeBase64, decodedBase64) {
  ensureChildCommonStyles();
  const items = [];
  const summaryInsight = compactTimeInsight(summaryText);
  if (summaryInsight && summaryInsight.text) {
    items.push({
      kind: "summary",
      text: summaryInsight.text,
      title: summaryInsight.title || summaryInsight.text,
    });
  }
  const addPayloadTimes = (label, base64Text) => {
    if (!base64Text) return;
    const ranges = collectTimestampHighlightsForPayload(base64Text);
    for (const item of ranges.slice(0, 8)) {
      const clock = formatTimestampDateTime(Number(item && item.value)) || formatTimestampClock(Number(item && item.value)) || String(item && item.value);
      const offset = formatHexValue(Number(item && item.start));
      const shape = timestampShapeDisplay(item && item.kind);
      items.push({
        kind: "offset",
        text: item && item.triplet
          ? `${label} 三时间 ${String(item.kind || "").replace(/_triplet$/i, "")} ${offset} ${clock}`
          : `${label} ${offset} ${clock}`,
        title: [shape, item && item.text].filter(Boolean).join(" | "),
      });
    }
  };
  addPayloadTimes("before", beforeBase64);
  addPayloadTimes("after", decodedBase64);

  const seen = new Set();
  const unique = items.filter((item) => {
    const key = `${item.kind}:${item.text}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  if (unique.length <= 0) return null;

  const strip = document.createElement("div");
  strip.className = "event-time-strip";
  const title = document.createElement("span");
  title.className = "event-time-title";
  title.textContent = "时间戳定位";
  strip.appendChild(title);
  for (const item of unique.slice(0, 10)) {
    const chip = document.createElement("span");
    chip.className = `event-time-chip${item.kind === "summary" ? " event-time-chip-summary" : ""}`;
    chip.textContent = item.text;
    chip.title = item.title || item.text;
    strip.appendChild(chip);
  }
  return strip;
}

function buildChildComparePanel(beforeBase64, decodedBase64, summaryText = "", panelOptions = {}) {
  if (!beforeBase64 && !decodedBase64) return null;
  if (isOpaqueUndecryptedSummary(summaryText)) return null;
  const forceCurrentOnly = Boolean(panelOptions && panelOptions.forceCurrentOnly);
  const originalOnly = !forceCurrentOnly && !beforeBase64 && Boolean(decodedBase64);
  const beforeBytes = b64ToBytes(beforeBase64);
  const afterBytes = b64ToBytes(decodedBase64);
  const forceSideBySideSame = Boolean(
    panelOptions
    && panelOptions.forceSideBySideSame
    && beforeBytes.length > 0
    && afterBytes.length > 0
  );
  const beforeParsed = parseTssChildRecords(beforeBytes);
  const afterParsed = parseTssChildRecords(afterBytes);
  const parsedBeforeChildren = Array.isArray(beforeParsed.children) ? beforeParsed.children : [];
  const parsedAfterChildren = Array.isArray(afterParsed.children) ? afterParsed.children : [];
  const hasChildRecords = parsedBeforeChildren.length > 0 || parsedAfterChildren.length > 0;
  const beforeRootNode = parsedBeforeChildren.length > 0 ? null : makeRootComparableNode(beforeBytes);
  const afterRootNode = parsedAfterChildren.length > 0 ? null : makeRootComparableNode(afterBytes);
  const beforeChildren = parsedBeforeChildren.length > 0 ? parsedBeforeChildren : (beforeRootNode ? [beforeRootNode] : []);
  const afterChildren = parsedAfterChildren.length > 0 ? parsedAfterChildren : (afterRootNode ? [afterRootNode] : []);
  const actionMap = parseChildActionDetails(summaryText);
  const currentOnly = forceCurrentOnly
    ? beforeChildren.length === 0 && afterChildren.length > 0
    : !originalOnly
      && beforeChildren.length === 0
      && afterChildren.length > 0
      && (!(actionMap instanceof Map) || actionMap.size === 0);
  const semanticTierOverride = String(panelOptions && panelOptions.semanticTierOverride || "").trim();
  if (semanticTierOverride && currentOnly) {
    for (const child of afterChildren) {
      if (child && !child.truncated) child.semanticTier = semanticTierOverride;
    }
  }
  const actionMaxIndex = actionMap instanceof Map
    ? Math.max(-1, ...Array.from(actionMap.keys()).filter((value) => Number.isFinite(Number(value))).map(Number))
    : -1;
  const total = Math.max(beforeChildren.length, afterChildren.length, actionMaxIndex + 1);
  if (total <= 0) return null;

  const summaryKv = parseSummaryKeyValues(summaryText);
  const timestampHintMap = parseSummaryChildTimestampHints(summaryText);
  const counts = parseChildSummaryCounts(summaryText);
  const visibleIndices = [];
  const addVisibleIndex = (value) => {
    const index = Number.parseInt(value, 10);
    if (!Number.isFinite(index) || index < 0 || index >= total) return;
    if (!visibleIndices.includes(index)) visibleIndices.push(index);
  };
  if (actionMap instanceof Map) {
    Array.from(actionMap.keys()).sort((left, right) => Number(left) - Number(right)).forEach(addVisibleIndex);
  }
  for (let index = 0; index < total && visibleIndices.length < 8; index += 1) {
    addVisibleIndex(index);
  }
  const visible = visibleIndices.length;
  const panel = document.createElement("section");
  panel.className = "child-compare";
  if (originalOnly || currentOnly) panel.classList.add("child-compare-current-only");

  const head = document.createElement("div");
  head.className = "child-compare-head";
  const title = document.createElement("span");
  title.textContent = String(panelOptions && panelOptions.title || "").trim() || (originalOnly
    ? (hasChildRecords ? "子节点结构观察（原包）" : "叶子节点结构观察（原包）")
    : currentOnly
      ? (hasChildRecords ? "当前子节点结构（before 无可解析 child）" : "当前叶子结构（before 无可解析节点）")
      : (hasChildRecords ? "子节点替换观察" : "叶子节点替换观察"));
  const meta = document.createElement("small");
  const countBits = [];
  const addCount = (label, value, always = false) => {
    const number = Number.parseInt(value, 10);
    if (!Number.isFinite(number)) return;
    if (!always && number <= 0) return;
    countBits.push(`${label}${number}`);
  };
  addCount("总数", counts.total, true);
  addCount("变化", counts.changed);
  addCount("同长替换", counts.sameLength);
  addCount("强制替换", counts.forced);
  addCount("兜底010a0011", counts.fallback);
  addCount("保留", counts.kept);
  addCount("未动", counts.noop);
  addCount("清理", counts.clean);
  meta.textContent = String(panelOptions && panelOptions.meta || "").trim() || (originalOnly
    ? `当前事件没有 before_pay，按原包/当前结构展示；显示 ${visible}/${total}`
    : currentOnly
      ? `before_pay 存在但未解析出可对应 child；不误标新增/删除，当前结构单栏展示；显示 ${visible}/${total}`
      : (countBits.length > 0
        ? `${countBits.join("，")}；显示 ${visible}/${total}`
        : `按 before/after 对比规则适配和替换结果；显示 ${visible}/${total}`));
  head.appendChild(title);
  head.appendChild(meta);
  panel.appendChild(head);

  const parentStrip = makeParentStructureStrip(beforeParsed.parent, afterParsed.parent, { originalOnly, currentOnly });
  if (parentStrip) panel.appendChild(parentStrip);

  const grid = document.createElement("div");
  grid.className = "child-compare-grid";
  for (const childIndex of visibleIndices) {
    grid.appendChild(makeChildCard(
      beforeChildren,
      afterChildren,
      beforeBytes,
      afterBytes,
      childIndex,
      actionMap,
      summaryKv,
      timestampHintMap,
      { originalOnly, currentOnly, forceSideBySideSame },
    ));
  }
  panel.appendChild(grid);

  if (total > visible) {
    const note = document.createElement("div");
    note.className = "child-compare-note";
    note.textContent = `还有 ${total - visible} 个节点未展开显示；当前视图优先展示前 8 个用于快速判断。`;
    panel.appendChild(note);
  }

  return panel;
}

function gcloudAceCarrierTransformLabel(carrier) {
  const kind = String(carrier && carrier.sourceKind || "");
  if (kind === "ace-xor") return "ACE XOR decode";
  if (kind === "double-hex") return "double hex decode";
  if (kind === "hex-bytes") return "ASCII hex decode";
  return "binary carrier";
}

function gcloudBytesEqual(left, right) {
  const first = Array.isArray(left) ? left : [];
  const second = Array.isArray(right) ? right : [];
  if (first.length !== second.length) return false;
  for (let index = 0; index < first.length; index += 1) {
    if ((first[index] & 0xff) !== (second[index] & 0xff)) return false;
  }
  return true;
}

function gcloudBytesBase64(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0 || typeof btoa !== "function") return "";
  try {
    return btoa(gcloudBytesToBinaryString(byteValues));
  } catch (_e) {
    return "";
  }
}

function gcloudFindByteSequence(byteValues, needle) {
  const bytes = Array.isArray(byteValues) ? byteValues : [];
  const pattern = Array.isArray(needle) ? needle : [];
  if (!bytes.length || !pattern.length || pattern.length > bytes.length) return -1;
  outer:
  for (let offset = 0; offset <= bytes.length - pattern.length; offset += 1) {
    for (let index = 0; index < pattern.length; index += 1) {
      if ((bytes[offset + index] & 0xff) !== (pattern[index] & 0xff)) continue outer;
    }
    return offset;
  }
  return -1;
}

function gcloudAceMarkerOffsetText(offset) {
  return Number.isFinite(offset) && offset >= 0 ? `+${formatHexValue(offset)}` : "";
}

function gcloudAceCsobMarkerRewritePreview(byteValues) {
  const bytes = Array.isArray(byteValues) ? byteValues.slice() : [];
  const beforeSeq = [0x01, 0x00, 0x00, 0x0a, 0x92, 0x00, 0x00];
  const afterSeq = [0x01, 0x00, 0x00, 0x27, 0x0f, 0x00, 0x00];
  let changed = 0;
  const offsets = [];
  for (let offset = 0; offset <= bytes.length - beforeSeq.length; offset += 1) {
    let matched = true;
    for (let index = 0; index < beforeSeq.length; index += 1) {
      if ((bytes[offset + index] & 0xff) !== beforeSeq[index]) {
        matched = false;
        break;
      }
    }
    if (!matched) continue;
    offsets.push(offset);
    for (let index = 0; index < afterSeq.length; index += 1) {
      bytes[offset + index] = afterSeq[index];
    }
    changed += 1;
    offset += beforeSeq.length - 1;
  }
  return changed > 0 ? { payload: bytes, offsets, changed } : null;
}

function gcloudSummaryHasBackendRebuild(summaryText) {
  return /payload_modified=1|wire_rebuilt=1|send_chain=replace_4013_plaintext|backend_rewrite_verified=1|rewrite_4013_samekey_ace_csob_dfm_patch|relay_4013_ace_csob_dfm_patch/i.test(String(summaryText || ""));
}

function gcloudSummaryHasSentWireChange(summaryText) {
  return /wire_header_modified=1|wire_changed=1|report_010a005f=outer_header_only|outer_header_0x15=01->00/i.test(String(summaryText || ""))
    || gcloudSummaryHasBackendRebuild(summaryText);
}

function makeGcloudAceCompareStatus(ev, summaryText, beforePayload, payload, beforeVariant, statusOptions = {}) {
  const beforePay = String(ev && ev.before_pay ? ev.before_pay : "");
  const fullPay = String(ev && ev.full_pay ? ev.full_pay : "");
  const rawPay = String(ev && ev.raw_pay ? ev.raw_pay : "");
  const summary = String(summaryText || "");
  const beforeBytes = Array.isArray(beforePayload) ? beforePayload : [];
  const afterBytes = Array.isArray(payload) ? payload : [];
  const syntheticAfter = Boolean(statusOptions && statusOptions.syntheticAfter);
  const beforeOk = beforeBytes.length > 0 && (beforeVariant || syntheticAfter);
  const afterOk = afterBytes.length > 0;
  const before0a92 = beforeOk ? gcloudFindByteSequence(beforeBytes, [0x01, 0x00, 0x00, 0x0a, 0x92, 0x00, 0x00]) : -1;
  const after0a92 = afterOk ? gcloudFindByteSequence(afterBytes, [0x01, 0x00, 0x00, 0x0a, 0x92, 0x00, 0x00]) : -1;
  const after270f = afterOk ? gcloudFindByteSequence(afterBytes, [0x01, 0x00, 0x00, 0x27, 0x0f, 0x00, 0x00]) : -1;
  const diff = beforeOk ? countChangedBytes(beforeBytes, afterBytes) : null;
  const backendRebuilt = !syntheticAfter && gcloudSummaryHasBackendRebuild(summary);
  const declaredModified = backendRebuilt || /payload_modified=1/i.test(summary);
  const fullBytes = fullPay ? b64ToBytes(fullPay) : [];
  const rawBytes = rawPay ? b64ToBytes(rawPay) : [];
  const wireDiff = fullBytes.length > 0 && rawBytes.length > 0 ? countChangedBytes(fullBytes, rawBytes) : null;

  const status = document.createElement("div");
  status.className = "ace-compare-status";
  const label = document.createElement("strong");
  const text = document.createElement("span");

  if (syntheticAfter) {
    status.classList.add("ace-compare-status-missing");
    label.textContent = "未发送证据";
    const markerText = before0a92 >= 0 && after270f >= 0
      ? `marker ${gcloudAceMarkerOffsetText(before0a92)} 0a92 -> ${gcloudAceMarkerOffsetText(after270f)} 270f`
      : "按 tersafe 结构 marker 预览替换";
    text.textContent = `算法预览已禁用，不展示模拟 after；只有 before_pay/pay/raw_pay 后端证据齐全时才显示修改前/修改后。${markerText} 仅作为未发送参考。`;
  } else if (!beforePay) {
    status.classList.add("ace-compare-status-missing");
    label.textContent = "未发送证据";
    text.textContent = after0a92 >= 0
      ? `当前事件没有 before_pay/raw_pay，当前 child 仍含 0a92${gcloudAceMarkerOffsetText(after0a92)}；只显示已捕获原包，不展示前端模拟 after。真实命中后 summary 必须出现 payload_modified=1 / wire_rebuilt=1 / raw_pay=raw_after_4013。`
      : "当前事件没有 before_pay/raw_pay，只能按当前解密结构观察；真实命中后才显示修改前/修改后双列。";
  } else if (!beforeOk) {
    status.classList.add("ace-compare-status-unparsed");
    label.textContent = "before 无法解析";
    text.textContent = "事件带有 before_pay，但前端没能解析出同 command 的 ACE carrier；先按当前结构显示，避免误标新增/删除。";
  } else if (diff && Number(diff.changed || 0) > 0) {
    status.classList.add("ace-compare-status-changed");
    label.textContent = backendRebuilt ? "后端确认 rebuild/send" : (declaredModified || after270f >= 0 ? "已形成修改对比" : "已形成差异对比");
    const markerText = before0a92 >= 0 && after270f >= 0
      ? `；marker ${gcloudAceMarkerOffsetText(before0a92)} 0a92 -> ${gcloudAceMarkerOffsetText(after270f)} 270f`
      : after0a92 >= 0
        ? `；修改后仍含 0a92${gcloudAceMarkerOffsetText(after0a92)}`
        : "";
    const wireText = wireDiff
      ? `；完整4013 full_pay(raw before) -> raw_pay(raw after/sent) 变化 ${wireDiff.changed}/${wireDiff.commonLen}${wireDiff.lenDelta ? ` lenΔ=${wireDiff.lenDelta}` : ""}`
      : rawPay
        ? "；有 raw_pay 转发后完整包"
        : backendRebuilt
          ? "；旧事件未展开 raw_pay，需刷新/重新选中拉取完整 payload"
          : "";
    const proofText = /raw_pay_is_sent_wire=1|tcpview_after_source=raw_pay_sent_wire/i.test(summary)
      ? "；证据 raw_pay_is_sent_wire=1，after 来自后端 sent wire"
      : "";
    const fieldText = backendRebuilt
      ? `；before_pay=原始解密，pay=修改后解密，raw_pay=重建后转发包${proofText}`
      : "";
    text.textContent = `before ${beforeBytes.length}B / after ${afterBytes.length}B，变化 ${diff.changed}/${diff.commonLen}${markerText}${fieldText}${wireText}`;
  } else {
    status.classList.add("ace-compare-status-same");
    label.textContent = "before/after 一致";
    text.textContent = after0a92 >= 0
      ? `事件带有 before_pay，但修改前后字节一致；当前仍含 0a92${gcloudAceMarkerOffsetText(after0a92)}，说明这条没有触发替换。`
      : "事件带有 before_pay，修改前后解析一致；仍按双列展示便于确认。";
  }

  status.appendChild(label);
  status.appendChild(text);
  return status;
}

function gcloudSecurityCommandFromInfo(info) {
  if (info && info.kind === "ace") return info.ace || null;
  if (info && info.kind === "tss") return info.tss || null;
  return null;
}

function gcloudSecurityDeepPanelKind(ev, summaryText = "") {
  const info = analyzeGcloudEvent(ev, summaryText);
  const command = gcloudSecurityCommandFromInfo(info);
  const kind = String(command && command.kind || "");
  // The compact GCloud view intentionally hides the old validation/evidence
  // wall.  Only the packet families whose useful content lives inside an ACE
  // carrier get the recursive child/reportcode view.
  return ["ace_antidata", "ace_light", "ace_transfer"].includes(kind) ? kind : "";
}

function gcloudSecurityDeepPanelTitle(info, securityCommand) {
  const kind = String(securityCommand && securityCommand.kind || "");
  if (kind === "ace_antidata") return "AntiData 二层/三层解析";
  if (kind === "ace_light") return "轻量特征子节点 / ReportCode";
  if (kind === "ace_transfer") return "AntiData Transfer 二层解析";
  return info && info.kind === "tss" ? "TSS 二层/三层解析" : "ACE 二层解析";
}

function gcloudSecurityThirdLayerTitle(securityCommand) {
  const kind = String(securityCommand && securityCommand.kind || "");
  if (kind === "ace_antidata") return "AntiData 三层解密结果";
  if (kind === "ace_light") return "轻量特征三层解密结果";
  return "TSS 第三层解密结果";
}

function analyzeGcloudBeforeSecurityVariant(ev, summaryText, currentCommandName) {
  const beforePay = String(ev && ev.before_pay ? ev.before_pay : "");
  if (!beforePay) return null;
  const variant = { ...ev, pay: beforePay, pfx: "", before_pfx: "", full_pfx: "", raw_pfx: "" };
  for (const key of Object.keys(variant)) {
    if (String(key).startsWith("__tcpvGcloud")) delete variant[key];
  }
  const info = analyzeGcloudEvent(variant, summaryText);
  const command = gcloudSecurityCommandFromInfo(info);
  if (!command || !command.carrier) return null;
  if (String(command.commandName || "") !== String(currentCommandName || "")) return null;
  return { info, command, carrier: command.carrier };
}

function makeGcloudOpaqueCarrierNode(carrier, payload, channelLabel) {
  const readable = Array.isArray(carrier && carrier.readable) && carrier.readable.length > 0
    ? carrier.readable.join(" | ")
    : `entropy=${Number(carrier && carrier.entropy || 0).toFixed(2)} prefix=${carrier && carrier.prefix || "-"}`;
  return {
    index: 0,
    nodeLabel: String(carrier && carrier.sourceKind || "").toLowerCase() === "ace-xor" ? "xor_payload[0]" : "carrier_payload[0]",
    offset: 0,
    recordStart: 0,
    recordEnd: payload.length,
    len: payload.length,
    lengthEndian: "",
    reportCode: null,
    reportOffset: -1,
    idValue: null,
    className: "binary-like",
    valuePreview: readable,
    timestampCandidates: extractTimestampCandidatesFromRecord(payload),
    hexSignature: formatHexSignature(payload),
    xorCommonPreview: "",
    semanticRole: `${channelLabel.toLowerCase()}_second_layer_payload`,
    semanticCategory: channelLabel === "TSS" ? "security.tss.carrier" : "security.ace.carrier",
    semanticLabel: carrier && carrier.profile ? carrier.profile : `${channelLabel} 二次解码载荷（字段待证）`,
    semanticTier: "observed",
    semanticEvidence: [String(carrier && carrier.sourceKind || "binary"), "second_layer_decode", "full_byte_view"],
  };
}

function buildGcloudAceOpaqueCarrierPanel(securityCommand, carrier, payload, identityText, channelLabel = "ACE", beforeCarrier = null, beforePayload = [], panelTitle = "") {
  ensureChildCommonStyles();
  const hasBefore = Array.isArray(beforePayload) && beforePayload.length > 0;
  const beforeChanged = hasBefore && !gcloudBytesEqual(beforePayload, payload);
  const panel = document.createElement("section");
  panel.className = `child-compare${hasBefore ? "" : " child-compare-current-only"}`;
  const head = document.createElement("div");
  head.className = "child-compare-head";
  const title = document.createElement("span");
  title.textContent = panelTitle || `${channelLabel} 二层解析`;
  const meta = document.createElement("small");
  meta.textContent = hasBefore
    ? `${securityCommand.commandName} · ${carrier.mode || "carrier"} · 修改前 ${beforePayload.length}B / 修改后 ${payload.length}B · ${beforeChanged ? "字节有变化" : "内容相同"}`
    : `${securityCommand.commandName} · ${carrier.mode || "carrier"} · 已解码 ${payload.length}B · ${identityText}`;
  head.appendChild(title);
  head.appendChild(meta);
  panel.appendChild(head);

  const synthetic = makeGcloudOpaqueCarrierNode(carrier, payload, channelLabel);
  const beforeSynthetic = hasBefore
    ? makeGcloudOpaqueCarrierNode(beforeCarrier || carrier, beforePayload, channelLabel)
    : null;
  const grid = document.createElement("div");
  grid.className = "child-compare-grid";
  grid.appendChild(makeChildCard(
    beforeSynthetic ? [beforeSynthetic] : [],
    [synthetic],
    hasBefore ? beforePayload : [],
    payload,
    0,
    new Map(),
    {},
    new Map(),
    { currentOnly: !hasBefore, forceSideBySideSame: hasBefore },
  ));
  panel.appendChild(grid);
  return panel;
}

function buildGcloudAceCarrierDeepPanel(ev, summaryText = "") {
  const info = analyzeGcloudEvent(ev, summaryText);
  const securityCommand = gcloudSecurityCommandFromInfo(info);
  if (!securityCommand || !securityCommand.carrier) return null;
  const carrier = securityCommand.carrier;
  const channelLabel = info.kind === "tss" ? "TSS" : "ACE";
  const payload = Array.isArray(carrier.payload) ? carrier.payload : [];
  if (payload.length <= 0) return null;

  const beforeVariant = analyzeGcloudBeforeSecurityVariant(ev, summaryText, securityCommand.commandName);
  const beforeCarrier = beforeVariant && beforeVariant.carrier ? beforeVariant.carrier : null;
  const beforePayloadCandidate = beforeCarrier && Array.isArray(beforeCarrier.payload) ? beforeCarrier.payload : [];
  // Do not render a synthetic "after" as if it were sent.  Before/after is
  // reserved for backend evidence: before_pay/pay/raw_pay emitted by mitm.
  const simulatedAfter = null;
  const beforePayload = beforePayloadCandidate.length > 0
    ? beforePayloadCandidate
    : (simulatedAfter ? payload : []);
  const displayPayload = simulatedAfter ? simulatedAfter.payload : payload;
  const syntheticAfter = Boolean(simulatedAfter);
  const beforePayloadChanged = beforePayload.length > 0 && !gcloudBytesEqual(beforePayload, displayPayload);
  const backendRebuilt = !syntheticAfter && gcloudSummaryHasBackendRebuild(summaryText);

  const detectedRoot = detectTssReport(displayPayload);
  const root = detectedRoot && isLikelyTssReportCode(detectedRoot.value) ? detectedRoot : null;
  const beforeDetectedRoot = beforePayload.length > 0 ? detectTssReport(beforePayload) : null;
  const beforeRoot = beforeDetectedRoot && isLikelyTssReportCode(beforeDetectedRoot.value) ? beforeDetectedRoot : null;

  const payloadBase64 = gcloudBytesBase64(displayPayload);
  if (!payloadBase64) return null;
  const beforePayloadBase64 = beforeRoot ? gcloudBytesBase64(beforePayload) : "";
  const compareRoot = Boolean(root && beforeRoot && beforePayloadBase64);
  const reportKey = Number(carrier.rootReport) === Number(root && root.value) ? "root_report" : "reportish";
  const reportText = root
    ? `${reportKey}=${formatHexValue(root.value, 8)}`
    : `profile=${carrier.profile || "unclassified"}`;
  const beforeReportText = beforeRoot ? formatHexValue(beforeRoot.value, 8) : "";
  const encrypted = root ? decryptTssEncryptedEnvelope(displayPayload) : null;
  const beforeEncrypted = beforeRoot ? decryptTssEncryptedEnvelope(beforePayload) : null;
  const panelTitle = gcloudSecurityDeepPanelTitle(info, securityCommand);
  const panel = root
    ? buildChildComparePanel(compareRoot ? beforePayloadBase64 : "", payloadBase64, "", {
      forceCurrentOnly: !compareRoot,
      semanticTierOverride: carrier.mode === "binary_carrier" ? "observed" : "",
      title: panelTitle,
      meta: compareRoot
        ? `${securityCommand.commandName} · ${carrier.mode || "carrier"} · ${syntheticAfter ? "local preview" : backendRebuilt ? "backend rebuilt" : "before"} ${beforePayload.length}B / after ${displayPayload.length}B · ${beforeReportText} -> ${formatHexValue(root.value, 8)} · ${beforePayloadChanged ? "diff" : "same"}`
        : `${securityCommand.commandName} · ${carrier.mode || "carrier"} · decoded ${displayPayload.length}B · ${reportText} · observe-only`,
      forceSideBySideSame: compareRoot,
    })
    : buildGcloudAceOpaqueCarrierPanel(
      securityCommand,
      carrier,
      displayPayload,
      reportText,
      channelLabel,
      beforeCarrier,
      beforePayload,
      panelTitle,
    );
  if (!panel) return null;

  panel.classList.add("gcloud-ace-deep", "child-compare-inline");
  const lineage = document.createElement("div");
  lineage.className = "ace-deep-lineage";
  const layers = [
    "65010",
    "0x4013 decrypted",
    info.proto && info.proto.compression
      ? `LZ4 解压 ${info.proto.compression.inputLength}->${info.proto.compression.outputLength}B`
      : "protobuf",
    gcloudAceCarrierTransformLabel(carrier),
    root ? `TSS record ${displayPayload.length}B` : `decoded payload ${displayPayload.length}B`,
    reportText,
  ];
  if (beforePayload.length > 0) {
    layers.push(`${syntheticAfter ? "local preview " : backendRebuilt ? "backend rebuilt " : ""}before/after ${beforePayload.length}/${displayPayload.length}B`);
  }
  if (backendRebuilt) {
    layers.push("raw_pay sent/rebuilt 4013");
  }
  if (encrypted) {
    layers.push(`${encrypted.familyName} slot[${encrypted.slot}] decrypt`);
    if (encrypted.supported) layers.push(encrypted.crcMatch ? "CRC32 ok" : "CRC32 failed");
    if (encrypted.crcMatch && encrypted.innerRoot) {
      layers.push(`inner ${formatHexValue(encrypted.innerRoot.value, 8)} ${encrypted.plain.length}B`);
    }
  }
  layers.forEach((text, index) => {
    if (index > 0) {
      const arrow = document.createElement("span");
      arrow.className = "ace-deep-arrow";
      arrow.textContent = ">";
      lineage.appendChild(arrow);
    }
    const chip = document.createElement("span");
    chip.className = "ace-deep-layer";
    chip.textContent = text;
    lineage.appendChild(chip);
  });
  panel.insertBefore(lineage, panel.children[1] || null);
  const compareStatus = makeGcloudAceCompareStatus(ev, summaryText, beforePayload, displayPayload, beforeVariant, {
    syntheticAfter,
  });
  panel.insertBefore(compareStatus, panel.children[2] || null);

  const stack = document.createElement("div");
  stack.className = "gcloud-security-deep-stack";
  stack.appendChild(panel);
  if (encrypted) {
    const status = document.createElement("div");
    status.className = `tss-crypto-status${encrypted.crcMatch ? " tss-crypto-status-ok" : " tss-crypto-status-error"}`;
    const expected = formatHexValue(encrypted.expectedCrc, 8);
    const actual = encrypted.supported ? formatHexValue(encrypted.actualCrc, 8) : "-";
    const beforeVerified = beforeEncrypted && beforeEncrypted.supported && beforeEncrypted.crcMatch;
    status.textContent = beforeVerified && encrypted.supported
      ? `修改前 ${beforeEncrypted.familyName} slot[${beforeEncrypted.slot}] ${beforeEncrypted.cipherLength}B -> ${beforeEncrypted.plain.length}B CRC32通过 · 修改后 ${encrypted.familyName} slot[${encrypted.slot}] ${encrypted.cipherLength}B -> ${encrypted.plain.length}B CRC32${encrypted.crcMatch ? "通过" : "失败"}`
      : encrypted.supported
        ? `${encrypted.familyName} · slot[${encrypted.slot}]${encrypted.keyLabel ? `=${encrypted.keyLabel}` : ""} · cipher ${encrypted.cipherLength}B -> plain ${encrypted.plain.length}B · CRC32 ${encrypted.crcMatch ? "通过" : "失败"} (${expected} / ${actual})`
        : `${encrypted.familyName} · slot[${encrypted.slot}] · cipher ${encrypted.cipherLength}B · 未解密：${encrypted.reason || "前端算法不支持"}`;
    panel.insertBefore(status, panel.children[3] || null);
  }

  if (encrypted && encrypted.supported && encrypted.crcMatch && encrypted.plain.length > 0) {
    const plainBase64 = gcloudBytesBase64(encrypted.plain);
    const beforePlain = beforeEncrypted && beforeEncrypted.supported && beforeEncrypted.crcMatch
      ? beforeEncrypted.plain
      : [];
    const beforePlainBase64 = beforePlain.length > 0 ? gcloudBytesBase64(beforePlain) : "";
    const beforePlainChanged = beforePlain.length > 0 && !gcloudBytesEqual(beforePlain, encrypted.plain);
    if (plainBase64) {
      const innerReport = encrypted.innerRoot
        ? formatHexValue(encrypted.innerRoot.value, 8)
        : "未识别 record root";
      const innerPanel = buildChildComparePanel(beforePlainBase64, plainBase64, "", {
        forceCurrentOnly: !beforePlainBase64,
        title: gcloudSecurityThirdLayerTitle(securityCommand),
        meta: beforePlainBase64
          ? `${securityCommand.commandName} · ${encrypted.familyName} slot[${encrypted.slot}] · CRC32 verified · before ${beforePlain.length}B / after ${encrypted.plain.length}B · ${innerReport} · ${beforePlainChanged ? "diff" : "same"}`
          : `${securityCommand.commandName} · ${encrypted.familyName} · slot[${encrypted.slot}] · CRC32 verified · ${innerReport} · ${encrypted.plain.length}B`,
        forceSideBySideSame: Boolean(beforePlainBase64),
      });
      if (innerPanel) {
        innerPanel.classList.add("gcloud-tss-decrypted", "child-compare-inline");
        stack.appendChild(innerPanel);
      }
    }
  }
  const decodeTree = root ? buildTssRecursiveDecodeTree(displayPayload, { kind: channelLabel }) : null;
  if (decodeTree && decodeTree.root) {
    const treeWrap = document.createElement("div");
    treeWrap.className = "gcloud-ace-recursive-tree-wrap";
    renderTssRecursiveTree(decodeTree, treeWrap);
    stack.appendChild(treeWrap);
  }
  return stack;
}

function buildGcloudStandaloneTssRecursivePanel(ev, summaryText = "") {
  const info = analyzeGcloudEvent(ev, summaryText);
  if (!info) return null;
  const candidates = [info.protoBytes, info.bytes];
  const seen = new Set();
  for (const candidate of candidates) {
    if (!Array.isArray(candidate) || candidate.length < 10) continue;
    const identity = `${candidate.length}:${candidate.slice(0, 12).join(",")}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    if (
      candidate[0] !== 0x00
      || candidate[1] !== 0x00
      || candidate[2] !== 0x00
      || candidate[3] !== 0x01
    ) continue;
    const declared = readBe16(candidate, 4);
    const reportCode = readBe32(candidate, 6);
    if (
      !Number.isFinite(declared)
      || declared < 10
      || declared > candidate.length
      || !isLikelyTssReportCode(reportCode)
    ) continue;
    const record = candidate.slice(0, declared);
    const tree = buildTssRecursiveDecodeTree(record, { kind: "TSS current payload" });
    if (!tree || !tree.root) continue;
    ensureChildCommonStyles();
    const treeWrap = document.createElement("div");
    treeWrap.className = "gcloud-ace-recursive-tree-wrap gcloud-standalone-tss-recursive";
    renderTssRecursiveTree(tree, treeWrap);
    return treeWrap;
  }
  return null;
}

function comparableNodesFromBytes(byteValues) {
  const parsed = parseTssChildRecords(byteValues);
  const children = Array.isArray(parsed.children) ? parsed.children : [];
  if (children.length > 0) return children;
  const rootNode = makeRootComparableNode(byteValues);
  return rootNode ? [rootNode] : [];
}

function comparableNodeBytes(byteValues, node) {
  if (!node) return [];
  if (node.nodeLabel && String(node.nodeLabel).startsWith("node[")) {
    return Array.isArray(byteValues) ? byteValues.slice() : [];
  }
  const childBytes = childBytesFromParsed(byteValues, node);
  if (childBytes.length > 0) return childBytes;
  if (Number(node.offset) === 0 && Number(node.len) === (Array.isArray(byteValues) ? byteValues.length : -1)) {
    return Array.isArray(byteValues) ? byteValues.slice() : [];
  }
  return childBytes;
}

function nodeReadableStringRows(node, nodeBytes, side, actionText = "", ruleText = "") {
  const rows = [];
  const prefix = [
    childNodeName(node),
    childReportText(node),
    childRichTypeText(node),
  ].filter(Boolean).join(" | ");
  const add = (label, value, offsetText = "") => {
    const text = normalizeVisibleText(value);
    if (!text || text.length < 3) return;
    const parts = [
      prefix,
      label,
      offsetText,
      text,
      ruleText ? `规则 ${ruleText}` : "",
      actionText,
    ].filter(Boolean);
    const line = parts.join(" | ");
    if (!rows.includes(line)) rows.push(line);
  };

  const overlay = childBestDecodedOverlay(nodeBytes);
  if (overlay && Array.isArray(overlay.runs)) {
    for (const run of overlay.runs.slice(0, 4)) {
      const runText = String(run && run.text ? run.text : "").trim();
      if (runText.length < 4 && !/^\d{6,}$/.test(runText)) continue;
      const off = Number(run && run.start);
      add(overlay.label || "string", runText, Number.isFinite(off) ? hexOffsetText(off) : "");
      if (rows.length >= 4) break;
    }
  }

  if (rows.length <= 0) {
    const runs = extractPrintableRuns(nodeBytes, 4, 6);
    for (const run of runs) {
      const runText = String(run && run.text ? run.text : "").trim();
      if (runText.length < 4 && !/^\d{6,}$/.test(runText)) continue;
      const kind = inferStringKind(runText);
      add(kind || "ascii", runText, hexOffsetText(run.off));
      if (rows.length >= 4) break;
    }
  }

  if (rows.length <= 0) {
    const semanticRows = splitChildSemanticRows(node).primaryRows;
    for (const [label, value] of semanticRows.slice(0, 2)) {
      add(label, value);
    }
  }

  return rows.map((row) => `${side} | ${row}`);
}

function stringRowsForComparableNodes(byteValues, summaryText, side = "before") {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
  const nodes = comparableNodesFromBytes(byteValues);
  if (!nodes.length) return [];
  const actionMap = parseChildActionDetails(summaryText);
  const summaryKv = parseSummaryKeyValues(summaryText);
  const rows = [];
  for (let i = 0; i < Math.min(nodes.length, 8); i += 1) {
    const node = nodes[i];
    if (!node || node.truncated) continue;
    const semanticRows = splitChildSemanticRows(node).primaryRows;
    const semanticText = semanticRows
      .map(([label, value]) => `${label} ${value}`)
      .filter(Boolean)
      .join("；");
    const action = side === "after"
      ? (actionMap instanceof Map ? actionMap.get(i) : null) || inferChildActionFromSummary(summaryKv, null, null, node)
      : null;
	    const actionText = side === "after" && action
	      ? `；${childActionBadgeText(action, { label: "" })}${action.reason ? `，${translatedReasonText(action.reason) || action.reason}` : ""}`
	      : "";
	    const ruleText = compactRuleText(childRuleAnnotations(side === "before" ? node : null, side === "after" ? node : null, action));
	    const nodeBytes = comparableNodeBytes(byteValues, node);
	    const readableRows = nodeReadableStringRows(node, nodeBytes, side, actionText, ruleText);
	    if (readableRows.length > 0) {
	      rows.push(...readableRows);
	    } else {
	      const parts = [
	        childNodeName(node),
	        childReportText(node),
	        childIdText(node) !== "-" ? `ID ${childIdText(node)}` : "",
	        semanticText,
	        ruleText ? `规则 ${ruleText}` : "",
	      ].filter(Boolean);
	      rows.push(`${side} | ${parts.join(" | ")}${actionText}`);
	    }
	  }
	  return rows;
	}

function buildStringResultPanel(beforeBase64, decodedBase64, summaryText = "") {
  const beforeRows = stringRowsForComparableNodes(b64ToBytes(beforeBase64), summaryText, "before");
  const afterRows = stringRowsForComparableNodes(b64ToBytes(decodedBase64), summaryText, "after");
  if (!beforeRows.length && !afterRows.length) return null;
  const panel = document.createElement("section");
  panel.className = "string-result-panel";
  const head = document.createElement("div");
  head.className = "string-result-head";
  head.textContent = "字符串 / 规则结果";
  panel.appendChild(head);
  const grid = document.createElement("div");
  grid.className = "string-result-grid";
  for (const [title, rows, sideClass] of [
    ["修改前字符串", beforeRows, "before"],
    ["修改后字符串", afterRows, "after"],
  ]) {
    const side = document.createElement("div");
    side.className = `string-result-side string-result-side-${sideClass}`;
    const label = document.createElement("div");
    label.className = "string-result-label";
    label.textContent = title;
    const pre = document.createElement("pre");
    pre.textContent = rows.length ? rows.join("\n") : "-";
    side.appendChild(label);
    side.appendChild(pre);
    grid.appendChild(side);
  }
  panel.appendChild(grid);
  return panel;
}

function buildTreeCompareRow(beforeBase64, decodedBase64, summaryText = "") {
  if (!beforeBase64 && !decodedBase64) return null;
  const sameLenExamples = parseLibrarySameLengthExamples(summaryText);
  const beforeTree = beforeBase64
    ? createTssTreeSummary("修改前解析 / child tree", beforeBase64, "tree-shell-compare", { sameLenExamples })
    : null;
  const afterTree = decodedBase64
    ? createTssTreeSummary("修改后/当前解析 / child tree", decodedBase64, "tree-shell-compare", { sameLenExamples })
    : null;
  if (!beforeTree && !afterTree) return null;

  const row = document.createElement("section");
  row.className = "tree-compare-row";
  if (!beforeTree || !afterTree) row.classList.add("tree-compare-single");

  if (beforeTree) {
    const before = document.createElement("div");
    before.className = "tree-compare-panel tree-compare-before";
    before.appendChild(beforeTree);
    row.appendChild(before);
  }

  if (afterTree) {
    const after = document.createElement("div");
    after.className = "tree-compare-panel tree-compare-after";
    after.appendChild(afterTree);
    row.appendChild(after);
  }
  return row;
}

function getEventAnalysis(ev) {
  const summaryText = String(ev && ev.summary ? ev.summary : "").trim();
  const semantic = ev && ev.analysis && typeof ev.analysis === "object" ? ev.analysis : null;
  if (!summaryText && !semantic) {
    return null;
  }
  const cacheKey = [
    getEventId(ev),
    String(ev?.summary || ""),
    String(ev?.pay || "").length,
    String(ev?.before_pay || "").length,
    String(ev?.full_pay || "").length,
    String(ev?.raw_pay || "").length,
    semantic ? JSON.stringify(semantic).length : 0,
  ].join("|");
  if (ev && ev.__tcpvAnalysisKey === cacheKey && ev.__tcpvAnalysis) {
    return ev.__tcpvAnalysis;
  }
  const decodedBytes = b64ToBytes(String(ev && ev.pay ? ev.pay : ""));
  const beforeBytes = b64ToBytes(String(ev && ev.before_pay ? ev.before_pay : ""));
  const fullBytes = b64ToBytes(String(ev && ev.full_pay ? ev.full_pay : ""));
  const summary = parseTssSummary(ev && ev.summary ? ev.summary : "");
  const decodedStrings = extractPrintableRuns(decodedBytes, ANALYSIS_ASCII_MIN_LEN, ANALYSIS_ASCII_MAX_ITEMS);
  const decodedUtf8Strings = extractUtf8Runs(decodedBytes, ANALYSIS_UTF8_MIN_CHARS, ANALYSIS_UTF8_MAX_ITEMS);
  const decodedBase64Strings = extractBase64DecodedRuns(decodedBytes, ANALYSIS_BASE64_MAX_ITEMS);
  const beforeStrings = beforeBytes.length > 0
    ? extractPrintableRuns(beforeBytes, ANALYSIS_ASCII_MIN_LEN, ANALYSIS_ASCII_MAX_ITEMS)
    : [];
  const beforeUtf8Strings = beforeBytes.length > 0
    ? extractUtf8Runs(beforeBytes, ANALYSIS_UTF8_MIN_CHARS, ANALYSIS_UTF8_MAX_ITEMS)
    : [];
  const beforeBase64Strings = beforeBytes.length > 0
    ? extractBase64DecodedRuns(beforeBytes, ANALYSIS_BASE64_MAX_ITEMS)
    : [];
  const fullStrings =
    fullBytes.length > 0 && String(ev && ev.full_pay ? ev.full_pay : "") !== String(ev && ev.pay ? ev.pay : "")
      ? extractPrintableRuns(fullBytes, 6, 6)
      : [];
  const fullUtf8Strings =
    fullBytes.length > 0 && String(ev && ev.full_pay ? ev.full_pay : "") !== String(ev && ev.pay ? ev.pay : "")
      ? extractUtf8Runs(fullBytes, 2, 4)
      : [];
  const xor = analyzeDecodedSliceXor(decodedBytes);
  if (xor && summary && summary.xor) {
    if (!xor.preview && summary.xor.preview) xor.preview = summary.xor.preview;
  }
  const analysis = {
    semantic,
    summary,
    decodedStrings,
    decodedUtf8Strings,
    decodedBase64Strings,
    beforeStrings,
    beforeUtf8Strings,
    beforeBase64Strings,
    fullStrings,
    fullUtf8Strings,
    xor: xor || (summary && summary.xor ? summary.xor : null),
  };
  if (ev && typeof ev === "object") {
    ev.__tcpvAnalysisKey = cacheKey;
    ev.__tcpvAnalysis = analysis;
  }
  return analysis;
}

function createAnalysisCard(title, className = "") {
  const card = document.createElement("section");
  card.className = `analysis-card ${className}`.trim();
  const head = document.createElement("div");
  head.className = "analysis-card-head";
  head.textContent = title;
  const body = document.createElement("div");
  body.className = "analysis-card-body";
  card.appendChild(head);
  card.appendChild(body);
  return { card, body };
}

function appendAnalysisEmpty(container, text) {
  const empty = document.createElement("div");
  empty.className = "analysis-empty";
  empty.textContent = text;
  container.appendChild(empty);
}

function appendAnalysisRows(container, rows) {
  const list = document.createElement("div");
  list.className = "analysis-list";
  for (const row of rows) {
    if (!row || !String(row.value || "").trim()) continue;
    const wrap = document.createElement("div");
    wrap.className = "analysis-row";
    const label = document.createElement("div");
    label.className = "analysis-row-label";
    label.textContent = row.label;
    const value = document.createElement("div");
    value.className = "analysis-row-value";
    value.textContent = String(row.value || "");
    wrap.appendChild(label);
    wrap.appendChild(value);
    list.appendChild(wrap);
  }
  if (list.childElementCount > 0) {
    container.appendChild(list);
  }
}

function appendAnalysisSectionTitle(container, text) {
  const title = document.createElement("div");
  title.className = "analysis-section-title";
  title.textContent = text;
  container.appendChild(title);
}

function formatAnalysisOffset(off, source = "") {
  const base = formatHexValue(off);
  const normalizedSource = String(source || "").trim();
  if (!normalizedSource) return base;
  return `${normalizedSource}+${base}`;
}

function appendAnalysisStringList(container, items, options = {}) {
  if (!Array.isArray(items) || items.length <= 0) {
    appendAnalysisEmpty(container, "没有识别到明显的可打印字符串。");
    return;
  }
  const source = String(options.source || "").trim();
  const list = document.createElement("div");
  list.className = "analysis-string-list";
  for (const item of items) {
    const wrap = document.createElement("div");
    wrap.className = "analysis-string-item";
    const off = document.createElement("div");
    off.className = "analysis-string-off";
    off.textContent = formatAnalysisOffset(item.off, source);
    const text = document.createElement("div");
    text.className = "analysis-string-text";
    const suffix = item.kind ? ` [${item.kind}]` : "";
    text.textContent = `${String(item.text || "")}${suffix}`;
    wrap.appendChild(off);
    wrap.appendChild(text);
    list.appendChild(wrap);
  }
  container.appendChild(list);
}

function collectAnalysisStringItems(...groups) {
  const out = [];
  const seen = new Set();
  for (const group of groups) {
    for (const item of Array.isArray(group) ? group : []) {
      const text = String(item && item.text ? item.text : "").trim();
      if (!text) continue;
      const off = Number(item && item.off);
      const key = `${Number.isFinite(off) ? off : ""}:${text}:${String(item && item.kind ? item.kind : "")}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(item);
    }
  }
  return out;
}

function appendAnalysisStringSide(container, title, items, source) {
  const side = document.createElement("div");
  side.className = `analysis-string-side analysis-string-side-${source || "current"}`;
  const label = document.createElement("div");
  label.className = "analysis-string-side-label";
  label.textContent = title;
  side.appendChild(label);
  appendAnalysisStringList(side, items, { source });
  container.appendChild(side);
}

function appendAnalysisHint(container, text) {
  const note = document.createElement("div");
  note.className = "analysis-note";
  note.textContent = text;
  container.appendChild(note);
}

function buildEventAnalysisGrid(ev) {
  const analysis = getEventAnalysis(ev);
  if (!analysis) return null;
  const opaqueUndecrypted = isOpaqueUndecryptedSummary(ev && ev.summary ? ev.summary : "");

  const grid = document.createElement("div");
  grid.className = "analysis-grid";

  const metaCard = createAnalysisCard(
    opaqueUndecrypted ? "封包概览（未解密）" : "解密概览",
    "analysis-card-meta"
  );
  const metaChips = document.createElement("div");
  metaChips.className = "analysis-chip-list";
  const summary = analysis.summary;
  const summaryKv = parseSummaryKeyValues(ev && ev.summary ? ev.summary : "");
  const metaChipValues = [];
  const reportText = formatReportCodeText(summaryKv.report || (summary && summary.code));
  if (reportText !== "-") metaChipValues.push(`report ${reportText}`);
  if (summary) {
    if (summary.code) metaChipValues.push(`code ${summary.code}`);
    if (summary.role) metaChipValues.push(`role ${summary.role}`);
    if (summary.hint) metaChipValues.push(`hint ${summary.hint}`);
    if (Number.isFinite(summary.beforedumpLen)) metaChipValues.push(`len ${summary.beforedumpLen}`);
  }
  if (metaChipValues.length > 0) {
    for (const text of metaChipValues) {
      const chip = document.createElement("span");
      chip.className = "analysis-chip";
      chip.textContent = text;
      metaChips.appendChild(chip);
    }
    metaCard.body.appendChild(metaChips);
  } else {
    appendAnalysisEmpty(
      metaCard.body,
      opaqueUndecrypted
        ? "当前包是未解密外层；只能按原始封包观察，未知 value 已保持。"
        : "当前包没有结构化摘要，仍可直接看下方原始封包和当前解密内容。"
    );
  }
  grid.appendChild(metaCard.card);

  const semantic = analysis.semantic;
  if (semantic && typeof semantic === "object") {
    const semanticCard = createAnalysisCard("语义状态 / 8091 → 8092", "analysis-card-semantic");
    const packet = semantic.packet && typeof semantic.packet === "object" ? semantic.packet : {};
    const packetPayloadRole = packet.semantic_role
      || (packet.shape && packet.shape.semantic_role)
      || packet.role
      || "目前不能证明含义";
    const semanticRows = [
      { label: "Schema", value: semantic.schema || "tersafe.semantic.v1" },
      { label: "Report", value: packet.report_code || "-" },
      { label: "Payload Role", value: packetPayloadRole },
      { label: "Family Role", value: packet.role || "目前不能证明含义" },
      { label: "Phase", value: semantic.state_phase || "unknown" },
      { label: "执行", value: `${semantic.mode || "active"} / ${semantic.action || "passthrough"}` },
      { label: "Reason", value: semantic.reason || "-" },
      { label: "Source", value: semantic.source_key || "-" },
      { label: "Delay", value: Number.isFinite(Number(semantic.source_age_ms)) ? `${Number(semantic.source_age_ms)} ms` : "-" },
      { label: "Consistency", value: Number.isFinite(Number(semantic.consistency)) ? `${(Number(semantic.consistency) * 100).toFixed(1)}%` : "-" },
      {
        label: "Shape",
        value: Array.isArray(semantic.match_kinds) && semantic.match_kinds.length > 0
          ? semantic.match_kinds.join(" / ")
          : "-",
      },
      {
        label: "长度变化",
        value: [
          Number.isFinite(Number(semantic.length_delta)) ? `${opaqueUndecrypted ? "封包" : "解密"} ${Number(semantic.length_delta) >= 0 ? "+" : ""}${Number(semantic.length_delta)}` : "",
          Number.isFinite(Number(semantic.packet_length_delta)) ? `线上 ${Number(semantic.packet_length_delta) >= 0 ? "+" : ""}${Number(semantic.packet_length_delta)}` : "",
        ].filter(Boolean).join(" / ") || "0",
      },
      {
        label: "65010",
        value: semantic.connection_65010 && semantic.connection_65010.status
          ? `${semantic.connection_65010.status} / ${semantic.connection_65010.source || "observed"}`
          : "unknown",
      },
      {
        label: "Response",
        value: semantic.response_correlation && semantic.response_correlation.status
          ? [
              semantic.response_correlation.status,
              semantic.response_correlation.request_seq ? `req#${semantic.response_correlation.request_seq}` : "",
              Number.isFinite(Number(semantic.response_correlation.delta_ms)) ? `${Number(semantic.response_correlation.delta_ms)}ms` : "",
              Number(semantic.response_correlation.burst_index || 0) > 0 ? `burst×${Number(semantic.response_correlation.burst_index)}` : "",
              semantic.response_correlation.reason || "",
            ].filter(Boolean).join(" / ")
          : "等待流时间线关联",
      },
      {
        label: "Safety",
        value: semantic.response_feedback && typeof semantic.response_feedback === "object"
          ? [
              semantic.response_feedback.report_code || "",
              semantic.response_feedback.field_c || "",
              Number(semantic.response_feedback.risk_0024_count_2s || 0) > 0
                ? `risk×${Number(semantic.response_feedback.risk_0024_count_2s)}`
                : "",
              semantic.response_feedback.safety_alert_reason || "",
              semantic.response_feedback.reason || "observed",
            ].filter(Boolean).join(" / ")
          : "-",
      },
    ];
    appendAnalysisRows(semanticCard.body, semanticRows);

    const actions = Array.isArray(semantic.actions) ? semantic.actions : [];
    const fieldRows = [];
    for (const action of actions) {
      for (const field of Array.isArray(action && action.fields) ? action.fields : []) {
        fieldRows.push({
          label: `${field.field || "field"} · ${field.action || action.action || "observe"}${Number(field.length_delta || 0) ? ` · len ${Number(field.length_delta) > 0 ? "+" : ""}${Number(field.length_delta)}` : ""}`,
          value: `8091=${field.source ?? "-"} | 8092 before=${field.before ?? "-"} | 实际上传=${field.after ?? "-"}`,
        });
      }
    }
    if (fieldRows.length > 0) {
      appendAnalysisSectionTitle(semanticCard.body, "8091来源 / 8092修改前 / 8092输出");
      appendAnalysisRows(semanticCard.body, fieldRows.slice(0, 24));
    }

    const packetNodes = [packet, ...(Array.isArray(packet.children) ? packet.children : [])];
    const roleRows = packetNodes
      .filter((node) => node && (node.semantic_role || (node.shape && node.shape.semantic_role)))
      .slice(0, 24)
      .map((node) => ({
        label: node.index === null || node.index === undefined
          ? `root · ${node.report_code || "-"}`
          : `child#${node.index} · ${node.report_code || "-"}`,
        value: [
          node.semantic_role || (node.shape && node.shape.semantic_role),
          node.semantic_role_confidence || "",
          ...(Array.isArray(node.semantic_role_evidence) ? node.semantic_role_evidence.slice(0, 5) : []),
        ].filter(Boolean).join(" / "),
      }));
    if (roleRows.length > 0) {
      appendAnalysisSectionTitle(semanticCard.body, "父子节点实际 payload 角色");
      appendAnalysisRows(semanticCard.body, roleRows);
    }
    const rejected = packetNodes.flatMap((node) => (
      node && node.timestamps && Array.isArray(node.timestamps.rejected) ? node.timestamps.rejected : []
    ));
    if (rejected.length > 0) {
      appendAnalysisSectionTitle(semanticCard.body, `已拒绝的时间候选 ×${rejected.length}`);
      appendAnalysisRows(
        semanticCard.body,
        rejected.slice(0, 12).map((item) => ({
          label: `+${formatHexValue(item.offset)} / ${item.value}`,
          value: item.reason || "普通 BE32 没有 schema 时间语义",
        }))
      );
    }
    grid.appendChild(semanticCard.card);
  }

  const xorCard = createAnalysisCard("XOR / 猜测", "analysis-card-xor");
  const xor = analysis.xor;
  if (xor) {
    appendAnalysisRows(xorCard.body, [
      { label: "Key", value: xor.key !== undefined && xor.key !== "" ? formatHexValue(xor.key, 2) : String(xor.key || "") },
      { label: "Type", value: xor.innerType !== undefined ? formatHexValue(xor.innerType, 4) : String(xor.type || "") },
      { label: "Body", value: xor.bodyOff !== undefined ? formatHexValue(xor.bodyOff) : "" },
      { label: "Score", value: xor.score !== undefined ? String(xor.score) : "" },
      { label: "Preview", value: xor.preview || "" },
      { label: "Keywords", value: Array.isArray(xor.keywordHits) ? xor.keywordHits.join(", ") : "" },
    ]);
    if (Array.isArray(xor.runs) && xor.runs.length > 0) {
      const title = document.createElement("div");
      title.className = "analysis-section-title";
      title.textContent = "可打印 XOR 结果";
      xorCard.body.appendChild(title);
      appendAnalysisStringList(xorCard.body, xor.runs.slice(0, 6));
    }
    if (Array.isArray(xor.commonPreviews) && xor.commonPreviews.length > 0) {
      appendAnalysisSectionTitle(xorCard.body, "常见 Key XOR 结果");
      appendAnalysisStringList(xorCard.body, xor.commonPreviews.slice(0, 8));
    }
  } else {
    appendAnalysisEmpty(xorCard.body, "当前切片没有命中明显的单字节 XOR 文本特征。");
  }
  grid.appendChild(xorCard.card);

  const beforeStringItems = collectAnalysisStringItems(
    analysis.beforeStrings,
    analysis.beforeUtf8Strings,
    analysis.beforeBase64Strings
  );
  const afterStringItems = collectAnalysisStringItems(
    analysis.decodedStrings,
    analysis.decodedUtf8Strings,
    analysis.decodedBase64Strings
  );
  if (beforeStringItems.length > 0 || afterStringItems.length > 0) {
    const stringCard = createAnalysisCard("字符串", "analysis-card-strings");
    const compare = document.createElement("div");
    compare.className = "analysis-string-compare";
    appendAnalysisStringSide(compare, "修改前", beforeStringItems, "before");
    appendAnalysisStringSide(compare, "修改后", afterStringItems, "after");
    stringCard.body.appendChild(compare);
    grid.appendChild(stringCard.card);
  }

  return grid;
}

function buildEventReadableSummary(ev, summaryText) {
  const block = document.createElement("div");
  block.className = "event-readable-summary";

  const { kv, items } = summaryPrimaryItems(ev, summaryText);
  const primary = document.createElement("div");
  primary.className = "event-summary-primary";
  const semantic = ev && ev.analysis && typeof ev.analysis === "object" ? ev.analysis : null;
  const isGcloud = isGcloud65010Summary(summaryText, ev);
  const isWssJson = isWssJsonSummary(summaryText, ev);
  if (isGcloud) {
    for (const item of buildGcloudSummaryInsights(ev, summaryText).slice(0, 6)) {
      const chip = document.createElement("div");
      chip.className = "event-summary-chip event-summary-chip-state";
      chip.textContent = item.text;
      chip.title = item.title || item.text;
      primary.appendChild(chip);
    }
  } else if (isWssJson) {
    for (const item of buildWssSummaryInsights(ev, summaryText).slice(0, 6)) {
      const chip = document.createElement("div");
      chip.className = `event-summary-chip event-summary-chip-${item.kind || "info"}`;
      chip.textContent = item.text;
      chip.title = item.title || item.text;
      primary.appendChild(chip);
    }
  } else if (semantic) {
    const packet = semantic.packet && typeof semantic.packet === "object" ? semantic.packet : {};
    const semanticActions = Array.isArray(semantic.actions) ? semantic.actions : [];
    const sourceAction = semanticActions.find((item) => (
      item && item.source_seq !== undefined && item.source_seq !== null
    )) || semanticActions[0] || null;
    const sourceSeq = sourceAction ? sourceAction.source_seq : null;
    const payloadRole = packet.semantic_role
      || (packet.shape && packet.shape.semantic_role)
      || packet.role
      || "";
    const semanticValues = [
      payloadRole ? `角色 ${payloadRole}` : "",
      semantic.state_phase ? `阶段 ${semantic.state_phase}` : "",
      sourceSeq !== null && sourceSeq !== undefined ? `8091 seq ${sourceSeq}` : "",
      Number.isFinite(Number(semantic.source_age_ms)) ? `同步 ${Number(semantic.source_age_ms)}ms` : "",
      semantic.action ? `动作 ${semantic.action}` : "",
    ].filter(Boolean);
    for (const text of semanticValues) {
      const chip = document.createElement("div");
      chip.className = "event-summary-chip event-summary-chip-state";
      chip.textContent = text;
      primary.appendChild(chip);
    }
  }
  if (!isGcloud && !isWssJson && items.length > 0) {
    for (const item of items.slice(0, 6)) {
      const chip = document.createElement("div");
      chip.className = `event-summary-chip event-summary-chip-${item.kind || "info"}`;
      chip.textContent = item.text;
      primary.appendChild(chip);
    }
  } else if (primary.childElementCount === 0) {
    const chip = document.createElement("div");
    chip.className = "event-summary-chip event-summary-chip-info";
    chip.textContent = "当前包没有结构化仿真摘要，可直接看 raw / before / after 字节视图";
    primary.appendChild(chip);
  }
  block.appendChild(primary);

  if (!isGcloud) {
    const transport = document.createElement("div");
    transport.className = "event-summary-transport";
    const proxyUsername = getProxyUsername(ev && ev.proxy_username);
    const transportBits = [
      `id=${ev && ev.id !== undefined ? ev.id : "-"}`,
      proxyUsername ? `kp=${proxyUsername}` : `cid=${stripDecoratorsFromCid(ev && ev.cid)}`,
      `seq=${ev && ev.seq !== undefined ? ev.seq : "-"}`,
      `msg=${ev && ev.msg_idx !== undefined ? ev.msg_idx : "-"}`,
      `chunk=${ev && ev.chunk_idx !== undefined ? ev.chunk_idx : "-"}`,
    ];
    for (const text of transportBits) {
      const node = document.createElement("span");
      node.textContent = text;
      transport.appendChild(node);
    }
    block.appendChild(transport);
  }

  if (summaryText && !isGcloud) {
    const details = document.createElement("details");
    details.className = "event-summary-debug";
    const summary = document.createElement("summary");
    summary.textContent = "调试详情";
    details.appendChild(summary);
    const debug = document.createElement("pre");
    const debugBits = [];
    if (kv.family) debugBits.push(`family=${kv.family}`);
    if (kv.slot) debugBits.push(`slot=${kv.slot}`);
    if (kv.slice) debugBits.push(`slice=${kv.slice}`);
    if (kv.score) debugBits.push(`score=${kv.score}`);
    if (kv.ref) debugBits.push(`ref=${kv.ref}`);
    if (kv.lead) debugBits.push(`lead=${kv.lead}`);
    if (kv.tpl) debugBits.push(`tpl=${kv.tpl}`);
    debugBits.push(`summary=${summaryText}`);
    debug.textContent = debugBits.join("\n");
    details.appendChild(debug);
    block.appendChild(details);
  }

  return block;
}

function buildEventBody(ev, hideAscii, eventId = "") {
  const body = document.createElement("div");
  body.className = "body";

  const summaryText = String(ev && ev.summary ? ev.summary : "").trim();
  const opaqueUndecrypted = isOpaqueUndecryptedSummary(summaryText);
  const isGcloudEvent = isGcloud65010Summary(summaryText, ev);
  const isWssJsonEvent = isWssJsonSummary(summaryText, ev);
  body.appendChild(buildEventReadableSummary(ev, summaryText));
  const gcloudPanel = buildGcloudPacketPanel(ev, summaryText);
  if (gcloudPanel) {
    body.appendChild(gcloudPanel);
  }
  const gcloudDeepKind = isGcloudEvent
    ? gcloudSecurityDeepPanelKind(ev, summaryText)
    : "";
  const gcloudSecurityDeepPanel = gcloudDeepKind
    ? buildGcloudAceCarrierDeepPanel(ev, summaryText)
    : null;
  if (gcloudSecurityDeepPanel) {
    body.appendChild(gcloudSecurityDeepPanel);
  }
  const gcloudStandaloneTssRecursivePanel = (
    isGcloudEvent && !gcloudSecurityDeepPanel
  ) ? buildGcloudStandaloneTssRecursivePanel(ev, summaryText) : null;
  if (gcloudStandaloneTssRecursivePanel) {
    body.appendChild(gcloudStandaloneTssRecursivePanel);
  }
  const wssJsonPanel = isWssJsonEvent ? buildWssJsonPanel(ev, summaryText) : null;
  if (wssJsonPanel) {
    body.appendChild(wssJsonPanel);
  }

  const fullPay = String(ev && ev.full_pay ? ev.full_pay : "");
  const beforePay = String(ev && ev.before_pay ? ev.before_pay : "");
  const decodedPay = String(ev && ev.pay ? ev.pay : "");
  const rawAfterPay = String(ev && ev.raw_pay ? ev.raw_pay : "");
  const hasFullDump = !!fullPay;
  const hasBeforeDump = !!beforePay;
  const hasRawAfterDump = !!rawAfterPay;
  const hasDecodedDump = !!decodedPay;
  const fullDumpSameAsDecoded = hasFullDump && hasDecodedDump && fullPay === decodedPay;
  const beforeDumpSameAsDecoded = hasBeforeDump && hasDecodedDump && beforePay === decodedPay;
  const isRequest = Number(ev && ev.dir) === 0;
  const isDecodedRequest = isRequest && isDecodedFlowEvent(ev, summaryText) && (hasFullDump || hasBeforeDump || hasDecodedDump);
  const gcloudWireRebuilt = isGcloudEvent && gcloudSummaryHasBackendRebuild(summaryText);
  const gcloudSentWireChanged = isGcloudEvent && gcloudSummaryHasSentWireChange(summaryText);
  const gcloudWireCompare = gcloudSentWireChanged && hasFullDump && hasRawAfterDump && fullPay !== rawAfterPay;
  const rawWireChangedOffsets = hasFullDump && hasRawAfterDump
    ? buildChangedOffsetSet(fullPay, rawAfterPay)
    : null;
  const showRawCompare =
    isDecodedRequest
    && hasFullDump
    && hasRawAfterDump
    && fullPay !== rawAfterPay
    && (currentFlowLooksLikePort8092(ev, summaryText) || gcloudWireRebuilt);
  const decodedChangedOffsets = hasBeforeDump && hasDecodedDump
    ? buildChangedOffsetSet(beforePay, decodedPay)
    : null;

  if (isRequest && gcloudWireCompare) {
    const beforeWireBytes = b64ToBytes(fullPay);
    const afterWireBytes = b64ToBytes(rawAfterPay);
    const wireDiff = countChangedBytes(beforeWireBytes, afterWireBytes);
    const changedOffsets = Array.from(rawWireChangedOffsets || []).sort((a, b) => a - b);
    const changedPreview = changedOffsets.slice(0, 8).map((offset) => {
      const beforeByte = offset < beforeWireBytes.length ? childHexByteText(beforeWireBytes[offset]) : "--";
      const afterByte = offset < afterWireBytes.length ? childHexByteText(afterWireBytes[offset]) : "--";
      return `+${formatHexValue(offset)} ${beforeByte}->${afterByte}`;
    }).join("，");
    const proof = document.createElement("div");
    proof.className = "ace-compare-status ace-compare-status-changed";
    const proofLabel = document.createElement("strong");
    proofLabel.textContent = "实际修改并发送";
    const proofText = document.createElement("span");
    const businessDiff = eventModificationDiffText(ev);
    proofText.textContent = `${businessDiff.detail ? `${businessDiff.detail}；` : ""}收到 full_pay -> 实际发送 raw_pay：变化 ${wireDiff.changed}/${wireDiff.commonLen}${wireDiff.lenDelta ? `，lenΔ=${wireDiff.lenDelta}` : ""}${changedPreview ? `；${changedPreview}` : ""}`;
    proof.appendChild(proofLabel);
    proof.appendChild(proofText);
    body.appendChild(proof);
  }

	  if (isDecodedRequest && !isGcloudEvent) {
	    const timeStrip = buildEventTimestampStrip(summaryText, beforePay, decodedPay);
	    if (timeStrip) body.appendChild(timeStrip);
	  }

  const dumpGrid = document.createElement("div");
  dumpGrid.className = `dump-grid ${isRequest ? "dump-grid-request" : "dump-grid-response"}`;
  if (isDecodedRequest) dumpGrid.classList.add("dump-grid-decrypted");
  if (showRawCompare) dumpGrid.classList.add("has-raw-compare");
  body.appendChild(dumpGrid);
  let semanticCompareAdded = false;

  const sourceShowsDecodedAsciiRows = (sourceKey) => (
    sourceKey === "decoded" || sourceKey === "before"
  );

  function appendDumpSection(title, base64Text, lengthValue, toneClass, sourceKey, dumpOptions = {}) {
    if (!base64Text) return;
    const collapsed = !!(dumpOptions && dumpOptions.collapsed);
    const panel = document.createElement(collapsed ? "details" : "section");
    panel.className = `dump-panel ${collapsed ? "dump-fold" : ""} ${toneClass || ""}`.trim();
    if (collapsed && dumpOptions.open) panel.open = true;
    const isRawSource = opaqueUndecrypted || sourceKey === "full" || sourceKey === "raw_after";
    const isDecodedSource = !opaqueUndecrypted && sourceShowsDecodedAsciiRows(sourceKey);
    const showDecodedAsciiRows = false;
    const enableTersafeAnnotations = !isGcloudEvent && !isWssJsonEvent;
    const tailChecksum = enableTersafeAnnotations && isDecodedSource ? findTrailingChecksumCandidate(b64ToBytes(base64Text)) : null;
    const timestampHighlights =
      isRawSource || !enableTersafeAnnotations
        ? []
        : mergeTimestampHighlightItems(
          collectTimestampHighlightsForPayload(base64Text),
          collectChildTimestampHighlightsForPayload(base64Text, summaryText)
        );
    const idfvHighlights =
      !isRawSource && enableTersafeAnnotations
        ? collectIdfvHighlightsForPayload(base64Text)
        : [];
    const historyHighlights =
      !isRawSource && enableTersafeAnnotations
        ? collectHistoryOpenidHighlightsForPayload(base64Text)
        : [];
    const semanticInfo = isRawSource || !enableTersafeAnnotations ? null : collectPacketSemanticInfoForPayload(base64Text);
    const timestampSummary = summarizeTimestampHighlights(timestampHighlights);

    const sectionTitle = document.createElement(collapsed ? "summary" : "div");
    sectionTitle.className = "dump-label";
    sectionTitle.appendChild(
      document.createTextNode(
        Number.isFinite(Number(lengthValue))
          ? `${title} [len=${Number(lengthValue)}]`
          : title
      )
    );
    if (semanticInfo) {
      const semanticChip = document.createElement("span");
      semanticChip.className = "dump-label-note dump-label-semantic";
      semanticChip.textContent = semanticInfo.text;
      semanticChip.title = semanticInfo.title || semanticInfo.text;
      sectionTitle.appendChild(semanticChip);
    }
    if (timestampHighlights.length > 0) {
      const timestampChip = document.createElement("span");
      timestampChip.className = "dump-label-note dump-label-timestamp";
      timestampChip.textContent = `时间戳×${timestampHighlights.length}`;
      timestampChip.title = timestampSummary;
      sectionTitle.appendChild(timestampChip);
    }
    if (idfvHighlights.length > 0) {
      const idfvChip = document.createElement("span");
      idfvChip.className = "dump-label-note dump-label-idfv";
      idfvChip.textContent = `iDevIDFV×${idfvHighlights.length}`;
      idfvChip.title = summarizeIdfvHighlights(idfvHighlights);
      sectionTitle.appendChild(idfvChip);
    }
    if (historyHighlights.length > 0) {
      const historyChip = document.createElement("span");
      historyChip.className = "dump-label-note dump-label-history-openid";
      historyChip.textContent = `HistoryOpenID×${historyHighlights.length}`;
      historyChip.title = summarizeHistoryOpenidHighlights(historyHighlights);
      sectionTitle.appendChild(historyChip);
    }
    if (tailChecksum) {
      const crcChip = document.createElement("span");
      crcChip.className = "dump-label-note";
      crcChip.textContent = "00+CRC?";
      crcChip.title = tailChecksum.text;
      sectionTitle.appendChild(crcChip);
    }
    if (collapsed) {
      const foldNote = document.createElement("span");
      foldNote.className = "dump-label-note";
      foldNote.textContent = dumpOptions.foldNote || "参考";
      sectionTitle.appendChild(foldNote);
    }
    panel.appendChild(sectionTitle);

    const stringAnnotationIndex = dumpOptions.showStringAnnotations
      ? getDumpAnnotationIndex(ev, sourceKey, base64Text)
      : new Map();
    const annotationIndex = mergeDumpAnnotationIndexes(
      stringAnnotationIndex,
      buildPacketSemanticAnnotationIndex(semanticInfo, getBytesPerRow()),
      buildTimestampAnnotationIndex(timestampHighlights, getBytesPerRow())
    );
    const dump = formatHexDump(base64Text, hideAscii, annotationIndex, {
      compactAscii: isRawSource,
      changedOffsets: dumpOptions.changedOffsets || null,
      timestampRanges: timestampHighlights,
      idfvRanges: idfvHighlights,
      historyRanges: historyHighlights,
      showTailChecksum: showDecodedAsciiRows,
    });
    const hexShell = document.createElement("div");
    hexShell.className = "hex-shell";
    attachDumpScrollPersistence(hexShell, makeDumpScrollKey(eventId, toneClass, title));
    const hexHead = document.createElement("div");
    hexHead.className = "hex-head";
    hexHead.textContent = dump.header;
    const pre = document.createElement("pre");
    pre.className = "hex-body";
    pre.innerHTML = renderHexBodyHtml(dump, hideAscii, {
      blockComments: true,
      asciiRows: false,
    });

    hexShell.appendChild(hexHead);
    hexShell.appendChild(pre);
    panel.appendChild(hexShell);
    dumpGrid.appendChild(panel);
  }

  function appendEmptyDumpSection(title, note, toneClass) {
    const panel = document.createElement("section");
    panel.className = `dump-panel dump-panel-empty ${toneClass || ""}`.trim();

    const sectionTitle = document.createElement("div");
    sectionTitle.className = "dump-label";
    sectionTitle.textContent = title;
    panel.appendChild(sectionTitle);

    const empty = document.createElement("div");
    empty.className = "dump-empty";
    empty.textContent = note;
    panel.appendChild(empty);
    dumpGrid.appendChild(panel);
  }

  if (isRequest) {
    if (hasFullDump) {
      appendDumpSection(
        showRawCompare
          ? (gcloudWireCompare
            ? "收到的原始4013 [raw before/full_pay]"
            : (opaqueUndecrypted ? "修改前原始封包 [raw before]" : "修改前加密 [raw before]"))
          : (isGcloudEvent ? "加密 Payload [raw]" : "原始封包 [raw]"),
        fullPay,
        ev.full_len,
        "dump-panel-full",
        "full",
        {
          collapsed: isDecodedRequest,
          foldNote: showRawCompare ? (gcloudWireCompare ? "收到原包" : "修改前") : "raw 参考",
          changedOffsets: showRawCompare ? rawWireChangedOffsets : null,
        }
      );
    } else if (!isGcloudEvent) {
      appendEmptyDumpSection("原始封包 [raw]", "当前事件没有 full_pay，无法显示完整原始封包。", "dump-panel-full");
    }
    if (showRawCompare) {
      appendDumpSection(
        gcloudWireCompare
          ? "修改后重建4013 [raw after/sent]"
          : (opaqueUndecrypted ? "修改后原始封包 [raw after]" : "修改后加密 [raw after]"),
        rawAfterPay,
        ev.raw_len,
        "dump-panel-raw-after",
        "raw_after",
        {
          collapsed: true,
          foldNote: gcloudWireCompare ? "已转发" : "8092 after",
          changedOffsets: rawWireChangedOffsets,
        }
      );
    }
    if (hasBeforeDump) {
      appendDumpSection(gcloudWireRebuilt ? "修改前解密 Payload [before/received]" : (opaqueUndecrypted ? "修改前原始封包 [before/raw]" : (isGcloudEvent ? "修改前解密 Payload [before]" : "修改前解密 [before]")), beforePay, ev.before_len, "dump-panel-before", "before", {
        changedOffsets: decodedChangedOffsets,
      });
    } else if (hasDecodedDump) {
      dumpGrid.classList.add("dump-grid-current-only");
    } else {
      appendEmptyDumpSection(
        opaqueUndecrypted ? "修改前原始封包 [before/raw missing]" : "修改前解密 [before missing]",
        opaqueUndecrypted
          ? "当前事件没有 before_pay，无法显示修改前原始封包。"
          : "当前事件没有 before_pay；通常是未经过仿生改写、旧事件、或该包只记录了当前解密片段。",
        "dump-panel-before"
      );
    }
    if (hasDecodedDump) {
      const decodedTitle = opaqueUndecrypted
        ? (hasBeforeDump
          ? (beforeDumpSameAsDecoded ? "修改后原始封包 [after/raw same]" : "修改后原始封包 [after/raw]")
          : "当前原始封包 [current/raw]")
        : (hasBeforeDump
          ? gcloudWireRebuilt
            ? "修改后解密 Payload [after/rebuilt]"
            : beforeDumpSameAsDecoded
            ? (isGcloudEvent ? "修改后解密 Payload [after same]" : "修改后解密 [after same]")
            : (isGcloudEvent ? "修改后解密 Payload [after]" : "修改后解密 [after]")
          : (isGcloudEvent ? "解密 Payload [current]" : "当前解密 [current]"));
      appendDumpSection(
        decodedTitle,
        decodedPay,
        ev.len,
        "dump-panel-decoded",
        "decoded",
        { changedOffsets: decodedChangedOffsets }
      );
    } else {
      appendEmptyDumpSection(
        opaqueUndecrypted ? "修改后原始封包 [after/raw missing]" : "修改后解密 [after missing]",
        opaqueUndecrypted ? "当前事件没有 pay，无法显示修改后/当前原始封包。" : "当前事件没有 pay，无法显示修改后/当前解密内容。",
        "dump-panel-decoded"
      );
    }
  } else if (isGcloudEvent) {
    if (gcloudWireCompare) {
      appendDumpSection(
        "修改前加密 Payload [full_pay]",
        fullPay,
        ev.full_len,
        "dump-panel-full",
        "full",
        { collapsed: true, foldNote: "修改前 wire", changedOffsets: rawWireChangedOffsets }
      );
      appendDumpSection(
        "修改后加密 Payload [raw_pay]",
        rawAfterPay,
        ev.raw_len,
        "dump-panel-raw-after",
        "raw_after",
        { collapsed: true, foldNote: "修改后 wire", changedOffsets: rawWireChangedOffsets }
      );
    } else if (hasFullDump && !fullDumpSameAsDecoded) {
      appendDumpSection(
        "加密 Payload [raw]",
        fullPay,
        ev.full_len,
        "dump-panel-full",
        "full",
        { collapsed: true, foldNote: "raw 参考" }
      );
    }
    if (hasBeforeDump) {
      appendDumpSection(
        "修改前解密 Payload [before]",
        beforePay,
        ev.before_len,
        "dump-panel-before",
        "before",
        { changedOffsets: decodedChangedOffsets }
      );
    }
    if (hasDecodedDump) {
      appendDumpSection(
        hasBeforeDump ? "修改后解密 Payload [after]" : "解密 Payload [current]",
        decodedPay,
        ev.len,
        "dump-panel-decoded",
        "decoded",
        { changedOffsets: decodedChangedOffsets }
      );
    } else if (!hasFullDump) {
      appendEmptyDumpSection("Payload", "当前事件没有可显示的 Payload。", "dump-panel-single");
    }
  } else if (hasFullDump && !fullDumpSameAsDecoded) {
    appendDumpSection("响应原始封包 [raw]", fullPay, ev.full_len, "dump-panel-full", "full");
    appendDumpSection("响应解密 [decoded]", decodedPay, ev.len, "dump-panel-decoded", "decoded");
  } else if (hasDecodedDump) {
    appendDumpSection("响应解密 [decoded]", decodedPay, ev.len, "dump-panel-decoded", "decoded");
  } else {
    appendDumpSection("响应封包 [raw]", fullPay, ev.full_len, "dump-panel-single", "full");
  }

  if (!isGcloudEvent && isRequest && !isWssJsonEvent && (hasBeforeDump || hasDecodedDump)) {
    const childCompare = buildChildComparePanel(beforePay, decodedPay, summaryText);
    if (childCompare) {
      childCompare.classList.add("child-compare-inline");
      if (childCompare.classList.contains("child-compare-current-only")) {
        dumpGrid.classList.add("child-structure-current-only");
      }
      dumpGrid.appendChild(childCompare);
      semanticCompareAdded = true;
    } else {
      const treeRow = buildTreeCompareRow(beforePay, decodedPay, summaryText);
      if (treeRow) {
        body.appendChild(treeRow);
      }
    }
  } else if (!isGcloudEvent && !isRequest && !isWssJsonEvent && hasDecodedDump) {
    const responseBeforePay = hasBeforeDump ? beforePay : "";
    const childCompare = buildChildComparePanel(responseBeforePay, decodedPay, summaryText);
    if (childCompare) {
      body.appendChild(childCompare);
      semanticCompareAdded = true;
    } else {
      const treeRow = buildTreeCompareRow(responseBeforePay, decodedPay, summaryText);
      if (treeRow) {
        body.appendChild(treeRow);
      }
    }
  }

  const analysisGrid = isGcloudEvent ? null : buildEventAnalysisGrid(ev);
  if (analysisGrid && !isWssJsonEvent) {
    if (semanticCompareAdded) {
      const details = document.createElement("details");
      details.className = "analysis-debug-details";
      const summary = document.createElement("summary");
      summary.textContent = "更多解析 / XOR / 字符串";
      details.appendChild(summary);
      details.appendChild(analysisGrid);
      body.appendChild(details);
    } else {
      body.appendChild(analysisGrid);
    }
  }

  return body;
}

function applyEventPayloadDetail(ev, detail) {
  if (!ev || typeof ev !== "object") return false;
  if (!detail || typeof detail !== "object") return false;

  const pay = String(detail.pay || "");
  if (!pay) return false;
  ev.pay = pay;
  if (detail.full_pay !== undefined) ev.full_pay = String(detail.full_pay || "");
  const fullLen = Number(detail.full_len);
  if (Number.isFinite(fullLen)) ev.full_len = fullLen;
  if (detail.full_pfx !== undefined) ev.full_pfx = String(detail.full_pfx || "");
  if (detail.before_pay !== undefined) ev.before_pay = String(detail.before_pay || "");
  const beforeLen = Number(detail.before_len);
  if (Number.isFinite(beforeLen)) ev.before_len = beforeLen;
  if (detail.before_pfx !== undefined) ev.before_pfx = String(detail.before_pfx || "");
  if (detail.raw_pay !== undefined) ev.raw_pay = String(detail.raw_pay || "");
  const rawLen = Number(detail.raw_len);
  if (Number.isFinite(rawLen)) ev.raw_len = rawLen;
  if (detail.raw_pfx !== undefined) ev.raw_pfx = String(detail.raw_pfx || "");
  if (detail.pfx) ev.pfx = String(detail.pfx);
  if (detail.cid) ev.cid = String(detail.cid);
  if (detail.proxy_username !== undefined) ev.proxy_username = String(detail.proxy_username || "");
  if (detail.summary !== undefined) ev.summary = String(detail.summary || "");
  if (detail.modified !== undefined) {
    ev.modified = detail.modified === true || String(detail.modified || "") === "1";
  }
  if (Array.isArray(detail.modification_evidence)) {
    ev.modification_evidence = detail.modification_evidence.map((item) => String(item || "")).filter(Boolean);
  }
  if (detail.analysis && typeof detail.analysis === "object") ev.analysis = detail.analysis;

  const seqNum = Number(detail.seq);
  if (Number.isFinite(seqNum)) ev.seq = seqNum;
  const msgIdx = Number(detail.msg_idx);
  if (Number.isFinite(msgIdx)) ev.msg_idx = msgIdx;
  const chunkIdx = Number(detail.chunk_idx);
  if (Number.isFinite(chunkIdx)) ev.chunk_idx = chunkIdx;

  ev.__tcpvPreviewCacheKey = "";
  ev.__tcpvPreviewInfo = null;
  ev.__tcpvPayloadLen = undefined;
  ev.__tcpvHiPreviewLabels = undefined;
  ev.__tcpvHasCsob = undefined;
  ev.__tcpvAnalysisKey = "";
  ev.__tcpvAnalysis = null;
  return true;
}

async function ensureEventPayload(ev, account, eventId) {
  if (!ev || typeof ev !== "object") {
    throw new Error("invalid event object");
  }
  const hasPayload = !!String(ev.pay || "");
  const isRequest = Number(ev.dir) === 0;
  const summaryText = String(ev && ev.summary ? ev.summary : "");
  const needsRawPayload =
    (
      (
        isRequest
        && isDecodedFlowEvent(ev, summaryText)
        && currentFlowLooksLikePort8092(ev, summaryText)
      )
      || (
        isGcloud65010Summary(summaryText, ev)
        && gcloudSummaryHasSentWireChange(summaryText)
      )
    )
    && !String(ev.raw_pay || "")
    && !ev.__tcpvPayloadDetailFetched;
  const needsFullPayload = !String(ev.full_pay || "");
  const needsBeforePayload = !String(ev.before_pay || "") && !ev.__tcpvPayloadDetailFetched;
  if (hasPayload && !needsFullPayload && !needsBeforePayload && !needsRawPayload) {
    return ev;
  }

  const accountText = String(account || "").trim();
  const idText = String(eventId || "").trim();
  if (!accountText || !idText) {
    throw new Error("invalid event id");
  }

  const cached = readPayloadCache(accountText, idText);
  const cachedHasNeededBefore = !needsBeforePayload || !!String(cached && cached.before_pay ? cached.before_pay : "");
  const cachedHasNeededRaw = !needsRawPayload || !!String(cached && cached.raw_pay ? cached.raw_pay : "");
  if (cached && cachedHasNeededBefore && cachedHasNeededRaw && applyEventPayloadDetail(ev, cached)) {
    ev.__tcpvPayloadDetailFetched = true;
    return ev;
  }

  const detail = (needsBeforePayload || needsRawPayload)
    ? await apiGetEvent(accountText, idText)
    : await fetchEventPayload(accountText, idText);
  if (!applyEventPayloadDetail(ev, detail)) {
    throw new Error("event payload is empty");
  }
  writePayloadCache(accountText, idText, detail);
  ev.__tcpvPayloadDetailFetched = true;
  if (currentFlowLooksLikeGcloud65010(ev)) {
    refreshAceOverviewUi();
  }
  return ev;
}

function collectGcloudAceStats(events = state.events) {
  const list = Array.isArray(events) ? events : [];
  const cacheable = list === state.events;
  const signature = cacheable
    ? `${state.flowId}|${list.length}|${list.length > 0 ? getEventId(list[0]) : "-"}|${list.length > 0 ? getEventId(list[list.length - 1]) : "-"}`
    : "";
  if (cacheable && state.gcloudAceStatsCache && state.gcloudAceStatsCache.signature === signature) {
    return state.gcloudAceStatsCache.value;
  }
  const stats = {
    total: list.length,
    accountLogin: 0,
    aceAll: 0,
    antiData: 0,
    aceAck: 0,
    lightFeature: 0,
    transfer: 0,
    aceOther: 0,
    cstssAll: 0,
    heartbeat: 0,
    network: 0,
    gcloud4013: 0,
    tgcpControl: 0,
    antiAsciiHex: 0,
    antiBinary: 0,
  };
  for (const ev of list) {
    const eventClass = gcloudEventClass(ev);
    if (eventClass.startsWith("ace_")) stats.aceAll += 1;
    if (eventClass === "account_login") stats.accountLogin += 1;
    else if (eventClass === "ace_antidata") stats.antiData += 1;
    else if (eventClass === "ace_ack") stats.aceAck += 1;
    else if (eventClass === "ace_light") stats.lightFeature += 1;
    else if (eventClass === "ace_transfer") stats.transfer += 1;
    else if (eventClass === "ace_other") stats.aceOther += 1;
    else if (eventClass === "cstss_all") stats.cstssAll += 1;
    else if (eventClass === "gcloud_heartbeat") stats.heartbeat += 1;
    else if (eventClass === "gcloud_network") stats.network += 1;
    else if (eventClass === "gcloud_4013") stats.gcloud4013 += 1;
    else if (eventClass === "tgcp_control") stats.tgcpControl += 1;

    if (eventClass === "ace_antidata") {
      const preview = getGcloudPreviewBytes(ev);
      const proto = getGcloudBusinessProtoCached(ev, preview.bytes, preview.complete);
      const protoBytes = proto && Array.isArray(proto.viewBytes) ? proto.viewBytes : preview.bytes;
      const carrier = analyzeGcloudAceCarrier(proto, protoBytes);
      if (carrier.mode === "ascii_hex") stats.antiAsciiHex += 1;
      else stats.antiBinary += 1;
    }
  }
  if (cacheable) {
    state.gcloudAceStatsCache = { signature, value: stats };
  }
  return stats;
}

function updateAceFilterUi() {
  if (!el.filterAceMode) return;
  const isGcloud = !!state.flowId && currentFlowLooksLikeGcloud65010();
  el.filterAceMode.hidden = !isGcloud;
  el.filterAceMode.disabled = !isGcloud;
  if (!isGcloud) return;

  const stats = collectGcloudAceStats();
  const mode = normalizeAceFilterMode(state.filters.aceMode);
  const options = [
    ["all", `全部事件 · ${stats.total}`],
    ["account_login", `Login 请求/响应 · ${stats.accountLogin}`],
    ["ace_all", `CSAce* · ${stats.aceAll}`],
    ["ace_antidata", `AntiData 上报 · ${stats.antiData}`],
    ["ace_ack", `AntiData ACK · ${stats.aceAck}`],
    ["ace_light", `LightFeature 周期 · ${stats.lightFeature}`],
    ["ace_transfer", `Transfer 下行 · ${stats.transfer}`],
    ["cstss_all", `CSTss* · ${stats.cstssAll}`],
    ["gcloud_heartbeat", `GCloud 心跳 · ${stats.heartbeat}`],
    ["gcloud_network", `网络状态 · ${stats.network}`],
    ["gcloud_4013", `其他 4013 · ${stats.gcloud4013}`],
    ["tgcp_control", `TGCP 控制 · ${stats.tgcpControl}`],
  ];
  el.filterAceMode.textContent = "";
  for (const [value, label] of options) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    el.filterAceMode.appendChild(option);
  }
  el.filterAceMode.value = mode;
}

function buildAceFlowOverviewPanel() {
  if (!state.flowId || !currentFlowLooksLikeGcloud65010()) return null;
  const stats = collectGcloudAceStats();
  const flow = getCurrentFlowMeta();
  const firstEvent = Array.isArray(state.events) && state.events.length > 0 ? state.events[0] : null;
  const lastEvent = Array.isArray(state.events) && state.events.length > 0 ? state.events[state.events.length - 1] : null;
  const gcloudPort = gcloudTargetPortFromText(
    flow && flow.last_cid,
    firstEvent && firstEvent.cid,
    lastEvent && lastEvent.cid,
    firstEvent && firstEvent.summary,
    lastEvent && lastEvent.summary,
  ) || "TGCP";
  const panel = document.createElement("section");
  panel.className = "ace-flow-overview";
  const title = document.createElement("div");
  title.className = "ace-flow-overview-title";
  title.textContent = `${gcloudPort} · GCloud 命令统计`;
  panel.appendChild(title);

  const chips = document.createElement("div");
  chips.className = "ace-flow-overview-chips";
  const activeMode = normalizeAceFilterMode(state.filters.aceMode);
  const values = [
    ["account_login", `Login ${stats.accountLogin}`],
    ["ace_all", `CSAce* ${stats.aceAll}`],
    ["ace_antidata", `AntiData ${stats.antiData} out`],
    ["ace_ack", `ACK ${stats.aceAck}`],
    ["ace_light", `LightFeature ${stats.lightFeature} out`],
    ["ace_transfer", `Transfer ${stats.transfer} in`],
    ["cstss_all", `CSTss* ${stats.cstssAll}`],
    ["gcloud_heartbeat", `Heartbeat ${stats.heartbeat}`],
    ["gcloud_network", `Network ${stats.network}`],
    ["carrier", `AntiData carrier: binary ${stats.antiBinary} / ascii_hex ${stats.antiAsciiHex}`],
    ["loaded", `已载入 ${stats.total} 包`],
  ];
  for (const [value, label] of values) {
    const chip = document.createElement("span");
    chip.className = `ace-flow-overview-chip${value === activeMode || (value === "ace_all" && activeMode === "ace_all") ? " ace-flow-overview-chip-active" : ""}`;
    chip.textContent = label;
    chips.appendChild(chip);
  }
  panel.appendChild(chips);
  return panel;
}

function refreshAceOverviewUi() {
  if (state.aceOverviewRefreshTimer) return;
  state.aceOverviewRefreshTimer = window.setTimeout(() => {
    state.aceOverviewRefreshTimer = 0;
    if (!currentFlowLooksLikeGcloud65010()) return;
    state.gcloudAceStatsCache = null;
    updateAceFilterUi();
    const current = el.events ? el.events.querySelector(".ace-flow-overview") : null;
    const next = buildAceFlowOverviewPanel();
    if (current && next) current.replaceWith(next);
  }, 80);
}

function eventMatchesFilters(ev) {
  if (!ev || typeof ev !== "object") return false;
  const dir = state.filters.dir || "all";
  if (dir === "req" && Number(ev.dir) !== 0) return false;
  if (dir === "resp" && Number(ev.dir) !== 1) return false;

  const len = Number(ev.len || 0);
  const minLen = state.filters.minLen ? Number(state.filters.minLen) : null;
  const maxLen = state.filters.maxLen ? Number(state.filters.maxLen) : null;
  if (minLen !== null && Number.isFinite(minLen) && len < minLen) return false;
  if (maxLen !== null && Number.isFinite(maxLen) && len > maxLen) return false;
  if (state.filters.csobOnly && !eventHasCsob(ev)) return false;
  const aceMode = normalizeAceFilterMode(state.filters.aceMode);
  if (aceMode !== "all" && currentFlowLooksLikeGcloud65010()) {
    const eventClass = gcloudEventClass(ev);
    if (aceMode === "ace_all" && !eventClass.startsWith("ace_")) return false;
    if (aceMode !== "ace_all" && eventClass !== aceMode) return false;
  }
  return true;
}

function findEventNodeById(eventId) {
  if (!eventId) return null;
  for (const node of el.events.querySelectorAll("details[data-event-id]")) {
    if (String(node.dataset.eventId || "") === String(eventId)) {
      return node;
    }
  }
  return null;
}

function focusCurrentHit(behavior = "smooth") {
  if (!Array.isArray(state.hitEventIds) || state.hitEventIds.length === 0) return;
  if (state.hitCursor < 0 || state.hitCursor >= state.hitEventIds.length) return;
  const eventId = state.hitEventIds[state.hitCursor];
  const node = findEventNodeById(eventId);
  if (!node) return;
  node.scrollIntoView({ behavior, block: "center" });
}

async function applySearch(focusFirstHit = true) {
  saveRules();
  const draft = updateSearchDraftState();
  if (!draft.text) {
    state.search = buildAppliedSearchState("", draft.mode, draft.color);
    state.hitCursor = -1;
    state.pendingHitScroll = false;
    saveAppliedSearch();
    renderEvents();
    return;
  }
  if (draft.invalidCount > 0) {
    setStatus(`search rule invalid: ${draft.invalidCount}`);
    return;
  }

  state.search = draft;
  state.hitCursor = focusFirstHit ? 0 : state.hitCursor;
  state.pendingHitScroll = focusFirstHit;
  saveAppliedSearch();
  const modeSpec = parseHighlightMode(state.search.mode || "full_contains");
  if (state.search.active && modeSpec.scope === "full") {
    state.events = [];
    state.afterId = null;
    state.hasMore = true;
    state.hitEventIds = [];
    state.filteredCount = 0;
    renderEvents();
    await syncLatestEvents({ drain: true, maxPages: 60 });
    return;
  }
  renderEvents();
}

function applyFilters() {
  state.filters = getFilterDraftState();
  if (el.filterDir) {
    el.filterDir.value = state.filters.dir || "all";
  }
  if (el.filterMinLen) {
    el.filterMinLen.value = state.filters.minLen || "";
  }
  if (el.filterMaxLen) {
    el.filterMaxLen.value = state.filters.maxLen || "";
  }
  if (el.filterAceMode) {
    el.filterAceMode.value = state.filters.aceMode || "all";
  }
  saveRules();
  saveAppliedFilters();
  renderEvents();
}

function clearFilters() {
  if (el.filterDir) {
    el.filterDir.value = "all";
  }
  if (el.filterMinLen) {
    el.filterMinLen.value = "";
  }
  if (el.filterMaxLen) {
    el.filterMaxLen.value = "";
  }
  if (el.filterCsobOnly) {
    el.filterCsobOnly.checked = false;
  }
  if (el.filterAceMode) {
    el.filterAceMode.value = "all";
  }
  state.filters = getFilterDraftState();
  saveRules();
  saveAppliedFilters();
  renderEvents();
}

function moveHit(step) {
  if (!Array.isArray(state.hitEventIds) || state.hitEventIds.length === 0) return;
  const total = state.hitEventIds.length;
  const base = state.hitCursor >= 0 ? state.hitCursor : 0;
  state.hitCursor = (base + step + total) % total;
  updateSearchUi();

  for (const node of el.events.querySelectorAll("details.event-hit-current")) {
    node.classList.remove("event-hit-current");
  }
  const currentId = state.hitEventIds[state.hitCursor] || "";
  const currentNode = findEventNodeById(currentId);
  if (currentNode) {
    currentNode.classList.add("event-hit-current");
  }
  focusCurrentHit("smooth");
}

function collectAutoExpandIds(visibleEvents, expandMode) {
  // Keep expansion state tied to explicit user toggles; preview/payload prefetch
  // rerenders should not open packets on their own.
  void visibleEvents;
  void expandMode;
  return new Set();
}

function buildSemanticTimelinePanel(events) {
  const semanticEvents = (Array.isArray(events) ? events : []).filter(
    (ev) => ev && ev.analysis && typeof ev.analysis === "object" && ev.analysis.schema === "tersafe.semantic.v1"
  );
  if (semanticEvents.length === 0) return null;

  const phaseTrack = [];
  const connectionTrack = [];
  const consistencyTrack = [];
  const burstMax = new Map();
  let lastPhase = "";
  let lastConnection = "";
  for (const ev of semanticEvents) {
    const analysis = ev.analysis || {};
    const phase = String(analysis.state_phase || "unknown");
    if (phase !== lastPhase) {
      phaseTrack.push(`${formatTsShort(ev.ts)} ${phase}`);
      lastPhase = phase;
    }
    const connection = analysis.connection_65010 && typeof analysis.connection_65010 === "object"
      ? String(analysis.connection_65010.status || "unknown")
      : String(ev.cid || "").includes(":65010")
        ? "open(observed)"
        : "unknown";
    if (connection !== lastConnection) {
      connectionTrack.push(`${formatTsShort(ev.ts)} ${connection}`);
      lastConnection = connection;
    }
    const consistency = Number(analysis.consistency);
    if (Number.isFinite(consistency)) {
      consistencyTrack.push(`${formatTsShort(ev.ts)} ${(consistency * 100).toFixed(0)}%`);
    }
    const correlation = analysis.response_correlation && typeof analysis.response_correlation === "object"
      ? analysis.response_correlation
      : {};
    const burst = Number(correlation.burst_index || 0);
    if (burst > 0) {
      const report = String(correlation.response_report_code || analysis.packet?.report_code || "unknown");
      burstMax.set(report, Math.max(Number(burstMax.get(report) || 0), burst));
    }
    const feedback = analysis.response_feedback && typeof analysis.response_feedback === "object"
      ? analysis.response_feedback
      : {};
    const riskBurst = Number(feedback.risk_0024_count_2s || 0);
    if (riskBurst > 0) {
      burstMax.set("0x010a0024(field_c=0x10194)", Math.max(Number(burstMax.get("0x010a0024(field_c=0x10194)") || 0), riskBurst));
    }
  }

  const panel = document.createElement("section");
  panel.className = "semantic-timeline";
  const title = document.createElement("div");
  title.className = "semantic-timeline-title";
  title.textContent = "语义状态总览（hex 下钻前）";
  panel.appendChild(title);

  const appendTrack = (labelText, values, risk = false) => {
    const row = document.createElement("div");
    row.className = "semantic-timeline-row";
    const label = document.createElement("div");
    label.className = "semantic-timeline-label";
    label.textContent = labelText;
    const track = document.createElement("div");
    track.className = "semantic-timeline-track";
    const safeValues = values.length > 0 ? values.slice(-12) : ["暂无证据"];
    for (const value of safeValues) {
      const chip = document.createElement("span");
      chip.className = `semantic-timeline-chip${risk ? " semantic-timeline-chip-risk" : ""}`;
      chip.textContent = value;
      track.appendChild(chip);
    }
    row.appendChild(label);
    row.appendChild(track);
    panel.appendChild(row);
  };

  appendTrack("状态阶段", phaseTrack);
  appendTrack("65010 连接", connectionTrack);
  appendTrack(
    "响应 burst/2s",
    Array.from(burstMax.entries()).map(([report, count]) => `${report} ×${count}`),
    Array.from(burstMax.values()).some((count) => Number(count) > 3)
  );
  appendTrack("一致度趋势", consistencyTrack);
  return panel;
}

function renderEvents() {
  snapshotDumpScrollPositions(el.events);
  const openIds = new Set();
  for (const node of el.events.querySelectorAll("details[data-event-id]")) {
    const nodeId = String(node.dataset.eventId || "").trim();
    if (!nodeId) continue;
    if (node.open) openIds.add(nodeId);
  }
  state.expandedIds = openIds;

  el.events.innerHTML = "";
  updateAceFilterUi();
  const hideAscii = el.hideAscii.value === "1";
  const modeSpec = parseHighlightMode(state.search.mode || "full_contains");
  const expandMode = getExpandMode();
  const highlightRules = state.search.active ? state.search.rules : [];
  const allowExpand = expandMode !== "off";
  if (!allowExpand) {
    state.expandedIds.clear();
  }
  const prevCurrentHitId =
    state.hitCursor >= 0 && state.hitCursor < state.hitEventIds.length
      ? state.hitEventIds[state.hitCursor]
      : "";

  if (!state.flowId) {
    state.filteredCount = 0;
    state.hitEventIds = [];
    state.hitCursor = -1;
    state.pendingHitScroll = false;
    updateSearchUi();
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "Select a flow on the left.";
    el.events.appendChild(empty);
    return;
  }

  if (state.events.length === 0) {
    state.filteredCount = 0;
    state.hitEventIds = [];
    state.hitCursor = -1;
    state.pendingHitScroll = false;
    updateSearchUi();
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No packets yet for selected flow.";
    el.events.appendChild(empty);
    return;
  }

  const needFullScan = state.search.active && modeSpec.scope === "full";
  const filteredEvents = state.events.filter((ev) => eventMatchesFilters(ev));
  let visibleEvents = filteredEvents;
  let omittedRenderCount = 0;
  if (!needFullScan && !state.search.active) {
    const gcloudFlow = currentFlowLooksLikeGcloud65010();
    const renderLimit = gcloudFlow
      ? (state.autoRefresh ? GCLOUD_MAX_RENDER_EVENTS_AUTO : GCLOUD_MAX_RENDER_EVENTS_MANUAL)
      : (state.autoRefresh ? MAX_RENDER_EVENTS_AUTO : MAX_RENDER_EVENTS_MANUAL);
    if (filteredEvents.length > renderLimit) {
      omittedRenderCount = filteredEvents.length - renderLimit;
      visibleEvents = filteredEvents.slice(-renderLimit);
    }
  }
  const autoExpandIds = collectAutoExpandIds(visibleEvents, expandMode);
  state.filteredCount = visibleEvents.length;
  const aceOverview = buildAceFlowOverviewPanel();
  if (aceOverview) {
    el.events.appendChild(aceOverview);
  }
  if (omittedRenderCount > 0) {
    const note = document.createElement("div");
    note.className = "render-window-note";
    note.textContent = `Redis 已加载 ${filteredEvents.length} 包；为保证页面响应，当前渲染最近 ${visibleEvents.length} 包，前面 ${omittedRenderCount} 包未丢失。启用搜索/过滤可扫描已加载全量。`;
    el.events.appendChild(note);
  }
  if (visibleEvents.length === 0) {
    state.hitEventIds = [];
    state.hitCursor = -1;
    state.pendingHitScroll = false;
    updateSearchUi();
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No packets match current filters.";
    el.events.appendChild(empty);
    return;
  }

  const semanticTimeline = buildSemanticTimelinePanel(visibleEvents);
  if (semanticTimeline) {
    el.events.appendChild(semanticTimeline);
  }

  const listFrag = document.createDocumentFragment();
  const nextHitEventIds = [];
  let windowPrefetchBudget = state.autoRefresh ? WINDOW_PREFETCH_BUDGET_AUTO : WINDOW_PREFETCH_BUDGET_MANUAL;
  let summaryHydrateBudget = state.autoRefresh
    ? SUMMARY_BADGE_HYDRATE_BUDGET_AUTO
    : SUMMARY_BADGE_HYDRATE_BUDGET_MANUAL;

  for (const ev of visibleEvents) {
    const wrap = document.createElement("details");
    const eventId = getEventId(ev);
    if (!needFullScan && !state.expandedIds.has(eventId) && !ev.__tcpvSummaryHydrated) {
      primeCompactEventCaches(ev);
      ev.pay = "";
    }
    wrap.dataset.eventId = eventId;
    wrap.className = ev.dir === 0 ? "event-req" : "event-resp";
    const summaryText = String(ev && ev.summary ? ev.summary : "").trim();
    if (isDecodedFlowEvent(ev, summaryText)) {
      wrap.classList.add("event-decoded-detail");
    }
    if (allowExpand && (state.expandedIds.has(eventId) || autoExpandIds.has(eventId))) {
      wrap.open = true;
    }
    if (!allowExpand) {
      wrap.classList.add("no-expand");
    }

    const summary = document.createElement("summary");
    if (!allowExpand) {
      summary.dataset.noExpandLabel = "expand-off";
    }
    const isReq = ev.dir === 0;
    const dirArrow = isReq ? "->" : "<-";
    const preview = getPreviewInfo(ev, needFullScan);
    const frag = ev.msg_idx >= 0 && ev.chunk_idx >= 0 ? `m${ev.msg_idx}/c${ev.chunk_idx}` : "m-/c-";
    const seqNum = Number(ev.seq || 0);
    const seqText = Number.isFinite(seqNum) && seqNum > 0 ? `#${seqNum}` : "#-";

    const matchTarget = needFullScan ? preview.scanBytes : preview.previewBytes;
    const matchRanges = state.search.active ? mergeRuleMatches(matchTarget, highlightRules, modeSpec.mode, 24) : [];
    const previewStart = Number(preview.previewOffset || 0);
    const previewEnd = previewStart + preview.previewBytes.length;
    const previewRanges =
      modeSpec.scope === "full"
        ? projectRangesToWindow(matchRanges, previewStart, preview.previewBytes.length)
        : matchRanges;
    const hasOutOfPreviewMatch =
      modeSpec.scope === "full" &&
      matchRanges.some((r) => {
        const start = Number(r.start || 0);
        const end = Number(r.end || 0);
        return end <= previewStart || start >= previewEnd;
      });
    const isHit = state.search.active && matchRanges.length > 0;
    if (isHit) {
      nextHitEventIds.push(eventId);
      wrap.classList.add("event-hit");
      wrap.dataset.hitIndex = String(nextHitEventIds.length);
    }

    const tsSpan = document.createElement("span");
    tsSpan.className = "summary-fixed summary-ts";
    tsSpan.textContent = `[${formatTsShort(ev.ts)}]`;
    tsSpan.title = formatTs(ev.ts);
    summary.appendChild(tsSpan);

    const dirWrap = document.createElement("span");
    dirWrap.className = "summary-fixed summary-dir";
    dirWrap.appendChild(document.createTextNode("["));
    const dirBadge = document.createElement("span");
    dirBadge.className = `dir-badge ${isReq ? "dir-req" : "dir-resp"}`;
    dirBadge.textContent = dirArrow;
    dirWrap.appendChild(dirBadge);
    dirWrap.appendChild(document.createTextNode("]"));
    summary.appendChild(dirWrap);

    const lenWrap = document.createElement("span");
    lenWrap.className = "summary-fixed summary-len";
    lenWrap.appendChild(document.createTextNode("[l="));
    const lenSpan = document.createElement("span");
    lenSpan.className = "len-field";
    lenSpan.textContent = String(ev.len ?? "");
    lenWrap.appendChild(lenSpan);
    lenWrap.appendChild(document.createTextNode("]"));
    lenWrap.title = `len=${String(ev.len ?? "")}`;
    summary.appendChild(lenWrap);

    const previewWrap = document.createElement("span");
    previewWrap.className = "summary-preview";
    previewWrap.title = `preview offset=${preview.previewOffset || 0} byte`;
    if (preview.missingWindowBytes > 0) {
      const suffix = preview.needsWindowFetch ? " (window loading...)" : " (window incomplete)";
      previewWrap.title += suffix;
    }
    previewWrap.appendChild(document.createTextNode("["));
    const previewSpan = document.createElement("span");
    previewSpan.className = "preview-hex";
    renderPreviewBytes(previewSpan, preview.previewBytes, previewRanges, preview.previewText || "");
    if (hasOutOfPreviewMatch && previewRanges.length === 0) {
      previewSpan.classList.add("preview-hit-outside");
      const firstColor = String(matchRanges[0]?.color || el.color.value || "").trim();
      if (firstColor) {
        previewSpan.style.borderColor = firstColor;
      }
    }
    previewWrap.appendChild(previewSpan);
    if (Array.isArray(preview.hiPreviewLabels) && preview.hiPreviewLabels.length > 0) {
      const hiPreview = document.createElement("span");
      hiPreview.className = "preview-hi";
      hiPreview.textContent = preview.hiPreviewLabels.join(" ");
      hiPreview.title = `010a0011 hi preview: ${preview.hiPreviewLabels.join(" ")}`;
      previewWrap.appendChild(hiPreview);
    }
    previewWrap.appendChild(document.createTextNode("]"));
    summary.appendChild(previewWrap);

    syncSummaryInsightStrip(summary, ev, summaryText);

    if (preview.needsWindowFetch && windowPrefetchBudget > 0 && state.flowId) {
      prefetchEventPayload(state.flowId, eventId);
      windowPrefetchBudget -= 1;
    }

    const extraSpan = document.createElement("span");
    extraSpan.className = "summary-extra";
    extraSpan.textContent = getEventExtraInfo(ev);
    summary.appendChild(extraSpan);

    const tailSpan = document.createElement("span");
    tailSpan.className = "summary-tail";
    tailSpan.textContent = `${seqText} ${frag}`;
    tailSpan.title = `seq=${ev.seq} msg_idx=${ev.msg_idx} chunk_idx=${ev.chunk_idx}`;
    summary.appendChild(tailSpan);
    syncSummaryTimestampBadge(summary, ev);
    syncSummaryIdfvBadge(summary, ev, summaryText);
    syncSummaryHistoryOpenidBadge(summary, ev, summaryText);
    if (
      summaryHydrateBudget > 0
      && hydrateSummaryBadges(summary, ev, summaryText, eventId)
    ) {
      summaryHydrateBudget -= 1;
    }
    syncEventModificationIndicator(wrap, summary, ev, summaryText);

    wrap.appendChild(summary);
    let prefetchTimer = 0;
    const clearPrefetch = () => {
      if (!prefetchTimer) return;
      clearTimeout(prefetchTimer);
      prefetchTimer = 0;
    };
    const schedulePrefetch = () => {
      if (needFullScan || !allowExpand) return;
      if (wrap.open || wrap.dataset.bodyLoading === "1") return;
      clearPrefetch();
      const flowIdAtSchedule = state.flowId;
      prefetchTimer = window.setTimeout(() => {
        prefetchTimer = 0;
        if (!wrap.isConnected) return;
        if (!flowIdAtSchedule || state.flowId !== flowIdAtSchedule) return;
        prefetchEventPayload(flowIdAtSchedule, eventId);
      }, PAYLOAD_PREFETCH_DELAY_MS);
    };
    summary.addEventListener("pointerenter", schedulePrefetch);
    summary.addEventListener("focus", schedulePrefetch);
    summary.addEventListener("pointerleave", clearPrefetch);
    summary.addEventListener("blur", clearPrefetch);

    const ensureBody = async () => {
      if (wrap.dataset.bodyReady === "1" || wrap.dataset.bodyLoading === "1") return;
      wrap.dataset.bodyLoading = "1";
      const flowIdAtStart = state.flowId;
      const loading = document.createElement("div");
      loading.className = "body";
      loading.textContent = "loading payload...";
      wrap.appendChild(loading);

      try {
        await ensureEventPayload(ev, flowIdAtStart, eventId);
        if (!wrap.isConnected || state.flowId !== flowIdAtStart) return;
        syncSummaryHiBadge(summary, ev);
        syncSummaryTimestampBadge(summary, ev);
        syncSummaryIdfvBadge(summary, ev, summaryText);
        syncSummaryHistoryOpenidBadge(summary, ev, summaryText);
        syncEventModificationIndicator(
          wrap,
          summary,
          ev,
          String(ev && ev.summary ? ev.summary : summaryText)
        );
        if (loading.isConnected) loading.remove();
        const bodyNode = buildEventBody(ev, hideAscii, eventId);
        wrap.appendChild(bodyNode);
        restoreDumpScrollPositions(bodyNode);
        wrap.dataset.bodyReady = "1";
      } catch (e) {
        if (loading.isConnected) {
          loading.textContent = `load payload error: ${e.message}`;
        }
      } finally {
        delete wrap.dataset.bodyLoading;
      }
    };
    if (allowExpand) {
      if (wrap.open) {
        ensureBody().catch((_e) => {});
      }
      wrap.addEventListener("toggle", () => {
        if (!eventId) return;
        if (wrap.open) {
          clearPrefetch();
          state.expandedIds.add(eventId);
          state.collapsedIds.delete(eventId);
          ensureBody().catch((_e) => {});
        } else {
          clearPrefetch();
          state.expandedIds.delete(eventId);
          state.collapsedIds.add(eventId);
          for (const node of wrap.querySelectorAll(".body")) {
            node.remove();
          }
          wrap.dataset.bodyReady = "0";
          if (!needFullScan && !ev.__tcpvSummaryHydrated) {
            ev.pay = "";
          }
        }
      });
    } else {
      state.expandedIds.delete(eventId);
      summary.addEventListener("click", (clickEv) => {
        clickEv.preventDefault();
      });
    }

    listFrag.appendChild(wrap);
  }
  el.events.appendChild(listFrag);

  state.hitEventIds = nextHitEventIds;
  if (nextHitEventIds.length <= 0) {
    state.hitCursor = -1;
  } else if (state.pendingHitScroll) {
    state.hitCursor = 0;
  } else if (prevCurrentHitId) {
    const keepIdx = nextHitEventIds.indexOf(prevCurrentHitId);
    state.hitCursor = keepIdx >= 0 ? keepIdx : Math.min(Math.max(state.hitCursor, 0), nextHitEventIds.length - 1);
  } else {
    state.hitCursor = Math.min(Math.max(state.hitCursor, 0), nextHitEventIds.length - 1);
  }

  if (state.hitCursor >= 0 && state.hitCursor < nextHitEventIds.length) {
    const currentNode = findEventNodeById(nextHitEventIds[state.hitCursor]);
    if (currentNode) {
      currentNode.classList.add("event-hit-current");
    }
  }

  updateSearchUi();
  if (state.pendingHitScroll) {
    state.pendingHitScroll = false;
    requestAnimationFrame(() => {
      focusCurrentHit("smooth");
    });
  }
}

async function tick() {
  try {
    const s = await apiJson("/stats");
    state.tick += 1;

    if (state.tick % 3 === 1 || !state.flowId) {
      await loadFlows(false);
      if (state.flowId && state.events.length === 0 && !state.loading) {
        await selectFlow(state.flowId);
      }
    }

    if (state.autoRefresh && state.flowId && !state.loading) {
      await syncLatestEvents();
    }

    const line =
      `emit=${s.emit_count} write=${s.write_count} err=${s.write_error_count} drop=${s.dropped_count} ` +
      `q=${s.queue_size} local=${state.events.length} view=${state.filteredCount}/${state.events.length} ` +
      `ofs=${getPreviewOffset()} follow=${state.autoRefresh ? "auto" : "manual"}` +
      `${state.search.active ? ` hit=${state.hitEventIds.length}` : ""}`;
    if (s.last_write_error) {
      setStatus(`${line} | last_error=${s.last_write_error}`);
    } else {
      setStatus(line);
    }
  } catch (e) {
    setStatus(`tick error: ${e.message}`);
  }
}

el.reload.addEventListener("click", async () => {
  try {
    await loadFlows(true);
    if (state.flowId) {
      await selectFlow(state.flowId);
    } else {
      state.events = [];
      renderEvents();
    }
  } catch (e) {
    setStatus(`reload error: ${e.message}`);
  }
});

if (el.importFlow && el.importFile) {
  el.importFlow.addEventListener("click", () => {
    el.importFile.click();
  });
  el.importFile.addEventListener("change", async () => {
    const file = el.importFile.files && el.importFile.files[0];
    el.importFile.value = "";
    if (!file) return;
    try {
      await importFlowFile(file);
    } catch (e) {
      setStatus(`import error: ${e.message}`);
    }
  });
}

if (el.saveFlow) {
  el.saveFlow.addEventListener("click", async () => {
    try {
      await saveCurrentFlow();
    } catch (e) {
      setStatus(`save error: ${e.message}`);
    }
  });
}

if (el.exportFlow) {
  el.exportFlow.addEventListener("click", async () => {
    try {
      await exportCurrentFlow();
    } catch (e) {
      setStatus(`export error: ${e.message}`);
    }
  });
}

if (el.deleteFlow) {
  el.deleteFlow.addEventListener("click", async () => {
    try {
      await clearCurrentFlow();
    } catch (e) {
      setStatus(`delete flow error: ${e.message}`);
    }
  });
}

if (el.sidebarToggle) {
  el.sidebarToggle.addEventListener("click", () => {
    setSidebarHidden(!state.sidebarHidden, true);
  });
}

el.prefix.addEventListener("input", () => {
  saveRules();
  updateSearchDraftState();
});

el.prefix.addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") {
    applySearch(true).catch((e) => setStatus(`search error: ${e.message}`));
    ev.preventDefault();
    return;
  }
  if (ev.key === "Escape") {
    el.prefix.value = "";
    updateSearchDraftState();
    saveRules();
    applySearch(false).catch((e) => setStatus(`search error: ${e.message}`));
    ev.preventDefault();
  }
});

if (el.highlightMode) {
  el.highlightMode.addEventListener("change", () => {
    saveRules();
    updateSearchDraftState();
  });
}

if (el.searchApply) {
  el.searchApply.addEventListener("click", () => {
    applySearch(true).catch((e) => setStatus(`search error: ${e.message}`));
  });
}

if (el.searchPrev) {
  el.searchPrev.addEventListener("click", () => {
    moveHit(-1);
  });
}

if (el.searchNext) {
  el.searchNext.addEventListener("click", () => {
    moveHit(1);
  });
}

el.color.addEventListener("input", () => {
  saveRules();
  updateSearchDraftState();
});

if (el.filterDir) {
  el.filterDir.addEventListener("change", () => {
    saveRules();
  });
}

if (el.filterMinLen) {
  el.filterMinLen.addEventListener("input", () => {
    saveRules();
  });
  el.filterMinLen.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      applyFilters();
      ev.preventDefault();
    }
  });
}

if (el.filterMaxLen) {
  el.filterMaxLen.addEventListener("input", () => {
    saveRules();
  });
  el.filterMaxLen.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      applyFilters();
      ev.preventDefault();
    }
  });
}

if (el.filterCsobOnly) {
  el.filterCsobOnly.addEventListener("change", () => {
    saveRules();
  });
}

if (el.filterApply) {
  el.filterApply.addEventListener("click", () => {
    applyFilters();
  });
}

if (el.filterClear) {
  el.filterClear.addEventListener("click", () => {
    clearFilters();
  });
}

el.hideAscii.addEventListener("change", () => {
  saveRules();
  renderEvents();
});

el.previewBytes.addEventListener("change", () => {
  saveRules();
  renderEvents();
});

if (el.previewOffsetRange) {
  el.previewOffsetRange.addEventListener("input", () => {
    applyPreviewOffset(el.previewOffsetRange.value, false);
  });
  el.previewOffsetRange.addEventListener("change", () => {
    applyPreviewOffset(el.previewOffsetRange.value, true);
  });
}

if (el.previewOffsetInput) {
  el.previewOffsetInput.addEventListener("input", () => {
    applyPreviewOffset(el.previewOffsetInput.value, false);
  });
  el.previewOffsetInput.addEventListener("change", () => {
    applyPreviewOffset(el.previewOffsetInput.value, true);
  });
  el.previewOffsetInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      applyPreviewOffset(el.previewOffsetInput.value, true);
      ev.preventDefault();
    }
  });
}

if (el.previewOffsetPrev) {
  el.previewOffsetPrev.addEventListener("click", () => {
    const next = Math.max(0, getPreviewOffset() - getPreviewOffsetStep());
    applyPreviewOffset(next, true);
  });
}

if (el.previewOffsetNext) {
  el.previewOffsetNext.addEventListener("click", () => {
    const next = Math.min(PREVIEW_OFFSET_MAX, getPreviewOffset() + getPreviewOffsetStep());
    applyPreviewOffset(next, true);
  });
}

if (el.previewSpace) {
  el.previewSpace.addEventListener("change", () => {
    saveRules();
    renderEvents();
  });
}

if (el.bodyTone) {
  el.bodyTone.addEventListener("change", () => {
    saveRules();
    applyBodyTone();
    renderEvents();
  });
}

if (el.expandMode) {
  el.expandMode.addEventListener("change", () => {
    saveRules();
    renderEvents();
  });
}

el.autoRefresh.addEventListener("change", () => {
  state.autoRefresh = el.autoRefresh.value === "1";
  saveRules();
});

el.themeMode.addEventListener("change", () => {
  state.themeMode = el.themeMode.value || "github-dark";
  saveRules();
  applyTheme();
  applyBodyTone();
});

if (systemThemeQuery) {
  const onSystemThemeChanged = () => {
    if (state.themeMode === "system") {
      applyTheme();
    }
  };
  if (typeof systemThemeQuery.addEventListener === "function") {
    systemThemeQuery.addEventListener("change", onSystemThemeChanged);
  } else if (typeof systemThemeQuery.addListener === "function") {
    systemThemeQuery.addListener(onSystemThemeChanged);
  }
}

(async function main() {
  installPreviewSummaryStyles();
  installFlowListBadgeStyles();
  installDumpAsciiRowStyles();
  installAceFilterControl();
  loadRules();
  setupSplitter();
  setupWheelRouting();
  try {
    await loadFlows(false);
    if (state.flowId) {
      await selectFlow(state.flowId);
    } else {
      renderEvents();
    }
  } catch (e) {
    setStatus(`init error: ${e.message}`);
  }

  await tick();
  setInterval(tick, 1500);
})();

function escapeHtml(text) {
  return String(text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
