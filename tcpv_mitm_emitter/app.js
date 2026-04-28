const state = {
  flowId: "",
  allFlows: [],
  flows: [],
  afterId: null,
  hasMore: true,
  events: [],
  loading: false,
  autoRefresh: true,
  tick: 0,
  expandedIds: new Set(),
  collapsedIds: new Set(),
  themeMode: "github-dark",
  search: {
    active: false,
    text: "",
    mode: "preview_contains",
    color: "#ffd166",
    rules: [],
    invalidCount: 0,
  },
  filters: {
    dir: "all",
    minLen: "",
    maxLen: "",
  },
  hitEventIds: [],
  hitCursor: -1,
  pendingHitScroll: false,
  filteredCount: 0,
  dumpScrollLeft: new Map(),
};

const el = {
  appRoot: document.getElementById("appRoot"),
  splitter: document.getElementById("splitter"),
  leftPane: document.getElementById("leftPane"),
  rightPane: document.getElementById("rightPane"),
  flowList: document.getElementById("flowList"),
  flowCount: document.getElementById("flowCount"),
  selectedTitle: document.getElementById("selectedFlowTitle"),
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

const MAX_FULL_SCAN_BYTES = 8192;
const MAX_EVENTS_IN_MEMORY = 10000;
const EVENTS_FETCH_LIMIT = 1000;
const PREVIEW_OFFSET_MAX = 4096;
const PAYLOAD_PREFETCH_DELAY_MS = 220;
const PAYLOAD_CACHE_MAX_ENTRIES = 24;
const PAYLOAD_CACHE_MAX_BYTES = 6 * 1024 * 1024;
const WINDOW_PREFETCH_BUDGET_AUTO = 16;
const WINDOW_PREFETCH_BUDGET_MANUAL = 48;
const MAX_RENDER_EVENTS_AUTO = 2000;
const MAX_RENDER_EVENTS_MANUAL = 5000;
const DUMP_SCROLL_CACHE_MAX = 800;
const AUTO_EXPAND_ON_COUNT = 3;
const AUTO_EXPAND_SMART_COUNT = 2;
const ANALYSIS_ASCII_MIN_LEN = 4;
const ANALYSIS_ASCII_MAX_ITEMS = 12;
const ANALYSIS_UTF8_MIN_CHARS = 2;
const ANALYSIS_UTF8_MAX_ITEMS = 8;
const ANALYSIS_BASE64_MAX_ITEMS = 6;
const ANALYSIS_BASE64_MAX_BYTES = 512;
const ANALYSIS_XOR_SCAN_MAX_BYTES = 768;
const PRINTABLE_RUN_ANCHOR_PATTERNS = [
  /\d{10,24}/,
  /(idevhw|idevsysver|iappversion|iappname|iappinfo)/i,
  /(model:|ver:|inc_id:|obf_id:|appname:|appid:|uuid:|client:|bundle:|mrpcs_|com\.|cn=|ou=|ip(hone|ad)\d|android)/i,
];
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
];
const TIMESTAMP_SECONDS_MIN = 1_672_531_200; // 2023-01-01
const TIMESTAMP_SECONDS_MAX = 1_893_456_000; // 2030-01-01
const TIMESTAMP_MAX_MARKS_PER_DUMP = 8;
const KNOWN_0102000A_TIMESTAMP_LAYOUTS = [
  { len: 68, innerType: 0x100a, selector0: 0x200e0002, selector1: 0x34560001, offsets: [0x40], label: "dfm-current" },
  { len: 80, innerType: 0x1001, selector0: 0x200e0002, selector1: 0x34560001, offsets: [0x20], label: "dfm-session" },
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

function normalizeFilterState(rawDir, rawMinLen, rawMaxLen) {
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
  const resp = await fetch(url, { cache: "no-store" });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`HTTP ${resp.status} ${resp.statusText}: ${body.slice(0, 200)}`);
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
      pfx: String(normalized.pfx || ""),
      cid: String(normalized.cid || ""),
      proxy_username: String(normalized.proxy_username || ""),
      summary: String(normalized.summary || ""),
      seq: Number.isFinite(Number(normalized.seq)) ? Number(normalized.seq) : undefined,
      msg_idx: Number.isFinite(Number(normalized.msg_idx)) ? Number(normalized.msg_idx) : undefined,
      chunk_idx: Number.isFinite(Number(normalized.chunk_idx)) ? Number(normalized.chunk_idx) : undefined,
    },
    size: pay.length + String(normalized.full_pay || "").length + String(normalized.before_pay || "").length,
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
  const appliedSearchMode = localStorage.getItem("tcpv_applied_highlight_mode") || "preview_contains";
  const appliedSearchColor = localStorage.getItem("tcpv_applied_rule_color") || "#ffd166";
  const draftSearchText = localStorage.getItem("tcpv_rule_prefix");
  const draftSearchMode = localStorage.getItem("tcpv_highlight_mode");
  const draftSearchColor = localStorage.getItem("tcpv_rule_color");
  const appliedFilterDir = localStorage.getItem("tcpv_applied_filter_dir") || "all";
  const appliedFilterMinLen = localStorage.getItem("tcpv_applied_filter_min_len") || "";
  const appliedFilterMaxLen = localStorage.getItem("tcpv_applied_filter_max_len") || "";
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
  el.hideAscii.value = localStorage.getItem("tcpv_hide_ascii") || "0";
  const savedPreviewBytes = String(localStorage.getItem("tcpv_preview_bytes") || "").trim();
  const initialPreviewBytes =
    savedPreviewBytes === "24" || savedPreviewBytes === "32" ? "16" : savedPreviewBytes || "16";
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
  state.search = buildAppliedSearchState(appliedSearchText, appliedSearchMode, appliedSearchColor);
  state.filters = normalizeFilterState(appliedFilterDir, appliedFilterMinLen, appliedFilterMaxLen);
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
    localStorage.setItem("tcpv_highlight_mode", el.highlightMode.value || "preview_contains");
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
  localStorage.setItem("tcpv_applied_highlight_mode", state.search.mode || "preview_contains");
  localStorage.setItem("tcpv_applied_rule_color", state.search.color || "#ffd166");
}

function saveAppliedFilters() {
  localStorage.setItem("tcpv_applied_filter_dir", state.filters.dir || "all");
  localStorage.setItem("tcpv_applied_filter_min_len", state.filters.minLen || "");
  localStorage.setItem("tcpv_applied_filter_max_len", state.filters.maxLen || "");
}

function getExpandMode() {
  if (!el.expandMode) return "smart";
  const mode = String(el.expandMode.value || "").toLowerCase();
  if (mode === "on" || mode === "off" || mode === "smart") {
    return mode;
  }
  return "smart";
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
  if (!Number.isFinite(ms) || ms <= 0) return "0s";
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  return `${Math.floor(sec / 3600)}h`;
}

function isFlowOpen(item) {
  if (!item || typeof item !== "object") return false;
  if (typeof item.is_open === "boolean") {
    return item.is_open;
  }
  const status = String(item.status || "").trim().toLowerCase();
  if (status === "open") return true;
  if (status === "closed") return false;
  const endedTs = Number(item.ended_ts || 0);
  return !Number.isFinite(endedTs) || endedTs <= 0;
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
  const proxyUsername = getProxyUsername(item && item.proxy_username);
  const proxyBadge = proxyUsername ? `[kp:${proxyUsername}]` : "";
  if (proxyBadge && cid) return `${proxyBadge} ${cid}`;
  if (cid) return cid;
  if (proxyBadge) return proxyBadge;
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
}

function renderFlowList() {
  const rows = state.flows;
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
    path.innerHTML = `<span class="badge-tcp">TCP</span>${escapeHtml(getFlowRowPath(item))}`;

    const proto = document.createElement("div");
    proto.textContent = "TCP";

    const size = document.createElement("div");
    size.textContent = formatSize(item.total_bytes ?? item.total);

    const duration = document.createElement("div");
    const open = isFlowOpen(item);
    duration.className = `flow-time ${open ? "flow-time-open" : "flow-time-closed"}`;
    duration.textContent = open ? "..." : formatDuration(item.duration_ms);
    duration.title = open ? "active flow" : "closed flow duration";

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

async function loadFlows(resetSelection = false, preferredFlowId = "") {
  const raw = await apiJson("/accounts");
  const data = normalizeAccounts(raw);
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

  renderFlowList();
  renderSelectedTitle();
}

function renderSelectedTitle() {
  updateActionButtons();
  if (!state.flowId) {
    el.selectedTitle.textContent = "No flow selected";
    return;
  }

  const item = state.flows.find((x) => String(x.account || "") === state.flowId);
  if (!item) {
    el.selectedTitle.textContent = "Flow selected";
    return;
  }

  const rawCid = String(item.last_cid || "");
  const cid = stripDecoratorsFromCid(rawCid);
  const proxyUsername = getProxyUsername(item && item.proxy_username);
  const proxyText = proxyUsername ? `[kp:${proxyUsername}]` : "";
  const text = cid ? `${proxyText} ${cid}`.trim() : proxyText;
  const dateTs = Number(item.first_ts || item.last_ts || 0);
  const dateText = dateTs > 0 ? `[${formatDateOnly(dateTs)}]` : "";
  el.selectedTitle.textContent = `${dateText} ${text || "Flow selected"}`.trim();
}

async function selectFlow(flowId) {
  if (!flowId) return;
  if (state.flowId !== flowId) {
    state.flowId = flowId;
  }
  state.dumpScrollLeft.clear();
  state.events = [];
  state.afterId = null;
  state.hasMore = true;
  state.expandedIds.clear();
  state.collapsedIds.clear();
  state.hitEventIds = [];
  state.hitCursor = -1;
  state.filteredCount = 0;
  renderFlowList();
  renderSelectedTitle();
  updateSearchUi();
  await syncLatestEvents({ drain: true, maxPages: 60 });
}

async function syncLatestEvents(options = {}) {
  if (!state.flowId || state.loading) return;
  const drain = !!(options && options.drain);
  const maxPagesRaw = Number(options && options.maxPages);
  const maxPages = Number.isFinite(maxPagesRaw) && maxPagesRaw > 0 ? Math.floor(maxPagesRaw) : 1;
  state.loading = true;

  try {
    const modeSpec = parseHighlightMode(state.search.mode || "preview_contains");
    const needPayloadInList = state.search.active && modeSpec.scope === "full";
    let page = 0;
    let changed = false;
    let shouldRenderEmpty = false;

    while (page < maxPages) {
      const params = new URLSearchParams({
        account: state.flowId,
        limit: String(EVENTS_FETCH_LIMIT),
        include_payload: needPayloadInList ? "1" : "0",
      });
      if (state.afterId) {
        params.set("after_id", state.afterId);
      }
      const data = await apiJson(`/events?${params.toString()}`);

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
        if (state.events.length > MAX_EVENTS_IN_MEMORY) {
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
    setStatus(`sync error: ${e.message}`);
  } finally {
    state.loading = false;
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
  setStatus("selected flow cleared");
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
    const d = new Date(ts || 0);
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    const hh = String(d.getHours()).padStart(2, "0");
    const mi = String(d.getMinutes()).padStart(2, "0");
    const ss = String(d.getSeconds()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
  } catch (_e) {
    return String(ts || 0);
  }
}

function formatDateOnly(ts) {
  try {
    const d = new Date(ts || 0);
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
  } catch (_e) {
    return String(ts || 0);
  }
}

function formatTsShort(ts) {
  try {
    const d = new Date(ts || 0);
    const hh = String(d.getHours()).padStart(2, "0");
    const mi = String(d.getMinutes()).padStart(2, "0");
    const ss = String(d.getSeconds()).padStart(2, "0");
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
    if (bucket.includes(rawText) || bucket.length >= 2) continue;
    bucket.push(rawText);
    grouped.set(rowBase, bucket);
  }
  return new Map(Array.from(grouped.entries(), ([rowBase, bucket]) => [rowBase, bucket.join("\n// ")]));
}

function mergeDumpAnnotationIndexes(...indexes) {
  const merged = new Map();
  for (const index of indexes) {
    if (!(index instanceof Map)) continue;
    for (const [rowBase, text] of index.entries()) {
      const normalized = normalizeDumpAnnotationText(text);
      if (!normalized) continue;
      const previous = normalizeDumpAnnotationText(merged.get(rowBase) || "");
      merged.set(rowBase, previous ? `${previous}\n// ${normalized}` : normalized);
    }
  }
  return merged;
}

function getDumpAnnotationIndex(ev, source) {
  const bytesPerRow = getBytesPerRow();
  const analysis = getEventAnalysis(ev);
  if (!analysis) return new Map();
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
    if (bucket.includes(text) || bucket.length >= 3) continue;
    bucket.push(text);
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

function formatHexDump(base64Text, hideAscii, annotationIndex = null, options = {}) {
  const bytes = b64ToBytes(base64Text);
  const bytesPerRow = getBytesPerRow();
  const groupSizes = getHexGroupSizes(bytesPerRow);
  const groupGap = getGroupGap();
  const compactAscii = !!(options && options.compactAscii);
  const changedOffsets = options && options.changedOffsets instanceof Set ? options.changedOffsets : null;
  const timestampOffsets = buildRangeOffsetSet(options && Array.isArray(options.timestampRanges) ? options.timestampRanges : []);
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
        ascii: "",
        compactAscii,
        comment: annotationIndex instanceof Map ? String(annotationIndex.get(i) || "") : "",
      });
      continue;
    }
    let ascii = chunk.map((v) => (v >= 32 && v <= 126 ? String.fromCharCode(v) : ".")).join("");
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
      ascii,
      compactAscii,
      comment: annotationIndex instanceof Map ? String(annotationIndex.get(i) || "") : "",
    });
  }
  return { header, rows };
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
    offsetInChunk += size;
    const html = bytes
      .map((value, idx) => {
        const hex = value.toString(16).padStart(2, "0");
        if (timestampMarks[idx]) return `<span class="hex-byte-timestamp">${hex}</span>`;
        return marks[idx] ? `<span class="hex-byte-changed">${hex}</span>` : escapeHtml(hex);
      })
      .join(" ");
    const width = Array.isArray(row.groupWidths) ? Number(row.groupWidths[groupIndex]) : size * 3 - 1;
    return html + "&nbsp;".repeat(Math.max(0, width - (bytes.length * 3 - 1)));
  });
  const gap = escapeHtml(String(row.groupGap || "  "));
  return `<span class="hex-bytes">${parts.join(gap)}</span>`;
}

function renderHexBodyHtml(dump, hideAscii) {
  if (!dump || !Array.isArray(dump.rows) || dump.rows.length === 0) {
    return "";
  }
  return dump.rows
    .map((row) => {
      const offsetHtml = `<span class="hex-offset">${escapeHtml(row.offset)}</span>`;
      const hexHtml = renderHexBytesHtml(row);
      if (hideAscii) {
        const commentHtml = row.comment ? ` <span class="hex-comment">// ${escapeHtml(row.comment)}</span>` : "";
        return `${offsetHtml} ${hexHtml}${commentHtml}`;
      }
      const asciiHtml =
        `<span class="hex-ascii-bar">|</span>` +
        `<span class="hex-ascii${row.compactAscii ? " hex-ascii-compact" : ""}">${escapeHtml(row.ascii)}</span>` +
        `<span class="hex-ascii-bar">|</span>`;
      const commentHtml = row.comment ? ` <span class="hex-comment">// ${escapeHtml(row.comment)}</span>` : "";
      return `${offsetHtml} ${hexHtml} ${asciiHtml}${commentHtml}`;
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
  return known[mode] || known.preview_contains;
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
    el.highlightMode ? el.highlightMode.value : "preview_contains",
    el.color ? el.color.value : "#ffd166",
  );
  if (el.prefix) {
    const invalid = draft.invalidCount > 0;
    el.prefix.classList.toggle("input-invalid", invalid);
    if (invalid) {
      el.prefix.title = `Invalid rule count=${draft.invalidCount}. Use: 19 00 00 00 xx 00 00 00 00 xx; 33 66@#8ec5ff`;
    } else {
      el.prefix.title = "Rule format: pattern; pattern@#RRGGBB. Wildcard: xx/??/**. Press Enter or Search to apply.";
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

function isPlausibleTimestampSeconds(value) {
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= TIMESTAMP_SECONDS_MIN && seconds <= TIMESTAMP_SECONDS_MAX;
}

function formatTimestampClock(seconds) {
  if (!Number.isFinite(Number(seconds))) return "";
  try {
    const d = new Date(Number(seconds) * 1000);
    const hh = String(d.getHours()).padStart(2, "0");
    const mi = String(d.getMinutes()).padStart(2, "0");
    const ss = String(d.getSeconds()).padStart(2, "0");
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
  if (lenOffset < 0 || selector1Offset + 3 >= record.length) return null;
  const declaredLen = readBe16(record, lenOffset);
  const normalizedLen = Number.isFinite(declaredLen) && declaredLen > 0 ? declaredLen : record.length - shift;
  return {
    shift,
    len: normalizedLen,
    innerType: readBe16(record, innerTypeOffset),
    selector0: readBe32(record, selector0Offset),
    selector1: readBe32(record, selector1Offset),
  };
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
  for (const offset of shape && Array.isArray(shape.offsets) ? shape.offsets : []) {
    offsets.push(Number(offset));
  }
  const offsetFromEnd = Number(shape && shape.offsetFromEnd);
  if (Number.isFinite(offsetFromEnd) && Number.isFinite(Number(layout && layout.len))) {
    offsets.push(Number(layout.len) - offsetFromEnd);
  }
  return offsets.filter((offset, index, all) => (
    Number.isFinite(offset) && offset >= 0 && all.indexOf(offset) === index
  ));
}

function buildTimestampRange(start, value, label) {
  const seconds = Number(value);
  const clock = formatTimestampClock(seconds);
  const offsetText = formatHexValue(start);
  const kind = String(label || "known");
  return {
    start,
    end: start + 4,
    value: seconds,
    kind,
    text: `时间戳 ${clock || seconds} @${offsetText}`,
  };
}

function collectRecordTimestampRanges(record, baseOffset) {
  if (!Array.isArray(record) || record.length < 0x24) return [];
  const report = detectTssReport(record);
  if (!report || Number(report.value) !== 0x0102000a) return [];

  const layout = read0102000aLayout(record, report);
  const ranges = new Map();
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

function summarizeTimestampHighlights(ranges) {
  const items = Array.isArray(ranges) ? ranges : [];
  if (items.length <= 0) return "";
  const preview = items
    .slice(0, 3)
    .map((item) => {
      const clock = formatTimestampClock(item.value);
      return `${formatHexValue(item.start)}${clock ? ` ${clock}` : ""}`;
    })
    .join(", ");
  return items.length > 3 ? `${preview}, ...x${items.length}` : preview;
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

function extractPrintableRuns(byteValues, minLen = ANALYSIS_ASCII_MIN_LEN, maxItems = ANALYSIS_ASCII_MAX_ITEMS) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return [];
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
    const text = shortenText(item.text, 96);
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

function formatHexSignature(byteValues) {
  if (!Array.isArray(byteValues) || byteValues.length <= 0) return "";
  const head = formatHexBytePreview(byteValues, 16);
  const tail = byteValues.length > 24 ? formatHexBytePreview(byteValues.slice(-8), 8) : "";
  return tail ? `head=${head} tail=${tail}` : `head=${head}`;
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
  const runs = bestChoice.best.runs.map((item) => ({
    off: bodyOff + Number(item.off || 0),
    text: shortenText(item.text, 96),
    kind: inferStringKind(item.text),
  }));
  return {
    ...baseInfo,
    bodyOff,
    key: bestChoice.best.key,
    score: bestChoice.best.score,
    preview: shortenText(runs.map((item) => item.text).join(" | "), 120),
    keywordHits: bestChoice.best.keywordHits,
    runs,
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

function reportName(reportCode) {
  const value = Number(reportCode);
  const names = {
    0x010a001b: "container",
    0x010a0011: "response-linked",
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
  if (report === 0x010a0011) return "protected-response-linked";
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
    const idValue = readBe32(record, childRecordIdOffset(record, report));
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
      idValue,
      className,
      valuePreview,
      timestampCandidates,
      hexSignature: className === "binary-like-leaf" ? formatHexSignature(record) : "",
      xorB6Preview: className === "binary-like-leaf" ? summarizeFixedXor(record, reportCode, 0xb6) : "",
    });
    offset += 4 + childLen;
  }
  return {
    children,
    consumed: offset - Number(startOffset || 0),
    complete: children.length > 0 && offset === byteValues.length,
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
    return { root, children: compactCounted.children, layout: "compact-count-u8" };
  }
  if (!Number.isFinite(childCount) || childCount < 0 || childCount > 256) {
    if (compactCounted.children.length > 0) {
      return { root, children: compactCounted.children, layout: "compact-count-u8-partial" };
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
    const idValue = readBe32(record, childRecordIdOffset(record, report));
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
      idValue,
      className,
      valuePreview,
      timestampCandidates,
      hexSignature: className === "binary-like-leaf" ? formatHexSignature(record) : "",
      xorB6Preview: className === "binary-like-leaf" ? summarizeFixedXor(record, reportCode, 0xb6) : "",
    });
    offset += 4 + childLen;
  }
  if (children.length === 0 && legacy.children.length > 0) {
    return { root, children: legacy.children, layout: "legacy-no-count" };
  }
  return { root, children, layout: "counted" };
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
    const idValue = readBe32(byteValues, childRecordIdOffset(byteValues, root));
    const preview = formatRecordValuePreview(byteValues, root.value);
    const timestampCandidates = extractTimestampCandidatesFromRecord(byteValues);
    lines.push(
      `  node[0] report=${formatHexValue(root.value, 8)} type=${classifyRecordBytes(byteValues, root.value)} len=${byteValues.length}` +
        (Number.isFinite(idValue) ? ` id=${formatHexValue(idValue, 4)}` : "") +
        (timestampCandidates.length > 0 ? ` timestamps=${timestampCandidates.join(",")}` : "")
    );
    if (preview) lines.push(`    value=${preview}`);
    return lines.join("\n");
  }

  lines.push(`child_count=${parsed.children.length}${parsed.layout ? ` layout=${parsed.layout}` : ""}`);
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
    const idText = Number.isFinite(child.idValue) ? ` id=${formatHexValue(child.idValue, 4)}` : "";
    const keepText = child.reportCode === 0x010a0011 ? " keep=target" : "";
    const tsText = Array.isArray(child.timestampCandidates) && child.timestampCandidates.length > 0
      ? ` timestamps=${child.timestampCandidates.join(",")}`
      : "";
    const sameLenCount = sameLenExamples.get(`child:${child.index}`);
    const sameLenText = Number.isFinite(sameLenCount) ? ` lib_same_len=${sameLenCount}` : "";
    lines.push(
      `  child[${child.index}] off=${formatHexValue(child.offset)} report=${reportText} type=${child.className} len=${child.len}${idText}${keepText}${tsText}${sameLenText}`
    );
    if (child.valuePreview) {
      lines.push(`    value=${child.valuePreview}`);
    }
    if (child.hexSignature) {
      lines.push(`    hex_sig=${child.hexSignature}`);
    }
    if (child.xorB6Preview) {
      lines.push(`    xor_b6=${child.xorB6Preview}`);
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
        /(root|child_count|binary_like_stats|child\[\d+\]|report=0x[0-9a-f]+|type=[^\s]+|len=\d+|id=0x[0-9a-f]+|keep=target|timestamps=[^\s]+|lib_same_len=\d+|value=.+|hex_sig=.+|xor_b6=.+)/gi,
        (token) => {
          let cls = "tree-token";
          if (/^child\[/i.test(token) || token === "root" || token === "binary_like_stats") cls += " tree-node";
          else if (/^report=/i.test(token)) cls += " tree-report";
          else if (/^type=/i.test(token)) cls += " tree-type";
          else if (/^id=/i.test(token)) cls += " tree-id";
          else if (/^value=/i.test(token)) cls += " tree-value";
          else if (/^(hex_sig|xor_b6|timestamps)=/i.test(token)) cls += " tree-value";
          else if (/^lib_same_len=/i.test(token)) cls += " tree-keep";
          else if (/^keep=/i.test(token)) cls += " tree-keep";
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

function buildTreeCompareRow(beforeBase64, decodedBase64, summaryText = "") {
  if (!beforeBase64 && !decodedBase64) return null;
  const sameLenExamples = parseLibrarySameLengthExamples(summaryText);
  const row = document.createElement("section");
  row.className = "tree-compare-row";

  const before = document.createElement("div");
  before.className = "tree-compare-panel tree-compare-before";
  const beforeTree = beforeBase64
    ? createTssTreeSummary("修改前解析 / child tree", beforeBase64, "tree-shell-compare", { sameLenExamples })
    : null;
  if (beforeTree) {
    before.appendChild(beforeTree);
  } else {
    const empty = document.createElement("div");
    empty.className = "dump-empty tree-compare-empty";
    empty.textContent = "修改前没有可解析 child tree。";
    before.appendChild(empty);
  }

  const after = document.createElement("div");
  after.className = "tree-compare-panel tree-compare-after";
  const afterTree = decodedBase64
    ? createTssTreeSummary("修改后/当前解析 / child tree", decodedBase64, "tree-shell-compare", { sameLenExamples })
    : null;
  if (afterTree) {
    after.appendChild(afterTree);
  } else {
    const empty = document.createElement("div");
    empty.className = "dump-empty tree-compare-empty";
    empty.textContent = "修改后/当前没有可解析 child tree。";
    after.appendChild(empty);
  }

  row.appendChild(before);
  row.appendChild(after);
  return row;
}

function getEventAnalysis(ev) {
  const summaryText = String(ev && ev.summary ? ev.summary : "").trim();
  if (!summaryText) {
    return null;
  }
  const cacheKey = `${getEventId(ev)}|${String(ev?.summary || "")}|${String(ev?.pay || "").length}|${String(ev?.full_pay || "").length}`;
  if (ev && ev.__tcpvAnalysisKey === cacheKey && ev.__tcpvAnalysis) {
    return ev.__tcpvAnalysis;
  }
  const decodedBytes = b64ToBytes(String(ev && ev.pay ? ev.pay : ""));
  const fullBytes = b64ToBytes(String(ev && ev.full_pay ? ev.full_pay : ""));
  const summary = parseTssSummary(ev && ev.summary ? ev.summary : "");
  const decodedStrings = extractPrintableRuns(decodedBytes, ANALYSIS_ASCII_MIN_LEN, ANALYSIS_ASCII_MAX_ITEMS);
  const decodedUtf8Strings = extractUtf8Runs(decodedBytes, ANALYSIS_UTF8_MIN_CHARS, ANALYSIS_UTF8_MAX_ITEMS);
  const decodedBase64Strings = extractBase64DecodedRuns(decodedBytes, ANALYSIS_BASE64_MAX_ITEMS);
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
    summary,
    decodedStrings,
    decodedUtf8Strings,
    decodedBase64Strings,
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

function appendAnalysisHint(container, text) {
  const note = document.createElement("div");
  note.className = "analysis-note";
  note.textContent = text;
  container.appendChild(note);
}

function buildEventAnalysisGrid(ev) {
  const analysis = getEventAnalysis(ev);
  if (!analysis) return null;

  const grid = document.createElement("div");
  grid.className = "analysis-grid";

  const metaCard = createAnalysisCard("解密概览", "analysis-card-meta");
  const metaChips = document.createElement("div");
  metaChips.className = "analysis-chip-list";
  const summary = analysis.summary;
  const metaChipValues = [];
  if (summary) {
    if (summary.code) metaChipValues.push(`code ${summary.code}`);
    if (summary.role) metaChipValues.push(`role ${summary.role}`);
    if (summary.hint) metaChipValues.push(`hint ${summary.hint}`);
    if (summary.family) metaChipValues.push(`family ${summary.family}`);
    if (summary.slot) metaChipValues.push(`slot ${summary.slot}`);
    if (Number.isFinite(summary.sliceOffset)) metaChipValues.push(`slice ${formatHexValue(summary.sliceOffset)}`);
    if (Number.isFinite(summary.beforedumpLen)) metaChipValues.push(`len ${summary.beforedumpLen}`);
    if (summary.score) metaChipValues.push(`score ${summary.score}`);
    if (summary.referenceLevel) metaChipValues.push(`ref ${summary.referenceLevel}`);
    if (summary.lead) metaChipValues.push(`lead ${summary.lead}`);
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
    appendAnalysisEmpty(metaCard.body, "当前包没有结构化摘要，仍可直接看下方原始封包和当前解密内容。");
  }
  grid.appendChild(metaCard.card);

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
  } else {
    appendAnalysisEmpty(xorCard.body, "当前切片没有命中明显的单字节 XOR 文本特征。");
  }
  grid.appendChild(xorCard.card);

  return grid;
}

function buildEventBody(ev, hideAscii, eventId = "") {
  const body = document.createElement("div");
  body.className = "body";

  const meta = document.createElement("div");
  meta.className = "meta";
  const metaParts = [`id=${ev.id}`];
  const proxyUsername = getProxyUsername(ev && ev.proxy_username);
  if (proxyUsername) {
    metaParts.push(`kp=${proxyUsername}`);
  }
  const summaryText = String(ev && ev.summary ? ev.summary : "").trim();
  if (summaryText) {
    metaParts.push(summaryText);
  } else {
    metaParts.push(`cid=${stripDecoratorsFromCid(ev && ev.cid)}`);
  }
  metaParts.push(`seq=${ev.seq}`);
  metaParts.push(`msg_idx=${ev.msg_idx}`);
  metaParts.push(`chunk_idx=${ev.chunk_idx}`);
  meta.textContent = metaParts.join(" ");
  body.appendChild(meta);

  const fullPay = String(ev && ev.full_pay ? ev.full_pay : "");
  const beforePay = String(ev && ev.before_pay ? ev.before_pay : "");
  const decodedPay = String(ev && ev.pay ? ev.pay : "");
  const hasFullDump = !!fullPay;
  const hasBeforeDump = !!beforePay;
  const hasDecodedDump = !!decodedPay;
  const fullDumpSameAsDecoded = hasFullDump && hasDecodedDump && fullPay === decodedPay;
  const beforeDumpSameAsDecoded = hasBeforeDump && hasDecodedDump && beforePay === decodedPay;
  const isRequest = Number(ev && ev.dir) === 0;
  const decodedChangedOffsets = hasBeforeDump && hasDecodedDump
    ? buildChangedOffsetSet(beforePay, decodedPay)
    : null;

  const dumpGrid = document.createElement("div");
  dumpGrid.className = `dump-grid ${isRequest ? "dump-grid-request" : "dump-grid-response"}`;
  body.appendChild(dumpGrid);

  function appendDumpSection(title, base64Text, lengthValue, toneClass, sourceKey, dumpOptions = {}) {
    if (!base64Text) return;
    const panel = document.createElement("section");
    panel.className = `dump-panel ${toneClass || ""}`.trim();
    const timestampHighlights =
      sourceKey === "full" ? [] : collectTimestampHighlightsForPayload(base64Text);
    const timestampSummary = summarizeTimestampHighlights(timestampHighlights);

    const sectionTitle = document.createElement("div");
    sectionTitle.className = "dump-label";
    sectionTitle.appendChild(
      document.createTextNode(
        Number.isFinite(Number(lengthValue))
          ? `${title} [len=${Number(lengthValue)}]`
          : title
      )
    );
    if (timestampHighlights.length > 0) {
      const timestampChip = document.createElement("span");
      timestampChip.className = "dump-label-note dump-label-timestamp";
      timestampChip.textContent = `时间戳×${timestampHighlights.length}`;
      timestampChip.title = timestampSummary;
      sectionTitle.appendChild(timestampChip);
    }
    panel.appendChild(sectionTitle);

    const annotationIndex = mergeDumpAnnotationIndexes(
      getDumpAnnotationIndex(ev, sourceKey),
      buildTimestampAnnotationIndex(timestampHighlights, getBytesPerRow())
    );
    const dump = formatHexDump(base64Text, hideAscii, annotationIndex, {
      compactAscii: sourceKey === "full",
      changedOffsets: dumpOptions.changedOffsets || null,
      timestampRanges: timestampHighlights,
    });
    const hexShell = document.createElement("div");
    hexShell.className = "hex-shell";
    attachDumpScrollPersistence(hexShell, makeDumpScrollKey(eventId, toneClass, title));
    const hexHead = document.createElement("div");
    hexHead.className = "hex-head";
    hexHead.textContent = dump.header;
    const pre = document.createElement("pre");
    pre.className = "hex-body";
    pre.innerHTML = renderHexBodyHtml(dump, hideAscii);

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
      appendDumpSection("原始封包 [raw]", fullPay, ev.full_len, "dump-panel-full", "full");
    } else {
      appendEmptyDumpSection("原始封包 [raw]", "当前事件没有 full_pay，无法显示完整原始封包。", "dump-panel-full");
    }
    if (hasBeforeDump) {
      appendDumpSection("修改前解密 [before]", beforePay, ev.before_len, "dump-panel-before", "before", {
        changedOffsets: decodedChangedOffsets,
      });
    } else {
      appendEmptyDumpSection(
        "修改前解密 [before missing]",
        "当前事件没有 before_pay；通常是未经过仿生改写、旧事件、或该包只记录了当前解密片段。",
        "dump-panel-before"
      );
    }
    if (hasDecodedDump) {
      const decodedTitle = hasBeforeDump
        ? beforeDumpSameAsDecoded
          ? "修改后解密 [after same]"
          : "修改后解密 [after]"
        : "当前解密 [current]";
      appendDumpSection(
        decodedTitle,
        decodedPay,
        ev.len,
        "dump-panel-decoded",
        "decoded",
        { changedOffsets: decodedChangedOffsets }
      );
    } else {
      appendEmptyDumpSection("修改后解密 [after missing]", "当前事件没有 pay，无法显示修改后/当前解密内容。", "dump-panel-decoded");
    }
  } else if (hasFullDump && !fullDumpSameAsDecoded) {
    appendDumpSection("响应原始封包 [raw]", fullPay, ev.full_len, "dump-panel-full", "full");
    appendDumpSection("响应解密 [decoded]", decodedPay, ev.len, "dump-panel-decoded", "decoded");
  } else if (hasDecodedDump) {
    appendDumpSection("响应解密 [decoded]", decodedPay, ev.len, "dump-panel-decoded", "decoded");
  } else {
    appendDumpSection("响应封包 [raw]", fullPay, ev.full_len, "dump-panel-single", "full");
  }

  if (isRequest && (hasBeforeDump || hasDecodedDump)) {
    const treeRow = buildTreeCompareRow(beforePay, decodedPay, summaryText);
    if (treeRow) {
      body.appendChild(treeRow);
    }
  } else if (!isRequest && hasDecodedDump) {
    const treeRow = buildTreeCompareRow("", decodedPay, summaryText);
    if (treeRow) {
      body.appendChild(treeRow);
    }
  }

  const analysisGrid = buildEventAnalysisGrid(ev);
  if (analysisGrid) {
    body.appendChild(analysisGrid);
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
  if (detail.pfx) ev.pfx = String(detail.pfx);
  if (detail.cid) ev.cid = String(detail.cid);
  if (detail.proxy_username !== undefined) ev.proxy_username = String(detail.proxy_username || "");
  if (detail.summary !== undefined) ev.summary = String(detail.summary || "");

  const seqNum = Number(detail.seq);
  if (Number.isFinite(seqNum)) ev.seq = seqNum;
  const msgIdx = Number(detail.msg_idx);
  if (Number.isFinite(msgIdx)) ev.msg_idx = msgIdx;
  const chunkIdx = Number(detail.chunk_idx);
  if (Number.isFinite(chunkIdx)) ev.chunk_idx = chunkIdx;

  ev.__tcpvPreviewCacheKey = "";
  ev.__tcpvPreviewInfo = null;
  ev.__tcpvPayloadLen = undefined;
  return true;
}

async function ensureEventPayload(ev, account, eventId) {
  if (!ev || typeof ev !== "object") {
    throw new Error("invalid event object");
  }
  const hasPayload = !!String(ev.pay || "");
  const isRequest = Number(ev.dir) === 0;
  const needsFullPayload = !String(ev.full_pay || "");
  const needsBeforePayload = isRequest && !String(ev.before_pay || "") && !ev.__tcpvPayloadDetailFetched;
  if (hasPayload && !needsFullPayload && !needsBeforePayload) {
    return ev;
  }

  const accountText = String(account || "").trim();
  const idText = String(eventId || "").trim();
  if (!accountText || !idText) {
    throw new Error("invalid event id");
  }

  const cached = readPayloadCache(accountText, idText);
  const cachedHasNeededBefore = !needsBeforePayload || !!String(cached && cached.before_pay ? cached.before_pay : "");
  if (cached && cachedHasNeededBefore && applyEventPayloadDetail(ev, cached)) {
    ev.__tcpvPayloadDetailFetched = true;
    return ev;
  }

  const detail = needsBeforePayload ? await apiGetEvent(accountText, idText) : await fetchEventPayload(accountText, idText);
  if (!applyEventPayloadDetail(ev, detail)) {
    throw new Error("event payload is empty");
  }
  writePayloadCache(accountText, idText, detail);
  ev.__tcpvPayloadDetailFetched = true;
  return ev;
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
  const modeSpec = parseHighlightMode(state.search.mode || "preview_contains");
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
  const out = new Set();
  if (!Array.isArray(visibleEvents) || visibleEvents.length <= 0) return out;
  if (state.autoRefresh) return out;

  let count = 0;
  if (expandMode === "on") {
    count = AUTO_EXPAND_ON_COUNT;
  } else if (expandMode === "smart") {
    count = AUTO_EXPAND_SMART_COUNT;
  }
  if (count <= 0) return out;

  for (let i = visibleEvents.length - 1; i >= 0 && out.size < count; i--) {
    const ev = visibleEvents[i];
    if (!String(ev && ev.summary ? ev.summary : "").trim()) {
      continue;
    }
    const eventId = getEventId(ev);
    if (!eventId || state.collapsedIds.has(eventId)) continue;
    out.add(eventId);
  }
  return out;
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
  const hideAscii = el.hideAscii.value === "1";
  const modeSpec = parseHighlightMode(state.search.mode || "preview_contains");
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
  if (!needFullScan && !state.search.active) {
    const renderLimit = state.autoRefresh ? MAX_RENDER_EVENTS_AUTO : MAX_RENDER_EVENTS_MANUAL;
    if (filteredEvents.length > renderLimit) {
      visibleEvents = filteredEvents.slice(-renderLimit);
    }
  }
  const autoExpandIds = collectAutoExpandIds(visibleEvents, expandMode);
  state.filteredCount = visibleEvents.length;
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

  const listFrag = document.createDocumentFragment();
  const nextHitEventIds = [];
  let windowPrefetchBudget = state.autoRefresh ? WINDOW_PREFETCH_BUDGET_AUTO : WINDOW_PREFETCH_BUDGET_MANUAL;

  for (const ev of visibleEvents) {
    const wrap = document.createElement("details");
    const eventId = getEventId(ev);
    if (!needFullScan && !state.expandedIds.has(eventId)) {
      ev.pay = "";
    }
    wrap.dataset.eventId = eventId;
    wrap.className = ev.dir === 0 ? "event-req" : "event-resp";
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
    previewWrap.appendChild(document.createTextNode("]"));
    summary.appendChild(previewWrap);

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
        syncSummaryTimestampBadge(summary, ev);
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
          if (!needFullScan) {
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
      if (state.flowId && state.events.length === 0) {
        await selectFlow(state.flowId);
      }
    }

    if (state.autoRefresh && state.flowId) {
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

if (el.deleteFlow) {
  el.deleteFlow.addEventListener("click", async () => {
    try {
      await clearCurrentFlow();
    } catch (e) {
      setStatus(`delete flow error: ${e.message}`);
    }
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
