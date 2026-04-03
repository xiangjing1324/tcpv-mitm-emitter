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
const MAX_EVENTS_IN_MEMORY = 5000;
const EVENTS_FETCH_LIMIT = 200;
const PREVIEW_OFFSET_MAX = 4096;
const PAYLOAD_PREFETCH_DELAY_MS = 220;
const PAYLOAD_CACHE_MAX_ENTRIES = 24;
const PAYLOAD_CACHE_MAX_BYTES = 6 * 1024 * 1024;
const WINDOW_PREFETCH_BUDGET_AUTO = 8;
const WINDOW_PREFETCH_BUDGET_MANUAL = 24;

const payloadCache = new Map();
const payloadInFlight = new Map();
let payloadCacheBytes = 0;
let previewOffsetRenderTimer = 0;

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
      pfx: String(normalized.pfx || ""),
      cid: String(normalized.cid || ""),
      proxy_username: String(normalized.proxy_username || ""),
      seq: Number.isFinite(Number(normalized.seq)) ? Number(normalized.seq) : undefined,
      msg_idx: Number.isFinite(Number(normalized.msg_idx)) ? Number(normalized.msg_idx) : undefined,
      chunk_idx: Number.isFinite(Number(normalized.chunk_idx)) ? Number(normalized.chunk_idx) : undefined,
    },
    size: pay.length,
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
  el.previewBytes.value = localStorage.getItem("tcpv_preview_bytes") || "32";
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
    el.expandMode.value = localStorage.getItem("tcpv_expand_mode") || "smart";
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
  return usePreviewSpace() ? "  " : " ";
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
  state.events = [];
  state.afterId = null;
  state.hasMore = true;
  state.expandedIds.clear();
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
  state.expandedIds.clear();
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
  return [16, 24, 32, 48, 64, 80, 96, 128].includes(raw) ? raw : 32;
}

function formatHexDump(base64Text, hideAscii) {
  const bytes = b64ToBytes(base64Text);
  const bytesPerRow = getBytesPerRow();
  const groupSizes = getHexGroupSizes(bytesPerRow);
  const groupGap = getGroupGap();
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
  const header = hideAscii ? headerCore : `${headerCore}  |ascii|`;
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
    if (hideAscii) {
      rows.push({ offset, hex: hexPadded, ascii: "" });
      continue;
    }
    const ascii = chunk.map((v) => (v >= 32 && v <= 126 ? String.fromCharCode(v) : ".")).join("");
    rows.push({ offset, hex: hexPadded, ascii });
  }
  return { header, rows };
}

function renderHexBodyHtml(dump, hideAscii) {
  if (!dump || !Array.isArray(dump.rows) || dump.rows.length === 0) {
    return "";
  }
  return dump.rows
    .map((row) => {
      const offsetHtml = `<span class="hex-offset">${escapeHtml(row.offset)}</span>`;
      const hexHtml = `<span class="hex-bytes">${escapeHtml(row.hex)}</span>`;
      if (hideAscii) {
        return `${offsetHtml}  ${hexHtml}`;
      }
      const asciiHtml =
        `<span class="hex-ascii-bar">|</span>` +
        `<span class="hex-ascii">${escapeHtml(row.ascii)}</span>` +
        `<span class="hex-ascii-bar">|</span>`;
      return `${offsetHtml}  ${hexHtml}  ${asciiHtml}`;
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

function buildEventBody(ev, hideAscii) {
  const body = document.createElement("div");
  body.className = "body";

  const meta = document.createElement("div");
  meta.className = "meta";
  const metaParts = [`id=${ev.id}`];
  const proxyUsername = getProxyUsername(ev && ev.proxy_username);
  if (proxyUsername) {
    metaParts.push(`kp=${proxyUsername}`);
  }
  metaParts.push(`cid=${stripDecoratorsFromCid(ev && ev.cid)}`);
  metaParts.push(`seq=${ev.seq}`);
  metaParts.push(`msg_idx=${ev.msg_idx}`);
  metaParts.push(`chunk_idx=${ev.chunk_idx}`);
  meta.textContent = metaParts.join(" ");
  body.appendChild(meta);

  const dump = formatHexDump(ev.pay, hideAscii);
  const hexShell = document.createElement("div");
  hexShell.className = "hex-shell";
  const hexHead = document.createElement("div");
  hexHead.className = "hex-head";
  hexHead.textContent = dump.header;
  const pre = document.createElement("pre");
  pre.className = "hex-body";
  pre.innerHTML = renderHexBodyHtml(dump, hideAscii);

  hexShell.appendChild(hexHead);
  hexShell.appendChild(pre);
  body.appendChild(hexShell);

  return body;
}

function applyEventPayloadDetail(ev, detail) {
  if (!ev || typeof ev !== "object") return false;
  if (!detail || typeof detail !== "object") return false;

  const pay = String(detail.pay || "");
  if (!pay) return false;
  ev.pay = pay;
  if (detail.pfx) ev.pfx = String(detail.pfx);
  if (detail.cid) ev.cid = String(detail.cid);
  if (detail.proxy_username !== undefined) ev.proxy_username = String(detail.proxy_username || "");

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
  if (String(ev.pay || "")) {
    return ev;
  }

  const accountText = String(account || "").trim();
  const idText = String(eventId || "").trim();
  if (!accountText || !idText) {
    throw new Error("invalid event id");
  }

  const cached = readPayloadCache(accountText, idText);
  if (cached && applyEventPayloadDetail(ev, cached)) {
    return ev;
  }

  const detail = await fetchEventPayload(accountText, idText);
  if (!applyEventPayloadDetail(ev, detail)) {
    throw new Error("event payload is empty");
  }
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

function renderEvents() {
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
  const flowHasTruncatedPayload = state.events.some((ev) => {
    const fullLen = Number(ev && ev.len);
    if (!Number.isFinite(fullLen) || fullLen <= 0) return false;
    const payloadLen = estimatePayloadByteLen(ev);
    if (payloadLen <= 0) return false;
    return fullLen > payloadLen;
  });
  const flowExpandLocked = expandMode === "off" || (expandMode === "smart" && flowHasTruncatedPayload);
  if (flowExpandLocked) {
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

  const visibleEvents = state.events.filter((ev) => eventMatchesFilters(ev));
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
  const needFullScan = state.search.active && modeSpec.scope === "full";
  let windowPrefetchBudget = state.autoRefresh ? WINDOW_PREFETCH_BUDGET_AUTO : WINDOW_PREFETCH_BUDGET_MANUAL;

  for (const ev of visibleEvents) {
    const wrap = document.createElement("details");
    const eventId = getEventId(ev);
    if (!needFullScan && !state.expandedIds.has(eventId)) {
      ev.pay = "";
    }
    const allowExpand = !flowExpandLocked;
    wrap.dataset.eventId = eventId;
    wrap.className = ev.dir === 0 ? "event-req" : "event-resp";
    if (allowExpand && state.expandedIds.has(eventId)) {
      wrap.open = true;
    }
    if (!allowExpand) {
      wrap.classList.add("no-expand");
    }

    const summary = document.createElement("summary");
    if (!allowExpand) {
      summary.dataset.noExpandLabel = expandMode === "off" ? "expand-off" : "preview-only";
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
        if (loading.isConnected) loading.remove();
        wrap.appendChild(buildEventBody(ev, hideAscii));
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
          ensureBody().catch((_e) => {});
        } else {
          clearPrefetch();
          state.expandedIds.delete(eventId);
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
      `ofs=${getPreviewOffset()}` +
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
