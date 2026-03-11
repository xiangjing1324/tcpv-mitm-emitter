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
  highlightMode: document.getElementById("highlightMode"),
  color: document.getElementById("ruleColor"),
  hideAscii: document.getElementById("hideAscii"),
  previewBytes: document.getElementById("previewBytes"),
  previewSpace: document.getElementById("previewSpace"),
  bodyTone: document.getElementById("bodyTone"),
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

function loadRules() {
  el.prefix.value = localStorage.getItem("tcpv_rule_prefix") || "";
  if (el.highlightMode) {
    el.highlightMode.value = localStorage.getItem("tcpv_highlight_mode") || "preview_contains";
  }
  el.color.value = localStorage.getItem("tcpv_rule_color") || "#ffd166";
  el.hideAscii.value = localStorage.getItem("tcpv_hide_ascii") || "0";
  el.previewBytes.value = localStorage.getItem("tcpv_preview_bytes") || "32";
  if (el.previewSpace) {
    el.previewSpace.value = localStorage.getItem("tcpv_preview_space") || "1";
  }
  if (el.bodyTone) {
    el.bodyTone.value = localStorage.getItem("tcpv_body_tone") || "slate";
  }
  el.autoRefresh.value = localStorage.getItem("tcpv_auto_refresh") || "1";
  el.themeMode.value = localStorage.getItem("tcpv_theme_mode") || "github-dark";

  state.autoRefresh = el.autoRefresh.value === "1";
  state.themeMode = el.themeMode.value;
  applyTheme();
  applyBodyTone();

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
  localStorage.setItem("tcpv_hide_ascii", el.hideAscii.value);
  localStorage.setItem("tcpv_preview_bytes", el.previewBytes.value);
  if (el.previewSpace) {
    localStorage.setItem("tcpv_preview_space", el.previewSpace.value || "1");
  }
  if (el.bodyTone) {
    localStorage.setItem("tcpv_body_tone", el.bodyTone.value || "slate");
  }
  localStorage.setItem("tcpv_auto_refresh", el.autoRefresh.value);
  localStorage.setItem("tcpv_theme_mode", el.themeMode.value);
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

function extractAccountInfoFromCid(cidText) {
  const cid = String(cidText || "");
  const match = cid.match(/\[acc:([^\]]+)\]/i);
  return match ? String(match[1] || "").trim() : "";
}

function stripAccountInfoFromCid(cidText) {
  return String(cidText || "").replace(/\s*\[acc:[^\]]+\]/gi, "").trim();
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
  const cid = stripAccountInfoFromCid(rawCid);
  const accountInfo = extractAccountInfoFromCid(rawCid);
  const accountBadge = accountInfo ? ` [acc:${accountInfo}]` : "";
  if (cid) return `${cid}${accountBadge}`;
  if (accountBadge) return accountBadge.trim();
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
  const cid = stripAccountInfoFromCid(rawCid);
  const accountInfo = extractAccountInfoFromCid(rawCid);
  const accountText = accountInfo ? `[acc:${accountInfo}]` : "";
  const text = cid ? `${accountText} ${cid}`.trim() : accountText;
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
  renderFlowList();
  renderSelectedTitle();
  await syncLatestEvents();
}

async function syncLatestEvents() {
  if (!state.flowId || state.loading) return;
  state.loading = true;

  try {
    const params = new URLSearchParams({ account: state.flowId, limit: "400" });
    if (state.afterId) {
      params.set("after_id", state.afterId);
    }
    const data = await apiJson(`/events?${params.toString()}`);

    const rows = Array.isArray(data.events) ? data.events : [];
    if (rows.length > 0) {
      state.events.push(...rows);
      if (state.events.length > 8000) {
        state.events = state.events.slice(-8000);
      }
      renderEvents();
    } else if (state.events.length === 0) {
      renderEvents();
    }

    state.afterId = data.last_id || state.afterId;
    state.hasMore = !!data.has_more;
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
  return [16, 24, 32, 48, 64, 80].includes(raw) ? raw : 32;
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
    preview_contains: { scope: "preview", mode: "contains" },
    preview_prefix: { scope: "preview", mode: "prefix" },
    preview_exact: { scope: "preview", mode: "exact" },
    full_contains: { scope: "full", mode: "contains" },
    full_prefix: { scope: "full", mode: "prefix" },
    full_exact: { scope: "full", mode: "exact" },
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

function clipRangesToLength(ranges, maxLen) {
  if (!Array.isArray(ranges) || ranges.length === 0) return [];
  const clipped = [];
  for (const r of ranges) {
    const start = Math.max(0, Number(r.start || 0));
    const end = Math.min(maxLen, Number(r.end || 0));
    if (end <= start) continue;
    clipped.push({ start, end, color: r.color || "" });
  }
  return clipped;
}

function renderPreviewBytes(previewSpan, byteValues, highlightRanges) {
  if (!previewSpan) return;
  previewSpan.textContent = "";
  if (!Array.isArray(byteValues) || byteValues.length === 0) return;

  const gap16 = usePreviewSpace();
  const colorByIndex = new Array(byteValues.length).fill("");
  if (Array.isArray(highlightRanges) && highlightRanges.length > 0) {
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

function getPreviewInfo(ev) {
  const previewLen = getBytesPerRow();
  const payloadBytes = b64ToBytes(ev.pay);
  let previewBytes = [];
  if (payloadBytes.length > 0) {
    previewBytes = payloadBytes.slice(0, previewLen);
  } else {
    const fallback = normalizeHex(ev.pfx || "");
    previewBytes = (fallback.match(/.{1,2}/g) || []).slice(0, previewLen).map((x) => parseInt(x, 16));
  }
  return { payloadBytes, previewBytes };
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
  meta.textContent = `id=${ev.id} cid=${ev.cid} seq=${ev.seq} msg_idx=${ev.msg_idx} chunk_idx=${ev.chunk_idx}`;
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
  const modeSpec = parseHighlightMode(el.highlightMode ? el.highlightMode.value : "preview_contains");
  const parsedRules = parseHighlightRules(el.prefix.value || "", el.color.value);
  if (el.prefix) {
    const invalid = parsedRules.invalidCount > 0;
    el.prefix.classList.toggle("input-invalid", invalid);
    if (invalid) {
      el.prefix.title = `Invalid rule count=${parsedRules.invalidCount}. Use: 19 00 00 00 xx 00 00 00 00 xx; 33 66@#8ec5ff`;
    } else {
      el.prefix.title = "Rule format: pattern; pattern@#RRGGBB. Wildcard: xx/??/**. Press Esc to clear.";
    }
  }
  const highlightRules = parsedRules.rules;

  if (!state.flowId) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "Select a flow on the left.";
    el.events.appendChild(empty);
    return;
  }

  if (state.events.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No packets yet for selected flow.";
    el.events.appendChild(empty);
    return;
  }

  const listFrag = document.createDocumentFragment();
  for (const ev of state.events) {
    const wrap = document.createElement("details");
    const eventId = getEventId(ev);
    wrap.dataset.eventId = eventId;
    wrap.className = ev.dir === 0 ? "event-req" : "event-resp";
    if (state.expandedIds.has(eventId)) {
      wrap.open = true;
    }

    const summary = document.createElement("summary");
    const isReq = ev.dir === 0;
    const dirArrow = isReq ? "->" : "<-";
    const preview = getPreviewInfo(ev);
    const frag = ev.msg_idx >= 0 && ev.chunk_idx >= 0 ? `m${ev.msg_idx}/c${ev.chunk_idx}` : "m-/c-";
    const seqNum = Number(ev.seq || 0);
    const seqText = Number.isFinite(seqNum) && seqNum > 0 ? `#${seqNum}` : "#-";

    const matchTarget =
      modeSpec.scope === "full"
        ? (preview.payloadBytes.length > 0
          ? preview.payloadBytes.slice(0, MAX_FULL_SCAN_BYTES)
          : preview.previewBytes)
        : preview.previewBytes;
    const matchRanges = mergeRuleMatches(matchTarget, highlightRules, modeSpec.mode, 24);
    const previewRanges =
      modeSpec.scope === "full"
        ? clipRangesToLength(matchRanges, preview.previewBytes.length)
        : matchRanges;
    const hasOutOfPreviewMatch =
      modeSpec.scope === "full" &&
      matchRanges.some((r) => Number(r.start || 0) >= preview.previewBytes.length);

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
    previewWrap.appendChild(document.createTextNode("["));
    const previewSpan = document.createElement("span");
    previewSpan.className = "preview-hex";
    renderPreviewBytes(previewSpan, preview.previewBytes, previewRanges);
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
    const ensureBody = () => {
      if (wrap.dataset.bodyReady === "1") return;
      wrap.appendChild(buildEventBody(ev, hideAscii));
      wrap.dataset.bodyReady = "1";
    };
    if (wrap.open) {
      ensureBody();
    }
    wrap.addEventListener("toggle", () => {
      if (!eventId) return;
      if (wrap.open) {
        state.expandedIds.add(eventId);
        ensureBody();
      } else {
        state.expandedIds.delete(eventId);
      }
    });

    listFrag.appendChild(wrap);
  }
  el.events.appendChild(listFrag);
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

    const line = `emit=${s.emit_count} write=${s.write_count} err=${s.write_error_count} drop=${s.dropped_count} q=${s.queue_size} local=${state.events.length}`;
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
  renderEvents();
});

el.prefix.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") {
    el.prefix.value = "";
    saveRules();
    renderEvents();
    ev.preventDefault();
  }
});

if (el.highlightMode) {
  el.highlightMode.addEventListener("change", () => {
    saveRules();
    renderEvents();
  });
}

el.color.addEventListener("input", () => {
  saveRules();
  renderEvents();
});

el.hideAscii.addEventListener("change", () => {
  saveRules();
  renderEvents();
});

el.previewBytes.addEventListener("change", () => {
  saveRules();
  renderEvents();
});

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
