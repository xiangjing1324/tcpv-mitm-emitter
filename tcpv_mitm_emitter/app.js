const state = {
  account: "",
  connection: "",
  afterId: null,
  hasMore: true,
  events: [],
  loading: false,
  autoRefresh: true,
  themeMode: "dark",
  tick: 0,
  expandedIds: new Set(),
};

const el = {
  account: document.getElementById("accountSelect"),
  conn: document.getElementById("connSelect"),
  prefix: document.getElementById("prefixRule"),
  color: document.getElementById("ruleColor"),
  hideAscii: document.getElementById("hideAscii"),
  previewBytes: document.getElementById("previewBytes"),
  previewSpace: document.getElementById("previewSpace"),
  autoRefresh: document.getElementById("autoRefresh"),
  themeMode: document.getElementById("themeMode"),
  reload: document.getElementById("reloadBtn"),
  more: document.getElementById("moreBtn"),
  events: document.getElementById("events"),
  status: document.getElementById("status"),
};

const systemThemeQuery = window.matchMedia
  ? window.matchMedia("(prefers-color-scheme: dark)")
  : null;

function resolveThemeMode(mode) {
  const normalized = String(mode || "").toLowerCase();
  if (normalized === "dark" || normalized === "light") {
    return normalized;
  }
  return systemThemeQuery && systemThemeQuery.matches ? "dark" : "light";
}

function applyTheme() {
  const resolved = resolveThemeMode(state.themeMode);
  document.documentElement.setAttribute("data-theme", resolved);
}

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

async function apiJson(url) {
  const resp = await fetch(url, { cache: "no-store" });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`HTTP ${resp.status} ${resp.statusText}: ${body.slice(0, 200)}`);
  }
  return resp.json();
}

function loadRules() {
  el.prefix.value = localStorage.getItem("tcpv_rule_prefix") || "";
  el.color.value = localStorage.getItem("tcpv_rule_color") || "#ffd166";
  el.hideAscii.value = localStorage.getItem("tcpv_hide_ascii") || "0";
  el.previewBytes.value = localStorage.getItem("tcpv_preview_bytes") || "16";
  el.previewSpace.value = localStorage.getItem("tcpv_preview_space") || "0";
  el.autoRefresh.value = localStorage.getItem("tcpv_auto_refresh") || "1";
  el.themeMode.value = localStorage.getItem("tcpv_theme_mode") || "dark";
  state.autoRefresh = el.autoRefresh.value === "1";
  state.themeMode = el.themeMode.value;
  applyTheme();
}

function saveRules() {
  localStorage.setItem("tcpv_rule_prefix", (el.prefix.value || "").trim().toLowerCase());
  localStorage.setItem("tcpv_rule_color", el.color.value);
  localStorage.setItem("tcpv_hide_ascii", el.hideAscii.value);
  localStorage.setItem("tcpv_preview_bytes", el.previewBytes.value);
  localStorage.setItem("tcpv_preview_space", el.previewSpace.value);
  localStorage.setItem("tcpv_auto_refresh", el.autoRefresh.value);
  localStorage.setItem("tcpv_theme_mode", el.themeMode.value);
}

async function loadAccounts(resetSelection = false) {
  const raw = await apiJson("/accounts");
  const data = normalizeAccounts(raw);

  const prev = state.account;
  el.account.innerHTML = "";
  for (const item of data) {
    const opt = document.createElement("option");
    opt.value = String(item.account || "");
    opt.textContent = `${item.account} (total=${item.total})`;
    el.account.appendChild(opt);
  }

  if (resetSelection) {
    state.account = "";
  }

  if (!state.account && prev && data.some((x) => String(x.account) === prev)) {
    state.account = prev;
  }

  if (!state.account && data.length > 0) {
    state.account = String(data[0].account || "");
  }

  if (state.account) {
    el.account.value = state.account;
  }

  if (!state.account) {
    setStatus("No account data yet.");
    return;
  }

  await loadConnections();
  if (resetSelection) {
    await resetAndLoadEvents();
  }
}

async function loadConnections() {
  if (!state.account) return;

  const data = await apiJson(`/connections?account=${encodeURIComponent(state.account)}`);
  const prev = state.connection;

  el.conn.innerHTML = "";
  const all = document.createElement("option");
  all.value = "";
  all.textContent = "All Connections";
  el.conn.appendChild(all);

  for (const item of data) {
    const opt = document.createElement("option");
    opt.value = item.cid;
    opt.textContent = `${item.cid} (x${item.count})`;
    el.conn.appendChild(opt);
  }

  if (prev && data.some((x) => x.cid === prev)) {
    state.connection = prev;
    el.conn.value = prev;
  } else {
    state.connection = "";
    el.conn.value = "";
  }
}

async function resetAndLoadEvents() {
  state.events = [];
  state.afterId = null;
  state.hasMore = true;
  state.expandedIds.clear();
  await syncLatestEvents();
}

async function syncLatestEvents() {
  if (!state.account || state.loading) return;
  state.loading = true;

  try {
    const params = new URLSearchParams({ account: state.account, limit: "200" });
    if (state.afterId) {
      params.set("after_id", state.afterId);
    }
    const data = await apiJson(`/events?${params.toString()}`);

    const rows = Array.isArray(data.events) ? data.events : [];
    if (rows.length > 0) {
      state.events.push(...rows);
      if (state.events.length > 5000) {
        state.events = state.events.slice(-5000);
      }
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

async function loadMoreEvents() {
  await syncLatestEvents();
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

function getBytesPerRow() {
  const raw = Number(el.previewBytes.value || "16");
  return [16, 24, 32].includes(raw) ? raw : 16;
}

function formatHexDump(base64Text, hideAscii) {
  const bytes = b64ToBytes(base64Text);
  const bytesPerRow = getBytesPerRow();
  const hexWidth = bytesPerRow * 3 - 1;
  const headCols = Array.from({ length: bytesPerRow }, (_x, i) =>
    i.toString(16).padStart(2, "0")
  ).join(" ");
  const headerCore = `offset  ${headCols}`.padEnd(8 + hexWidth, " ");
  const header = hideAscii ? headerCore : `${headerCore}  |ascii|`;
  if (bytes.length === 0) {
    return { header, body: "" };
  }

  const lines = [];
  for (let i = 0; i < bytes.length; i += bytesPerRow) {
    const chunk = bytes.slice(i, i + bytesPerRow);
    const hex = chunk.map((v) => v.toString(16).padStart(2, "0")).join(" ");
    const hexPadded = hex.padEnd(hexWidth, " ");
    const offset = i.toString(16).padStart(6, "0");
    if (hideAscii) {
      lines.push(`${offset}  ${hexPadded}`);
      continue;
    }
    const ascii = chunk.map((v) => (v >= 32 && v <= 126 ? String.fromCharCode(v) : ".")).join("");
    lines.push(`${offset}  ${hexPadded}  |${ascii}|`);
  }
  return { header, body: lines.join("\n") };
}

function shouldHighlight(prefixHex) {
  const rule = normalizeHex(el.prefix.value || "");
  if (!rule) return false;
  return normalizeHex(prefixHex || "").startsWith(rule);
}

function normalizeHex(text) {
  return String(text || "").toLowerCase().replace(/[^0-9a-f]/g, "");
}

function getPreviewInfo(ev) {
  const previewLen = getBytesPerRow();
  const withSpace = el.previewSpace.value === "1";
  const bytes = b64ToBytes(ev.pay);

  let hexBytes = [];
  if (bytes.length > 0) {
    hexBytes = bytes.slice(0, previewLen).map((v) => v.toString(16).padStart(2, "0"));
  } else {
    const fallback = normalizeHex(ev.pfx || "");
    hexBytes = (fallback.match(/.{1,2}/g) || []).slice(0, previewLen);
  }

  const raw = hexBytes.join("");
  const displayCore = withSpace ? formatHexWithGroup(hexBytes, 16) : raw;
  const targetChars = withSpace ? getGroupedTargetChars(previewLen, 16) : previewLen * 2;
  const display = displayCore.padEnd(targetChars, " ");
  return { raw, display };
}

function formatHexWithGroup(hexBytes, groupSize) {
  const groups = [];
  for (let i = 0; i < hexBytes.length; i += groupSize) {
    groups.push(hexBytes.slice(i, i + groupSize).join(" "));
  }
  return groups.join("  ");
}

function getGroupedTargetChars(byteCount, groupSize) {
  if (byteCount <= 0) return 0;
  const groupCount = Math.ceil(byteCount / groupSize);
  // base: aa bb cc (single-space between bytes), extra: one more space between groups
  return byteCount * 2 + (byteCount - 1) + (groupCount - 1);
}

function getEventId(ev) {
  const streamId = String(ev.id ?? "").trim();
  if (streamId) return streamId;
  return `${ev.ts ?? 0}|${ev.cid ?? ""}|${ev.seq ?? 0}|${ev.msg_idx ?? -1}|${ev.chunk_idx ?? -1}|${ev.dir ?? -1}|${ev.len ?? -1}`;
}

function renderEvents() {
  // Keep currently opened rows during incremental re-renders.
  const openIds = new Set();
  for (const node of el.events.querySelectorAll("details[data-event-id]")) {
    const nodeId = String(node.dataset.eventId || "").trim();
    if (!nodeId) continue;
    if (node.open) {
      openIds.add(nodeId);
    }
  }
  state.expandedIds = openIds;

  el.events.innerHTML = "";
  const hideAscii = el.hideAscii.value === "1";

  for (const ev of state.events) {
    if (state.connection && ev.cid !== state.connection) {
      continue;
    }

    const wrap = document.createElement("details");
    const eventId = getEventId(ev);
    wrap.dataset.eventId = eventId;
    wrap.className = ev.dir === 0 ? "event-req" : "event-resp";
    if (state.expandedIds.has(eventId)) {
      wrap.open = true;
    }

    wrap.addEventListener("toggle", () => {
      if (!eventId) return;
      if (wrap.open) {
        state.expandedIds.add(eventId);
      } else {
        state.expandedIds.delete(eventId);
      }
    });
    const summary = document.createElement("summary");
    const isReq = ev.dir === 0;
    const dirArrow = isReq ? "→" : "←";
    const preview = getPreviewInfo(ev);
    const frag = ev.msg_idx >= 0 && ev.chunk_idx >= 0 ? `m${ev.msg_idx}/c${ev.chunk_idx}` : "m-/c-";

    const tsSpan = document.createElement("span");
    tsSpan.className = "summary-fixed";
    tsSpan.textContent = `[${formatTs(ev.ts)}]`;
    summary.appendChild(tsSpan);

    const dirWrap = document.createElement("span");
    dirWrap.className = "summary-fixed";
    dirWrap.appendChild(document.createTextNode("["));

    const dirBadge = document.createElement("span");
    dirBadge.className = `dir-badge ${isReq ? "dir-req" : "dir-resp"}`;
    dirBadge.textContent = dirArrow;
    dirWrap.appendChild(dirBadge);
    dirWrap.appendChild(document.createTextNode("]"));
    summary.appendChild(dirWrap);

    const lenWrap = document.createElement("span");
    lenWrap.className = "summary-fixed";
    lenWrap.appendChild(document.createTextNode("[len="));

    const lenSpan = document.createElement("span");
    lenSpan.className = "len-field";
    lenSpan.textContent = String(ev.len ?? "");
    lenWrap.appendChild(lenSpan);
    lenWrap.appendChild(document.createTextNode("]"));
    summary.appendChild(lenWrap);

    const previewWrap = document.createElement("span");
    previewWrap.className = "summary-preview";
    previewWrap.appendChild(document.createTextNode("["));

    const previewSpan = document.createElement("span");
    previewSpan.className = "preview-hex";
    previewSpan.textContent = preview.display;
    if (shouldHighlight(preview.raw)) {
      previewSpan.className += " preview-mark";
      previewSpan.style.background = el.color.value;
    }
    previewWrap.appendChild(previewSpan);
    previewWrap.appendChild(document.createTextNode("]"));
    summary.appendChild(previewWrap);

    const tailSpan = document.createElement("span");
    tailSpan.className = "summary-tail";
    tailSpan.textContent = frag;
    tailSpan.title = `msg_idx=${ev.msg_idx} chunk_idx=${ev.chunk_idx}`;
    summary.appendChild(tailSpan);

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
    pre.textContent = dump.body;

    hexShell.appendChild(hexHead);
    hexShell.appendChild(pre);
    body.appendChild(hexShell);
    wrap.appendChild(summary);
    wrap.appendChild(body);
    el.events.appendChild(wrap);
  }
}

async function tick() {
  try {
    const s = await apiJson("/stats");
    state.tick += 1;

    if (!state.account && s.write_count > 0) {
      await loadAccounts(false);
      if (state.account && state.events.length === 0) {
        await resetAndLoadEvents();
      }
    }

    if (state.autoRefresh && state.account) {
      await syncLatestEvents();
      if (state.tick % 5 === 0) {
        await loadConnections();
      }
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
    await loadAccounts(true);
  } catch (e) {
    setStatus(`reload error: ${e.message}`);
  }
});

el.more.addEventListener("click", async () => {
  try {
    await loadMoreEvents();
  } catch (e) {
    setStatus(`load more error: ${e.message}`);
  }
});

el.account.addEventListener("change", async (e) => {
  try {
    state.account = e.target.value;
    state.connection = "";
    await loadConnections();
    await resetAndLoadEvents();
  } catch (e2) {
    setStatus(`account change error: ${e2.message}`);
  }
});

el.conn.addEventListener("change", (e) => {
  state.connection = e.target.value;
  renderEvents();
});

el.prefix.addEventListener("input", () => {
  saveRules();
  renderEvents();
});

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

el.previewSpace.addEventListener("change", () => {
  saveRules();
  renderEvents();
});

el.autoRefresh.addEventListener("change", () => {
  state.autoRefresh = el.autoRefresh.value === "1";
  saveRules();
});

el.themeMode.addEventListener("change", () => {
  state.themeMode = el.themeMode.value || "dark";
  saveRules();
  applyTheme();
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
  try {
    await loadAccounts(false);
    if (state.account) {
      await resetAndLoadEvents();
    }
  } catch (e) {
    setStatus(`init error: ${e.message}`);
  }

  await tick();
  setInterval(tick, 1500);
})();
