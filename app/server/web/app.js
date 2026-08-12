/* FnNginxConf - frontend logic */
"use strict";

const APP_BASE = window.APP_BASE || "";
const API = APP_BASE + "/api";

const state = {
  rules: [],
  admin: true,
  applied: true,
  busy: false,               // 后台是否正在应用配置
  lastLocStatus: null,       // "ok" | "warn" | "reject"
};

const $ = (sel) => document.querySelector(sel);

/* ---------- helpers ---------- */

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function toast(type, msg) {
  const box = $("#toasts");
  const el = document.createElement("div");
  el.className = "toast toast-" + type;
  el.innerHTML = `<span class="dot"></span><span class="t-msg">${esc(msg)}</span>`;
  box.appendChild(el);
  setTimeout(() => {
    el.classList.add("leaving");
    setTimeout(() => el.remove(), 200);
  }, 3200);
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, opts);
  let body = null;
  try { body = await res.json(); } catch (_) { /* ignore */ }
  if (!res.ok && !body) throw new Error("HTTP " + res.status);
  if (body && body.code !== 0) {
    const e = new Error(body.msg || "请求失败");
    e.code = body.code;
    e.detail = body.data && body.data.detail;
    throw e;
  }
  return body ? body.data : null;
}

const jsonOpts = (method, payload) => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(payload),
});

/* ---------- loading ---------- */

async function refreshStatus() {
  try {
    const st = await api("/status");
    state.admin = !!st.admin;
    state.applied = !!st.applied;
    state.busy = !!st.busy;
    renderPills(st);
    renderAdminUI();
  } catch (_) { /* keep last state */ }
}

function renderPills(st) {
  const nginx = $("#nginxPill");
  if (st.nginxActive === true) {
    nginx.textContent = "Nginx 运行中";
    nginx.className = "pill pill-ok";
  } else if (st.nginxActive === false) {
    nginx.textContent = "Nginx 未运行";
    nginx.className = "pill pill-bad";
  } else {
    nginx.textContent = "Nginx 检测中…";
    nginx.className = "pill pill-unknown";
  }
  const applied = $("#appliedPill");
  if (state.applied) {
    applied.textContent = "配置已应用";
    applied.className = "pill pill-ok";
  } else {
    applied.textContent = "有未应用的更改";
    applied.className = "pill pill-warn";
  }
  $("#versionBadge").textContent = "v" + (st.version || "1.0.0");
}

function renderAdminUI() {
  const admin = state.admin;
  $("#adminBadge").hidden = !admin;
  $("#readonlyBanner").hidden = admin;
  $("#btnNew").disabled = !admin;
  $("#btnApply").disabled = state.busy || !admin;
  document.querySelectorAll(".card").forEach((c) => {
    c.querySelector(".mini.delete").disabled = !admin;
    c.querySelector(".mini.edit").disabled = !admin;
    c.querySelector(".switch input").disabled = !admin;
  });
}

async function loadRules() {
  const data = await api("/rules");
  state.rules = data.rules || [];
  render();
  renderAdminUI();
}

/* ---------- render ---------- */

function targetText(rule) {
  return rule.type === "socket" ? "unix:" + rule.socket : rule.target;
}

function render() {
  const grid = $("#rulesGrid");
  const empty = $("#emptyState");
  if (!state.rules.length) {
    grid.innerHTML = "";
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  grid.innerHTML = state.rules.map((r) => {
    const typeLabel = r.type === "socket" ? "Socket" : "HTTP";
    return `
      <article class="card ${r.enabled ? "" : "card-disabled"}" data-id="${esc(r.id)}">
        <div class="card-top">
          <div class="card-name">${esc(r.name)}</div>
          <label class="switch" title="${r.enabled ? "点击停用" : "点击启用"}">
            <input type="checkbox" class="enable" ${r.enabled ? "checked" : ""}>
            <span></span>
          </label>
        </div>
        <div class="card-meta">
          <span class="chip path">${esc(r.location)}</span>
          <span class="chip type-${r.type}">${typeLabel}</span>
        </div>
        <div class="card-target"><span class="t-label">目标</span>${esc(targetText(r))}</div>
        <div class="card-foot">
          <button class="mini edit">编辑</button>
          <button class="mini danger delete">删除</button>
        </div>
      </article>`;
  }).join("");
}

/* ---------- grid actions (event delegation) ---------- */

let armedDeleteId = null;
let armedTimer = null;

$("#rulesGrid").addEventListener("click", async (ev) => {
  const card = ev.target.closest(".card");
  if (!card) return;
  const id = card.dataset.id;
  const rule = state.rules.find((r) => r.id === id);
  if (!rule) return;

  if (ev.target.closest(".enable")) {
    await toggleRule(rule);
  } else if (ev.target.closest(".edit")) {
    openModal(rule);
  } else if (ev.target.closest(".delete")) {
    const btn = ev.target.closest(".delete");
    if (armedDeleteId === id) {
      clearTimeout(armedTimer);
      armedDeleteId = null;
      await deleteRule(id);
    } else {
      armedDeleteId = id;
      btn.textContent = "确认删除？";
      btn.classList.add("armed");
      armedTimer = setTimeout(() => {
        armedDeleteId = null;
        btn.textContent = "删除";
        btn.classList.remove("armed");
      }, 3000);
    }
  }
});

async function toggleRule(rule) {
  try {
    await api("/rules/" + rule.id, jsonOpts("PUT", { enabled: !rule.enabled }));
    rule.enabled = !rule.enabled;
    render();
    await refreshStatus();
  } catch (e) {
    toast("error", e.message || "切换失败");
  }
}

async function deleteRule(id) {
  try {
    await api("/rules/" + id, { method: "DELETE" });
    state.rules = state.rules.filter((r) => r.id !== id);
    toast("success", "已删除规则");
    render();
    await refreshStatus();
  } catch (e) {
    toast("error", e.message || "删除失败");
  }
}

/* ---------- modal ---------- */

const modal = $("#modal");
const form = $("#ruleForm");
let editingId = null;

function openModal(rule) {
  editingId = rule ? rule.id : null;
  $("#modalTitle").textContent = rule ? "编辑规则" : "新增规则";
  $("#fName").value = rule ? rule.name : "";
  $("#fLocation").value = rule ? rule.location : "";
  setType(rule ? rule.type : "http");
  if (rule) {
    if (rule.type === "http") $("#fTarget").value = rule.target || "";
    else $("#fSocket").value = rule.socket || "";
    $("#fStrip").checked = !!rule.stripPrefix;
  } else {
    $("#fTarget").value = "";
    $("#fSocket").value = "";
    $("#fStrip").checked = true;
  }
  state.lastLocStatus = null;
  hideLocHint();
  modal.hidden = false;
  setTimeout(() => $("#fName").focus(), 40);
}

function closeModal() {
  modal.hidden = true;
  editingId = null;
  state.lastLocStatus = null;
}

function setType(type) {
  document.querySelectorAll("#typeSeg [data-type]").forEach((b) =>
    b.classList.toggle("active", b.dataset.type === type));
  $("#targetField").hidden = type !== "http";
  $("#socketField").hidden = type !== "socket";
}

$("#typeSeg").addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-type]");
  if (b) setType(b.dataset.type);
});

$("#modalClose").addEventListener("click", closeModal);
$("#modalCancel").addEventListener("click", closeModal);
modal.addEventListener("mousedown", (ev) => {
  if (ev.target === modal) closeModal();
});

function hideLocHint() {
  const h = $("#locHint");
  h.hidden = true;
  h.className = "field-hint";
  h.textContent = "";
  $("#fLocation").classList.remove("invalid");
}

async function checkLocation() {
  const loc = $("#fLocation").value.trim();
  hideLocHint();
  if (!loc || !loc.startsWith("/")) {
    state.lastLocStatus = null;
    return;
  }
  try {
    const data = await api("/check-location", jsonOpts("POST", { location: loc }));
    const h = $("#locHint");
    h.hidden = false;
    state.lastLocStatus = data.status;
    if (data.status === "reject") {
      h.textContent = data.message || "该路径与系统已有路径冲突";
      h.className = "field-hint err";
      $("#fLocation").classList.add("invalid");
    } else if (data.status === "warn") {
      h.textContent = data.message || "注意：该路径位于系统路径之下";
      h.className = "field-hint warn";
    } else {
      h.textContent = "✓ 路径可用";
      h.className = "field-hint ok";
    }
  } catch (_) {
    state.lastLocStatus = null;
  }
}

$("#fLocation").addEventListener("blur", checkLocation);

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const name = $("#fName").value.trim();
  const location = $("#fLocation").value.trim();
  const type = $("[data-type].active").dataset.type;
  const target = type === "http" ? $("#fTarget").value.trim() : null;
  const socket = type === "socket" ? $("#fSocket").value.trim() : null;

  if (!name) return toast("error", "请填写名称");
  if (!location || !location.startsWith("/")) return toast("error", "路径需以 / 开头");
  if (location === "/") return toast("error", "根路径 / 被系统占用");
  if (type === "http" && !target) return toast("error", "请填写目标地址");
  if (type === "socket" && !socket) return toast("error", "请填写 socket 路径");
  if (state.lastLocStatus === "reject") return toast("error", "请先修改冲突的路径");

  const payload = {
    name, location, type,
    target, socket,
    stripPrefix: $("#fStrip").checked,
  };
  try {
    if (editingId) {
      await api("/rules/" + editingId, jsonOpts("PUT", payload));
      toast("success", "已更新规则");
    } else {
      await api("/rules", jsonOpts("POST", payload));
      toast("success", "已新增规则");
    }
    closeModal();
    await loadRules();
    await refreshStatus();
  } catch (e) {
    toast("error", e.message || "保存失败");
  }
});

/* ---------- apply ---------- */

/* ---------- apply（异步：立即返回，后台执行，前端轮询结果） ---------- */

const applyBtn = $("#btnApply");
const applyOrigHTML = applyBtn.innerHTML;

function setBusyUI(busy) {
  state.busy = !!busy;
  applyBtn.disabled = busy || !state.admin;
  applyBtn.innerHTML = busy ? '<span class="spin"></span>应用中…' : applyOrigHTML;
}

function pollUntilDone() {
  let n = 0;
  const t = setInterval(async () => {
    n++;
    let st = null;
    try {
      st = await api("/status");
    } catch (_) {
      // nginx 重启中，瞬时失败忽略
    }
    if (st) {
      state.busy = !!st.busy;
      setBusyUI(state.busy);
      renderPills(st);
      if (!st.busy && st.lastApplyAt) {
        clearInterval(t);
        if (st.lastApplyResult === false) {
          $("#errorDetail").textContent = st.lastApplyDetail || st.lastApplyMessage || "未知错误";
          $("#errorPanel").hidden = false;
          toast("error", st.lastApplyMessage || "应用失败");
        } else {
          toast("success", st.lastApplyMessage || "配置已应用");
        }
      }
    }
    if (n >= 12) clearInterval(t);   // 24s 兜底
  }, 2000);
}

applyBtn.addEventListener("click", async () => {
  if (state.busy) return;
  $("#errorPanel").hidden = true;
  applyBtn.disabled = true;
  try {
    const data = await api("/apply", { method: "POST" });
    toast("info", data.message || "已提交，正在后台执行");
    setBusyUI(true);
    pollUntilDone();
  } catch (e) {
    toast("error", e.message || "提交失败");
    setBusyUI(false);
  }
});

$("#btnRefresh").addEventListener("click", async () => {
  try { await loadRules(); await refreshStatus(); }
  catch (e) { toast("error", e.message || "刷新失败"); }
});

$("#errorClose").addEventListener("click", () => { $("#errorPanel").hidden = true; });

$("#btnNew").addEventListener("click", () => openModal(null));

/* ---------- init ---------- */

(async function init() {
  try {
    await Promise.all([loadRules(), refreshStatus()]);
  } catch (e) {
    toast("error", "加载失败：" + (e.message || ""));
  }
  setInterval(() => { refreshStatus().catch(() => {}); }, 15000);
})();
