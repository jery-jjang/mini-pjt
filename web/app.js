// VulnWatch 로컬 화면. 같은 서버의 API(/query, /projects, /settings)를 부른다.
// 계정은 고정 데모 토큰 3개로 고른다(PoC에는 로그인 화면이 없다). 교육용 더미 데이터입니다.
"use strict";

const ACCOUNTS = [
  { id: "team_a_member", name: "팀 A 팀원", token: "demo-token-team-a" },
  { id: "team_b_member", name: "팀 B 팀원", token: "demo-token-team-b" },
  { id: "security_admin", name: "보안 담당자", token: "demo-token-security" },
];

const EXAMPLES = [
  "Log4j 2.14.1에 해당하는 취약점이 뭐야?",
  "결제 API 프로젝트 현황 보여줘",
  "CVE-2021-44228은 어떤 취약점이야?",
  "사내 포털에 OpenSSL 3.0.6 등록해줘",
  "배치 서버에서 KEV에 오른 취약점만 알려줘",
];

const LABELS = {
  answer: { text: "답변", cls: "tag-ok" },
  no_answer: { text: "확인할 수 없음", cls: "tag-warn" },
  guardrail: { text: "거절", cls: "tag-danger" },
};

const STORE_KEY = "vulnwatch.account";

const $ = (id) => document.getElementById(id);
const state = { accountId: loadAccount(), messages: [], selected: null, busy: false, role: null };

// ---------------- 작은 도우미 ----------------

/** 저장해 둔 계정을 읽는다. 저장소를 못 쓰면 기본 계정. */
function loadAccount() {
  try {
    const saved = localStorage.getItem(STORE_KEY);
    if (ACCOUNTS.some((a) => a.id === saved)) return saved;
  } catch (_) { /* 저장소를 쓸 수 없는 환경 */ }
  return ACCOUNTS[0].id;
}

function saveAccount(id) {
  try { localStorage.setItem(STORE_KEY, id); } catch (_) { /* 무시 */ }
}

function currentAccount() {
  return ACCOUNTS.find((a) => a.id === state.accountId) || ACCOUNTS[0];
}

/** 요소를 만든다. text는 글자로만 넣어 HTML로 해석되지 않게 한다. */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** 답변의 **굵게** 표시는 기호만 지우고 글자로 보여 준다. */
function plain(text) {
  return String(text || "").replace(/\*\*(.+?)\*\*/g, "$1");
}

function formatTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("ko-KR", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatHours(h) {
  if (h === null || h === undefined) return "-";
  if (h < 1) return `${Math.round(h * 60)}분`;
  return `${Number.isInteger(h) ? h : h.toFixed(2).replace(/0+$/, "")}시간`;
}

/** API를 부른다. 오류면 {status, detail}을 던진다. */
async function api(path, { method = "GET", body } = {}) {
  const headers = { Authorization: `Bearer ${currentAccount().token}` };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res;
  try {
    res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch (_) {
    throw { status: 0, detail: "서버에 연결하지 못했습니다. 서버가 켜져 있는지 확인해 주세요." };
  }
  let data = null;
  try { data = await res.json(); } catch (_) { /* 본문 없음 */ }
  if (!res.ok) {
    let detail = data && data.detail;
    if (Array.isArray(detail)) detail = detail.map((d) => d.msg).join(", ");
    throw { status: res.status, detail: detail || `요청이 실패했습니다 (${res.status}).` };
  }
  return data;
}

// ---------------- 계정 ----------------

function renderAccounts() {
  const select = $("account-select");
  select.replaceChildren(...ACCOUNTS.map((a) => el("option", { value: a.id, text: a.name })));
  select.value = state.accountId;
  select.addEventListener("change", () => {
    state.accountId = select.value;
    saveAccount(state.accountId);
    loadProjects();
    loadSettings();
  });
}

// ---------------- 등록된 SW ----------------

async function loadProjects() {
  const list = $("inventory-list");
  list.setAttribute("aria-busy", "true");
  try {
    const data = await api("/projects");
    state.role = data.account.role;
    $("inventory-scope").textContent = data.account.role === "security_admin"
      ? `${data.account.name}: 모든 팀의 프로젝트`
      : `${data.account.name}: 자기 팀 프로젝트만 보입니다`;
    list.replaceChildren(...data.projects.map(renderProject));
    if (!data.projects.length) list.append(el("p", { class: "muted", text: "볼 수 있는 프로젝트가 없습니다." }));
  } catch (err) {
    list.replaceChildren(el("p", { class: "error-text", text: err.detail }));
  } finally {
    list.removeAttribute("aria-busy");
  }
}

function renderProject(project) {
  const unmonitored = project.items.filter((i) => !i.monitored).length;
  const summary = el("summary", {},
    el("div", {},
      el("div", { class: "project-name", text: project.name }),
      el("div", { class: "project-meta", text: `${project.team} · ${project.items.length}개 항목` })),
    unmonitored ? el("span", { class: "tag tag-warn", text: `감시 불가 ${unmonitored}` }) : null,
    chevron());
  // 감시 중인 항목은 표준 제품 이름, 감시 불가 항목은 입력한 문장 그대로 보여 준다
  const items = el("ul", { class: "items" }, project.items.map((item) =>
    el("li", { class: "item", title: `등록할 때 입력: ${item.raw_text}` },
      el("div", { class: "item-main" },
        el("span", { class: "item-name", text: item.product || item.raw_text }),
        item.version && item.product ? el("span", { class: "item-version", text: item.version }) : null),
      item.monitored
        ? el("span", { class: "tag tag-ok", text: "감시 중" })
        : el("span", { class: "tag tag-warn", text: "감시 불가" }))));
  if (!project.items.length) items.append(el("li", { class: "muted small", text: "등록된 항목이 없습니다." }));
  return el("details", { class: "project", open: true }, summary, items);
}

function chevron() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "icon chev");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "m9 18 6-6-6-6");
  svg.append(path);
  return svg;
}

// ---------------- 질문과 답변 ----------------

function renderExamples() {
  $("examples").replaceChildren(...EXAMPLES.map((q) =>
    el("button", { type: "button", class: "chip", onclick: () => ask(q) }, q)));
}

/** 응답의 trace에서 등록 후보를 꺼낸다. 후보가 없으면 빈 목록. */
function candidatesOf(response) {
  const step = [...(response.trace || [])].reverse().find((t) => t.step === "propose_candidates");
  if (!step) return [];
  try {
    const out = JSON.parse(step.output);
    return out.status === "candidates" ? out.candidates || [] : [];
  } catch (_) {
    return [];
  }
}

function renderChat() {
  const log = $("chat-log");
  const nodes = state.messages.map((m, index) => {
    if (m.role === "user") {
      return el("div", { class: "msg msg-user" },
        el("div", { class: "who", text: m.account }), el("div", { class: "msg-text", text: m.text }));
    }
    if (m.role === "error") {
      return el("div", { class: "msg msg-error", role: "alert" },
        el("div", { class: "who", text: m.status ? `오류 ${m.status}` : "오류" }),
        el("div", { class: "msg-text", text: m.text }));
    }
    const r = m.response;
    const label = LABELS[r.label] || { text: r.label, cls: "tag-neutral" };
    const bubble = el("button", {
      type: "button", class: "msg msg-bot", "aria-pressed": String(state.selected === index),
      "aria-label": `답변 ${index + 1}, 라벨 ${label.text}. 눌러서 상세 보기`,
      onclick: () => select(index),
    },
      el("div", { class: "who", text: "VulnWatch" }),
      el("div", { class: "msg-text", text: plain(r.answer) }),
      el("div", { class: "msg-meta" },
        el("span", { class: `tag ${label.cls}`, text: label.text }),
        r.cve_ids.length ? el("span", { text: `취약점 ${r.cve_ids.length}건` }) : null,
        r.tools_called.length ? el("span", { text: `도구 ${r.tools_called.length}개` }) : null));
    const candidates = candidatesOf(r);
    if (!candidates.length || index !== state.messages.length - 1) return bubble;
    // 가장 최근 답변이 후보를 제시했으면 번호 버튼으로 바로 확정할 수 있게 한다
    return el("div", { class: "msg-group" }, bubble,
      el("div", { class: "candidates", role: "group", "aria-label": "등록 후보 확정" },
        candidates.map((c) => el("button", {
          type: "button", class: "chip chip-strong", onclick: () => ask(`${c.no}번으로 확정해줘`),
        }, `${c.no}번 확정 · ${c.name}`))));
  });
  if (state.busy) {
    nodes.push(el("div", { class: "pending", role: "status" },
      el("span", { class: "spinner", "aria-hidden": "true" }), "답변을 만드는 중입니다 (몇 초 걸립니다)"));
  }
  $("chat-empty").hidden = nodes.length > 0;
  log.replaceChildren($("chat-empty"), ...nodes);
  log.scrollTop = log.scrollHeight;
}

async function ask(question) {
  question = question.trim();
  if (!question || state.busy) return;
  const account = currentAccount();
  state.messages.push({ role: "user", text: question, account: account.name });
  state.busy = true;
  setBusy(true);
  renderChat();
  try {
    const response = await api("/query", { method: "POST", body: { question } });
    state.messages.push({ role: "bot", response });
    state.selected = state.messages.length - 1;
    renderDetail();
    if (response.tools_called.includes("confirm_registration") || response.tools_called.includes("propose_candidates")) {
      loadProjects(); // 등록이 바뀌었을 수 있다
    }
  } catch (err) {
    state.messages.push({ role: "error", status: err.status, text: err.detail });
  } finally {
    state.busy = false;
    setBusy(false);
    renderChat();
  }
}

function setBusy(busy) {
  $("ask-button").disabled = busy;
  $("question").setAttribute("aria-busy", String(busy));
  for (const chip of $("examples").querySelectorAll("button")) chip.disabled = busy;
}

function select(index) {
  state.selected = index;
  renderChat();
  renderDetail();
  if (window.matchMedia("(max-width: 1180px)").matches) $("detail-title").scrollIntoView({ block: "start" });
}

// ---------------- 응답 상세 ----------------

function renderDetail() {
  const body = $("detail-body");
  const m = state.messages[state.selected];
  if (!m || m.role !== "bot") {
    body.replaceChildren(el("p", { class: "muted", text: "답변을 고르면 라벨, 근거 문서, 실행 기록을 보여 줍니다." }));
    return;
  }
  const r = m.response;
  const label = LABELS[r.label] || { text: r.label, cls: "tag-neutral" };
  body.replaceChildren(
    row("라벨", el("span", { class: `tag ${label.cls}`, text: `${label.text} (${r.label})` })),
    row("답에 나온 취약점", r.cve_ids.length
      ? el("div", { class: "id-list" }, r.cve_ids.map((id) => el("span", { class: "tag tag-neutral mono", text: id })))
      : el("span", { class: "muted", text: "없음" })),
    row("호출한 도구", r.tools_called.length
      ? el("div", { class: "id-list" }, r.tools_called.map((t) => el("span", { class: "tag tag-neutral mono", text: t })))
      : el("span", { class: "muted", text: "없음" })),
    block(`근거 문서 (contexts) ${r.contexts.length}건`, r.contexts.length > 0,
      r.contexts.length
        ? r.contexts.map((c) => el("div", { class: "doc" },
            el("div", { class: "mono", text: c.doc_id }), el("pre", { class: "code", text: c.text })))
        : [el("p", { class: "muted small", text: "이 답변에는 근거로 쓴 취약점 문서가 없습니다." })]),
    block(`실행 기록 (trace) ${r.trace.length}단계`, false,
      r.trace.map((t, i) => el("div", { class: "step" },
        el("div", { class: "mono", text: `${i + 1}. ${t.step}` }),
        el("div", { class: "detail-label", text: "입력" }), el("pre", { class: "code", text: t.input }),
        el("div", { class: "detail-label", text: "출력" }), el("pre", { class: "code", text: t.output })))),
  );
}

function row(name, value) {
  return el("div", { class: "detail-row" }, el("div", { class: "detail-label", text: name }), value);
}

function block(title, open, children) {
  return el("details", { class: "block", open }, el("summary", { text: title }), el("div", { class: "block-body" }, children));
}

// ---------------- 주기 검색 설정 ----------------

async function loadSettings() {
  try {
    const s = await api("/settings");
    showSettings(s);
  } catch (err) {
    $("scan-summary").textContent = "검색 주기를 불러오지 못함";
  }
}

function showSettings(s) {
  $("scan-summary").textContent = s.scheduler_enabled
    ? `검색 주기 ${formatHours(s.scan_interval_hours)} · 다음 ${formatTime(s.next_run_at)}`
    : `검색 주기 ${formatHours(s.scan_interval_hours)} · 주기 검색 꺼짐`;
  $("set-enabled").textContent = s.scheduler_enabled ? "켜짐" : "꺼짐";
  $("set-interval").textContent = formatHours(s.scan_interval_hours);
  $("set-last").textContent = formatTime(s.last_run_at);
  $("set-next").textContent = formatTime(s.next_run_at);
  $("interval-input").value = s.scan_interval_hours;
}

function openSettings() {
  const admin = currentAccount().id === "security_admin";
  $("interval-input").disabled = !admin;
  $("interval-save").disabled = !admin;
  $("interval-error").textContent = admin ? "" : "지금 계정은 주기를 바꿀 수 없습니다. 보안 담당자로 바꿔 주세요.";
  $("interval-input").removeAttribute("aria-invalid");
  loadSettings();
  $("settings-dialog").showModal();
}

async function saveInterval() {
  const input = $("interval-input");
  const error = $("interval-error");
  const hours = Number(input.value);
  if (!input.value || !Number.isFinite(hours) || hours <= 0) {
    input.setAttribute("aria-invalid", "true");
    error.textContent = "0보다 큰 숫자를 넣어 주세요.";
    input.focus();
    return;
  }
  $("interval-save").disabled = true;
  try {
    const s = await api("/settings/scan-interval", { method: "PUT", body: { hours } });
    input.removeAttribute("aria-invalid");
    error.textContent = "";
    showSettings(s);
    $("set-interval").textContent = `${formatHours(s.scan_interval_hours)} (바꿨습니다)`;
  } catch (err) {
    input.setAttribute("aria-invalid", "true");
    error.textContent = err.detail;
  } finally {
    $("interval-save").disabled = currentAccount().id !== "security_admin";
  }
}

// ---------------- 시작 ----------------

function init() {
  renderAccounts();
  renderExamples();
  renderChat();

  $("ask-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const q = $("question").value;
    $("question").value = "";
    ask(q);
  });
  // Enter로 보내고, Shift+Enter는 줄바꿈
  $("question").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      $("ask-form").requestSubmit();
    }
  });
  $("chat-clear").addEventListener("click", () => {
    state.messages = [];
    state.selected = null;
    renderChat();
    renderDetail();
  });
  $("inventory-refresh").addEventListener("click", loadProjects);
  $("settings-open").addEventListener("click", openSettings);
  $("settings-close").addEventListener("click", () => $("settings-dialog").close());
  $("interval-save").addEventListener("click", saveInterval);

  loadProjects();
  loadSettings();
  setInterval(loadSettings, 60_000); // 다음 검색 시각을 1분마다 새로 고친다
}

init();
