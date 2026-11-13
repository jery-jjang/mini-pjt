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
// generation: 계정을 바꾸거나 대화를 지울 때마다 1씩 올린다. 그 전에 보낸 요청의 답은 화면에 넣지 않는다.
// view: 근거 문서 보기 방식(sw, cve). 다른 답변을 골라도 유지한다. pick: 고른 CVE ID 또는 SW 이름.
const state = {
  accountId: loadAccount(), messages: [], selected: null, busy: false, role: null, generation: 0,
  view: "sw", pick: null,
};

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

/** 시간(소수)을 분 단위로 반올림한 {hours, minutes}로 나눈다. */
function splitHours(h) {
  const total = Math.max(0, Math.round(Number(h) * 60));
  return { hours: Math.floor(total / 60), minutes: total % 60 };
}

/** 검색 주기를 "6시간", "1시간 30분", "5분"처럼 보여 준다. */
function formatHours(h) {
  if (h === null || h === undefined) return "-";
  const { hours, minutes } = splitHours(h);
  if (!hours && !minutes) return "1분 미만";
  return [hours ? `${hours}시간` : "", minutes ? `${minutes}분` : ""].filter(Boolean).join(" ");
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
    resetConversation(); // 다른 계정의 질문과 답이 남아 보이지 않게 한다
    refreshUnread(); // 읽음 현황은 계정마다 따로다
    loadProjects();
    loadSettings();
  });
}

/** 대화, 응답 상세, 입력 중인 질문을 지운다. 진행 중이던 요청의 답은 버린다. */
function resetConversation() {
  state.generation += 1;
  state.messages = [];
  state.selected = null;
  state.busy = false;
  setBusy(false);
  $("question").value = "";
  renderChat();
  renderDetail();
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
      el("div", { class: "item-side" },
        item.monitored
          ? el("span", { class: "tag tag-ok", text: "감시 중" })
          : el("span", { class: "tag tag-warn", text: "감시 불가" }),
        el("button", {
          type: "button", class: "icon-button remove-button",
          "aria-label": `${itemLabel(item)} 삭제`, title: "삭제",
          onclick: () => openRemove(project, item),
        }, trashIcon())))));
  if (!project.items.length) items.append(el("li", { class: "muted small", text: "등록된 항목이 없습니다." }));
  return el("details", { class: "project", open: true }, summary, items);
}

function itemLabel(item) {
  return item.product ? `${item.product} ${item.version || ""}`.trim() : item.raw_text;
}

function trashIcon() {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ["M3 6h18", "M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2", "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6", "M10 11v6", "M14 11v6"]) {
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

// ---------------- 알림함 (DB에 저장된 가짜 발송 메일) ----------------

const MAIL_KIND = { alert: { text: "알림", cls: "tag-danger" }, scan_failure: { text: "조회 실패", cls: "tag-warn" } };

/** 알림함 버튼의 안 읽은 메일 수 배지를 새로 고친다. 읽음 현황은 계정마다 따로다. */
async function refreshUnread() {
  const badge = $("mails-badge");
  try {
    const { unread_count: n } = await api("/mails");
    badge.hidden = n === 0;
    badge.textContent = n > 99 ? "99+" : String(n);
    $("mails-open").setAttribute("aria-label", n ? `알림함, 안 읽은 메일 ${n}건` : "알림함");
  } catch (_) {
    badge.hidden = true;
  }
}

async function openMails() {
  $("mails-scope").textContent = isSecurityAdmin()
    ? "보안 담당자: 모든 프로젝트의 알림과 조회 실패 통지"
    : `${currentAccount().name}: 자기 팀 프로젝트의 알림만 보입니다`;
  $("mail-view").replaceChildren(el("p", { class: "muted", text: "메일을 고르면 본문을 보여 줍니다. 열면 읽음으로 표시됩니다." }));
  $("mails-list").replaceChildren(el("li", { class: "muted small", text: "불러오는 중" }));
  if (!$("mails-dialog").open) $("mails-dialog").showModal();
  await renderMailList();
}

async function renderMailList(selectedId = null) {
  try {
    const { mails, unread_count: unread } = await api("/mails");
    $("mails-read-all").disabled = unread === 0;
    if (!mails.length) {
      $("mails-list").replaceChildren(el("li", { class: "muted small",
        text: "저장된 알림 메일이 없습니다. 주기 검색이나 '지금 검색 실행해줘'로 알림이 생기면 여기에 쌓입니다." }));
      return;
    }
    $("mails-list").replaceChildren(...mails.map((m) => el("li", {},
      el("button", {
        type: "button", class: `mail-item${m.read ? "" : " unread"}`, "data-id": m.id,
        "aria-pressed": String(m.id === selectedId),
        "aria-label": `${m.read ? "" : "안 읽음, "}${m.subject}`,
        onclick: () => showMail(m.id),
      },
        el("span", { class: "mail-item-head" },
          el("span", { class: "mail-tags" },
            m.read ? null : el("span", { class: "new-badge", "aria-hidden": "true", text: "N" }),
            el("span", { class: `tag ${(MAIL_KIND[m.kind] || {}).cls || "tag-neutral"}`, text: (MAIL_KIND[m.kind] || {}).text || m.kind })),
          el("span", { class: "muted small", text: formatTime(m.created_at) })),
        el("span", { class: "mail-subject", text: m.subject }),
        m.vuln_ids.length ? el("span", { class: "muted small mono", text: m.vuln_ids.join(", ") }) : null))));
  } catch (err) {
    $("mails-list").replaceChildren(el("li", { class: "error-text", text: err.detail }));
  }
}

/** 메일을 열면 이 계정 기준으로 읽음 표시하고 본문을 보여 준다. */
async function showMail(id) {
  for (const b of $("mails-list").querySelectorAll(".mail-item")) b.setAttribute("aria-pressed", String(b.dataset.id === String(id)));
  try {
    const m = await api(`/mails/${id}/read`, { method: "POST" });
    const item = $("mails-list").querySelector(`.mail-item[data-id="${id}"]`);
    if (item) {
      item.classList.remove("unread");
      item.querySelector(".new-badge")?.remove();
      item.setAttribute("aria-label", m.subject);
    }
    refreshUnread();
    $("mails-read-all").disabled = !$("mails-list").querySelector(".mail-item.unread");
    $("mail-view").replaceChildren(...[
      el("h3", { class: "mail-title", text: m.subject }),
      el("dl", { class: "settings-grid" },
        m.recipient ? [el("dt", { text: "받는 사람" }), el("dd", { text: m.recipient })] : [],
        el("dt", { text: "프로젝트" }), el("dd", { text: m.project || "전체 (보안 담당자)" }),
        el("dt", { text: "저장 시각" }), el("dd", { text: formatTime(m.created_at) }),
        el("dt", { text: "내가 읽은 시각" }), el("dd", { text: formatTime(m.read_at) })),
      m.readers ? el("div", { class: "readers" },
        el("div", { class: "detail-label", text: "읽음 현황 (계정별)" }),
        el("ul", {}, m.readers.map((r) => el("li", {},
          el("span", { text: r.name }),
          r.read_at
            ? el("span", { class: "tag tag-ok", text: `읽음 · ${formatTime(r.read_at)}` })
            : el("span", { class: "tag tag-warn", text: "안 읽음" }))))) : null,
      el("pre", { class: "code mail-body", text: m.body }),
    ].filter(Boolean));
  } catch (err) {
    $("mail-view").replaceChildren(el("p", { class: "error-text", text: err.detail }));
  }
}

async function readAllMails() {
  $("mails-read-all").disabled = true;
  try {
    await api("/mails/read-all", { method: "POST" });
  } catch (_) { /* 목록을 다시 불러와 상태를 맞춘다 */ }
  const selected = $("mails-list").querySelector('.mail-item[aria-pressed="true"]');
  await renderMailList(selected ? Number(selected.dataset.id) : null);
  refreshUnread();
}

// ---------------- SW 삭제 (화면에서만, 확인 창을 거쳐 코드가 처리) ----------------

let removing = null; // 확인 창에 띄운 {project, item}

function openRemove(project, item) {
  removing = { project, item };
  $("remove-project").textContent = project.name;
  $("remove-item").textContent = itemLabel(item);
  $("remove-state").textContent = item.monitored ? "감시 중" : "감시 불가";
  $("remove-error").textContent = "";
  $("remove-confirm").disabled = false;
  $("remove-dialog").showModal();
  $("remove-cancel").focus(); // 실수로 Enter를 눌러도 지워지지 않게 취소에 먼저 초점을 둔다
}

async function confirmRemove() {
  if (!removing) return;
  const { project, item } = removing;
  $("remove-confirm").disabled = true;
  try {
    await api(`/projects/${encodeURIComponent(project.id)}/items/${item.id}`, { method: "DELETE" });
    $("remove-dialog").close();
    removing = null;
    await loadProjects();
  } catch (err) {
    $("remove-error").textContent = err.detail;
    $("remove-confirm").disabled = false;
    if (err.status === 404) loadProjects(); // 이미 지워졌으면 목록을 새로 고친다
  }
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
        el("span", { class: "selected-mark", text: "▸ 상세 보는 중" }),
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
  const generation = state.generation;
  state.messages.push({ role: "user", text: question, account: account.name });
  state.busy = true;
  setBusy(true);
  renderChat();
  try {
    const response = await api("/query", { method: "POST", body: { question } });
    if (generation !== state.generation) return; // 그사이 계정을 바꿨거나 대화를 지웠다
    state.messages.push({ role: "bot", response });
    state.selected = state.messages.length - 1;
    state.pick = null;
    renderDetail();
    if (response.tools_called.includes("run_scan_now")) refreshUnread(); // 검색으로 새 알림이 생겼을 수 있다
    if (response.tools_called.includes("confirm_registration") || response.tools_called.includes("propose_candidates")) {
      loadProjects(); // 등록이 바뀌었을 수 있다
    }
  } catch (err) {
    if (generation !== state.generation) return;
    state.messages.push({ role: "error", status: err.status, text: err.detail });
  } finally {
    // 이전 계정의 요청이 끝났을 때는 지금 화면의 진행 상태를 건드리지 않는다
    if (generation !== state.generation) return;
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
  state.pick = null; // 다른 답변이면 그 답변의 첫 CVE·SW부터 본다
  renderChat();
  renderDetail();
  if (window.matchMedia("(max-width: 1180px)").matches) $("detail-title").scrollIntoView({ block: "start" });
}

// ---------------- 응답 상세 ----------------

function renderDetail() {
  const body = $("detail-body");
  const m = state.messages[state.selected];
  if (!m || m.role !== "bot") {
    body.replaceChildren(el("p", { class: "muted", text: "답변을 고르면 근거 문서를 보여 줍니다." }));
    return;
  }
  const r = m.response;
  // 라벨·취약점 수·도구 수는 답변 말풍선에 이미 보이므로 여기서는 근거 문서와 실행 기록만 보여 준다
  body.replaceChildren(...[
    renderContexts(r.contexts),
    // 실행 기록(도구 입력·출력)은 보안 담당자 화면에만 보여 준다. 화면에서 숨기는 것이고 API 응답의 trace는 규약대로 남는다
    isSecurityAdmin()
      ? block(`실행 기록 (trace) ${r.trace.length}단계`, false,
          r.trace.map((t, i) => el("div", { class: "step" },
            el("div", { class: "mono", text: `${i + 1}. ${t.step}` }),
            el("div", { class: "detail-label", text: "입력" }), el("pre", { class: "code", text: t.input }),
            el("div", { class: "detail-label", text: "출력" }), el("pre", { class: "code", text: t.output }))))
      : null,
  ].filter(Boolean));
}

function isSecurityAdmin() {
  return currentAccount().id === "security_admin";
}

// ---------------- 근거 문서: SW / CVE ----------------
// 근거 문서 본문은 서버 코드가 만드는 고정 형식이다(src/retriever.py의 _doc_text와 tools.add_context):
//   제목 "ID (별칭: ...)", "참고 링크: ...", "점수: 10.0 (NVD) / CISA KEV: 등재",
//   "영향 제품과 버전: log4j 2.0.1 이상 ...; nginx ...", "설명: ...", 그리고 0개 이상의 "판정: ..." 줄.

const VIEWS = [
  { id: "sw", text: "SW" },
  { id: "cve", text: "CVE" },
];

/** 근거 문서 하나를 화면에 쓸 조각으로 나눈다. */
function parseDoc(context) {
  const { links, rest } = splitLinks(context.text);
  const lines = rest.split("\n");
  const doc = {
    id: context.doc_id, title: lines[0] || context.doc_id, links,
    score: null, scoreText: "점수 미정", kev: false, affects: "", products: [], description: "", verdicts: [],
  };
  for (const line of lines.slice(1)) {
    if (line.startsWith("점수:")) {
      const m = line.match(/^점수:\s*(.+?)\s*\/\s*CISA KEV:\s*(.+)$/);
      if (m) {
        doc.scoreText = m[1];
        const num = parseFloat(m[1]);
        doc.score = Number.isFinite(num) ? num : null;
        doc.kev = m[2].trim() === "등재";
      }
    } else if (line.startsWith("영향 제품과 버전:")) {
      doc.affects = line.slice("영향 제품과 버전:".length).trim();
      doc.products = doc.affects.split(";").map((p) => p.trim().split(/\s+/)[0]).filter(Boolean);
    } else if (line.startsWith("설명:")) {
      doc.description = line.slice("설명:".length).trim();
    } else if (line.startsWith("판정:")) {
      const text = line.slice("판정:".length).trim();
      const m = text.match(/^(.+?)은 영향 범위(에 들어 해당함| 밖이라 해당하지 않음)$/);
      doc.verdicts.push(m ? { sw: m[1], affected: m[2].startsWith("에"), text } : { sw: null, affected: null, text });
    } else if (doc.description && line) {
      doc.description += `\n${line}`; // 설명문이 여러 줄이면 이어 붙인다
    }
  }
  return doc;
}

/** 이 문서가 묶이는 SW 이름들. 판정 줄이 있으면 등록된 SW 이름, 없으면 영향 제품 이름. */
function swKeys(doc) {
  const named = doc.verdicts.map((v) => v.sw).filter(Boolean);
  return named.length ? [...new Set(named)] : doc.products;
}

function byScore(a, b) {
  return (b.score ?? -1) - (a.score ?? -1);
}

function renderContexts(contexts) {
  if (!contexts.length) {
    return el("p", { class: "muted small", text: "이 답변에는 근거로 쓴 취약점 문서가 없습니다." });
  }
  const docs = contexts.map(parseDoc);
  const view = state.view;

  const switcher = el("div", { class: "segmented", role: "group", "aria-label": "근거 문서 보기 방식" },
    VIEWS.map((v) => el("button", {
      type: "button", class: "segment", "aria-pressed": String(view === v.id),
      onclick: () => { state.view = v.id; state.pick = null; renderDetail(); },
    }, v.text)));

  let content;
  if (view === "cve") {
    const options = docs.map((d) => ({ key: d.id, label: d.id, sub: d.score === null ? "점수 미정" : String(d.score), kev: d.kev }));
    const pick = pickKey(options);
    content = [picker(options, pick, "CVE 고르기"), ...docs.filter((d) => d.id === pick).map(docCard)];
  } else {
    const groups = new Map();
    for (const d of docs) for (const key of swKeys(d)) groups.set(key, [...(groups.get(key) || []), d]);
    const options = [...groups.entries()].map(([key, list]) => ({ key, label: key, sub: `${list.length}건`, kev: list.some((d) => d.kev) }));
    const pick = pickKey(options);
    content = [picker(options, pick, "SW 고르기"), ...(groups.get(pick) || []).slice().sort(byScore).map(docCard)];
  }
  // 제목 없이 보기 버튼과 문서 카드만 둔다
  return el("div", { class: "contexts" }, switcher, ...content);
}

/** 고른 항목이 목록에 없으면 첫 항목을 고른다. */
function pickKey(options) {
  if (!options.some((o) => o.key === state.pick)) state.pick = options.length ? options[0].key : null;
  return state.pick;
}

function picker(options, pick, label) {
  // 항목이 많으면 버튼이 패널을 다 차지하므로 드롭다운으로 고른다
  if (options.length > 4) {
    const select = el("select", { class: "pick-select", "aria-label": label },
      options.map((o) => el("option", { value: o.key, text: `${o.label} · ${o.sub}${o.kev ? " · KEV" : ""}` })));
    select.value = pick;
    select.addEventListener("change", () => { state.pick = select.value; renderDetail(); });
    return el("div", { class: "field" }, el("span", { class: "detail-label", text: `${label} (${options.length}개)` }), select);
  }
  return el("div", { class: "picker", role: "group", "aria-label": label },
    options.map((o) => el("button", {
      type: "button", class: "pick", "aria-pressed": String(o.key === pick),
      onclick: () => { state.pick = o.key; renderDetail(); },
    },
      el("span", { class: "pick-label", text: o.label }),
      el("span", { class: "pick-sub", text: o.sub }),
      o.kev ? el("span", { class: "tag tag-danger", text: "KEV" }) : null)));
}

function docCard(doc) {
  const scoreCls = doc.score === null ? "tag-neutral" : doc.score >= 9 ? "tag-danger" : doc.score >= 7 ? "tag-warn" : "tag-neutral";
  return el("article", { class: "doc-card", "aria-label": doc.id },
    el("header", { class: "doc-head" },
      el("span", { class: "mono doc-id", text: doc.title }),
      el("span", { class: "doc-badges" },
        el("span", { class: `tag ${scoreCls}`, text: `점수 ${doc.scoreText}` }),
        doc.kev ? el("span", { class: "tag tag-danger", text: "KEV 등재" }) : el("span", { class: "tag tag-neutral", text: "KEV 미등재" }))),
    doc.affects ? el("div", { class: "doc-row" }, el("span", { class: "detail-label", text: "영향 SW" }), el("span", { class: "small", text: doc.affects })) : null,
    doc.verdicts.length
      ? el("div", { class: "doc-row" }, el("span", { class: "detail-label", text: "판정" }),
          el("ul", { class: "verdicts" }, doc.verdicts.map((v) => el("li", {},
            v.affected === null ? null : el("span", { class: `tag ${v.affected ? "tag-danger" : "tag-ok"}`, text: v.affected ? "해당" : "해당 안 함" }),
            " ", v.text))))
      : null,
    doc.links.length
      ? el("div", { class: "links", role: "list", "aria-label": `${doc.id} 참고 링크` },
          doc.links.map((l) => el("a", {
            role: "listitem", class: "link-chip", href: l.url, target: "_blank", rel: "noopener noreferrer",
            title: l.url, "aria-label": `${l.name}에서 ${doc.id} 보기 (새 탭)`,
          }, l.name, externalIcon())))
      : el("p", { class: "muted small", text: "참고 링크 없음 (교육용 가상 항목)" }),
    doc.description
      ? el("details", { class: "doc-desc" }, el("summary", { text: "설명문" }), el("p", { class: "small", text: doc.description }))
      : null);
}

// 근거 문서의 "참고 링크:" 줄은 서버 코드가 만든 고정 형식이다: "이름 URL | 이름 URL ..."
// 알려진 공개 정보원(https)만 링크로 만든다.
const LINK_HOSTS = ["nvd.nist.gov", "osv.dev", "github.com", "www.cisa.gov"];

/** 문서 본문에서 참고 링크 줄을 꺼내 [{name, url}]과 나머지 본문으로 나눈다. */
function splitLinks(text) {
  const lines = String(text || "").split("\n");
  const index = lines.findIndex((line) => line.startsWith("참고 링크:"));
  if (index < 0) return { links: [], rest: text };
  const links = [];
  for (const part of lines[index].slice("참고 링크:".length).split("|")) {
    const m = part.trim().match(/^(.+?)\s+(https:\/\/\S+)$/);
    if (!m) continue;
    try {
      const url = new URL(m[2]);
      if (url.protocol === "https:" && LINK_HOSTS.includes(url.hostname)) links.push({ name: m[1], url: url.href });
    } catch (_) { /* 주소가 아니면 건너뛴다 */ }
  }
  lines.splice(index, 1);
  return { links, rest: lines.join("\n") };
}

function externalIcon() {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "icon icon-sm");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ["M15 3h6v6", "M10 14 21 3", "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"]) {
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
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
  $("set-snapshot").textContent = s.snapshot;
  $("snapshot-select").value = s.snapshot;
  const { hours, minutes } = splitHours(s.scan_interval_hours);
  $("interval-hours").value = hours;
  $("interval-minutes").value = minutes;
}

function openSettings() {
  const admin = currentAccount().id === "security_admin";
  for (const id of ["interval-hours", "interval-minutes"]) {
    $(id).disabled = !admin;
    $(id).removeAttribute("aria-invalid");
  }
  $("interval-save").disabled = !admin;
  $("snapshot-select").disabled = !admin;
  $("snapshot-save").disabled = !admin;
  $("snapshot-error").textContent = "";
  $("interval-error").textContent = admin ? "" : "지금 계정은 주기와 데이터 시점을 바꿀 수 없습니다. 보안 담당자로 바꿔 주세요.";
  loadSettings();
  $("settings-dialog").showModal();
}

/** 화면의 시간·분 입력을 검사한다. 맞으면 API에 보낼 시간 값, 틀리면 {error, field}. */
function readInterval() {
  const hText = $("interval-hours").value.trim();
  const mText = $("interval-minutes").value.trim();
  const h = hText === "" ? 0 : Number(hText);
  const m = mText === "" ? 0 : Number(mText);
  if (!Number.isInteger(h) || h < 0) return { error: "시간은 0 이상의 정수로 넣어 주세요.", field: "interval-hours" };
  if (!Number.isInteger(m) || m < 0 || m > 59) return { error: "분은 0~59 사이의 정수로 넣어 주세요.", field: "interval-minutes" };
  if (h === 0 && m === 0) return { error: "주기는 1분 이상이어야 합니다.", field: "interval-minutes" };
  return { hours: h + m / 60 }; // API는 시간 단위(소수)를 받는다
}

async function saveInterval() {
  const error = $("interval-error");
  for (const id of ["interval-hours", "interval-minutes"]) $(id).removeAttribute("aria-invalid");
  const value = readInterval();
  if (value.error) {
    $(value.field).setAttribute("aria-invalid", "true");
    error.textContent = value.error;
    $(value.field).focus();
    return;
  }
  $("interval-save").disabled = true;
  try {
    const s = await api("/settings/scan-interval", { method: "PUT", body: { hours: value.hours } });
    error.textContent = "";
    showSettings(s);
    $("set-interval").textContent = `${formatHours(s.scan_interval_hours)} (바꿨습니다)`;
  } catch (err) {
    $("interval-hours").setAttribute("aria-invalid", "true");
    error.textContent = err.detail;
  } finally {
    $("interval-save").disabled = currentAccount().id !== "security_admin";
  }
}

/** 취약점 데이터 시점(T1/T2)을 바꾼다. 보안 담당자만 할 수 있고 권한은 서버가 확인한다. */
async function saveSnapshot() {
  const error = $("snapshot-error");
  $("snapshot-save").disabled = true;
  try {
    const s = await api("/settings/snapshot", { method: "PUT", body: { snapshot: $("snapshot-select").value } });
    error.textContent = "";
    showSettings(s);
    $("set-snapshot").textContent = `${s.snapshot} (바꿨습니다. 다음 검색부터 반영)`;
  } catch (err) {
    error.textContent = err.detail;
  } finally {
    $("snapshot-save").disabled = currentAccount().id !== "security_admin";
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
  $("chat-clear").addEventListener("click", resetConversation);
  $("inventory-refresh").addEventListener("click", loadProjects);
  $("settings-open").addEventListener("click", openSettings);
  $("settings-close").addEventListener("click", () => $("settings-dialog").close());
  $("mails-open").addEventListener("click", openMails);
  $("mails-close").addEventListener("click", () => $("mails-dialog").close());
  $("mails-read-all").addEventListener("click", readAllMails);
  $("remove-cancel").addEventListener("click", () => { removing = null; $("remove-dialog").close(); });
  $("remove-confirm").addEventListener("click", confirmRemove);
  $("interval-save").addEventListener("click", saveInterval);
  $("snapshot-save").addEventListener("click", saveSnapshot);

  loadProjects();
  loadSettings();
  refreshUnread();
  setInterval(() => { loadSettings(); refreshUnread(); }, 60_000); // 다음 검색 시각과 새 알림 수를 1분마다 새로 고친다
}

init();
