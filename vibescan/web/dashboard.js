"use strict";
const $ = (id) => document.getElementById(id);
const levels = ["Critical", "High", "Medium", "Low", "Info"];
const statuses = {open: "열림", dismissed: "오탐 후보", fixed: "수정됨"};
const changes = {new: "새로 발견", existing: "기존", fixed: "해결"};
const token = location.hash.slice(1) || sessionStorage.getItem("vibescan-token") || "";
if (location.hash) {
  sessionStorage.setItem("vibescan-token", token);
  history.replaceState(null, "", location.pathname);
}
let result = null;
let scanList = [];
let repoList = [];
let stages = [];
let latestSeen;  // undefined until the first poll; null means the folder had no results
let detailVersion = 0;
let scanning = false;
let pollTimer = null;
let jobVersion = 0;
let auth = null;
let authTimer = null;
let loginRequested = false;

function node(tag, text, className) {
  const item = document.createElement(tag);
  item.textContent = text;
  if (className) item.className = className;
  return item;
}
function badge(level) { return node("span", level, "badge " + (levels.includes(level) ? level : "Info")); }
function findingStatus(f) { return f.change === "fixed" ? "fixed" : f.status; }
function message(text, error = false) {
  $("message").textContent = text;
  $("message").classList.toggle("error", error);
}
async function api(path, body) {
  const response = await fetch(path, {method: body ? "POST" : "GET",
    headers: {"X-VibeScan-Token": token, "Content-Type": "application/json"},
    body: body ? JSON.stringify(body) : undefined, cache: "no-store"});
  if (!response.ok) {
    if (response.status === 403) throw new Error("접속 권한이 만료되었습니다. 터미널에 표시된 대시보드 주소로 다시 여세요.");
    const error = await response.json().catch(() => ({}));
    throw new Error(typeof error.detail === "string" ? error.detail : "요청을 처리할 수 없습니다. 입력과 파일 상태를 확인하세요.");
  }
  return response.json();
}
function locationText(f) {
  return (f.location.file || "파일 미확인") + (f.location.line ? ":" + f.location.line : "");
}
function sortedFindings() {
  return [...result.findings].sort((a, b) => Number(b.change === "new") - Number(a.change === "new") || levels.indexOf(a.severity) - levels.indexOf(b.severity));
}
function showDetail(f) {
  $("detail-badge").replaceChildren(badge(f.severity));
  $("detail-title").textContent = f.title;
  $("detail-meta").textContent = `${locationText(f)} · ${f.cwe} · ${f.owasp} · ${f.confidence} · ${statuses[findingStatus(f)]} · 최초 심각도 ${f.original_severity || f.severity}${f.introduced_in ? ` · 처음 발견 커밋 ${f.introduced_in.slice(0, 12)}` : ""}`;
  $("evidence").textContent = f.evidence || "근거 없음";
  $("how-found").textContent = f.how_found.join(" · ");
  $("impact").textContent = f.impact_ko || "영향 설명 없음";
  $("triage").textContent = f.triage_reason || "로컬 규칙 탐지 · 모델 검토 없음";
  $("remediation").textContent = f.remediation_ko || "수정 방법 없음";
  $("fix-note").textContent = f.fix_note || "동작 검증 전 제안 · 실제 코드 문맥에서 검토 필요";
  $("fix-diff").textContent = f.fix_diff || "제공된 수정 코드가 없습니다.";
  $("copy-status").textContent = "";
  $("copy-diff").disabled = !f.fix_diff;
  $("copy-diff").onclick = async () => {
    try { await navigator.clipboard.writeText(f.fix_diff); $("copy-status").textContent = "수정안을 복사했습니다."; }
    catch { $("copy-status").textContent = "복사 권한이 없습니다. 수정안 텍스트를 선택해 복사하세요."; }
  };
  $("detail").showModal();
}
function findingButton(f) {
  const button = node("button", f.title);
  button.type = "button";
  button.addEventListener("click", () => showDetail(f));
  return button;
}
function filterFindings() {
  if (!result) return;
  const severity = $("severity-filter").value, status = $("status-filter").value;
  const search = $("search").value.toLocaleLowerCase();
  const findings = sortedFindings().filter(f => (!severity || f.severity === severity) && (!status || findingStatus(f) === status) &&
    `${f.title} ${f.location.file || ""} ${f.cwe} ${f.owasp}`.toLocaleLowerCase().includes(search));
  $("findings").replaceChildren();
  $("filtered-count").textContent = `${findings.length}건`;
  $("no-findings").hidden = findings.length !== 0;
  for (const f of findings) {
    const row = node("tr", ""), severityCell = node("td", ""), name = node("td", "");
    severityCell.append(badge(f.severity));
    name.append(findingButton(f), node("p", locationText(f), "muted"));
    row.append(severityCell, name, node("td", statuses[findingStatus(f)] || f.status), node("td", f.confidence), node("td", changes[f.change] || "비교 전"));
    $("findings").append(row);
  }
}
function renderTrend(d) {
  // Last 12 scans of this repository up to the one on screen, on the fixed 0-100 risk scale.
  const points = scanList.filter(s => s.repo.path === d.repo.path && s.scanned_at <= d.scanned_at)
    .sort((a, b) => a.scanned_at.localeCompare(b.scanned_at)).slice(-12);
  const svg = $("risk-trend"), ns = "http://www.w3.org/2000/svg";
  svg.replaceChildren();
  svg.hidden = points.length < 2;
  $("risk-trend-note").textContent = points.length < 2 ? "커밋별 추이는 두 번째 스캔부터 표시됩니다" :
    `최근 ${points.length}회 스캔 추이 · ${points[0].risk_score} → ${d.risk_score}`;
  svg.setAttribute("aria-label", points.map(p => `${(p.commit || "커밋 미확인").slice(0, 7)} ${p.risk_score}점`).join(", "));
  if (points.length < 2) return;
  const xy = points.map((p, i) => [4 + i * 112 / (points.length - 1), 32 - p.risk_score * 0.28]);
  const shape = (tag, attrs) => {
    const item = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attrs)) item.setAttribute(key, value);
    return item;
  };
  svg.append(shape("polyline", {class: "line", points: xy.map(p => p.join(",")).join(" ")}));
  points.forEach((p, i) => {
    const [x, y] = xy[i], current = p.scan_id === d.scan_id;
    svg.append(shape("circle", {class: current ? "now" : "dot", cx: x, cy: y, r: current ? 5 : 4}));
    const hit = shape("circle", {class: "hit", cx: x, cy: y, r: 9});
    const label = shape("title", {});
    label.textContent = `${(p.commit || "커밋 미확인").slice(0, 12)} · 위험 점수 ${p.risk_score} · ${new Date(p.scanned_at).toLocaleString("ko-KR")}`;
    hit.append(label);
    svg.append(hit);
  });
}
function render() {
  const d = result;
  $("repo-name").textContent = d.repo.name;
  $("repo-meta").textContent = `${d.repo.branch || "브랜치 미확인"} / ${(d.commit || "커밋 미확인").slice(0, 12)} · ${new Date(d.scanned_at).toLocaleString("ko-KR")} · ${d.repo.path}`;
  $("risk").textContent = d.risk_score;
  renderTrend(d);
  $("total").textContent = Object.values(d.summary).reduce((a, b) => a + b, 0);
  $("dismissed").textContent = `오탐 후보 ${d.dismissed_count}건 · 목록에서 근거 확인`;
  const compared = Boolean(d.baseline_commit);
  $("delta").textContent = compared ? `+${d.delta.new} / −${d.delta.fixed}` : "아직 비교 전";
  $("delta-note").textContent = compared ? `새 발견 ${d.delta.new}건 · 해결 ${d.delta.fixed}건 · 직전 스캔 ${d.baseline_commit.slice(0, 12)} 대비` : "비교할 이전 결과가 없습니다";
  $("severity-bars").replaceChildren();
  for (const level of levels) {
    const row = node("div", "", "bar-row"), meter = document.createElement("meter");
    meter.min = 0; meter.max = Math.max(1, ...Object.values(d.summary)); meter.value = d.summary[level];
    meter.setAttribute("aria-label", `${level} ${d.summary[level]}건`);
    row.append(node("span", level, "severity"), meter, node("span", d.summary[level]));
    $("severity-bars").append(row);
  }
  $("analysis-note").textContent = d.analysis_note || "모델 분석 기록 없음";
  $("profile").textContent = `${d.profile.framework || "프레임워크 미확인"} · 라우트 ${d.profile.routes}개 · ${d.profile.auth || "인증 방식 미확인"}`;
  $("coverage").replaceChildren();
  const execution = {completed: "자동 점검 범위 검사 완료", unsupported: "지원 소스 없음 · 미검사", manual: "수동 확인 필요 · 미검사", partial: "부분 점검 · 수동 확인 포함"};
  for (const check of d.coverage) $("coverage").append(node("li", `${check.name} — ${execution[check.execution] || "검사 여부 미확인"}. ${check.reason || ""}`));
  if (!d.coverage.length) $("coverage").append(node("li", "이 결과에는 검사 범위 기록이 없습니다."));
  $("limitations").replaceChildren(...d.profile.limitations.map(text => node("li", text)));
  $("priorities").replaceChildren();
  const priorities = sortedFindings().filter(f => findingStatus(f) === "open").slice(0, 3);
  for (const f of priorities) {
    const row = node("div", "", "priority"), text = node("div", "");
    text.append(findingButton(f), node("p", locationText(f), "muted"));
    row.append(badge(f.severity), text); $("priorities").append(row);
  }
  if (!priorities.length) $("priorities").append(node("p", "열린 발견이 없습니다. 미검사 항목과 오탐 후보도 확인하세요.", "muted"));
  filterFindings();
  $("result").hidden = false;
}
async function selectScan() {
  const version = ++detailVersion;
  $("result").hidden = true;
  result = null;
  try {
    const data = await api("/api/scans/" + encodeURIComponent($("scan-select").value));
    if (version !== detailVersion) return;
    result = data;
    render();
  } catch (error) { if (version === detailVersion) message(error.message, true); }
}
async function refresh(preferred = null) {
  $("refresh").disabled = true;
  $("scan-select").disabled = true;
  ++detailVersion;
  $("result").hidden = true;
  $("empty").hidden = true;
  message("저장된 진단 결과를 불러오는 중입니다.");
  try {
    const previous = preferred || $("scan-select").value;
    const data = await api("/api/scans");
    scanList = data.scans;
    $("results-path").textContent = `결과 폴더: ${data.results_path}`;
    $("scan-select").replaceChildren();
    for (const scan of data.scans) {
      const option = node("option", `${scan.repo.name} · ${(scan.commit || "커밋 미확인").slice(0, 12)} · ${new Date(scan.scanned_at).toLocaleString("ko-KR")}`);
      option.value = scan.scan_id; $("scan-select").append(option);
    }
    $("scan-select").disabled = !data.scans.length;
    $("empty").hidden = !!data.scans.length;
    message(data.unavailable ? `읽을 수 없는 결과 폴더 ${data.unavailable}개를 제외했습니다. 파일 형식과 접근 권한을 확인하세요.` : "");
    if (data.scans.length) {
      if (data.scans.some(s => s.scan_id === previous)) $("scan-select").value = previous;
      await selectScan();
    } else $("scan-select").append(node("option", "저장된 스캔 없음"));
  } catch (error) { message(error.message, true); }
  finally { $("refresh").disabled = false; }
}
function jobMessage(text, error = false) {
  $("job-message").textContent = text;
  $("job-message").classList.toggle("error", error);
}
// What the user can do about each model problem the engine reports (SessionError.kind).
const issueHints = {
  limit: "ChatGPT 사용량 한도에 도달했습니다. ChatGPT 설정의 사용량(Usage)에서 이 앱의 한도를 확인하세요.",
  plan: "ChatGPT Plus/Pro 구독과 ‘Use your ChatGPT plan’ 승인이 필요합니다.",
  login: "ChatGPT 연결이 필요합니다. 위의 ‘ChatGPT로 로그인’을 누르세요.",
  register: "먼저 터미널에서 python -m vibescan.register 로 이 PC를 등록하세요.",
  error: "모델 분석 일부를 완료하지 못했습니다.",
};
function busy(running) {
  scanning = running;
  for (const id of ["connect", "repo-path"]) $(id).disabled = running;
  $("use-model").disabled = running || auth?.state !== "ready";
  $("repo-select").disabled = running || !$("repo-select").value;
  $("scan").disabled = running || !$("repo-select").value;
  $("scan").textContent = running ? "스캔 중…" : "다시 스캔";
  const repo = repoList.find(r => r.path === $("repo-select").value);
  $("hook-toggle").hidden = !repo || repo.hook === null;  // null: GitHub clone, never committed to here
  $("hook-toggle").disabled = running;
  $("hook-toggle").textContent = repo?.hook ? "커밋 후 자동 스캔 끄기" : "커밋 후 자동 스캔 켜기";
  $("notify").hidden = !repo?.hook || !("Notification" in globalThis) || Notification.permission !== "default";
  $("background-llm").disabled = running || (auth?.state !== "ready" && !$("background-llm").checked);
}
function renderProgress(title, state) {
  // state: {stage, log} from the dashboard's own scan or from a commit hook's live file; null hides it.
  $("progress").hidden = !state;
  if (!state) return;
  $("progress-title").textContent = title;
  $("progress-steps").replaceChildren(...stages.map((name, i) => {
    const item = node("li", name, i < state.stage ? "done" : i === state.stage ? "current" : "");
    if (i === state.stage) item.setAttribute("aria-current", "step");
    return item;
  }));
  $("activity").replaceChildren(...(state.log || []).slice(-8).map(text => node("li", text)));
}
function alertNewRisks(scan) {
  // Only what this commit introduced: existing findings never alert twice.
  const fresh = scan.findings.filter(f => f.change === "new" && f.status === "open" && ["Critical", "High"].includes(f.severity));
  if (!fresh.length) return false;
  const text = `커밋 ${(scan.commit || "").slice(0, 12)}에서 새 Critical/High ${fresh.length}건: ${fresh[0].title}${fresh.length > 1 ? " 외" : ""}`;
  jobMessage(text, true);
  if ("Notification" in globalThis && Notification.permission === "granted") new Notification("VibeScan · 새 위험 발견", {body: text});
  return true;
}
async function loadRepos(preferred = null) {
  const data = await api("/api/repos");
  repoList = data.repos;
  const previous = preferred || $("repo-select").value;
  $("repo-select").replaceChildren();
  for (const repo of data.repos) {
    const option = node("option", `${repo.name} · ${repo.path}`);
    option.value = repo.path;
    $("repo-select").append(option);
  }
  if (data.repos.some(repo => repo.path === previous)) $("repo-select").value = previous;
  if (!data.repos.length) {
    const option = node("option", "연결된 레포 없음"); option.value = ""; $("repo-select").append(option);
  }
  busy(scanning);
}
async function pollJob() {
  clearTimeout(pollTimer);
  const version = ++jobVersion;
  try {
    const job = await api("/api/scan");
    if (version !== jobVersion) return;
    stages = job.stages || stages;
    busy(job.state === "running");
    renderProgress(`${job.repo} · ${job.offline ? "정적 검사" : "정적 검사 및 ChatGPT 분석"}`, scanning ? job : null);
    if (scanning) {
      jobMessage(`${job.repo} · ${job.offline ? "정적 검사" : "정적 검사 및 ChatGPT 분석"} 진행 중입니다. 완료되면 결과가 자동으로 열립니다.`);
      pollTimer = setTimeout(pollJob, 1000);
    } else if (job.state === "completed" && job.issue) {
      jobMessage(`스캔 완료 · 정적 검사 결과는 저장되었습니다. ${issueHints[job.issue] || ""} (${job.message})`, true);
      await Promise.all([refresh(job.scan_id), loadAuth()]);
    } else if (job.state === "completed") {
      jobMessage(`스캔 완료 · ${job.message}`);
      await refresh(job.scan_id);
    } else if (job.state === "failed") jobMessage(job.message, true);
  } catch (error) {
    if (version !== jobVersion) return;
    jobMessage(error.message, true);
    if (scanning) pollTimer = setTimeout(pollJob, 3000);
  }
}
$("connect-form").addEventListener("submit", async event => {
  event.preventDefault();
  $("connect").disabled = true;
  if (/^(https?:\/\/|git@)/.test($("repo-path").value.trim())) jobMessage("GitHub에서 저장소를 복제하는 중입니다. 저장소 크기에 따라 몇 분 걸릴 수 있습니다.");
  try {
    const repo = await api("/api/repos", {path: $("repo-path").value});
    await loadRepos(repo.path);
    jobMessage(`${repo.name} 연결 완료 · ${repo.branch || "분리된 HEAD"} / ${repo.commit.slice(0, 12)}. ‘다시 스캔’을 눌러 검사하세요.`);
  } catch (error) { jobMessage(error.message, true); }
  finally { $("connect").disabled = scanning; }
});
async function loadAuth() {
  clearTimeout(authTimer);
  try {
    auth = await api("/api/auth");
    const running = auth.login.state === "running";
    const failed = auth.login.state === "failed" && auth.state !== "ready";
    $("auth-status").textContent = running ? auth.login.message : failed ? `${auth.login.message} · ${auth.message}` : auth.message;
    $("auth-status").classList.toggle("error", !running && auth.state !== "ready");
    $("login").hidden = auth.state === "register";
    $("login").disabled = running;
    $("login").textContent = auth.state === "ready" ? "다시 로그인" : "ChatGPT로 로그인";
    $("logout").hidden = !["ready", "plan"].includes(auth.state);
    $("logout").disabled = running;
    if (auth.state !== "ready") $("use-model").checked = false;
    // Only the tab that pressed the button follows the login; ChatGPT sends it back here afterwards.
    if (running && loginRequested && auth.login.url) return location.assign(auth.login.url);
    if (running) authTimer = setTimeout(loadAuth, loginRequested ? 300 : 1500);
  } catch (error) {
    auth = null;
    $("auth-status").textContent = error.message;
    $("auth-status").classList.add("error");
  }
  busy(scanning);
}
$("login").addEventListener("click", async () => {
  $("login").disabled = true;
  try { await api("/api/login", {}); loginRequested = true; }
  catch (error) { $("auth-status").textContent = error.message; $("auth-status").classList.add("error"); }
  await loadAuth();
});
$("logout").addEventListener("click", async () => {
  $("logout").disabled = true;
  try { await api("/api/logout", {}); }
  catch (error) { $("auth-status").textContent = error.message; $("auth-status").classList.add("error"); }
  await loadAuth();
});
$("repo-select").addEventListener("change", () => busy(scanning));
$("notify").addEventListener("click", async () => {
  await Notification.requestPermission();
  busy(scanning);
});
$("background-llm").addEventListener("change", async () => {
  const wanted = $("background-llm").checked;
  try {
    const saved = await api("/api/settings", {background_llm: wanted});
    $("background-llm").checked = saved.background_llm;
    jobMessage(saved.background_llm ? "자동 스캔에서 새로 생긴 High 이상 발견만 ChatGPT로 검토합니다. 구독 사용량이 차감됩니다."
      : "자동 스캔은 ChatGPT를 사용하지 않습니다.");
  } catch (error) { $("background-llm").checked = !wanted; jobMessage(error.message, true); }
  busy(scanning);
});
$("hook-toggle").addEventListener("click", async () => {
  const repo = repoList.find(r => r.path === $("repo-select").value);
  if (!repo) return;
  $("hook-toggle").disabled = true;
  try {
    const data = await api("/api/hook", {path: repo.path, enabled: !repo.hook});
    jobMessage(data.hook ? "커밋 후 자동 스캔을 켰습니다. 이 레포에서 커밋하면 몇 초 뒤 결과가 여기에 나타납니다."
      : "커밋 후 자동 스캔을 껐습니다.");
    await loadRepos(repo.path);
  } catch (error) { jobMessage(error.message, true); busy(scanning); }
});
async function pollLatest() {
  // Results written by the commit hook appear without pressing anything.
  try {
    const job = await api("/api/scan");
    stages = job.stages || stages;
    if (!scanning) {
      const live = job.hook;
      renderProgress(live ? `커밋 ${live.commit.slice(0, 12)} 자동 스캔 · ${live.repo}` : "", live);
      if (live) jobMessage("커밋 후 자동 스캔이 진행 중입니다. 완료되면 결과가 자동으로 열립니다.");
    }
    const {scan_id: id} = await api("/api/latest");
    if (id && latestSeen !== undefined && id !== latestSeen && !scanning && !scanList.some(s => s.scan_id === id)) {
      await refresh(id);
      if (result?.scan_id === id && !alertNewRisks(result)) jobMessage(`커밋 ${(result.commit || "").slice(0, 12)}의 자동 스캔 결과가 도착했습니다.`);
    }
    latestSeen = id;
  } catch { /* the next poll retries; manual refresh still works */ }
  setTimeout(pollLatest, 3000);
}
$("scan").addEventListener("click", async () => {
  ++jobVersion;
  clearTimeout(pollTimer);
  busy(true);
  jobMessage("스캔을 시작하고 있습니다.");
  try {
    await api("/api/scan", {path: $("repo-select").value, offline: !$("use-model").checked});
    await pollJob();
  } catch (error) {
    jobMessage(error.message, true);
    // The request may have started a scan even if its response was lost.
    await pollJob();
  }
});
$("refresh").addEventListener("click", () => refresh());
$("scan-select").addEventListener("change", selectScan);
for (const id of ["severity-filter", "status-filter"]) $(id).addEventListener("change", filterFindings);
$("search").addEventListener("input", filterFindings);
$("close-detail").addEventListener("click", () => $("detail").close());
$("download").addEventListener("click", () => {
  if (!result) return;
  const url = URL.createObjectURL(new Blob([result.report_md], {type: "text/markdown;charset=utf-8"}));
  const link = node("a", ""); link.href = url; link.download = `vibescan-${result.scan_id}.md`;
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
refresh();
loadRepos().catch(error => jobMessage(error.message, true));
loadAuth();
pollJob();
pollLatest();
api("/api/settings").then(saved => { $("background-llm").checked = saved.background_llm; busy(scanning); }).catch(() => {});
