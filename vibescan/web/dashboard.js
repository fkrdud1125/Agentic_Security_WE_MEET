"use strict";
// Constants and storage. The URL hash is exclusively the loopback access ticket.
const $ = id => document.getElementById(id);
const levels = ["Critical", "High", "Medium", "Low", "Info"];
const severityLabels = {Critical: "치명", High: "높음", Medium: "보통", Low: "낮음", Info: "정보"};
const confidenceLabels = {Confirmed: "확인됨", Likely: "가능성 높음", Potential: "잠재적"};
const statuses = {open: "열림", dismissed: "오탐 후보", fixed: "해결됨"};
const changes = {new: "새로 발견", existing: "기존", fixed: "해결"};
const issueHints = {
  limit: "ChatGPT 사용량 한도에 도달했습니다. ChatGPT 설정의 사용량에서 이 앱의 한도를 확인하세요.",
  plan: "ChatGPT Plus/Pro 구독과 구독 사용 승인이 필요합니다.",
  login: "설정에서 ChatGPT에 다시 연결하세요.",
  register: "먼저 터미널에서 python -m vibescan.register 로 이 PC를 등록하세요.",
  error: "모델 분석 일부를 완료하지 못했습니다.",
};
function stored(storage, key, fallback = "") {
  try { return globalThis[storage].getItem(key) || fallback; } catch { return fallback; }
}
function remember(storage, key, value) {
  try { globalThis[storage].setItem(key, value); } catch { /* Persistence is optional. */ }
}
const token = location.hash.slice(1) || stored("sessionStorage", "vibescan-token");
if (location.hash) {
  remember("sessionStorage", "vibescan-token", token);
  history.replaceState(null, "", location.pathname + (location.search || ""));
}

// State
let result = null, scanList = [], repoList = [], visibleFindings = [], stages = [];
let selectedProject = stored("localStorage", "vibescan-project");
let scanMode = stored("localStorage", "vibescan-mode", "local") === "ai" ? "ai" : "local";
let statusFilter = "open", severityFilter = new Set(), newOnly = false;
let latestSeen, detailVersion = 0, refreshVersion = 0, jobVersion = 0;
let scanning = false, connecting = false, hookPending = false, backgroundPending = false;
let pollTimer = null, authTimer = null, toastTimer = null, loginRequested = false, auth = null;
let activeDrawer = null, returnFocus = null, detailFinding = null, lastJob = "";
let retryAction = null, resultsPath = "", latestPollFailed = false;
const jobIssues = new Map(), notifiedScans = new Set();

// DOM and API
function node(tag, text = "", className = "") {
  const item = document.createElement(tag);
  item.textContent = text;
  if (className) item.className = className;
  return item;
}
function badge(level) {
  const known = levels.includes(level) ? level : "Info";
  return node("span", severityLabels[known], "badge " + known);
}
function findingStatus(f) { return f.change === "fixed" ? "fixed" : (f.status || "open"); }
function locationText(f) { return (f.location?.file || "파일 미확인") + (f.location?.line ? ":" + f.location.line : ""); }
function dateText(value) { return new Date(value).toLocaleString("ko-KR", {month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit"}); }
function message(text, error = false, retry = null) {
  clearTimeout(toastTimer);
  $("message").textContent = text;
  $("toast").hidden = !text;
  $("toast").classList.toggle("error", error);
  retryAction = retry;
  $("retry").hidden = !retry;
  if (text && !error) toastTimer = setTimeout(() => { $("toast").hidden = true; }, 6000);
}
async function api(path, body) {
  const response = await fetch(path, {method: body === undefined ? "GET" : "POST",
    headers: {"X-VibeScan-Token": token, "Content-Type": "application/json"},
    body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store"});
  if (!response.ok) {
    if (response.status === 403) throw new Error("접속 권한이 만료되었습니다. 터미널에 표시된 대시보드 주소로 다시 여세요.");
    const data = await response.json().catch(() => ({}));
    throw new Error(typeof data.detail === "string" ? data.detail : "요청을 처리할 수 없습니다. 입력과 파일 상태를 확인하세요.");
  }
  return response.json();
}
async function copyText(text, success) {
  try { await navigator.clipboard.writeText(text); message(success); }
  catch { message("복사 권한이 없습니다. 텍스트를 선택해 복사하세요.", true); }
}
function selectedRepo() { return repoList.find(repo => repo.path === selectedProject); }
function projectScans(path = selectedProject) { return scanList.filter(scan => scan.repo.path === path); }
function projects() {
  const combined = new Map(repoList.map(repo => [repo.path, {...repo, connected: true}]));
  for (const scan of scanList) {
    if (!combined.has(scan.repo.path)) combined.set(scan.repo.path, {...scan.repo, connected: false, hook: null});
    const project = combined.get(scan.repo.path);
    if (!project.latest || scan.scanned_at > project.latest.scanned_at) project.latest = scan;
  }
  return [...combined.values()];
}

// Project selection: project, history and visible result always move together.
function renderProjects() {
  const items = projects();
  $("project-count").textContent = String(items.length).padStart(2, "0");
  $("projects").replaceChildren(...items.map(project => {
    const button = node("button", "", "project-button");
    button.type = "button";
    button.dataset.path = project.path;
    button.setAttribute("aria-current", project.path === selectedProject ? "page" : "false");
    const state = !project.connected ? "결과만 있음 · 스캔하려면 연결 필요" : project.hook ? "자동 감시 켜짐" : "자동 감시 꺼짐";
    button.title = project.path + " · " + state;
    const dot = node("span", !project.connected ? "◌" : project.hook ? "●" : "○", "project-dot" + (project.hook ? " watching" : ""));
    dot.setAttribute("aria-label", state);
    button.append(dot, node("span", project.name, "project-name"), node("span", project.latest ? project.latest.risk_score : "··", "project-score"));
    button.addEventListener("click", () => chooseProject(project.path));
    return button;
  }));
}
function renderHistory(preferred) {
  const scans = projectScans();
  $("scan-select").replaceChildren(...scans.map(scan => {
    const trigger = scan.trigger === "git-hook" || scan.trigger === "watcher" ? "자동" : "수동";
    const option = node("option", `${(scan.commit || "커밋 없음").slice(0, 7)} · ${dateText(scan.scanned_at)} · ${scan.risk_score}점 · ${trigger}`);
    option.value = scan.scan_id;
    return option;
  }));
  if (!scans.length) {
    const option = node("option", "스캔 기록 없음"); option.value = "";
    $("scan-select").append(option);
  }
  $("scan-select").value = scans.some(scan => scan.scan_id === preferred) ? preferred : scans[0]?.scan_id || "";
  $("scan-select").disabled = !scans.length;
}
function resetFilters() {
  statusFilter = "open"; severityFilter.clear(); newOnly = false; $("search").value = "";
  if (result) { renderTabs(); renderSeverity(); filterFindings(); }
}
function emptyState() {
  const project = projects().find(p => p.path === selectedProject);
  $("result").hidden = true; $("empty").hidden = false;
  $("download").disabled = true; $("analysis-badge").hidden = true;
  $("repo-name").textContent = project?.name || "진단 대시보드";
  $("repo-name").title = project?.path || "";
  $("repo-meta").textContent = project ? "아직 스캔 기록이 없습니다" : "프로젝트를 연결해 시작하세요";
  $("empty-description").textContent = project ? "연결이 완료됐습니다. 첫 스캔을 실행해 발견한 문제와 수정 방법을 확인하세요." : "코드에서 발견한 문제와 근거, 수정 방법을 한곳에 모읍니다.";
  renderOnboarding();
}
function renderOnboarding() {
  for (const [id, done, number] of [
    ["step-project", Boolean(selectedRepo()), "01"], ["step-scan", projectScans().length > 0, "02"], ["step-auth", auth?.state === "ready", "03"]]) {
    $(id).textContent = done ? "✓ 완료" : number; $(id).classList.toggle("complete", done);
  }
  $("onboard-scan").disabled = scanning || !selectedRepo();
}
async function chooseProject(path, preferred = null) {
  if (!projects().some(project => project.path === path)) return;
  const changed = path !== selectedProject;
  selectedProject = path;
  remember("localStorage", "vibescan-project", path);
  ++detailVersion;
  if (changed) { closeDrawer(); result = null; resetFilters(); }
  renderProjects(); renderHistory(preferred); busy(scanning);
  if ($("scan-select").value) await selectScan();
  else { result = null; emptyState(); }
}
async function selectScan() {
  const id = $("scan-select").value, path = selectedProject, version = ++detailVersion;
  if (!id) { result = null; emptyState(); return; }
  // Old results must not remain actionable while their replacement is loading.
  $("download").disabled = true;
  if (result?.repo.path !== path) $("result").hidden = true;
  $("result").setAttribute("aria-busy", "true");
  try {
    const data = await api("/api/scans/" + encodeURIComponent(id));
    if (version !== detailVersion || path !== selectedProject) return;
    if (data.repo.path !== path || data.scan_id !== id) throw new Error("프로젝트와 스캔 결과가 일치하지 않습니다.");
    closeDrawer();
    result = data; render();
  } catch (error) {
    if (version === detailVersion) {
      result = null; emptyState();
      $("repo-meta").textContent = "결과를 불러오지 못했습니다";
      message(error.message, true, selectScan);
    }
  } finally { if (version === detailVersion) $("result").setAttribute("aria-busy", "false"); }
}
async function refresh(preferred = null) {
  const version = ++refreshVersion;
  try {
    const data = await api("/api/scans");
    if (version !== refreshVersion) return;
    const oldId = $("scan-select").value;
    scanList = data.scans || []; resultsPath = data.results_path || "";
    $("results-path").textContent = resultsPath;
    const items = projects();
    if (!items.some(p => p.path === selectedProject)) {
      selectedProject = items[0]?.path || "";
      remember("localStorage", "vibescan-project", selectedProject);
      result = null; resetFilters();
    }
    renderProjects();
    const preferredScan = projectScans().find(scan => scan.scan_id === preferred);
    renderHistory(preferredScan?.scan_id || oldId);
    busy(scanning);
    if ($("scan-select").value) {
      if (result?.scan_id !== $("scan-select").value || result?.repo.path !== selectedProject) await selectScan();
    } else { ++detailVersion; result = null; emptyState(); }
    if (data.unavailable) message(`읽을 수 없는 결과 폴더 ${data.unavailable}개를 제외했습니다. 파일 형식과 권한을 확인하세요.`, true, refresh);
  } catch (error) { if (version === refreshVersion) message(error.message, true, refresh); }
}
async function loadRepos() {
  const data = await api("/api/repos");
  repoList = data.repos || [];
  renderProjects(); busy(scanning);
}

// Result rendering
function sortedFindings() {
  return [...(result?.findings || [])].sort((a, b) =>
    Number(b.change === "new") - Number(a.change === "new") || levels.indexOf(a.severity) - levels.indexOf(b.severity));
}
function riskGrade(findings) {
  const highest = levels.find(level => findings.some(f => findingStatus(f) === "open" && f.severity === level));
  return {label: ({Critical: "심각", High: "위험", Medium: "주의", Low: "낮음", Info: "낮음"})[highest] || "발견 없음", level: highest || "Info"};
}
function freshRisks(scan) { return scan.findings.filter(f => f.change === "new" && findingStatus(f) === "open" && ["Critical", "High"].includes(f.severity)); }
function renderTrend(d) {
  const points = projectScans(d.repo.path).filter(s => new Date(s.scanned_at) <= new Date(d.scanned_at))
    .sort((a, b) => new Date(a.scanned_at) - new Date(b.scanned_at)).slice(-8);
  const svg = $("risk-trend");
  svg.replaceChildren(); svg.hidden = points.length < 2;
  $("risk-trend-note").textContent = points.length < 2 ? "다음 스캔부터 추이 표시" : `최근 ${points.length}회 · ${points[0].risk_score} → ${d.risk_score}점`;
  svg.setAttribute("aria-label", points.map(p => `${(p.commit || "커밋 없음").slice(0, 7)} ${p.risk_score}점`).join(", "));
  if (points.length < 2) return;
  const shape = (tag, attrs) => {
    const item = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attrs)) item.setAttribute(key, String(value));
    return item;
  };
  const xy = points.map((p, i) => [5 + i * 350 / (points.length - 1), 58 - Math.max(0, Math.min(100, p.risk_score)) * .52]);
  svg.append(shape("line", {class: "grid-line", x1: 0, x2: 360, y1: 58, y2: 58}));
  svg.append(shape("polygon", {class: "area", points: [[5, 64], ...xy, [355, 64]].map(p => p.join(",")).join(" ")}));
  svg.append(shape("polyline", {class: "line", points: xy.map(p => p.join(",")).join(" ")}));
  points.forEach((p, i) => {
    const [x, y] = xy[i];
    svg.append(shape("circle", {class: p.scan_id === d.scan_id ? "now" : "dot", cx: x, cy: y, r: 3}));
    const hit = shape("circle", {class: "hit", cx: x, cy: y, r: 9}), label = shape("title", {});
    label.textContent = `${(p.commit || "커밋 없음").slice(0, 12)} · ${p.risk_score}점 · ${dateText(p.scanned_at)}`;
    hit.append(label); svg.append(hit);
  });
}
function renderSeverity() {
  const summary = result.summary || {};
  const total = levels.reduce((sum, level) => sum + (summary[level] || 0), 0);
  $("severity-bars").replaceChildren();
  $("severity-bars").setAttribute("aria-label", levels.map(l => `${severityLabels[l]} ${summary[l] || 0}건`).join(", "));
  for (const level of levels) {
    if (!summary[level]) continue;
    const segment = node("span", "", "stack-segment " + level);
    segment.style.flexGrow = String(summary[level] / Math.max(1, total));
    segment.title = `${severityLabels[level]} ${summary[level]}건`;
    $("severity-bars").append(segment);
  }
  $("severity-chips").replaceChildren(...levels.map(level => {
    const chip = node("button", "", "severity-chip " + level);
    chip.type = "button"; chip.dataset.severity = level;
    chip.setAttribute("aria-pressed", String(severityFilter.has(level)));
    chip.setAttribute("aria-label", `${severityLabels[level]} ${summary[level] || 0}건 필터`);
    const name = node("span", "", "chip-name");
    name.append(node("span", "", "chip-dot"), node("span", severityLabels[level]));
    chip.append(name, node("strong", summary[level] || 0));
    chip.addEventListener("click", () => {
      severityFilter.has(level) ? severityFilter.delete(level) : severityFilter.add(level);
      renderSeverity(); filterFindings();
      $("severity-chips").querySelector(`[data-severity="${level}"]`)?.focus();
    });
    return chip;
  }));
}
function renderTabs() {
  const counts = {open: 0, dismissed: 0, fixed: 0};
  for (const finding of result.findings) counts[findingStatus(finding)]++;
  $("status-tabs").replaceChildren(...["open", "dismissed", "fixed", ""].map(status => {
    const tab = node("button", status ? statuses[status] : "전체", "tab");
    tab.type = "button"; tab.dataset.status = status;
    tab.id = "tab-" + (status || "all");
    tab.setAttribute("role", "tab"); tab.setAttribute("aria-controls", "findings");
    tab.setAttribute("aria-selected", String(status === statusFilter));
    tab.tabIndex = status === statusFilter ? 0 : -1;
    tab.append(node("span", status ? counts[status] : result.findings.length, "tab-count"));
    tab.addEventListener("click", () => { statusFilter = status; renderTabs(); filterFindings(); $(tab.id).focus(); });
    tab.addEventListener("keydown", event => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const options = ["open", "dismissed", "fixed", ""], index = options.indexOf(statusFilter);
      statusFilter = event.key === "Home" ? options[0] : event.key === "End" ? "" : options[(index + (event.key === "ArrowRight" ? 1 : 3)) % 4];
      renderTabs(); filterFindings(); $("tab-" + (statusFilter || "all")).focus();
    });
    return tab;
  }));
  $("findings").setAttribute("aria-labelledby", "tab-" + (statusFilter || "all"));
}
function filterFindings() {
  if (!result) return;
  const query = $("search").value.toLocaleLowerCase().trim();
  visibleFindings = sortedFindings().filter(f => (!statusFilter || findingStatus(f) === statusFilter)
    && (!severityFilter.size || severityFilter.has(f.severity)) && (!newOnly || f.change === "new")
    && `${f.title} ${f.location?.file || ""} ${f.cwe || ""}`.toLocaleLowerCase().includes(query));
  $("filtered-count").textContent = String(visibleFindings.length).padStart(2, "0");
  $("no-findings").hidden = visibleFindings.length !== 0;
  $("new-filter").hidden = !newOnly; $("new-filter").setAttribute("aria-pressed", String(newOnly));
  const narrowed = severityFilter.size || newOnly || query;
  $("no-findings-title").textContent = narrowed ? "조건에 맞는 발견이 없습니다"
    : statusFilter === "open" ? "열린 발견이 없습니다" : "이 상태의 발견이 없습니다";
  $("no-findings-hint").textContent = narrowed ? "심각도 선택을 해제하거나 검색어를 지워 보세요."
    : "적용한 규칙에서 찾은 항목이 없다는 뜻이며, 안전을 보증하지는 않습니다.";
  $("findings").replaceChildren(...visibleFindings.map(f => {
    const row = node("button", "", "finding-row " + (levels.includes(f.severity) ? f.severity : "Info"));
    row.type = "button"; row.dataset.findingId = f.id;
    row.setAttribute("aria-label", `${severityLabels[f.severity]} · ${f.title} · ${locationText(f)} · ${statuses[findingStatus(f)]}`);
    const name = node("span", "", "finding-title-wrap"), title = node("span", f.title, "finding-title");
    title.title = f.title; name.append(title);
    if (f.change === "new") name.append(node("span", changes.new, "new-tag"));
    const loc = node("span", locationText(f), "finding-location"); loc.title = locationText(f);
    row.append(badge(f.severity), name, loc, node("span", "›", "row-arrow"));
    row.addEventListener("click", () => showDetail(f));
    return row;
  }));
}
function renderCoverage() {
  const checks = result.coverage || [], completed = checks.filter(c => c.execution === "completed").length;
  $("coverage-summary").textContent = checks.length ? `${checks.length}개 점검 중 ${completed}개 완료${completed < checks.length ? ` · ${checks.length - completed}개 미완료·수동 확인` : ""}` : "검사 범위 기록 없음";
  const execution = {completed: "✓ 자동 점검 범위 검사 완료", partial: "◐ 부분 점검 · 수동 확인 포함", manual: "◐ 수동 확인 필요 · 미검사", unsupported: "✕ 지원 소스 없음 · 미검사"};
  $("coverage").replaceChildren(...checks.map(c => node("li", `${c.name} — ${execution[c.execution] || "✕ 검사 여부 미확인"}. ${c.reason || ""}`)));
  const profile = result.profile || {};
  $("limitations").replaceChildren(...(profile.limitations || []).map(text => node("li", text)));
  $("profile").textContent = `${profile.framework || "프레임워크 미확인"} · 라우트 ${profile.routes || 0}개 · ${profile.auth || "인증 방식 미확인"}`;
}
function analysisState(d) {
  const note = d.analysis_note || "", issue = jobIssues.get(d.scan_id);
  if (issue || /실패|미완료|한도|중단|오류|모델.*못|분석.*못|검토.*못/.test(note))
    return {label: "AI 분석 일부 실패 ⓘ", className: "warning", hint: [note, issueHints[issue] || issueHints.error].filter(Boolean).join(" · ")};
  if (/모델|ChatGPT|AI/.test(note) && !/미사용|사용하지|없음|오프라인/.test(note))
    return {label: "AI 분석 포함", className: "", hint: note};
  return {label: "로컬 검사만", className: "local", hint: note || "모델 분석 기록 없음"};
}
function render() {
  const d = result, grade = riskGrade(d.findings), analysis = analysisState(d);
  $("repo-name").textContent = d.repo.name; $("repo-name").title = d.repo.path;
  $("repo-meta").textContent = `${d.repo.branch || "브랜치 미확인"} · ${(d.commit || "커밋 없음").slice(0, 7)} · ${dateText(d.scanned_at)}`;
  $("analysis-badge").textContent = analysis.label; $("analysis-badge").className = "analysis-badge " + analysis.className;
  $("analysis-badge").title = analysis.hint; $("analysis-badge").hidden = false;
  $("risk-grade").textContent = grade.label; $("risk").textContent = d.risk_score;
  renderTrend(d);
  $("delta").textContent = d.baseline_commit ? `+${d.delta?.new || 0} 새 위험 · −${d.delta?.fixed || 0} 해결` : "첫 스캔 · 다음 스캔부터 비교";
  $("delta").title = d.baseline_commit ? "기준 커밋 " + d.baseline_commit : "";
  const fresh = freshRisks(d);
  $("risk-alert").hidden = !fresh.length;
  $("risk-alert-text").textContent = `이번 커밋에서 치명·높음 위험 ${fresh.length}건이 새로 발견됐어요.`;
  renderSeverity(); renderTabs(); filterFindings(); renderCoverage();
  $("empty").hidden = true; $("result").hidden = false; $("download").disabled = false;
  renderOnboarding();
}

// Drawers: keep the list visible while isolating keyboard focus.
function setPageInert(value) {
  $("workspace").inert = value;
  document.querySelector(".sidebar").inert = value;
}
function openDrawer(id) {
  if (activeDrawer === id) return;
  const origin = document.activeElement;
  closeDrawer(false); returnFocus = origin; activeDrawer = id;
  $(id).hidden = false;
  document.body.classList.toggle("detail-open", id === "detail");
  $("settings-backdrop").hidden = id !== "settings";
  setPageInert(true); $(id).focus();
}
function closeDrawer(restore = true) {
  if (!activeDrawer) return;
  $(activeDrawer).hidden = true; activeDrawer = null;
  document.body.classList.remove("detail-open"); $("settings-backdrop").hidden = true;
  setPageInert(false);
  if (restore && returnFocus?.isConnected) returnFocus.focus();
  returnFocus = null;
}
function showDetail(f) {
  detailFinding = f;
  $("detail-badge").replaceChildren(badge(f.severity));
  if (f.change === "new") $("detail-badge").append(node("span", changes.new, "new-tag"));
  $("detail-title").textContent = f.title; $("detail-location").textContent = locationText(f);
  $("impact").textContent = f.impact_ko || "영향 설명 없음";
  $("evidence").textContent = f.evidence || "근거 없음";
  $("remediation").textContent = f.remediation_ko || "수정 방법 없음";
  $("fix-diff").replaceChildren(...(f.fix_diff || "제공된 수정 코드가 없습니다.").split("\n").map(line =>
    node("span", line, "diff-line" + (line.startsWith("+") && !line.startsWith("+++") ? " diff-add" : line.startsWith("-") && !line.startsWith("---") ? " diff-remove" : ""))));
  $("fix-note").textContent = "동작 검증 전 제안 · " + (f.fix_note || "실제 코드 문맥에서 검토 필요");
  $("copy-diff").disabled = !f.fix_diff;
  $("ai-fix-hint").hidden = !!f.fix_diff || auth?.state !== "ready" || !selectedRepo();
  $("detail-meta").textContent = [f.cwe, f.owasp, "신뢰도 " + (confidenceLabels[f.confidence] || "미확인"),
    statuses[findingStatus(f)], f.introduced_in ? "처음 발견 커밋 " + f.introduced_in.slice(0, 12) : ""].filter(Boolean).join(" · ");
  $("how-found").textContent = (f.how_found || []).join(" · ") || "기록 없음";
  $("triage").textContent = f.triage_reason || "로컬 규칙 탐지 · 모델 검토 없음";
  $("severity-adjustment").textContent = f.original_severity && f.original_severity !== f.severity
    ? `모델이 ${severityLabels[f.original_severity]} → ${severityLabels[f.severity]}으로 조정` : "";
  $("decision-details").open = false;
  const index = visibleFindings.indexOf(f);
  $("previous-finding").disabled = index <= 0; $("next-finding").disabled = index < 0 || index >= visibleFindings.length - 1;
  for (const row of $("findings").children) row.classList.toggle("selected", row.dataset.findingId === f.id);
  openDrawer("detail");
  $("detail").querySelector(".drawer-body").scrollTop = 0;
}
function moveDetail(offset) {
  const index = visibleFindings.indexOf(detailFinding), next = visibleFindings[index + offset];
  if (next) showDetail(next);
}
function showProjectDialog() {
  closeDrawer(); $("connected-next").hidden = true; $("connect-form").hidden = false;
  $("project-dialog").showModal(); $("repo-path").focus();
}
function applyTheme(theme) {
  if (!["system", "light", "dark"].includes(theme)) theme = "system";
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  remember("localStorage", "vibescan-theme", theme);
  for (const button of $("theme-options").children) button.setAttribute("aria-pressed", String(button.dataset.theme === theme));
}

// Scan, login and background watchers
function busy(running) {
  scanning = running;
  const repo = selectedRepo(), ready = auth?.state === "ready";
  $("connect").disabled = running || connecting; $("repo-path").disabled = running || connecting;
  $("scan").disabled = running || !repo; $("scan-menu-toggle").disabled = running || !repo;
  $("scan").textContent = scanMode === "ai" && ready ? "↗ 지금 스캔 · AI" : "↗ 지금 스캔";
  $("scan").title = repo ? (scanMode === "ai" && ready ? "AI 심층 분석" : "빠른 검사 · 로컬") : "프로젝트를 연결하면 스캔할 수 있습니다";
  $("mode-ai").disabled = !ready || running; $("mode-local").disabled = running;
  $("connect-ai").hidden = ready; $("mode-local").setAttribute("aria-pressed", String(scanMode === "local"));
  $("mode-ai").setAttribute("aria-pressed", String(scanMode === "ai"));
  $("watch-project").textContent = repo?.name || "연결된 프로젝트를 선택하세요";
  $("hook-toggle").checked = !!repo?.hook;
  $("hook-toggle").disabled = running || hookPending || !repo || repo.hook === null;
  $("hook-note").textContent = !repo ? "결과만 있는 프로젝트는 먼저 연결하세요." : repo.hook === null ? "이 PC에서 커밋하지 않는 프로젝트 · 자동 감시를 지원하지 않습니다." : "이 프로젝트에 커밋하면 자동으로 검사하고 결과를 업데이트합니다.";
  $("background-llm").disabled = running || backgroundPending || (!ready && !$("background-llm").checked);
  $("notification-note").textContent = !("Notification" in globalThis) ? "이 브라우저는 데스크톱 알림을 지원하지 않습니다." :
    Notification.permission === "denied" ? "알림이 차단됐습니다. 브라우저 설정에서 허용하세요." :
    Notification.permission === "granted" ? "새로운 치명·높음 위험을 데스크톱 알림으로 알려드립니다." : "자동 스캔을 켤 때 새 위험 알림 권한을 요청합니다.";
  renderOnboarding();
}
function renderProgress(title, state) {
  $("progress").hidden = !state; $("scan-controls").hidden = !!state;
  if (!state) return;
  $("progress-title").textContent = title;
  $("progress-steps").replaceChildren(...stages.map((name, index) => {
    const item = node("li", name, index < state.stage ? "done" : index === state.stage ? "current" : "");
    if (index === state.stage) item.setAttribute("aria-current", "step");
    return item;
  }));
  $("activity").replaceChildren(...(state.log || []).slice(-8).map(text => node("li", text)));
}
function alertNewRisks(scan) {
  const fresh = freshRisks(scan);
  if (!fresh.length || notifiedScans.has(scan.scan_id)) return false;
  notifiedScans.add(scan.scan_id);
  const text = `${scan.repo?.name || "프로젝트"} · 커밋 ${(scan.commit || "").slice(0, 7)}에서 새 치명·높음 ${fresh.length}건: ${fresh[0].title}`;
  message(text);
  if ("Notification" in globalThis && Notification.permission === "granted") {
    try { new Notification("VibeScan · 새 위험 발견", {body: text}); } catch { /* Toast remains available. */ }
  }
  return true;
}
async function pollJob() {
  clearTimeout(pollTimer);
  const version = ++jobVersion;
  try {
    const job = await api("/api/scan");
    if (version !== jobVersion) return;
    stages = job.stages || stages;
    busy(job.state === "running");
    renderProgress(`${job.repo || ""} · ${job.offline ? "빠른 검사" : "AI 심층 분석"}`, scanning ? job : job.hook || null);
    if (scanning) { pollTimer = setTimeout(pollJob, 1000); return; }
    const signature = [job.state, job.scan_id, job.message].join("|");
    if (signature === lastJob) return;
    lastJob = signature;
    if (job.state === "completed") {
      if (job.issue) jobIssues.set(job.scan_id, job.issue);
      await refresh(job.scan_id);
      if (job.issue) { message(`스캔 완료 · 정적 검사 결과는 저장되었습니다. ${issueHints[job.issue] || issueHints.error} ${job.message || ""}`, true); await loadAuth(); }
      else message("스캔 완료 · " + (job.message || "결과를 저장했습니다."));
    } else if (job.state === "failed") message(job.message, true);
  } catch (error) {
    if (version !== jobVersion) return;
    message(error.message, true, pollJob);
    if (scanning) pollTimer = setTimeout(pollJob, 3000);
  }
}
async function startScan(mode = scanMode) {
  const repo = selectedRepo();
  if (!repo || scanning) return;
  if (mode === "ai" && auth?.state !== "ready") { openDrawer("settings"); message("AI 심층 분석을 사용하려면 ChatGPT를 연결하세요."); return; }
  scanMode = mode; remember("localStorage", "vibescan-mode", mode);
  closeScanMenu(); ++jobVersion; clearTimeout(pollTimer); busy(true);
  try { await api("/api/scan", {path: repo.path, offline: mode !== "ai"}); lastJob = ""; await pollJob(); }
  catch (error) { message(error.message, true); await pollJob(); }
}
async function loadAuth() {
  clearTimeout(authTimer);
  try {
    auth = await api("/api/auth");
    const running = auth.login?.state === "running";
    $("auth-label").textContent = running ? "ChatGPT 연결 중" : auth.state === "ready" ? "ChatGPT 연결됨" : "ChatGPT 연결 필요";
    $("account-state").textContent = running ? auth.login.message : auth.login?.state === "failed" && auth.state !== "ready" ? auth.login.message + " · " + auth.message : auth.message;
    $("login").hidden = auth.state === "register"; $("login").disabled = running;
    $("login").textContent = auth.state === "ready" ? "다시 로그인" : "ChatGPT로 로그인";
    $("logout").hidden = !["ready", "plan"].includes(auth.state); $("logout").disabled = running;
    $("register-hint").hidden = auth.state !== "register";
    $("account-state").hidden = auth.state === "register" && !running;  // the notice below already says it
    if (running && loginRequested && auth.login.url) { location.assign(auth.login.url); return; }
    if (running) authTimer = setTimeout(loadAuth, loginRequested ? 300 : 1500);
  } catch (error) {
    auth = null; $("auth-label").textContent = "ChatGPT 상태 확인 실패";
    $("account-state").textContent = error.message; message(error.message, true, loadAuth);
  }
  busy(scanning);
}
async function pollLatest() {
  try {
    const job = await api("/api/scan");
    stages = job.stages || stages;
    if (job.state === "running" && !scanning) await pollJob();
    else if (!scanning) renderProgress(job.hook ? `커밋 ${(job.hook.commit || "").slice(0, 7)} 자동 스캔 · ${job.hook.repo}` : "", job.hook || null);
    const {scan_id: id} = await api("/api/latest");
    if (id && latestSeen !== undefined && id !== latestSeen && !scanning && !scanList.some(s => s.scan_id === id)) {
      await refresh(id);  // New results in another project never change the current selection.
      const arrived = await api("/api/scans/" + encodeURIComponent(id));
      alertNewRisks(arrived);
    }
    latestSeen = id; latestPollFailed = false;
  } catch (error) {
    if (!latestPollFailed) message(error.message, true, refresh);
    latestPollFailed = true;
  }
  setTimeout(pollLatest, 3000);
}
function closeScanMenu() { $("scan-menu").hidden = true; $("scan-menu-toggle").setAttribute("aria-expanded", "false"); }

// Events
$("connect-form").addEventListener("submit", async event => {
  event.preventDefault(); if (connecting || scanning) return;
  connecting = true; busy(scanning);
  if (/^(https?:\/\/|git@)/.test($("repo-path").value.trim())) message("GitHub에서 프로젝트를 복제하는 중입니다. 저장소 크기에 따라 몇 분 걸릴 수 있습니다.");
  try {
    const repo = await api("/api/repos", {path: $("repo-path").value.trim()});
    await loadRepos(); await chooseProject(repo.path);
    $("connect-form").hidden = true; $("connected-next").hidden = false;
    $("connected-name").textContent = repo.name + " 연결 완료";
    $("first-scan").focus(); message("프로젝트를 연결했습니다. 첫 스캔을 실행하세요.");
  } catch (error) { message(error.message, true); }
  finally { connecting = false; busy(scanning); }
});
$("first-scan").addEventListener("click", () => { $("project-dialog").close(); startScan("local"); });
for (const id of ["add-project", "onboard-add"]) $(id).addEventListener("click", showProjectDialog);
$("close-project").addEventListener("click", () => $("project-dialog").close());
for (const id of ["settings-open", "auth-chip", "connect-ai", "onboard-auth"]) $(id).addEventListener("click", () => { closeScanMenu(); openDrawer("settings"); });
$("close-settings").addEventListener("click", () => closeDrawer());
$("settings-backdrop").addEventListener("click", () => closeDrawer());
$("close-detail").addEventListener("click", () => closeDrawer());
$("previous-finding").addEventListener("click", () => moveDetail(-1));
$("next-finding").addEventListener("click", () => moveDetail(1));
$("copy-diff").addEventListener("click", () => detailFinding?.fix_diff && copyText(detailFinding.fix_diff, "수정안을 복사했습니다."));
$("copy-path").addEventListener("click", () => copyText(resultsPath, "결과 폴더 경로를 복사했습니다."));
$("ai-fix-hint").addEventListener("click", () => { closeDrawer(); startScan("ai"); });
$("scan").addEventListener("click", () => startScan(scanMode === "ai" && auth?.state !== "ready" ? "local" : scanMode));
$("onboard-scan").addEventListener("click", () => startScan("local"));
$("scan-menu-toggle").addEventListener("click", () => {
  const show = $("scan-menu").hidden; $("scan-menu").hidden = !show;
  $("scan-menu-toggle").setAttribute("aria-expanded", String(show));
  if (show) $("mode-local").focus();
});
$("mode-local").addEventListener("click", () => startScan("local"));
$("mode-ai").addEventListener("click", () => startScan("ai"));
$("scan-select").addEventListener("change", () => { resetFilters(); selectScan(); });
$("search").addEventListener("input", filterFindings);
$("risk-alert").addEventListener("click", () => {
  statusFilter = "open"; newOnly = true; severityFilter.clear(); $("search").value = "";
  renderTabs(); renderSeverity(); filterFindings(); $("findings").scrollIntoView({block: "nearest"});
  $("findings").querySelector("button")?.focus();
});
$("new-filter").addEventListener("click", () => { newOnly = false; filterFindings(); });
$("dismiss-toast").addEventListener("click", () => { $("toast").hidden = true; });
$("retry").addEventListener("click", () => { const action = retryAction; message(""); if (action) action(); });
$("login").addEventListener("click", async () => {
  $("login").disabled = true;
  try { await api("/api/login", {}); loginRequested = true; }
  catch (error) { message(error.message, true); }
  await loadAuth();
});
$("logout").addEventListener("click", async () => {
  $("logout").disabled = true;
  try { await api("/api/logout", {}); } catch (error) { message(error.message, true); }
  await loadAuth();
});
$("hook-toggle").addEventListener("change", async () => {
  const repo = selectedRepo(); if (!repo || repo.hook === null || hookPending) return;
  const wanted = $("hook-toggle").checked;
  // Request synchronously inside the user's click, before network awaits lose activation.
  let permission = Promise.resolve();
  if (wanted && "Notification" in globalThis && Notification.permission === "default") {
    try { permission = Promise.resolve(Notification.requestPermission()).catch(() => {}); } catch { /* No notification support. */ }
  }
  hookPending = true; busy(scanning);
  try {
    await api("/api/hook", {path: repo.path, enabled: wanted});
    await loadRepos(); message(wanted ? "커밋 후 자동 스캔을 켰습니다." : "커밋 후 자동 스캔을 껐습니다.");
  } catch (error) { message(error.message, true); }
  finally { hookPending = false; busy(scanning); }
  await permission; busy(scanning);
});
$("background-llm").addEventListener("change", async () => {
  const wanted = $("background-llm").checked;
  backgroundPending = true; busy(scanning);
  try {
    const saved = await api("/api/settings", {background_llm: wanted});
    $("background-llm").checked = saved.background_llm;
    message(saved.background_llm ? "자동 스캔에서 새 치명·높음 발견을 AI로 검토합니다. 구독 사용량이 차감됩니다." : "자동 스캔은 로컬 검사만 사용합니다.");
  } catch (error) { $("background-llm").checked = !wanted; message(error.message, true); }
  finally { backgroundPending = false; busy(scanning); }
});
for (const button of $("theme-options").children) button.addEventListener("click", () => applyTheme(button.dataset.theme));
$("download").addEventListener("click", () => {
  if (!result || result.repo.path !== selectedProject) return;
  const url = URL.createObjectURL(new Blob([result.report_md], {type: "text/markdown;charset=utf-8"}));
  const link = node("a"); link.href = url; link.download = `vibescan-${result.scan_id}.md`;
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
document.addEventListener("click", event => { if (!$("scan-controls").contains(event.target)) closeScanMenu(); });
document.addEventListener("keydown", event => {
  if (activeDrawer) {
    if (event.key === "Escape") { event.preventDefault(); closeDrawer(); return; }
    if (event.key === "Tab") {
      const focusable = [...$(activeDrawer).querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), summary, [tabindex="0"]')].filter(el => !el.hidden && el.getClientRects().length);
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (!first) { event.preventDefault(); $(activeDrawer).focus(); }
      else if (event.shiftKey && (document.activeElement === first || document.activeElement === $(activeDrawer))) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || document.activeElement === $(activeDrawer))) { event.preventDefault(); first.focus(); }
    }
    if (activeDrawer === "detail" && ["ArrowUp", "ArrowDown"].includes(event.key)) { event.preventDefault(); moveDetail(event.key === "ArrowDown" ? 1 : -1); }
    return;
  }
  if (event.key === "Escape" && !$("scan-menu").hidden) { closeScanMenu(); $("scan-menu-toggle").focus(); return; }
  if ($("project-dialog").open || event.ctrlKey || event.metaKey || event.altKey || /INPUT|TEXTAREA|SELECT/.test(event.target.tagName) || event.target.isContentEditable) return;
  if (event.key === "/" && result) { event.preventDefault(); $("search").focus(); }
  if (["j", "k"].includes(event.key) && result) {
    const rows = [...$("findings").children], index = rows.indexOf(document.activeElement);
    const next = rows[Math.max(0, Math.min(rows.length - 1, index + (event.key === "j" ? 1 : -1)))];
    if (next) { event.preventDefault(); next.focus(); }
  }
});
async function initialize() {
  applyTheme(stored("localStorage", "vibescan-theme", "system"));
  const settings = api("/api/settings").then(saved => { $("background-llm").checked = saved.background_llm; }).catch(error => message(error.message, true));
  await Promise.all([loadRepos().catch(error => message(error.message, true, loadRepos)), loadAuth(), settings]);
  await refresh(); await pollJob(); pollLatest();
}
initialize();

