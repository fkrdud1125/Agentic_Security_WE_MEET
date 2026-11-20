// Behavioral tests against the shipped HTML + JS, without a browser dependency.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const html = fs.readFileSync(path.join(__dirname, "../vibescan/web/index.html"), "utf8");
const source = fs.readFileSync(path.join(__dirname, "../vibescan/web/dashboard.js"), "utf8");

function harness({blockedStorage = false, hash = ""} = {}) {
  const elements = new Map();
  let document;
  class Element {
    constructor(tag = "div") {
      this.tagName = tag.toUpperCase(); this.children = []; this.handlers = {};
      this.value = ""; this._text = ""; this.dataset = {}; this.style = {};
      this.attributes = {}; this.hidden = false; this.disabled = false; this.isConnected = true;
    }
    set textContent(text) { this._text = String(text); this.children = []; }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }
    set innerHTML(_) { throw new Error("Untrusted HTML must never be parsed"); }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this._text = ""; this.children = children; }
    addEventListener(type, callback) { this.handlers[type] = callback; }
    setAttribute(name, value) { this.attributes[name] = String(value); }
    getAttribute(name) { return this.attributes[name]; }
    get classList() {
      const self = this;
      return {
        contains(name) { return (self.className || "").split(" ").includes(name); },
        toggle(name, force) {
          const names = new Set((self.className || "").split(" ").filter(Boolean));
          if (force === undefined) force = !names.has(name);
          force ? names.add(name) : names.delete(name);
          self.className = [...names].join(" ");
        },
        add(name) { this.toggle(name, true); },
        remove(name) { this.toggle(name, false); },
      };
    }
    querySelectorAll(selector) {
      const all = this.children.flatMap(c => [c, ...c.querySelectorAll("*")]);
      if (selector === "*") return all;
      if (selector.startsWith(".")) return all.filter(c => c.classList.contains(selector.slice(1)));
      const attr = selector.match(/^\[data-(\w+)="([^"]*)"\]$/);
      if (attr) return all.filter(c => c.dataset[attr[1]] === attr[2]);
      if (selector === "button") return all.filter(c => c.tagName === "BUTTON");
      return all.filter(c => ["BUTTON", "INPUT", "SELECT", "SUMMARY"].includes(c.tagName) && !c.disabled);
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    focus() { document.activeElement = this; }
    click() { this.focus(); return this.handlers.click?.({target: this, preventDefault() {}}); }
    contains(target) { return this === target || this.querySelectorAll("*").includes(target); }
    showModal() { this.open = true; } close() { this.open = false; }
    scrollIntoView() {} getClientRects() { return this.hidden ? [] : [{}]; }
  }
  for (const match of html.matchAll(/<([a-z0-9]+)\b([^>]*\bid="([^"]+)"[^>]*)>/gi)) {
    assert(!elements.has(match[3]), "Duplicate HTML id " + match[3]);
    const element = new Element(match[1]); element.id = match[3];
    element.hidden = /\bhidden\b/.test(match[2]); element.disabled = /\bdisabled\b/.test(match[2]);
    elements.set(match[3], element);
  }
  const get = id => {
    if (elements.has(id)) return elements.get(id);
    for (const el of elements.values()) {
      const found = el.querySelectorAll("*").find(c => c.id === id);
      if (found) return found;
    }
    throw new Error("Missing HTML element: " + id);
  };
  const sidebar = new Element("aside"), body = new Element("body");
  document = {getElementById: get, body, documentElement: new Element("html"), activeElement: body,
    createElement: tag => new Element(tag), createElementNS: (_, tag) => new Element(tag),
    querySelector: selector => selector === ".sidebar" ? sidebar : null, handlers: {},
    addEventListener(type, fn) { this.handlers[type] = fn; }};
  for (const id of ["detail", "settings"]) { const content = new Element(); content.className = "drawer-body"; get(id).append(content); }
  for (const theme of ["system", "light", "dark"]) { const button = new Element("button"); button.dataset.theme = theme; get("theme-options").append(button); }
  const storage = new Map([["vibescan-token", "test-ticket"]]), requests = [], notices = [], copies = [], downloads = [], replaced = [];
  const store = {getItem(key) { if (blockedStorage) throw Error("blocked"); return storage.get(key); },
    setItem(key, value) { if (blockedStorage) throw Error("blocked"); storage.set(key, value); }};
  const context = vm.createContext({document, location: {hash, pathname: "/", search: "", assign: url => replaced.push(url)},
    history: {replaceState: (...args) => replaced.push(args)}, localStorage: store, sessionStorage: store,
    fetch: () => new Promise(() => {}), clearTimeout() {}, setTimeout() {},
    navigator: {clipboard: {writeText: async value => copies.push(value)}},
    URL: {createObjectURL: blob => { downloads.push(blob); return "blob:test"; }, revokeObjectURL() {}}, Blob,
    Notification: class { static permission = "granted"; constructor(_, opts) { notices.push(opts.body); } }});
  vm.runInContext(source, context);
  const run = code => vm.runInContext(code, context);
  const seed = data => { context.seed = data; run("result = seed; selectedProject = seed.repo.path; render();"); };
  const respond = handler => {
    context.fetch = async (url, options) => { requests.push({url, options}); return {ok: true, json: async () => handler(url, options)}; };
  };
  return {context, get, run, seed, respond, requests, notices, copies, downloads, storage, document, replaced};
}
const finding = (id, severity = "High", extra = {}) => ({
  id, title: "문제 " + id, severity, confidence: "Likely", status: "open", change: "existing",
  location: {file: "app.py", line: 12}, cwe: "CWE-89", owasp: "A03", evidence: "execute(query)",
  how_found: ["정적 규칙"], impact_ko: "입력값이 쿼리 구조를 바꿉니다.", remediation_ko: "매개변수 바인딩을 사용하세요.",
  fix_diff: "--- a/app.py\n+++ b/app.py\n-query\n+safe_query", ...extra,
});
const sample = (id = "scan-a", repo = "C:/a", findings = []) => {
  const summary = {Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0};
  findings.filter(f => f.status === "open" && f.change !== "fixed").forEach(f => summary[f.severity]++);
  return {scan_id: id, repo: {name: repo.split("/").pop(), path: repo, branch: "main"},
    commit: "abcdef1234", scanned_at: "2026-11-20T00:00:00Z", risk_score: 40, findings, summary,
    delta: {new: 1, fixed: 1}, baseline_commit: "previous", analysis_note: "로컬 규칙으로 작성",
    profile: {routes: 2, limitations: ["자동 검사는 안전 보증이 아닙니다."]}, coverage: [], report_md: "# 보고서"};
};
async function main() {
  const h = harness(), {get, run} = h;
  const data = sample("scan-a", "C:/a", [
    finding("critical", "Critical", {status: "dismissed"}),
    finding("fixed", "High", {change: "fixed"}),
    finding("medium", "Medium"),
    finding("new", "High", {change: "new"}),
    finding("info", "Info"),
  ]);
  h.seed(data);
  assert.equal(get("risk-grade").textContent, "위험"); // dismissed Critical is excluded
  assert.equal(get("findings").children.length, 3);
  assert.equal(get("findings").children[0].dataset.findingId, "new");
  assert.equal(get("tab-open").textContent, "열림3");
  assert.equal(get("tab-dismissed").textContent, "오탐 후보1");
  assert.equal(get("tab-fixed").textContent, "해결됨1");
  assert.equal(get("risk-alert").hidden, false);
  await get("tab-fixed").click();
  assert.equal(get("findings").children.length, 1);
  assert.equal(get("findings").children[0].dataset.findingId, "fixed");
  run("resetFilters()");
  const chip = level => get("severity-chips").children.find(c => c.dataset.severity === level);
  await chip("High").click(); assert.equal(get("findings").children.length, 1);
  await chip("Medium").click(); assert.equal(get("findings").children.length, 2);
  get("search").value = "CWE-89"; run("filterFindings()"); assert.equal(get("findings").children.length, 2);
  get("search").value = "missing"; run("filterFindings()"); assert.equal(get("no-findings").hidden, false);
  await get("reset-empty").click(); assert.equal(get("findings").children.length, 3);
  await get("risk-alert").click(); assert.equal(get("findings").children.length, 1);
  assert.equal(get("new-filter").hidden, false);
  await get("new-filter").click(); assert.equal(get("findings").children.length, 3);
  for (const [level, expected] of [["Critical", "심각"], ["High", "위험"], ["Medium", "주의"], ["Low", "낮음"], ["Info", "낮음"]]) {
    h.context.input = [finding("x", level)]; assert.equal(run("riskGrade(input).label"), expected);
  }
  h.context.input = [finding("x", "Critical", {status: "fixed"})];
  assert.equal(run("riskGrade(input).label"), "발견 없음");
  h.seed(sample("clean")); assert.equal(get("risk-alert").hidden, true);
  assert.equal(get("risk-grade").textContent, "발견 없음");
  console.log("Grades, Korean labels, tabs, multi-select severity, banner and search: OK");

  const hostile = finding("hostile", "High", {title: '<img src=x onerror=alert(1)>',
    evidence: "<script>alert(1)</script>", fix_diff: "+<img onerror=alert(1)>\n-unsafe\n context",
    original_severity: "Critical", change: "new"});
  h.seed(sample("unsafe", "C:/a", [hostile, finding("second")]));
  await get("findings").children[0].click();
  assert.equal(get("detail-title").textContent, hostile.title);
  assert.equal(get("evidence").textContent, hostile.evidence);
  assert.equal(get("fix-diff").children[0].textContent, "+<img onerror=alert(1)>");
  assert.equal(get("fix-diff").children[0].className, "diff-line diff-add");
  assert.match(get("detail-meta").textContent, /가능성 높음/);
  assert.match(get("severity-adjustment").textContent, /치명 → 높음/);
  assert.equal(get("workspace").inert, true);
  await get("copy-diff").click(); assert.equal(h.copies[0], hostile.fix_diff);
  await get("next-finding").click(); assert.equal(get("detail-title").textContent, "문제 second");
  h.document.handlers.keydown({key: "Escape", preventDefault() {}});
  assert.equal(get("detail").hidden, true); assert.equal(get("workspace").inert, false);
  assert.equal(h.document.activeElement.dataset.findingId, "hostile");
  console.log("Hostile code stays text, diff coloring, copying, drawer navigation and focus restoration: OK");

  const a1 = sample("a1"), a2 = {...sample("a2"), scanned_at: "2026-11-21T00:00:00Z", trigger: "git-hook"};
  const b = sample("b1", "C:/b");
  h.context.scans = [a2, b, a1];
  run('scanList = scans; repoList = [{path:"C:/a", name:"a", hook:true}, {path:"C:/empty",name:"empty",hook:null}]; selectedProject="C:/a";');
  h.respond(url => ({a1, a2, b1: b}[url.split("/").pop()]));
  await run('chooseProject("C:/a")');
  assert.equal(get("scan-select").children.length, 2);
  assert.match(get("scan-select").children[0].textContent, /자동/);
  assert.equal(get("projects").children.length, 3);
  await run('chooseProject("C:/b")');
  assert.equal(get("repo-name").textContent, "b"); assert.equal(get("scan").disabled, true);
  assert.equal(get("scan-select").children.length, 1);
  assert.equal(h.storage.get("vibescan-project"), "C:/b");
  await run('chooseProject("C:/empty")');
  assert.equal(get("empty").hidden, false); assert.equal(get("result").hidden, true);
  assert.equal(get("scan").disabled, false); assert.equal(get("hook-toggle").disabled, true);
  console.log("Connected + result-only project union, scoped history, persistent selection and empty state: OK");

  // Out-of-order network replies cannot show A's scan below B's heading.
  const race = harness(); race.context.rows = [a1, b];
  race.run('scanList=rows; repoList=[]; selectedProject="C:/a";');
  const pending = {};
  race.context.fetch = url => new Promise(resolve => { pending[url] = data => resolve({ok:true,json:async () => data}); });
  const first = race.run('chooseProject("C:/a")');
  const second = race.run('chooseProject("C:/b")');
  pending["/api/scans/b1"](b); await second;
  pending["/api/scans/a1"](a1); await first;
  assert.equal(race.get("repo-name").textContent, "b");
  assert.equal(race.run("result.repo.path"), "C:/b");
  console.log("Stale scan response ignored after project switch: OK");

  h.context.scans = [a1, b, a2]; run("scanList=scans;");
  run('renderTrend({...scanList[2],repo:{path:"C:/a"}})');
  assert.equal(get("risk-trend").children.filter(c => c.tagName === "CIRCLE").length, 4);
  assert.match(get("risk-trend-note").textContent, /최근 2회/);
  run("renderTrend(scanList[0])"); assert.equal(get("risk-trend").hidden, true);
  h.context.fresh = sample("alert", "C:/a", [finding("f", "High", {change: "new"})]);
  assert.equal(run("alertNewRisks(fresh)"), true); assert.equal(run("alertNewRisks(fresh)"), false);
  assert.equal(h.notices.length, 1); assert.match(h.notices[0], /치명·높음/);
  console.log("Per-project historical trend and deduplicated new-risk notification: OK");

  const scan = harness(), saved = sample("saved", "C:/a", [finding("f")]);
  scan.context.saved = saved;
  scan.run('selectedProject="C:/a"; repoList=[{path:"C:/a",name:"a",hook:false}]; stages=["수집","정찰","계획","검사","검토"];');
  let running = true;
  scan.respond((url, options) => {
    if (url === "/api/scan") return running ? {state:"running",repo:"C:/a",offline:true,stage:2,log:["검사 중"]} : {state:"completed",repo:"C:/a",scan_id:"saved",issue:"limit",message:"사용량 초과"};
    if (url === "/api/scans") return {scans:[saved],results_path:"C:/out"};
    if (url === "/api/auth") return {state:"ready",message:"연결됨",login:{state:"idle"}};
    return saved;
  });
  await scan.run('startScan("local")');
  assert.deepEqual(JSON.parse(scan.requests[0].options.body), {path:"C:/a",offline:true});
  assert.equal(scan.requests[0].options.headers["X-VibeScan-Token"], "test-ticket");
  assert.equal(scan.get("progress").hidden, false);
  assert.equal(scan.get("progress-steps").children[2].className, "current");
  running = false; await scan.run("pollJob()");
  assert.equal(scan.get("result").hidden, false); assert.equal(scan.get("scan").disabled, false);
  assert.match(scan.get("message").textContent, /정적 검사 결과는 저장/);
  assert.match(scan.get("analysis-badge").textContent, /일부 실패/);
  assert.match(scan.get("analysis-badge").title, /한도/);
  await scan.get("download").click(); assert.equal(await scan.downloads[0].text(), "# 보고서");
  scan.respond(url => url === "/api/auth" ? {state:"register",message:"등록 필요",login:{state:"idle"}} : {});
  await scan.run("loadAuth()");
  assert.equal(scan.get("login").hidden, true); assert.equal(scan.get("register-hint").hidden, false); assert.equal(scan.get("account-state").hidden, true);
  assert.equal(scan.get("mode-ai").disabled, true);
  console.log("Explicit offline POST, progress, AI failure recovery, report download and auth gating: OK");

  const poll = harness();
  poll.respond(url => url === "/api/scan" ? {state:"idle"} : {scan_id:null});
  await poll.run("pollLatest()");
  const arrivals = []; poll.context.arrivals = arrivals;
  poll.run("refresh = async id => arrivals.push(id)");
  poll.respond(url => url === "/api/scan" ? {state:"idle"} : url === "/api/latest" ? {scan_id:"first"} : sample("first"));
  await poll.run("pollLatest()"); assert.deepEqual(arrivals, ["first"]);
  const blocked = harness({blockedStorage:true,hash:"#fresh-ticket"});
  assert.equal(blocked.run("token"), "fresh-ticket");
  assert.equal(blocked.replaced[0][2], "/");
  blocked.run('applyTheme("dark")'); assert.equal(blocked.document.documentElement.dataset.theme, "dark");
  blocked.run('applyTheme("system")'); assert.equal(blocked.document.documentElement.dataset.theme, undefined);
  assert.equal((html.match(/aria-live=/g) || []).length, 1);
  assert.doesNotMatch(source, /\.innerHTML\s*=/);
  assert(html.indexOf("/assets/theme.js") < html.indexOf("/assets/dashboard.css"));
  console.log("First hook result, unavailable storage, ticket hash isolation, themes and single live region: OK");
}
main().catch(error => { console.error(error); process.exitCode = 1; });

