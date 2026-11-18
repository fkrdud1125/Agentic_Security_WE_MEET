// Exercise the shipped script with a small DOM stand-in; no browser dependency.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
class Element {
  constructor() { this.children = []; this.value = ''; this.textContent = ''; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  handlers = {};
  addEventListener(type, callback) { this.handlers[type] = callback; }
  setAttribute() {}
  showModal() { this.open = true; }
  classList = {toggle() {}};
}
const elements = new Map();
const get = id => {
  if (!elements.has(id)) elements.set(id, new Element());
  return elements.get(id);
};
const context = vm.createContext({
  document: {getElementById: get, createElement: () => new Element(), createElementNS: (ns, tag) => Object.assign(new Element(), {tag})},
  location: {hash: ''}, sessionStorage: {getItem: () => 'test-ticket'},
  fetch: () => new Promise(() => {}),
  clearTimeout() {}, setTimeout() {},
});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../vibescan/web/dashboard.js'), 'utf8'), context);
vm.runInContext(`result = {findings: [
  {title: 'Resolved', status: 'open', change: 'fixed', severity: 'High', confidence: 'Likely', location: {file:'a.py', line:1}, how_found: [], cwe:'CWE-89'},
  {title: 'Open', status: 'open', change: 'existing', severity: 'Medium', location: {file:'b.py', line:2}},
  {title: 'Dismissed', status: 'dismissed', change: null, severity: 'Low', location: {file:'c.py', line:3}}
]};`, context);
get('status-filter').value = 'open';
vm.runInContext('filterFindings()', context);
assert.equal(get('findings').children.length, 1);
assert.equal(get('findings').children[0].children[1].children[0].textContent, 'Open');
get('status-filter').value = 'fixed';
vm.runInContext('filterFindings(); showDetail(result.findings[0]);', context);
assert.equal(get('findings').children.length, 1);
assert.equal(get('findings').children[0].children[2].textContent, '수정됨');
assert.match(get('detail-meta').textContent, /수정됨/);
get('status-filter').value = 'dismissed';
vm.runInContext('filterFindings()', context);
assert.equal(get('findings').children.length, 1);
assert.equal(get('findings').children[0].children[2].textContent, '오탐 후보');
console.log('Dashboard resolved-status regression: OK');

vm.runInContext(`scanList = [
  {scan_id:'a', repo:{path:'C:/r'}, commit:'c1', scanned_at:'2026-11-18T01:00:00+00:00', risk_score:40},
  {scan_id:'other', repo:{path:'C:/elsewhere'}, commit:'x', scanned_at:'2026-11-18T01:30:00+00:00', risk_score:99},
  {scan_id:'b', repo:{path:'C:/r'}, commit:'c2', scanned_at:'2026-11-18T02:00:00+00:00', risk_score:20},
  {scan_id:'later', repo:{path:'C:/r'}, commit:'c3', scanned_at:'2026-11-18T03:00:00+00:00', risk_score:0}];
renderTrend({scan_id:'b', repo:{path:'C:/r'}, scanned_at:'2026-11-18T02:00:00+00:00', risk_score:20});`, context);
const trend = get('risk-trend');
assert.equal(trend.hidden, false);
assert.equal(trend.children.filter(c => c.tag === 'circle').length, 4);  // 2 marks + 2 hover targets
assert.match(get('risk-trend-note').textContent, /최근 2회 스캔 추이 · 40 → 20/);
vm.runInContext(`renderTrend({scan_id:'a', repo:{path:'C:/r'}, scanned_at:'2026-11-18T01:00:00+00:00', risk_score:40});`, context);
assert.equal(trend.hidden, true);
console.log('Dashboard risk trend: only this repo, up to the scan on screen: OK');

get('repo-select').value = 'C:/r';
vm.runInContext(`repoList = [{path:'C:/r', hook:true}]; busy(false);`, context);
assert.equal(get('hook-toggle').hidden, false);
assert.match(get('hook-toggle').textContent, /끄기/);
vm.runInContext(`repoList = [{path:'C:/r', hook:null}]; busy(false);`, context);
assert.equal(get('hook-toggle').hidden, true);  // GitHub clones get no commit hook
vm.runInContext(`repoList = [{path:'C:/r', hook:false}]; busy(true);`, context);
assert.equal(get('hook-toggle').disabled, true);
assert.match(get('hook-toggle').textContent, /켜기/);
console.log('Dashboard hook toggle states: OK');

vm.runInContext(`stages = ['수집','정찰','계획','정적','검토']; renderProgress('repo', {stage: 2, log: ['a', 'b']});`, context);
assert.equal(get('progress').hidden, false);
assert.deepEqual(get('progress-steps').children.map(li => li.className || ''), ['done', 'done', 'current', '', '']);
assert.deepEqual(get('activity').children.map(li => li.textContent), ['a', 'b']);
vm.runInContext('renderProgress("", null)', context);
assert.equal(get('progress').hidden, true);

const shown = [];
context.Notification = class { constructor(title, options) { shown.push(options.body); } };
context.Notification.permission = 'granted';
const high = (change, status = 'open') => ({change, status, severity: 'High', title: 'SQL 인젝션'});
assert.equal(vm.runInContext(`alertNewRisks({commit: 'abc', findings: ${JSON.stringify([high('existing'), high('new', 'dismissed')])}})`, context), false);
assert.deepEqual(shown, []);  // already-known and dismissed findings never alert
assert.equal(vm.runInContext(`alertNewRisks({commit: 'abc', findings: ${JSON.stringify([high('new'), high('new')])}})`, context), true);
assert.match(shown[0], /새 Critical\/High 2건: SQL 인젝션 외/);
assert.match(get('job-message').textContent, /커밋 abc/);
console.log('Dashboard progress stepper and new-risk alerts: OK');

async function firstHookResult() {
  // The folder starts empty; the first result written by the commit hook must still open.
  const opened = [];
  context.setTimeout = () => {};
  vm.runInContext('latestSeen = undefined; scanList = []; scanning = false;', context);
  context.refresh = undefined;
  vm.runInContext('refresh = async id => { opened.push(id); }', Object.assign(context, {opened}));
  context.fetch = async () => ({ok: true, json: async () => ({scan_id: null})});
  await vm.runInContext('pollLatest()', context);
  assert.deepEqual(opened, []);
  context.fetch = async () => ({ok: true, json: async () => ({scan_id: 'hook-scan'})});
  await vm.runInContext('pollLatest()', context);
  assert.deepEqual(opened, ['hook-scan']);
  console.log('Dashboard opens the first hook result in an empty folder: OK');
}

async function scanFlow() {
  get('repo-select').value = 'C:/repo';
  get('result').hidden = false;
  context.fetch = async () => ({ok: true, json: async () => ({state:'running', repo:'C:/repo', offline:true})});
  await vm.runInContext('pollJob()', context);
  assert.equal(get('scan').disabled, true);
  assert.equal(get('result').hidden, false);
  assert.match(get('job-message').textContent, /정적 검사/);

  context.fetch = async () => ({ok: true, json: async () => ({state:'failed', message:'Engine failed'})});
  await vm.runInContext('pollJob()', context);
  assert.equal(get('scan').disabled, false);
  assert.equal(get('result').hidden, false);
  assert.equal(get('job-message').textContent, 'Engine failed');

  const requests = [];
  const saved = {scan_id:'new-scan', repo:{name:'Scanned repo',path:'C:/repo',branch:'main'},
    commit:'abcdef', scanned_at:'2026-11-18T10:00:00Z', risk_score:0, findings:[],
    summary:{Critical:0,High:0,Medium:0,Low:0,Info:0}, profile:{routes:0,limitations:[]}, coverage:[],
    dismissed_count:0, scan_type:'full'};
  context.fetch = async (url, options) => {
    requests.push({url, options});
    const data = url === '/api/scan' ? {state:'completed', scan_id:'new-scan', message:'Saved'} :
      url === '/api/scans' ? {scans:[saved],unavailable:0,results_path:'C:/out'} : saved;
    return {ok:true, json:async () => data};
  };
  get('use-model').checked = false;
  await get('scan').handlers.click();
  assert.deepEqual(JSON.parse(requests[0].options.body), {path:'C:/repo', offline:true});
  assert.equal(requests[0].options.headers['X-VibeScan-Token'], 'test-ticket');
  assert.equal(get('scan').disabled, false);
  assert.equal(get('scan-select').value, 'new-scan');
  assert.equal(get('repo-name').textContent, 'Scanned repo');
  assert.equal(get('result').hidden, false);
  assert.match(get('job-message').textContent, /스캔 완료/);
  console.log('Dashboard scan states, explicit POST, and result refresh: OK');

  const authFetch = data => async () => ({ok: true, json: async () => data});
  get('use-model').checked = true;
  context.fetch = authFetch({state:'plan', message:'구독 필요', login:{state:'idle'}});
  await vm.runInContext('loadAuth()', context);
  assert.equal(get('use-model').checked, false);
  assert.equal(get('use-model').disabled, true);
  assert.equal(get('login').hidden, false);
  assert.equal(get('auth-status').textContent, '구독 필요');
  context.fetch = authFetch({state:'register', message:'register first', login:{state:'idle'}});
  await vm.runInContext('loadAuth()', context);
  assert.equal(get('login').hidden, true);
  assert.equal(get('logout').hidden, true);
  context.fetch = authFetch({state:'ready', message:'연결됨', login:{state:'idle'}});
  await vm.runInContext('loadAuth()', context);
  assert.equal(get('use-model').disabled, false);
  assert.equal(get('login').textContent, '다시 로그인');
  assert.equal(get('logout').hidden, false);

  const visited = [];
  context.location.assign = url => visited.push(url);
  const loginUrl = 'http://127.0.0.1:9999/auth/login?key=k';
  context.fetch = authFetch({state:'ready', message:'연결됨', login:{state:'running', message:'진행', url:loginUrl}});
  await vm.runInContext('loadAuth()', context);
  assert.deepEqual(visited, []);  // a tab that did not press the button stays put
  await get('login').handlers.click();
  assert.deepEqual(visited, [loginUrl]);
  vm.runInContext('loginRequested = false', context);

  context.fetch = async url => ({ok: true, json: async () => url === '/api/scan'
    ? {state:'completed', scan_id:'new-scan', message:'모델 응답 생성 실패', issue:'limit'}
    : url === '/api/auth' ? {state:'ready', message:'연결됨', login:{state:'idle'}}
    : url === '/api/scans' ? {scans:[saved],unavailable:0,results_path:'C:/out'} : saved});
  await vm.runInContext('pollJob()', context);
  assert.match(get('job-message').textContent, /정적 검사 결과는 저장/);
  assert.match(get('job-message').textContent, /사용량 한도/);
  assert.equal(get('scan-select').value, 'new-scan');
  console.log('Dashboard login states and model failure hints: OK');
}
scanFlow().then(firstHookResult).catch(error => { console.error(error); process.exitCode = 1; });
