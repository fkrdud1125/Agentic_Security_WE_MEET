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
  document: {getElementById: get, createElement: () => new Element()},
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
scanFlow().catch(error => { console.error(error); process.exitCode = 1; });
