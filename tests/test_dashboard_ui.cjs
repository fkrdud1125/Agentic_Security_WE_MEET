// Exercise the shipped script with a small DOM stand-in; no browser dependency.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
class Element {
  constructor() { this.children = []; this.value = ''; this.textContent = ''; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener() {}
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
