/* Safe headless DOM integration. No actual target scanning or visual-browser claims. */
'use strict';const {test}=require('node:test');const assert=require('node:assert/strict');const vm=require('node:vm');const fs=require('node:fs');const path=require('node:path');const {parseHTML}=require('linkedom');const core=require('../dist/report-core.js');
const root=path.join(__dirname,'../dist');
function app(){
  const {document,window}=parseHTML(fs.readFileSync(path.join(root,'index.html'),'utf8')),tools=new Map(),downloads=[];const $=id=>document.getElementById(id);
  // Emulate APIs that linkedom omits (dialog, select setter, print and blobs).
  for(const select of document.querySelectorAll('select'))Object.defineProperty(select,'value',{value:'',writable:true,configurable:true});
  $('confirm-dialog').showModal=()=>{$('confirm-dialog').open=true;};$('confirm-dialog').close=()=>{$('confirm-dialog').open=false;};window.print=()=>{};
  document.modelContext={registerTool:tool=>tools.set(tool.name,tool)};
  const SafeURL=URL;SafeURL.createObjectURL=blob=>{downloads.push(blob);return 'blob:test';};SafeURL.revokeObjectURL=()=>{};
  const context=vm.createContext({document,window,SentinelReport:core,TextEncoder,URL:SafeURL,Blob,AbortController,setTimeout,clearTimeout});
  vm.runInContext(fs.readFileSync(path.join(root,'reports.js'),'utf8'),context);
  for(const select of document.querySelectorAll('#cvss-metrics select'))Object.defineProperty(select,'value',{value:'',writable:true,configurable:true});
  const click=id=>$(id).dispatchEvent(new window.Event('click'));
  const input=(id,value)=>{$(id).value=value;$(id).dispatchEvent(new window.Event('input'));};
  return {$,document,window,click,input,tools,downloads};
}
test('Workspace opens blank with unknown risk and exact four-section preview',()=>{
  const a=app();assert.equal(a.$('stat-total').textContent,'0');assert.equal(a.$('stat-risk').textContent,'Not established');assert.ok(a.$('markdown-preview').value.includes('## 1. Executive Summary'));assert.ok(a.$('report-preview').textContent.includes(core.MISSING));assert.equal(a.$('demo-banner').hidden,true);
});
test('Notes extract safely; manually confirming evidence updates risk; evidence edits invalidate confirmation',()=>{
  const a=app();a.click('tab-evidence');a.input('raw-notes','FINDING-01: Actual note title\nSeverity: High\nEndpoint: GET /api/example\nPoC: Exact supplied evidence');a.click('extract-findings');assert.equal(a.$('stat-total').textContent,'1');assert.equal(a.$('finding-title').value,'Actual note title');assert.equal(a.$('stat-risk').textContent,'Not established');a.input('finding-status','Confirmed');a.click('view-markdown');a.click('export-markdown');assert.equal(a.$('stat-risk').textContent,'High');a.input('finding-poc','Changed evidence');a.click('export-markdown');assert.equal(a.$('finding-status').value,'Needs verification');assert.equal(a.$('stat-risk').textContent,'Not established');
});
test('Report renderer treats hostile HTML and fenced content as text and never loads user URLs',()=>{
  const a=app();a.input('meta-client','<img src="https://example.test/x" onerror="alert(1)">');a.click('add-finding');a.input('finding-title','<script>alert(1)</script>');a.input('finding-poc','```\n<img src=x onerror=alert(1)>\n```');a.click('export-markdown');assert.equal(a.$('report-preview').querySelectorAll('img,script,iframe').length,0);assert.ok(a.$('report-preview').textContent.includes('<script>alert(1)</script>'));assert.ok(a.$('report-preview').textContent.includes('<img src=x'));
});
test('Markdown and project exports redact secrets while retaining a resumable project schema',async()=>{
  const a=app();a.click('add-finding');a.input('finding-poc','Authorization: Bearer EXAMPLE_PRIVATE');a.click('export-markdown');a.click('export-project');assert.equal(a.downloads.length,2);assert.ok(!(await a.downloads[0].text()).includes('EXAMPLE_PRIVATE'));const p=JSON.parse(await a.downloads[1].text());assert.equal(p.version,1);assert.ok(p.findings[0].poc.includes('[REDACTED]'));assert.equal(core.normalize(p).findings.length,1);
});
test('CVSS builder requires all metrics; demo has synthetic marker; destructive changes require confirmation',()=>{
  const a=app();a.click('add-finding');a.click('apply-cvss');assert.ok(a.$('feedback').textContent.includes('all eight'));
  for(const [key,value]of Object.entries({AV:'N',AC:'L',PR:'N',UI:'N',S:'U',C:'H',I:'H',A:'H'}))a.$('metric-'+key).value=value;
  a.click('apply-cvss');assert.equal(a.$('cvss-result').textContent,'9.8');
  a.click('load-demo');assert.equal(a.$('confirm-dialog').open,true);a.click('confirm-cancel');assert.equal(a.$('finding-vector').value.startsWith('CVSS:3.1'),true);
  a.click('load-demo');a.click('confirm-accept');assert.equal(a.$('demo-banner').hidden,false);assert.ok(a.$('markdown-preview').value.includes('DEMONSTRATION ONLY'));
  a.click('clear-project');a.click('confirm-accept');assert.equal(a.$('stat-total').textContent,'0');
});
test('Optional agent tools expose counts only, reject arguments, and navigate without entering evidence',()=>{
  const a=app();assert.equal(a.tools.size,2);const tool=a.tools.get('read_report_review_counts');assert.deepEqual(Object.keys(tool.execute({})).sort(),['confirmed','demo','findings','reviewItems']);assert.throws(()=>tool.execute({notes:'private'}));a.tools.get('open_report_evidence_panel').execute({});assert.equal(a.$('panel-evidence').hidden,false);assert.equal(a.$('raw-notes').value,'');
});
test('Both routes reference present assets; identifiers are unique; reports have no network or storage operations',()=>{
  for(const name of ['index.html','password.html']){const html=fs.readFileSync(path.join(root,name),'utf8'),ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);assert.equal(new Set(ids).size,ids.length);for(const match of html.matchAll(/(?:src|href)="\.\/([^"#]+)"/g))assert.ok(fs.existsSync(path.join(root,match[1])),match[1]);}
  const script=fs.readFileSync(path.join(root,'reports.js'),'utf8');assert.ok(!/\bfetch\s*\(|localStorage|sessionStorage|indexedDB|console\.|\.innerHTML\s*=/.test(script));
});
