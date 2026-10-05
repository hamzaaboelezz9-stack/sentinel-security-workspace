'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');const core=require('../dist/report-core.js');
const fullVector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
test('CVSS v3.1 Base uses FIRST formulas, changed-scope PR weights and rounding',()=>{
  for(const [vector,score]of [[fullVector,9.8],['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',8.8],['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',6.1],['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',7.5],['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',0]])assert.equal(core.cvss(vector).score,score);
  for(const vector of ['CVSS:3.0/AV:N','CVSS:3.1/AV:N/AC:L','CVSS:3.1/AV:INVALID/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',fullVector+'/AV:N',fullVector+'/E:F'])assert.throws(()=>core.cvss(vector));
  assert.equal(core.cvss(''),null);
});
test('Labeled note extraction preserves supplied PoC and never confirms candidates',()=>{
  const input='FINDING-01: Observed test behavior\nSeverity: High | CVSS v3.1 Score: 7.5\nEndpoint: GET /api/status\nDescription: Observed detail\nPoC: GET /api/status HTTP/1.1\nHTTP/1.1 500 Internal Server Error\nImpact: Supplied impact\nRemediation: Supplied fix\nStatus: Confirmed\n---\nFINDING-02: Another observed issue\nEvidence: actual evidence';
  const results=core.parseNotes(input);assert.equal(results.length,2);assert.equal(results[0].severity,'High');assert.equal(results[0].score,'7.5');assert.equal(results[0].status,'Needs verification');assert.equal(results[0].endpoint,'GET /api/status');assert.ok(results[0].poc.includes('HTTP/1.1 500'));assert.equal(results[1].severity,'');
  const unstructured=core.parseNotes('tool --example\nUNSTRUCTURED SCAN OUTPUT');assert.equal(unstructured[0].title,'');assert.equal(unstructured[0].poc,'tool --example\nUNSTRUCTURED SCAN OUTPUT');
});
test('Fenced evidence cannot become finding labels; output fences preserve embedded backticks',()=>{
  const notes='FINDING-01: Evidence example\nPoC: start\n```text\nImpact: literal response field\n---\nFINDING-99: literal response field\n```\nImpact: Verified impact';
  const findings=core.parseNotes(notes);assert.equal(findings.length,1);assert.equal(findings[0].impact,'Verified impact');assert.ok(findings[0].poc.includes('FINDING-99'));
  const p=core.blank();p.findings=findings;const out=core.buildReport(p).markdown;assert.ok(out.includes('````text'));assert.equal((out.match(/^### FINDING-/gm)||[]).length,1);
});
test('Only confirmed severities establish overall risk; unknown severity is never treated as Low',()=>{
  const p=core.blank(),high={...core.finding(),severity:'High'};p.findings=[high];assert.equal(core.overall(p),core.MISSING);high.status='Confirmed';assert.equal(core.overall(p),'High');p.findings.push({...core.finding(),status:'Confirmed'});assert.equal(core.overall(p),core.MISSING);
  assert.equal(core.overall(core.blank()),core.MISSING);
});
test('An unstructured scan within the advertised note limit is preserved without silent PoC truncation',()=>{
  const notes='PUBLIC SCAN LINE\n'.repeat(5000),p=core.blank();p.notes=notes;p.findings=core.parseNotes(notes);const result=core.buildReport(p);assert.equal(result.project.findings[0].poc,notes);assert.ok(result.markdown.includes(notes));
});
test('Report follows all four requested sections and exact missing-detail markers without invented findings',()=>{
  const out=core.buildReport(core.blank());for(const section of ['## 1. Executive Summary','## 2. Assessment Scope & Methodology','## 3. Detailed Vulnerability Findings','## 4. Strategic Recommendations'])assert.ok(out.markdown.includes(section));
  assert.ok(out.markdown.includes(core.MISSING));assert.ok(!out.markdown.includes('SQL Injection in Login'));assert.equal(out.confirmed,0);assert.ok(out.gaps.length>0);
  const p=core.blank();p.findings=[{...core.finding(),title:'Recorded observation',poc:'ACTUAL SUPPLIED EVIDENCE'}];const report=core.buildReport(p).markdown;for(const name of ['Severity','CVSS v3.1 Score','Affected Endpoint / Parameter','Description','Proof of Concept (PoC)','Impact','Remediation / Fix'])assert.ok(report.includes(name));assert.ok(report.includes('ACTUAL SUPPLIED EVIDENCE'));assert.ok(report.includes('unverified candidate'));
});
test('Secret redaction covers authorization, cookies, token parameters, JSON credentials and JWTs; it is idempotent',()=>{
  const notes='Authorization: Bearer EXAMPLE_SECRET\nCookie: session=EXAMPLE_COOKIE\nGET /api?token=EXAMPLE_TOKEN&password=EXAMPLE_PASSWORD\n{"password":"EXAMPLE_JSON"}\nBearer EXAMPLE_BEARER\neyJhbGciOiJIUzI1NiJ9.eyJleGFtcGxlIjp0cnVlfQ.EXAMPLE_SIGNATURE';
  const redacted=core.redact(notes);for(const secret of ['EXAMPLE_SECRET','EXAMPLE_COOKIE','EXAMPLE_TOKEN','EXAMPLE_PASSWORD','EXAMPLE_JSON','EXAMPLE_BEARER','EXAMPLE_SIGNATURE'])assert.ok(!redacted.includes(secret));assert.equal(core.redact(redacted),redacted);
  const p=core.blank();p.notes=notes;p.findings=[{...core.finding(),poc:notes}];const safe=core.sanitizeProject(p);assert.ok(!JSON.stringify(safe).includes('EXAMPLE_SECRET'));assert.ok(!core.buildReport(p).markdown.includes('EXAMPLE_TOKEN'));assert.ok(p.notes.includes('EXAMPLE_SECRET'));
});
test('Markdown fields cannot inject headings, links, HTML, summary columns or report sections',()=>{
  const p=core.blank();p.metadata.client='<script>alert(1)</script>\n## Fake section';p.findings=[{...core.finding(),title:'x | y\n## Fake finding',endpoint:'[click](javascript:alert(1))'}];const md=core.buildReport(p).markdown;assert.ok(!md.includes('\n## Fake section'));assert.ok(!md.includes('\n## Fake finding'));assert.ok(md.includes('x \\| y'));assert.ok(md.includes('\\<script\\>'));
});
test('Project imports are bounded, reject malformed fields and do not merge prototype keys',()=>{
  const p=core.blank();assert.deepEqual(core.normalize(p),p);assert.throws(()=>core.normalize({findings:[]}));p.findings=Array.from({length:51},core.finding);assert.throws(()=>core.normalize(p));
  const oversized=core.blank();oversized.metadata.client='a'.repeat(65537);assert.throws(()=>core.normalize(oversized));const wrong=core.blank();wrong.metadata.client={text:'wrong'};assert.throws(()=>core.normalize(wrong));
  const poisoned=JSON.parse(JSON.stringify(core.blank()).replace('"metadata":{','"metadata":{"__proto__":{"polluted":true},'));core.normalize(poisoned);assert.equal({}.polluted,undefined);
  assert.throws(()=>core.parseNotes('a'.repeat(core.MAX_NOTES+1)));assert.throws(()=>core.parseNotes('🔐'.repeat(70000)));
});
test('Draft completeness catches literal verification markers and scoring inconsistencies',()=>{
  const p=core.blank();for(const key of core.META)p.metadata[key]='Assessor-supplied context';p.findings=[{...core.finding(),title:'Finding',endpoint:'GET /example',description:'Observed behavior',poc:'Supplied evidence',impact:'Supplied impact',remediation:'Supplied patch',vector:fullVector,status:'Confirmed'}];assert.equal(core.completeness(p).length,0);p.findings[0].impact=core.MISSING;assert.ok(core.completeness(p).some(g=>g.field==='impact'));p.findings[0].severity='Low';assert.ok(core.completeness(p).some(g=>g.field.includes('differs')));
});
test('Framework guidance and executive draft use user selection; demo remains explicitly synthetic',()=>{
  assert.ok(core.guidance('SQL injection','Node.js / Express').includes('pool.query'));assert.ok(core.guidance('SQL injection','Django').includes('User.objects'));assert.ok(core.guidance('SQL injection','PHP / PDO').includes('$pdo->prepare'));assert.ok(core.guidance('Cross-site scripting','React').includes('<span>{untrustedValue}</span>'));
  assert.throws(()=>core.draftExecutive(core.blank()));const p=core.blank();p.findings=[{...core.finding(),title:'Supplied title',severity:'Medium',status:'Confirmed'}];const summary=core.draftExecutive(p);assert.ok(summary.includes('1 assessor-confirmed'));assert.ok(summary.includes('Medium'));assert.ok(!summary.includes('data breach confirmed'));
  const demo=core.buildReport(core.demo());assert.ok(demo.markdown.includes('DEMONSTRATION ONLY'));assert.equal(demo.confirmed,0);
});
