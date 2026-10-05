/* Sentinel Report Composer: deterministic, evidence-preserving, offline.
 * Never invent findings, execute commands, fetch targets, or make compliance
 * attestations. Imported scan candidates require an assessor's confirmation.
 */
(function(root){
  'use strict';
  const MISSING='[Needs manual verification]';
  const MAX_NOTES=262144, MAX_FINDINGS=50;
  const FIELDS=['title','endpoint','description','poc','impact','remediation','severity','vector','score','status','category','references','compliance','retest'];
  const META=['title','client','assessor','target','assessmentType','date','stack','inScope','outScope','roles','methodology','executive','businessImpact','immediate','shortTerm','longTerm','limitations'];
  const STANDARDS={owasp:['OWASP Top 10:2025','https://top10.owasp.org/2025/en/'],wstg:['OWASP Web Security Testing Guide v4.2','https://wstg.owasp.org/v4.2/'],nist:['NIST SP 800-115','https://csrc.nist.gov/pubs/sp/800/115/final'],ptes:['Penetration Testing Execution Standard (PTES)','http://www.pentest-standard.org/index.php/Main_Page']};
  const SEVERITIES=['Critical','High','Medium','Low','Informational'];
  const BASE={AV:{N:.85,A:.62,L:.55,P:.2},AC:{L:.77,H:.44},PR:{N:.85,L:.62,H:.27},UI:{N:.85,R:.62},S:{U:0,C:1},C:{H:.56,L:.22,N:0},I:{H:.56,L:.22,N:0},A:{H:.56,L:.22,N:0}};
  const safeString=(value,max=65536)=>typeof value==='string'?value.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replace(/\u0000/g,'').slice(0,max):'';
  const bytes=value=>new TextEncoder().encode(value).byteLength;
  const supplied=value=>typeof value==='string'&&value.trim()&&!value.includes(MISSING);
  function blank(){return {version:1,demo:false,metadata:Object.fromEntries(META.map(k=>[k,k==='title'?'Web Application Penetration Test Report':''])),standards:['owasp','wstg','nist'],notes:'',findings:[],redact:true};}
  function finding(){return {title:'',endpoint:'',description:'',poc:'',impact:'',remediation:'',severity:'',vector:'',score:'',status:'Needs verification',category:'Other',references:'',compliance:'',retest:''};}
  function normalize(input){
    if(!input||typeof input!=='object'||Array.isArray(input)||input.version!==1||!input.metadata||!Array.isArray(input.findings)||input.findings.length>MAX_FINDINGS) throw new Error('INVALID_PROJECT');
    const project=blank();
    for(const key of META){
      if(input.metadata[key]!==undefined&&(typeof input.metadata[key]!=='string'||input.metadata[key].length>65536))throw new Error('INVALID_FIELD');
      project.metadata[key]=safeString(input.metadata[key]);
    }
    if(input.notes!==undefined&&(typeof input.notes!=='string'||bytes(input.notes)>MAX_NOTES))throw new Error('NOTES_TOO_LARGE');
    project.notes=safeString(input.notes,MAX_NOTES);
    project.redact=input.redact!==false; project.demo=input.demo===true;
    project.standards=Array.isArray(input.standards)?[...new Set(input.standards.filter(k=>Object.hasOwn(STANDARDS,k)))]:[];
    project.findings=input.findings.map(item=>{
      if(!item||typeof item!=='object'||Array.isArray(item))throw new Error('INVALID_FINDING');
      const out=finding();for(const key of FIELDS){const limit=key==='poc'?MAX_NOTES:65536;if(item[key]!==undefined&&(typeof item[key]!=='string'||item[key].length>limit))throw new Error('INVALID_FIELD');out[key]=safeString(item[key],limit);}
      out.status=item.status==='Confirmed'?'Confirmed':'Needs verification';
      out.severity=normalizeSeverity(item.severity);
      return out;
    });
    return project;
  }
  function redact(text){
    return safeString(text,MAX_NOTES)
      .replace(/^((?:authorization|proxy-authorization|cookie|set-cookie)\s*:)[^\r\n]*/gim,'$1 [REDACTED]')
      .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi,'$1 [REDACTED]')
      .replace(/((?:[?&]|\b)(?:access_token|refresh_token|api[_-]?key|password|passwd|client_secret|secret|token)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&,;\]}]+)/gi,(match,prefix,value)=>value.startsWith('[REDACTED')?match:prefix+'[REDACTED]')
      .replace(/("(?:access_token|refresh_token|api[_-]?key|password|passwd|client_secret|secret|token)"\s*:\s*)"[^"]*"/gi,'$1"[REDACTED]"')
      .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,'[REDACTED JWT]');
  }
  function sanitizeProject(input){
    const project=normalize(input);
    if(!project.redact)return project;
    for(const key of META)project.metadata[key]=redact(project.metadata[key]);
    project.notes=redact(project.notes);
    for(const item of project.findings)for(const key of FIELDS)item[key]=redact(item[key]);
    return project;
  }
  function normalizeSeverity(value){const text=String(value||'').trim().toLowerCase();return text==='info'?'Informational':SEVERITIES.find(s=>s.toLowerCase()===text)||'';}
  function severity(score){return score===0?'Informational':score<4?'Low':score<7?'Medium':score<9?'High':'Critical';}
  // FIRST CVSS v3.1 Base equations. All eight metrics are mandatory; duplicate,
  // unknown, missing or temporal/environmental metrics fail rather than guess.
  function cvss(vector){
    const input=String(vector||'').trim();if(!input)return null;
    if(!input.startsWith('CVSS:3.1/'))throw new Error('INVALID_VECTOR');
    const metrics=Object.create(null);
    for(const entry of input.slice(9).split('/')){
      const pair=entry.split(':');
      if(pair.length!==2||!Object.hasOwn(BASE,pair[0])||!Object.hasOwn(BASE[pair[0]],pair[1])||Object.hasOwn(metrics,pair[0]))throw new Error('INVALID_VECTOR');
      metrics[pair[0]]=pair[1];
    }
    if(Object.keys(metrics).length!==8)throw new Error('INCOMPLETE_VECTOR');
    const changed=metrics.S==='C';
    const iss=1-(1-BASE.C[metrics.C])*(1-BASE.I[metrics.I])*(1-BASE.A[metrics.A]);
    const impact=changed?7.52*(iss-.029)-3.25*Math.pow(iss-.02,15):6.42*iss;
    const pr=changed?(metrics.PR==='N'?.85:metrics.PR==='L'?.68:.5):BASE.PR[metrics.PR];
    const exploit=8.22*BASE.AV[metrics.AV]*BASE.AC[metrics.AC]*pr*BASE.UI[metrics.UI];
    // Integer-based Roundup from FIRST Appendix A avoids floating-point drift.
    const roundUp=value=>{const integer=Math.round(value*100000);return integer%10000===0?integer/100000:(Math.floor(integer/10000)+1)/10;};
    const score=impact<=0?0:roundUp(Math.min((changed?1.08:1)*(impact+exploit),10));
    const canonical='CVSS:3.1/'+Object.keys(BASE).map(k=>k+':'+metrics[k]).join('/');
    return {score,severity:severity(score),vector:canonical};
  }
  function rating(item){
    const notes=[];let computed=null, score=null;
    try{computed=cvss(item.vector);}catch{notes.push('Invalid or incomplete CVSS v3.1 Base vector.');}
    if(computed)score=computed.score;
    else if(String(item.score||'').trim()){
      if(/^(?:10(?:\.0)?|[0-9](?:\.[0-9])?)$/.test(item.score.trim())){score=Number(item.score);notes.push('CVSS score supplied by assessor; vector '+MISSING+'.');}
      else notes.push('CVSS score must be from 0.0 to 10.0 with at most one decimal place.');
    }
    const explicit=normalizeSeverity(item.severity), level=explicit||(score!==null?severity(score):'');
    if(explicit&&score!==null&&explicit!==severity(score))notes.push('Assessor severity differs from the CVSS Base band; document the business-risk rationale.');
    return {score,severity:level,vector:computed?.vector||'',warnings:notes};
  }
  const alias={title:'title',vulnerability:'title',endpoint:'endpoint','affected endpoint':'endpoint',parameter:'endpoint',description:'description',poc:'poc','proof of concept':'poc',evidence:'poc',request:'poc',response:'poc',impact:'impact','business impact':'impact',remediation:'remediation',fix:'remediation',severity:'severity',cvss:'score','cvss score':'score','cvss v3.1 score':'score',vector:'vector','cvss vector':'vector',status:'status',category:'category',references:'references',compliance:'compliance',retest:'retest'};
  function parseNotes(text){
    if(typeof text!=='string'||bytes(text)>MAX_NOTES)throw new Error('NOTES_TOO_LARGE');
    if(!text.trim())throw new Error('EMPTY_NOTES');
    const findings=[];let item=finding(), key='', fence=null, saw=false;
    const finish=()=>{if(!saw)return;item.severity=normalizeSeverity(item.severity);item.status='Needs verification';findings.push(item);item=finding();key='';saw=false;};
    for(const raw of safeString(text,MAX_NOTES).split(/\r?\n/)){
      const line=raw.trim();
      const tick=/^(`{3,}|~{3,})/.exec(line);
      if(tick){if(!fence)fence=tick[1][0];else if(tick[1][0]===fence)fence=null;item[key||'poc']+=(item[key||'poc']?'\n':'')+raw;saw=true;continue;}
      if(!fence){
        const heading=/^(?:#{1,4}\s*)?(?:FINDING[- ]?\d+|Vulnerability\s*\d+)\s*[:.—-]\s*(.*)$/i.exec(line);
        if(heading){finish();item.title=heading[1];saw=true;continue;}
        if(/^---+$/.test(line)){finish();continue;}
        const label=/^(?:[-*]\s*)?(?:\*\*)?([A-Za-z][A-Za-z .0-9-]{1,35})(?:\*\*)?\s*:\s*(.*)$/.exec(line);
        if(label&&Object.hasOwn(alias,label[1].toLowerCase())){
          const next=alias[label[1].toLowerCase()];
          if(next==='title'&&item.title&&saw)finish();
          key=next;
          if(key==='severity'){
            const severityMatch=/^(Critical|High|Medium|Low|Info(?:rmational)?)(?:\b|$)/i.exec(label[2]);
            if(severityMatch)item.severity=severityMatch[1];
            const scoreMatch=/CVSS(?:\s+v3\.1)?(?:\s+Score)?\s*:\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)(?![\d.])/i.exec(label[2]);
            if(scoreMatch)item.score=scoreMatch[1];
          }else item[key]+=(item[key]?'\n':'')+label[2];
          saw=true;continue;
        }
      }
      item[key||'poc']+=(item[key||'poc']?'\n':'')+raw;if(line)saw=true;
    }
    finish();if(findings.length>MAX_FINDINGS)throw new Error('TOO_MANY_FINDINGS');
    return findings;
  }
  const markdown=value=>safeString(value,MAX_NOTES).replace(/\\/g,'\\\\').replace(/([`*_\[\]<>|#!])/g,'\\$1').replace(/^([>+\-=])/gm,'\\$1');
  const text=value=>value?.trim()?markdown(value):MISSING;
  function fence(value){
    const source=value?.trim()?value:MISSING;
    const runs=[...source.matchAll(/`+/g)].map(m=>m[0].length);
    const marker='`'.repeat(Math.max(3,...runs.map(n=>n+1)));
    return marker+'text\n'+source+'\n'+marker;
  }
  function completeness(project){
    const gaps=[];
    for(const key of META)if(!supplied(project.metadata[key]))gaps.push({location:'Assessment',field:key});
    if(!project.standards.length)gaps.push({location:'Assessment',field:'reference standards'});
    if(!project.findings.length)gaps.push({location:'Findings',field:'no findings entered; conclusions need assessor verification'});
    project.findings.forEach((item,index)=>{
      const id='FINDING-'+String(index+1).padStart(2,'0');
      for(const key of ['title','endpoint','description','poc','impact','remediation'])if(!supplied(item[key]))gaps.push({location:id,field:key});
      if(item.status!=='Confirmed')gaps.push({location:id,field:'evidence not confirmed'});
      const result=rating(item);if(!result.severity)gaps.push({location:id,field:'severity'});
      if(result.score===null)gaps.push({location:id,field:'CVSS score'});
      if(!result.vector)gaps.push({location:id,field:'CVSS Base vector'});
      for(const warning of result.warnings)gaps.push({location:id,field:warning});
    });
    if(project.demo)gaps.push({location:'Report',field:'synthetic demonstration data'});
    return gaps;
  }
  function overall(project){
    const confirmed=project.findings.filter(f=>f.status==='Confirmed');
    if(!confirmed.length)return MISSING;
    const levels=confirmed.map(f=>rating(f).severity);
    // Unknown confirmed severity can conceal higher risk, so never assign a
    // lower report rating just because another confirmed finding has a score.
    if(levels.some(s=>!s))return MISSING;
    return SEVERITIES.find(level=>levels.includes(level))||MISSING;
  }
  function buildReport(input){
    const project=sanitizeProject(input), m=project.metadata, gaps=completeness(project), risk=overall(project);
    const counts=Object.fromEntries(SEVERITIES.map(s=>[s,project.findings.filter(f=>rating(f).severity===s).length]));
    const confirmed=project.findings.filter(f=>f.status==='Confirmed').length;
    const lines=['# '+text(m.title),'', '**Client:** '+text(m.client),'**Target application / URL:** '+text(m.target),'**Assessment type:** '+text(m.assessmentType),'**Assessment date:** '+text(m.date),'**Prepared by:** '+text(m.assessor),'**Classification:** Confidential','**Review state:** '+(gaps.length?'Draft — manual verification required':'Assessor-reviewed draft — approve before publication'),''];
    if(project.demo)lines.push('> DEMONSTRATION ONLY — synthetic assessment data; not a real test or attestation.','');
    lines.push('## 1. Executive Summary','',text(m.executive),'','**Overall risk rating:** '+risk,'','The overall rating uses the highest assessor-confirmed finding severity. Unverified candidates do not establish a confirmed application risk rating. This is an assessment summary, not a compliance certification.','',`**Finding inventory:** ${project.findings.length} recorded; ${confirmed} assessor-confirmed; ${project.findings.length-confirmed} awaiting confirmation.`, '', '**Key business impacts**','',text(m.businessImpact),'','### Vulnerability Summary','', '| ID | Vulnerability | Severity | CVSS v3.1 | Evidence status | Affected endpoint / parameter |','| --- | --- | --- | --- | --- | --- |');
    if(!project.findings.length)lines.push('| — | No findings entered; assessment conclusions '+MISSING+' | '+MISSING+' | '+MISSING+' | '+MISSING+' | '+MISSING+' |');
    project.findings.forEach((item,i)=>{const r=rating(item);const cell=value=>text(value).replace(/\r?\n/g,'<br>');lines.push('| FINDING-'+String(i+1).padStart(2,'0')+' | '+cell(item.title)+' | '+(r.severity||MISSING)+' | '+(r.score===null?MISSING:r.score.toFixed(1))+' | '+item.status+' | '+cell(item.endpoint)+' |');});
    lines.push('','## 2. Assessment Scope & Methodology','','### In Scope','',text(m.inScope),'','### Out of Scope','',text(m.outScope),'','### User Roles and Access','',text(m.roles),'','### Assessment Methodology','',text(m.methodology),'','**Application stack:** '+text(m.stack),'','### Reference Standards','');
    if(!project.standards.length)lines.push(MISSING);
    for(const key of project.standards){const [name,url]=STANDARDS[key];lines.push('- ['+name+']('+url+')');}
    lines.push('','These are reference standards selected by the assessor. Referencing a standard does not claim that every test was performed. Testing activities and coverage must be supported by the methodology and evidence above.','','### Limitations','',text(m.limitations),'','## 3. Detailed Vulnerability Findings','');
    if(!project.findings.length)lines.push('No findings have been supplied. Security posture and absence of vulnerabilities '+MISSING+'.','');
    project.findings.forEach((item,i)=>{
      const r=rating(item),id='FINDING-'+String(i+1).padStart(2,'0');
      lines.push('### '+id+': '+text(item.title),'','- **Severity:** '+(r.severity||MISSING)+' | **CVSS v3.1 Score:** '+(r.score===null?MISSING:r.score.toFixed(1)),'- **CVSS v3.1 Vector:** '+(r.vector||MISSING),'- **Affected Endpoint / Parameter:** '+text(item.endpoint),'- **Evidence Status:** '+item.status,'','#### Description','',text(item.description),'','#### Proof of Concept (PoC)','',fence(item.poc),'','#### Impact','',text(item.impact),'','#### Remediation / Fix','',fence(item.remediation),'');
      if(item.status!=='Confirmed')lines.push('**Verification note:** This is an unverified candidate from the supplied material. Independent reproduction and exploitability '+MISSING+'.','');
      if(r.warnings.length)lines.push('**Scoring notes:** '+r.warnings.map(markdown).join(' '),'');
      if(item.references.trim())lines.push('**References / classification:** '+text(item.references),'');
      if(item.compliance.trim())lines.push('**Assessor-supplied compliance mapping:** '+text(item.compliance),'Mapping applicability and control ownership '+MISSING+'. This report does not certify SOC 2, ISO 27001, or PCI DSS compliance.','');
      if(item.retest.trim())lines.push('**Retest criteria / result:** '+text(item.retest),'');
    });
    lines.push('## 4. Strategic Recommendations','','### Immediate','',text(m.immediate),'','### Short-term','',text(m.shortTerm),'','### Long-term','',text(m.longTerm),'','### Publication Review','');
    if(gaps.length){lines.push('Outstanding details require manual verification before publication.');for(const gap of gaps)lines.push('- '+markdown(gap.location+': '+gap.field)+' — '+MISSING);}
    else lines.push('All required fields are populated and findings are marked confirmed by the assessor. Evidence validity, authorization, business-risk rationale, and final publication approval remain the assessor’s responsibility.');
    lines.push('','This report was composed from assessor-supplied material. The report composer does not scan targets, execute commands, independently reproduce vulnerabilities, or attest to certifications.');
    return {markdown:lines.join('\n'),gaps,risk,counts,confirmed,project};
  }
  function guidance(category,stack){
    const framework=stack||'the application';
    const lead='Baseline guidance — tailor to the actual affected code path and verify the fix.\n';
    if(category==='SQL injection'){
      const example=stack==='Node.js / Express'?"// PostgreSQL / node-postgres\nconst result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);":stack==='Django'?"# Django ORM; do not interpolate user-controlled SQL\nuser = User.objects.filter(email=email).first()":stack==='PHP / PDO'?"// Disable emulated prepares when supported by the database driver.\n$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);\n$stmt = $pdo->prepare('SELECT id FROM users WHERE email = :email');\n$stmt->execute(['email' => $email]);":"Use the database driver's parameter binding for values. Allowlist identifiers such as column names; they cannot generally be bound as query parameters.";
      return lead+'Replace string-concatenated queries with parameterized queries. Use a least-privileged database account. Return generic errors to clients and protect server logs.\n\n'+example+'\n\nRetest the supplied reproduction, benign input, and authorization boundaries. Do not treat a WAF rule as the primary fix.';
    }
    if(category==='Cross-site scripting')return lead+'Use context-appropriate output encoding and safe DOM APIs. Avoid concatenating untrusted content into HTML, attributes, JavaScript, or URLs.\n\n'+(stack==='React'?"// React escapes text by default.\nreturn <span>{untrustedValue}</span>;\n// Avoid dangerouslySetInnerHTML for untrusted HTML.":"// DOM text context\nconst element = document.createElement('span');\nelement.textContent = untrustedValue;")+'\n\nIf rich HTML is a business requirement, use a maintained sanitizer with a strict allowlist. Adopt a nonce-based Content Security Policy as defense in depth and retest the specific execution context.';
    if(category==='Broken access control / IDOR')return lead+'Enforce server-side authorization on every object access and mutation. Scope database queries to the authenticated principal or authorized tenant; deny by default. Apply the same rules to APIs, exports, bulk operations, and file downloads. Opaque IDs alone do not establish authorization.\n\nTest the documented request with a second authorized test account and with no authenticated session. Verify both read and write paths in '+framework+'.';
    if(category==='Security misconfiguration')return lead+'Disable debug mode and verbose client errors in production. Remove unnecessary services and default credentials. Configure a context-appropriate Content Security Policy, X-Content-Type-Options: nosniff, and Referrer-Policy. Enable HSTS only after confirming the entire applicable deployment supports HTTPS. Scope cache rules for sensitive responses.\n\nVerify observed behavior and effective response headers in the deployed environment. Record evidence of the fixed configuration.';
    if(category==='Sensitive data exposure')return lead+'Identify the exposed data and affected authorization boundary. Remove unnecessary fields from responses and use allowlisted response schemas. Restrict logs and backups, redact secrets, and enforce least privilege. Rotate any confirmed exposed credentials through the incident-response process.\n\nUse HTTPS in transit and an appropriate encryption/key-management design for stored sensitive data. Retest the exact documented disclosure without collecting unnecessary personal data.';
    if(category==='Server-side request forgery')return lead+'Prefer a fixed allowlist of approved outbound destinations and restrict network egress. Validate scheme, host, port and resolved IP address; block loopback, private, link-local, and metadata destinations as applicable. Validate every redirect and resolution step, or disable redirects. Prevent DNS rebinding and URL-parser discrepancies.\n\nDo not rely on a string prefix check. Retest the documented request against controlled test destinations, with agreed limits.';
    if(category==='Cross-site request forgery')return lead+'Use the framework’s built-in anti-CSRF protection for state-changing cookie-authenticated endpoints. Verify tokens server-side and apply appropriate SameSite and Secure cookie settings. Validate Origin where applicable and avoid state changes via GET.\n\n'+(stack==='Django'?'Keep CsrfViewMiddleware enabled and include {% csrf_token %} in forms. Do not bypass protection with csrf_exempt.':'Use a maintained framework-compatible CSRF mechanism and validate it for all state-changing request formats.')+'\n\nRetest the documented cross-origin request and legitimate application flows.';
    return lead+'[Needs manual verification] Identify the exact root cause, affected code path, framework and trust boundary. Specify a concrete patch and regression/retest criteria based on the supplied evidence.';
  }
  function draftExecutive(input){
    const project=sanitizeProject(input),confirmed=project.findings.filter(f=>f.status==='Confirmed');
    if(!confirmed.length)throw new Error('NO_CONFIRMED_FINDINGS');
    const risk=overall(project),target=project.metadata.target.trim()||MISSING;
    const names=confirmed.map(f=>f.title.trim()||MISSING);
    return 'The submitted assessment material for '+target+' documents '+confirmed.length+' assessor-confirmed security finding'+(confirmed.length===1?'':'s')+'. The overall risk rating, based on the highest confirmed severity, is '+risk+'.\n\nThe confirmed findings concern: '+names.join('; ')+'. Prioritize their remediation according to the documented impact and agreed business requirements, then perform a controlled retest.\n\n'+(project.findings.length>confirmed.length?'An additional '+(project.findings.length-confirmed.length)+' candidate finding(s) require manual verification. ':'')+'This summary reflects the submitted evidence and assessor review; it does not establish comprehensive test coverage or compliance certification.';
  }
  function demo(){const p=blank();p.demo=true;p.metadata={...p.metadata,client:'Demo organization (synthetic)',assessor:'Demo assessor (synthetic)',target:'https://app.example.test',assessmentType:'Gray-box / authenticated',date:'October 2026',stack:'Node.js / Express',inScope:'Demo web UI and GET /api/status in an isolated test environment.',outScope:'Production systems, third-party services, denial-of-service, and social engineering.',roles:'Standard test user. Administrative roles were not assessed.',methodology:'Synthetic illustration of a manually reproduced application error. No real target was tested.',executive:'This demonstration illustrates how an evidence-led security report is structured. It contains a synthetic candidate finding, which requires assessor verification.',businessImpact:'[Needs manual verification] Determine whether the reported error detail exposes information that could assist an attacker.',immediate:'Verify the candidate behavior and the actual information disclosed before assigning remediation urgency.',shortTerm:'If confirmed, remove verbose client-facing errors and record regression evidence.',longTerm:'Add secure error-handling review and regression checks to the delivery process.',limitations:'Demonstration data only. No security assessment or compliance evaluation was performed.'};p.notes='FINDING-01: Detailed application error in API response\nSeverity: Low\nEndpoint: GET /api/status\nDescription: Synthetic notes report a server stack trace returned to a standard test user.\nPoC: DEMONSTRATION ONLY\nGET /api/status HTTP/1.1\nHost: app.example.test\n\nHTTP/1.1 500 Internal Server Error\n{ "error": "DemoError", "stack": "SYNTHETIC STACK TRACE" }\nImpact: [Needs manual verification] Assess whether implementation details were disclosed.\nRemediation: Disable verbose client-facing errors and handle exceptions centrally.\n';p.findings=parseNotes(p.notes);p.findings[0].category='Security misconfiguration';return p;}
  const api=Object.freeze({MISSING,MAX_NOTES,MAX_FINDINGS,FIELDS,META,STANDARDS,SEVERITIES,blank,finding,normalize,redact,sanitizeProject,normalizeSeverity,cvss,rating,parseNotes,buildReport,completeness,overall,guidance,draftExecutive,demo});
  if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.SentinelReport=api;
})(typeof self!=='undefined'?self:globalThis);
