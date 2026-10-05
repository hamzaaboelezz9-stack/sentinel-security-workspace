/* The report workspace has no network, analytics, storage or command execution.
 * All untrusted report content is rendered through DOM text nodes. Exports are
 * explicit browser downloads; no raw notes are passed to WebMCP or an AI API.
 */
'use strict';
(()=>{
  const core=SentinelReport, $=id=>document.getElementById(id);
  let project=core.blank(), selected=-1, dirty=false, updateTimer=null, pending=null;
  const tabNames=['assessment','evidence','findings'];
  const colors={Critical:'#f8a897',High:'#f4b095',Medium:'#efca83',Low:'#a9c9f0',Informational:'#c5ef73'};
  function message(text,error=false){$('feedback').textContent=text;$('feedback').className='feedback'+(error?' error':'');$('feedback').hidden=false;}
  function activateTab(name){
    for(const key of tabNames){const active=key===name;const tab=$('tab-'+key);tab.classList.toggle('active',active);tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1;$('panel-'+key).hidden=!active;}
  }
  function setView(name){
    for(const key of ['report','markdown']){const active=key===name;const tab=$('view-'+key);tab.classList.toggle('active',active);tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1;}
    $('report-preview').hidden=name!=='report';$('markdown-preview').hidden=name!=='markdown';
  }
  function bindTabs(ids,activate){
    ids.forEach((id,index)=>{
      $(id).addEventListener('click',()=>activate(index));
      $(id).addEventListener('keydown',event=>{
        let next=index;
        if(event.key==='ArrowRight')next=(index+1)%ids.length;else if(event.key==='ArrowLeft')next=(index+ids.length-1)%ids.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=ids.length-1;else return;
        event.preventDefault();activate(next);$(ids[next]).focus();
      });
    });
  }
  bindTabs(tabNames.map(k=>'tab-'+k),index=>activateTab(tabNames[index]));
  bindTabs(['view-report','view-markdown'],index=>setView(index===0?'report':'markdown'));

  // Small renderer for the generated Markdown subset. No HTML interpolation,
  // eval, dangerous URL schemes, remote images, embeds or external plugins.
  function inline(element,value){
    let buffer='';const flush=()=>{if(buffer){element.append(document.createTextNode(buffer));buffer='';}};
    for(let i=0;i<value.length;){
      if(value[i]==='\\'&&i+1<value.length){buffer+=value[i+1];i+=2;continue;}
      if(value.startsWith(core.MISSING,i)){flush();const mark=document.createElement('span');mark.className='verification-marker';mark.textContent=core.MISSING;element.append(mark);i+=core.MISSING.length;continue;}
      if(value.startsWith('**',i)){const end=value.indexOf('**',i+2);if(end>=0){flush();const strong=document.createElement('strong');strong.textContent=value.slice(i+2,end);element.append(strong);i=end+2;continue;}}
      if(value[i]==='['){const match=/^\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/.exec(value.slice(i));if(match){try{const url=new URL(match[2]);if(['https:','http:'].includes(url.protocol)){flush();const a=document.createElement('a');a.textContent=match[1];a.href=url.href;a.target='_blank';a.rel='noopener noreferrer';element.append(a);i+=match[0].length;continue;}}catch{ /* Render malformed link as literal text. */ }}}
      buffer+=value[i++];
    }
    flush();
  }
  function cells(line){
    const out=[];let value='',escaped=false;
    for(const char of line.slice(1,-1)){
      if(char==='|'&&!escaped){out.push(value.trim());value='';}else value+=char;
      escaped=char==='\\'&&!escaped;
      if(char!=='\\')escaped=false;
    }
    out.push(value.trim());return out;
  }
  function renderMarkdown(markdown){
    const fragment=document.createDocumentFragment(), lines=markdown.split('\n');let i=0;
    while(i<lines.length){
      const line=lines[i];if(!line.trim()){i++;continue;}
      const tick=/^(`{3,})(?:text)?$/.exec(line);
      if(tick){const code=[];i++;while(i<lines.length&&lines[i]!==tick[1])code.push(lines[i++]);if(i<lines.length)i++;const pre=document.createElement('pre');pre.textContent=code.join('\n');fragment.append(pre);continue;}
      const heading=/^(#{1,4}) (.*)$/.exec(line);
      if(heading){const el=document.createElement('h'+heading[1].length);inline(el,heading[2]);fragment.append(el);i++;continue;}
      if(line.startsWith('|')){
        const table=document.createElement('table'),head=document.createElement('thead'),body=document.createElement('tbody');let first=true;
        while(i<lines.length&&lines[i].startsWith('|')){
          const rowCells=cells(lines[i++]);if(rowCells.every(cell=>/^:?-+:?$/.test(cell.trim())))continue;
          const tr=document.createElement('tr');for(const value of rowCells){const cell=document.createElement(first?'th':'td');if(first)cell.scope='col';inline(cell,value.replace(/<br>/g,'\n'));tr.append(cell);}(first?head:body).append(tr);first=false;
        }
        table.append(head,body);fragment.append(table);continue;
      }
      if(line.startsWith('- ')){const list=document.createElement('ul');while(i<lines.length&&lines[i].startsWith('- ')){const li=document.createElement('li');inline(li,lines[i++].slice(2));list.append(li);}fragment.append(list);continue;}
      if(line.startsWith('> ')){const block=document.createElement('blockquote');inline(block,line.slice(2));fragment.append(block);i++;continue;}
      const p=document.createElement('p'),paragraph=[];
      do{paragraph.push(lines[i++]);}while(i<lines.length&&lines[i].trim()&&!/^(?:#{1,4} |\||- |> |`{3,})/.test(lines[i]));
      inline(p,paragraph.join('\n'));fragment.append(p);
    }
    $('report-preview').replaceChildren(fragment);
  }
  function refresh(){
    clearTimeout(updateTimer);updateTimer=null;
    try{
      const report=core.buildReport(project);
      $('stat-total').textContent=String(project.findings.length);$('stat-confirmed').textContent=String(report.confirmed);
      $('stat-risk').textContent=report.risk===core.MISSING?'Not established':report.risk;$('stat-risk').style.color=colors[report.risk]||'';
      $('stat-gaps').textContent=String(report.gaps.length);$('finding-count').textContent=String(project.findings.length);
      $('checklist-count').textContent=report.gaps.length+' to review';$('report-review-state').textContent=project.demo?'SYNTHETIC DEMO · NOT AN ASSESSMENT':report.gaps.length?'DRAFT · REVIEW REQUIRED':'ASSESSOR-REVIEWED · APPROVE PUBLICATION';
      $('demo-banner').hidden=!project.demo;
      const list=document.createDocumentFragment();for(const gap of report.gaps){const li=document.createElement('li');li.textContent=gap.location+': '+gap.field;list.append(li);}if(!report.gaps.length){const li=document.createElement('li');li.textContent='Required fields are populated. Review evidence validity and approve publication.';list.append(li);}$('review-gaps').replaceChildren(list);
      $('markdown-preview').value=report.markdown;renderMarkdown(report.markdown);
      return report;
    }catch{message('The report could not be composed. Review the imported project format and field lengths.',true);return null;}
  }
  function schedule(){clearTimeout(updateTimer);updateTimer=setTimeout(refresh,180);}
  function renderList(){
    const fragment=document.createDocumentFragment();
    project.findings.forEach((item,index)=>{
      const button=document.createElement('button');button.type='button';button.className='finding-card'+(index===selected?' selected':'');button.setAttribute('aria-pressed',String(index===selected));
      const content=document.createElement('div'),id=document.createElement('small'),title=document.createElement('strong'),pill=document.createElement('span');
      id.textContent='FINDING-'+String(index+1).padStart(2,'0')+' · '+item.status;title.textContent=item.title.trim()||core.MISSING;content.append(id,title);
      const level=core.rating(item).severity;pill.className='severity-pill '+(level?level.toLowerCase():'');pill.textContent=level||'Unrated';button.append(content,pill);
      button.addEventListener('click',()=>{selected=index;renderList();fillFinding();});fragment.append(button);
    });
    $('finding-list').replaceChildren(fragment);$('finding-empty').hidden=project.findings.length>0;$('finding-editor').hidden=selected<0;
  }
  const METRICS={AV:['Attack vector',{N:'Network',A:'Adjacent',L:'Local',P:'Physical'}],AC:['Attack complexity',{L:'Low',H:'High'}],PR:['Privileges required',{N:'None',L:'Low',H:'High'}],UI:['User interaction',{N:'None',R:'Required'}],S:['Scope',{U:'Unchanged',C:'Changed'}],C:['Confidentiality impact',{N:'None',L:'Low',H:'High'}],I:['Integrity impact',{N:'None',L:'Low',H:'High'}],A:['Availability impact',{N:'None',L:'Low',H:'High'}]};
  for(const [metric,[labelText,values]]of Object.entries(METRICS)){
    const label=document.createElement('label'),select=document.createElement('select');select.id='metric-'+metric;label.append(document.createTextNode(labelText));
    const empty=document.createElement('option');empty.value='';empty.textContent='Select verified metric';select.append(empty);
    for(const [value,name]of Object.entries(values)){const option=document.createElement('option');option.value=value;option.textContent=name+' ('+value+')';select.append(option);}label.append(select);$('cvss-metrics').append(label);
  }
  function updateCVSS(){
    const item=project.findings[selected];if(!item)return;const r=core.rating(item);let computed=null;
    try{computed=core.cvss(item.vector);}catch{ /* Preserve user input and show validation warning. */ }
    $('cvss-result').textContent=computed?computed.score.toFixed(1):'—';$('cvss-band').textContent=computed?computed.severity:'Complete vector required';
    $('cvss-warning').textContent=r.warnings.join(' ');$('cvss-warning').hidden=!r.warnings.length;
  }
  function fillFinding(){
    const item=project.findings[selected];$('finding-editor').hidden=!item;if(!item)return;
    for(const key of core.FIELDS)$('finding-'+key).value=item[key]||'';
    $('active-finding-id').textContent='FINDING-'+String(selected+1).padStart(2,'0');
    let values={};try{const result=core.cvss(item.vector);if(result)values=Object.fromEntries(result.vector.slice(9).split('/').map(part=>part.split(':')));}catch{}
    for(const key of Object.keys(METRICS))$('metric-'+key).value=values[key]||'';updateCVSS();
  }
  function syncInputs(){
    for(const key of core.META)$('meta-'+key).value=project.metadata[key];
    for(const input of document.querySelectorAll('[data-standard]'))input.checked=project.standards.includes(input.dataset.standard);
    $('raw-notes').value=project.notes;$('redact-toggle').checked=project.redact;updateNotesCount();renderList();fillFinding();refresh();
  }
  function updateNotesCount(){$('notes-count').textContent=(new TextEncoder().encode(project.notes).length/1024).toFixed(1)+' / 256 KB';}
  function requestReplace(action,title='Replace current work?',description='This replaces work in this tab. Export the project first if you need a copy.'){
    if(!dirty){action();return;}
    pending=action;$('confirm-title').textContent=title;$('confirm-description').textContent=description;$('confirm-dialog').showModal();
  }
  $('confirm-cancel').addEventListener('click',()=>{pending=null;$('confirm-dialog').close();});
  $('confirm-accept').addEventListener('click',()=>{const action=pending;pending=null;$('confirm-dialog').close();if(action)action();});
  $('confirm-dialog').addEventListener('cancel',()=>{pending=null;});
  for(const key of core.META)$('meta-'+key).addEventListener('input',event=>{project.metadata[key]=event.target.value;dirty=true;schedule();});
  for(const input of document.querySelectorAll('[data-standard]'))input.addEventListener('change',()=>{project.standards=[...document.querySelectorAll('[data-standard]')].filter(el=>el.checked).map(el=>el.dataset.standard);dirty=true;schedule();});
  $('raw-notes').addEventListener('input',event=>{project.notes=event.target.value;dirty=true;updateNotesCount();});
  $('redact-toggle').addEventListener('change',event=>{project.redact=event.target.checked;dirty=true;refresh();message(project.redact?'Best-effort secret redaction enabled for the preview and all exports.':'Redaction disabled. Review the report and project export for secrets before sharing.');});
  for(const key of core.FIELDS)$('finding-'+key).addEventListener('input',event=>{
    const item=project.findings[selected];if(!item)return;item[key]=event.target.value;
    // Changing the evidential basis invalidates the previous confirmation.
    if(['title','endpoint','description','poc'].includes(key)&&item.status==='Confirmed'){item.status='Needs verification';$('finding-status').value=item.status;}
    dirty=true;renderList();updateCVSS();schedule();
  });
  function addFinding(){if(project.findings.length>=core.MAX_FINDINGS){message('This bounded workspace supports up to 50 findings.',true);return;}project.findings.push(core.finding());selected=project.findings.length-1;dirty=true;renderList();fillFinding();activateTab('findings');refresh();$('finding-title').focus();}
  for(const id of ['add-finding','add-empty-evidence'])$(id).addEventListener('click',addFinding);
  $('go-evidence').addEventListener('click',()=>{activateTab('evidence');$('raw-notes').focus();});
  $('extract-findings').addEventListener('click',()=>{
    let findings;try{findings=core.parseNotes(project.redact?core.redact(project.notes):project.notes);}catch(error){message(error.message==='EMPTY_NOTES'?'Paste actual notes before extracting candidates.':'Notes exceed the supported size or finding limit.',true);return;}
    const apply=()=>{project.findings=findings;selected=findings.length?0:-1;dirty=true;renderList();fillFinding();activateTab('findings');refresh();message(findings.length+' candidate finding'+(findings.length===1?'':'s')+' extracted. Review evidence and fill missing details before confirming.');};
    if(project.findings.length)requestReplace(apply,'Replace current findings?','Extraction will replace your existing finding edits with unverified candidates from the current notes. Export the project first if you need a copy.');else apply();
  });
  $('remove-finding').addEventListener('click',()=>{if(selected<0)return;requestReplace(()=>{project.findings.splice(selected,1);selected=project.findings.length?Math.min(selected,project.findings.length-1):-1;dirty=true;renderList();fillFinding();refresh();},'Remove this finding?','This removes the selected finding from the report. Other findings and raw notes remain available.');});
  $('draft-executive').addEventListener('click',()=>{
    let draft;try{draft=core.draftExecutive(project);}catch{message('Confirm at least one evidence-reviewed finding before drafting the executive overview.',true);return;}
    const apply=()=>{project.metadata.executive=draft;$('meta-executive').value=draft;dirty=true;refresh();message('Executive overview drafted from confirmed finding counts, titles and severity. Review its wording and business context.');};
    if(project.metadata.executive.trim())requestReplace(apply,'Replace executive overview?','This replaces the overview with a deterministic draft based on assessor-confirmed findings.');else apply();
  });
  $('apply-cvss').addEventListener('click',()=>{
    if(selected<0)return;const entries=Object.keys(METRICS).map(key=>[key,$('metric-'+key).value]);
    if(entries.some(([,value])=>!value)){message('Select all eight verified CVSS Base metrics. No missing values are assumed.',true);return;}
    const vector='CVSS:3.1/'+entries.map(([key,value])=>key+':'+value).join('/');
    try{core.cvss(vector);project.findings[selected].vector=vector;$('finding-vector').value=vector;dirty=true;updateCVSS();renderList();refresh();message('CVSS v3.1 Base vector calculated from your selected metrics.');}catch{message('The selected CVSS vector could not be validated.',true);}
  });
  $('insert-guidance').addEventListener('click',()=>{
    const item=project.findings[selected];if(!item)return;
    const apply=()=>{item.remediation=core.guidance(item.category,project.metadata.stack);$('finding-remediation').value=item.remediation;dirty=true;refresh();message('Baseline fix guidance inserted. Tailor it to the affected code and verify the remediation.');};
    if(item.remediation.trim())requestReplace(apply,'Replace remediation text?','This will replace the selected finding’s remediation with baseline guidance for its category and application stack.');else apply();
  });
  $('load-demo').addEventListener('click',()=>requestReplace(()=>{project=core.demo();selected=0;dirty=true;syncInputs();activateTab('findings');message('Synthetic demonstration loaded. No real application was assessed.');}));
  $('clear-project').addEventListener('click',()=>requestReplace(()=>{project=core.blank();selected=-1;dirty=false;syncInputs();activateTab('assessment');message('Workspace cleared. No project was saved automatically.');},'Clear this workspace?','All scope, raw notes and finding edits in this tab will be cleared. Export your project first to retain a copy.'));
  $('import-file').addEventListener('click',()=>$('file-input').click());
  $('file-input').addEventListener('change',async event=>{
    const file=event.target.files?.[0];if(!file)return;
    try{
      if(file.size>1048576)throw new Error('FILE_TOO_LARGE');
      const content=await file.text();
      if(/\.json$/i.test(file.name)){
        const imported=core.normalize(JSON.parse(content));
        requestReplace(()=>{project=imported;selected=project.findings.length?0:-1;dirty=true;syncInputs();activateTab('assessment');message('Project imported locally. Confirm its evidence and scope before publication.');});
      }else{
        if(!/\.(txt|md|log)$/i.test(file.name)||new TextEncoder().encode(content).byteLength>core.MAX_NOTES)throw new Error('INVALID_NOTES');
        requestReplace(()=>{project.notes=content;project.findings=[];project.demo=false;selected=-1;dirty=true;syncInputs();activateTab('evidence');message('Notes imported locally. Extract candidates to begin the review.');},'Import new evidence?','This replaces raw notes and findings. Assessment scope is retained; verify that it applies to the imported evidence.');
      }
    }catch{message('Import failed. Use a valid Sentinel project JSON (up to 1 MB) or a TXT, MD or LOG notes file (up to 256 KB).',true);}
    finally{event.target.value='';}
  });
  function download(content,type,extension){
    const title=(project.metadata.client||'assessment').replace(/[^a-zA-Z0-9_-]+/g,'-').replace(/^-|-$/g,'').slice(0,50)||'assessment';
    const url=URL.createObjectURL(new Blob([content],{type})),a=document.createElement('a');a.href=url;a.download='Sentinel-'+title+'.'+extension;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  $('export-markdown').addEventListener('click',()=>{const report=refresh();if(!report)return;download(report.markdown,'text/markdown;charset=utf-8','md');message('Markdown exported'+(report.gaps.length?' as a draft with '+report.gaps.length+' review items.':'. Review and approve it before publication.'));});
  $('export-project').addEventListener('click',()=>{try{download(JSON.stringify(core.sanitizeProject(project),null,2),'application/json;charset=utf-8','json');message('Project exported locally. Keep the file secure; it includes your assessment evidence.');}catch{message('Project export could not complete.',true);}});
  $('print-report').addEventListener('click',()=>{if(!refresh())return;setView('report');window.print();});
  window.addEventListener('beforeunload',event=>{if(dirty){event.preventDefault();event.returnValue='';}});
  window.addEventListener('pagehide',()=>{clearTimeout(updateTimer);project=core.blank();selected=-1;dirty=false;syncInputs();});
  // Existing Site extension: agent tools intentionally accept no evidence,
  // client data, credentials, or report text because transcripts may retain it.
  const context=document.modelContext;
  if(context?.registerTool){const lifetime=new AbortController();window.addEventListener('pagehide',()=>lifetime.abort(),{once:true});
    for(const tool of [
      {name:'read_report_review_counts',title:'Read report review counts',description:'Read aggregate finding and publication-review counts only; returns no evidence or client details.',inputSchema:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:false},execute(input){if(!input||typeof input!=='object'||Object.keys(input).length)throw new Error('Invalid input');const report=refresh();if(!report)throw new Error('Report unavailable');return {findings:project.findings.length,confirmed:report.confirmed,reviewItems:report.gaps.length,demo:project.demo};}},
      {name:'open_report_evidence_panel',title:'Open evidence input',description:'Open the raw evidence panel without entering or extracting notes.',inputSchema:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:false,untrustedContentHint:false},execute(input){if(!input||typeof input!=='object'||Object.keys(input).length)throw new Error('Invalid input');activateTab('evidence');return {panel:'evidence'};}}
    ])try{Promise.resolve(context.registerTool(tool,{signal:lifetime.signal})).catch(()=>{});}catch{}
  }
  syncInputs();
})();
