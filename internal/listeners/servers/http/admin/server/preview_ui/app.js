(() => {
  "use strict";
  const S=globalThis.RouterOSPreview, $=id=>document.getElementById(id), gate=new S.Gate();
  const endpoint=new URL("../../import/routeros/preview",document.currentScript.src);
  const editorPath=new URL("../",location.href).pathname,handoff=S.handoffConfig(location.hash,editorPath);
  if(handoff?.rulesetID)$("ruleset").value=handoff.rulesetID;
  if(endpoint.origin!==location.origin)throw new Error("Invalid preview origin");
  if(location.hash)history.replaceState(null,"",location.pathname+location.search);
  $("endpoint").textContent=endpoint.origin+endpoint.pathname;
  const handoffChannel=handoff&&typeof BroadcastChannel==="function"?new BroadcastChannel("secdns-routeros-draft-"+handoff.channelID):null;
  let token="",verified=false,controller=null,result=null,resultOperation="",page=0,provenance="",transferRequest="",transferTimer=null;
  const status=(text,kind="")=>{$("status").textContent=text;$("status").className=kind;};
  const bytes=n=>n>=1024?(n/1024).toFixed(2)+" KiB":n+" B";
  function controls(){
    $("preview").disabled=gate.busy || (window.secDNSAgent && !window.secDNSAgent.allows("routeros:preview"));
    $("transfer").disabled=gate.busy||!!transferRequest;
    $("disconnect").hidden=!!window.secDNSAgent?.active;
    $("authentication").textContent=window.secDNSAgent?.active?(verified?"Export analyzed":"Ready to analyze"):verified?"Last preview authenticated":token?"Token held · not verified":"Token not verified";
    $("ruleset-source").hidden=$("operation").value!=="exact";$("preview").textContent=$("operation").value==="exact"?"Prepare records for review":"Analyze export";
    $("paste-source").hidden=$("mode").value!=="paste";$("file-source").hidden=$("mode").value!=="file";
    try{const file=$("file").files[0], size=$("mode").value==="file"?(file?S.fileSize(file):0):S.encodeText($("source").value).length;
      $("source-info").textContent=($("mode").value==="file"?(file?file.name+" · ":"No file selected · "):"Pasted text · submitted UTF-8 · ")+bytes(size)+" / 1 MiB maximum";
    }catch{$("source-info").textContent="Source exceeds 1 MiB or contains invalid text. It cannot be submitted.";}
  }
  function invalidate(session=false){
    for(const id of ["step-source","step-analyze","step-review"])$(id).removeAttribute("aria-current");$("step-source").setAttribute("aria-current","step");$("handoff-help").textContent="";if(session)gate.session();else gate.change();controller?.abort();controller=null;if(transferTimer)clearTimeout(transferTimer);transferTimer=null;transferRequest="";$("transfer-status").textContent="";result=null;resultOperation="";provenance="";page=0;render();controls();
  }
  function disconnect(show=true){token="";verified=false;$("token").value="";invalidate(true);if(show)status("Disconnected. Source retained locally; no automatic submission.");}
  const diagnosticLabels={unsupported_type:'This record type cannot be converted. Review the source; no records from this export will be transferred.',unsupported_record_type:'This record type needs review before conversion.',disabled_entry_retained:'This entry is disabled in the source and is retained for review.',forward_semantics_not_compiled:'Forwarding rules cannot be converted to DNS records.',negative_semantics_not_compiled:'Negative-answer rules cannot be converted to DNS records.',regexp_semantics_not_compiled:'Regular-expression matching cannot be converted to an exact DNS name.',subdomain_semantics_not_compiled:'Subdomain matching cannot be converted to an exact DNS name.',duplicate_owner_type:'More than one entry has this name and type. Resolve the duplicate in the source.',cname_owner_conflict:'An alias shares its name with another record. Resolve the conflicting entries.',cname_cycle:'These aliases form a loop. Correct their targets before converting.',empty_source:'The source has no records to convert.',invalid_address_family:'The address does not match the selected record type. Check the address and type.',missing_cname_fields:'An alias requires both a name and a target.',unsupported_ttl:'The TTL cannot be converted exactly. Check the source value.',unsupported_property:'This entry contains an unsupported property. Review its meaning before changing the source.',invalid_boolean:'Use explicit yes or no values for the source flags.'};
  function diagnosticText(code){if(Object.hasOwn(diagnosticLabels,code))return diagnosticLabels[code];if(/^omitted_(type|ttl|disabled|match_subdomain)_requires_source_defaults$/.test(code))return 'A required source setting is missing. Supply its actual value explicitly; defaults are not assumed.';return 'This source entry needs review. See the diagnostic code in Details.';}
  function diagnosticDetails(code){const details=document.createElement('details'),summary=document.createElement('summary'),value=document.createElement('code');summary.textContent='Diagnostic details';value.textContent=code;details.append(summary,value);return details;}
  function diagnostics(items){
    const list=document.createElement("ul");list.className="diagnostics";
    for(const item of items){if(item.code==="preview_only_no_apply")continue;const li=document.createElement("li");li.textContent=(item.line===0?"Notice: ":"Line "+item.line+", byte column "+item.column+": ")+diagnosticText(item.code);li.append(diagnosticDetails(item.code));list.append(li);}return list;
  }
  function blockerList(items){
    const list=document.createElement("ul");list.className="diagnostics";
    for(const item of items){if(item.code==="preview_only_no_apply")continue;const li=document.createElement("li"),where=item.ordinal?"Entry "+item.ordinal+" · source line "+item.line:"Complete source";li.textContent=where+": "+diagnosticText(item.code)+(item.related_ordinal?" · related entry "+item.related_ordinal:"");li.append(diagnosticDetails(item.code));list.append(li);}return list;
  }
  function render(){
    $("results").hidden=!result;$("prepare-records").hidden=!result||resultOperation==="exact";$("entries").replaceChildren();$("global-diagnostics").replaceChildren();$("blockers").replaceChildren();$("candidate").textContent="";$("candidate-rows").replaceChildren();
    if(!result){$("summary").textContent=$("provenance").textContent=$("hash").textContent=$("exact-title").textContent=$("exact-hash").textContent="";$("exact-result").hidden=true;$("transfer").hidden=true;return;}
    const preview=resultOperation==="exact"?result.source:result,candidates=preview.entries.filter(e=>e.classification==="exact_record_candidate").length;
    $("summary").textContent=preview.entries.length+" source entries / "+candidates+" potential records / "+(preview.entries.length-candidates)+" requiring attention.";
    $("provenance").textContent=provenance;$("hash").textContent="Submitted bytes SHA-256 · "+preview.source_sha256;
    $("exact-result").hidden=resultOperation!=="exact";
    if(resultOperation==="exact"){
      $("exact-title").textContent=result.compiled?"Records ready for review":"Resolve import issues";
      $("exact-hash").textContent=result.compiled?"Canonical content SHA-256 · "+result.content_sha256:"No candidate content was produced.";
      if(result.blockers?.length)$("blockers").append(blockerList(result.blockers));
      if(result.compiled){$("candidate").hidden=false;$("candidate").textContent=JSON.stringify({bindings:result.bindings,content:result.content},null,2);$("transfer").hidden=!handoffChannel;$("transfer").classList.add("primary");$("download").classList.toggle("primary",!handoffChannel);$("handoff-help").textContent=handoffChannel?"This replaces the complete local record list in the originating editor only when that editor has no unsaved work. Review additions and removals there before applying.":"Open Import records from DNS records to send this review to that editor. You can download the review here.";
        for(const record of result.content.records){const tr=document.createElement("tr");for(const value of [record.name,record.type,record.values.join("; "),record.ttl_seconds+" s"]){const td=document.createElement("td");td.textContent=value;tr.append(td);}$("candidate-rows").append(tr);}}else{$("candidate").hidden=true;$("transfer").hidden=true;}
    }
    $("global-diagnostics").append(diagnostics(preview.diagnostics));$("source-entries").open=resultOperation!=="exact";
    const start=page*S.PAGE,end=Math.min(start+S.PAGE,preview.entries.length);
    $("page-info").textContent=preview.entries.length?"Entries "+(start+1)+"–"+end+" of "+preview.entries.length:"0 entries";
    $("previous").disabled=page===0;$("next").disabled=end>=preview.entries.length;$("empty").hidden=preview.entries.length!==0;
    for(const entry of preview.entries.slice(start,end)){
      const card=document.createElement("article"),heading=document.createElement("div"),title=document.createElement("h3"),classification=document.createElement("span"),fields=document.createElement("dl");
      card.className="entry";card.dataset.ordinal=String(entry.ordinal);heading.className="entry-heading";title.textContent="Entry "+entry.ordinal+" · source line "+entry.line;
      classification.className="classification "+entry.classification;classification.textContent=entry.classification==="exact_record_candidate"?"Potential record":"Needs attention";heading.append(title,classification);fields.className="fields";
      for(const key of [...new Set([...Object.keys(entry.fields),"type","ttl","disabled","match-subdomain"])].sort()){
        const term=document.createElement("dt"),detail=document.createElement("dd");term.textContent=key;
        if(Object.hasOwn(entry.fields,key)){const text=document.createElement("code");text.textContent=JSON.stringify(entry.fields[key]);detail.append(text);}else{detail.className="missing";detail.textContent="Not supplied · source defaults not established";}
        fields.append(term,detail);
      }
      card.append(heading,fields);if(entry.diagnostics?.length)card.append(diagnostics(entry.diagnostics));$("entries").append(card);
    }
  }
  function showResults(){
    $("source-panel").open=false;for(const id of ["step-source","step-analyze","step-review"])$(id).removeAttribute("aria-current");$(resultOperation==="exact"&&result?.compiled?"step-review":"step-analyze").setAttribute("aria-current","step");$("results-title").focus({preventScroll:true});$("results").scrollIntoView({block:"start"});
  }
  function httpMessage(code,data){
    if(code===400&&data?.error==="routeros_preview_parse_error"&&S.parseDiagnostic(data.diagnostic)){const d=data.diagnostic;return "Complete input rejected: "+diagnosticText(d.code)+" (line "+d.line+", byte column "+d.column+"). No partial preview.";}
    const allowed={400:["routeros_preview_read_failed","routeros_exact_options","routeros_exact_config"],413:["routeros_preview_too_large"],415:["routeros_preview_media_type","routeros_preview_encoding"],503:["routeros_preview_unavailable","routeros_exact_unavailable"]};
    if(code===400&&data?.error==="routeros_exact_config")return "Ruleset ID was rejected. Source retained; no conversion attempted.";
    if(code===400&&data?.error==="routeros_exact_options")return "Exact conversion options were rejected. Source retained.";
    return allowed[code]?.includes(data?.error)?({400:"Input could not be read. Source retained.",413:"Input exceeds 1 MiB. Source retained.",415:"The preview request format was rejected. Source retained.",503:"Review unavailable. Source retained; retry explicitly."})[code]:"Unexpected response. Source retained; no preview accepted.";
  }
  $("preview-form").addEventListener("submit",async event=>{
    event.preventDefault();if(gate.busy)return;
    const entered=$("token").value.trim();if(entered){$("token").value="";try{await window.secDNSAgent?.switchToLegacy();}catch{status("Could not end the agent session. Legacy access was not started.","error");return;}token=entered;verified=false;$("token").value="";invalidate(true);}
    if(!token&&!window.secDNSAgent?.active){status("Sign in before analyzing an export.","error");return;}
    if(window.secDNSAgent && !window.secDNSAgent.allows("routeros:preview")){status("This agent cannot preview imports.","error");return;}
    const operation=$("operation").value,ruleset=$("ruleset").value.trim();
    if(operation==="exact"&&!S.validRulesetID(ruleset)){status("Enter a valid ruleset ID before strict conversion.","error");return;}
    const captured=gate.begin(),capturedToken=token,mode=$("mode").value,file=$("file").files[0],text=$("source").value;
    result=null;render();controls();status("Preparing the selected bytes…");
    try{
      let data;
      if(mode==="file"){if(!file)throw new Error("file_required");S.fileSize(file);const buffer=await file.arrayBuffer();if(!gate.current(captured))return;if(buffer.byteLength>S.INPUT||buffer.byteLength!==file.size)throw new Error("input_limit");data=new Uint8Array(buffer);}else data=S.encodeText(text);
      if(!gate.current(captured))return;
      const active=new AbortController(),requestURL=new URL(endpoint.href);controller=active;if(operation==="exact"){requestURL.searchParams.set("profile","exact");requestURL.searchParams.set("ruleset_id",ruleset);}status(operation==="exact"?"Requesting strict whole-source conversion. Nothing will be applied…":"Requesting a preview. No records will be changed…");
      const response=await fetch(requestURL.href,{method:"POST",headers:{...(window.secDNSAgent?.headers(capturedToken,"POST") || {Authorization:"Bearer "+capturedToken}),"Content-Type":"application/octet-stream"},body:data,credentials:window.secDNSAgent?.credentials() || "omit",redirect:"error",cache:"no-store",signal:active.signal});
      if(!gate.current(captured))return;
      if(response.status===401||response.status===403){void response.body?.cancel().catch(()=>{});if(response.status===401&&window.secDNSAgent?.active)window.secDNSAgent.expire();else disconnect(false);status("Authentication rejected. Sign in again; source retained without automatic retry.","error");return;}
      if(response.redirected||response.type==="opaqueredirect")throw new Error("invalid_response");
      const payload=await S.readJSON(response);if(!gate.current(captured))return;
      if(operation==="exact"){
        if(response.status!==200&&response.status!==422){status(httpMessage(response.status,payload),"error");return;}
        if(!S.validExact(payload,ruleset)||payload.compiled!==response.ok||response.status!==(payload.compiled?200:422))throw new Error("invalid_response");
        result=payload;resultOperation=operation;page=0;provenance=(mode==="file"?"Original file bytes: "+file.name:"Pasted text: submitted UTF-8 bytes")+" · "+bytes(data.byteLength)+" · ruleset "+ruleset+" · "+payload.profile;verified=true;render();showResults();status(payload.compiled?"Exact conversion review loaded. Nothing applied.":"Exact conversion refused. Complete blockers loaded; no candidate produced.",payload.compiled?"success":"error");return;
      }
      if(!response.ok){status(httpMessage(response.status,payload),"error");return;}
      if(!S.validPreview(payload))throw new Error("invalid_response");
      result=payload;resultOperation=operation;page=0;provenance=(mode==="file"?"Original file bytes: "+file.name:"Pasted text: submitted UTF-8 bytes")+" · "+bytes(data.byteLength);verified=true;render();showResults();status("Complete preview loaded. Nothing applied.","success");
    }catch(error){if(gate.current(captured))status(({input_limit:"Source exceeds 1 MiB or file bytes changed. No preview sent.",invalid_text:"Pasted text contains invalid Unicode. No preview sent.",file_required:"Choose a local export file.",response_limit:"Response exceeds the preview limit. No preview accepted.",invalid_response:"Invalid preview response. No preview accepted."})[error.message]||"Preview failed or was interrupted. Source retained; retry explicitly.","error");}
    finally{if(gate.current(captured)){gate.finish(captured);controller=null;controls();}}
  });
  for(const id of ["source","file","mode","operation","ruleset"])$(id).addEventListener(["source","ruleset"].includes(id)?"input":"change",()=>{invalidate();status("Review settings changed locally. Click the review button to submit these bytes.");});
  $("token").addEventListener("input",()=>{token="";verified=false;invalidate(true);status("Token changed locally; not yet verified.");});
  $("clear").addEventListener("click",()=>{$("source").value="";$("file").value="";invalidate();status("Source and preview cleared from this page.");});
  $("disconnect").addEventListener("click",()=>{if(window.secDNSAgent?.active)void window.secDNSAgent.logout().catch(()=>{});disconnect();});
  window.addEventListener("agentconnected",()=>{token="";$("token").value="";invalidate(true);status("");});
  window.addEventListener("agentexpired",()=>disconnect());
  $("prepare-records").addEventListener("click",()=>{$("source-panel").open=true;$("operation").value="exact";$("operation").dispatchEvent(new Event("change"));$("ruleset").focus();});
  $("download").addEventListener("click",()=>{if(!result||resultOperation!=="exact")return;const blob=new Blob([JSON.stringify(result,null,2)+"\n"],{type:"application/json"}),href=URL.createObjectURL(blob),a=document.createElement("a");a.href=href;a.download="routeros-exact-"+result.ruleset_id+".json";a.click();setTimeout(()=>URL.revokeObjectURL(href),0);});
  function randomID(){if(!globalThis.crypto?.getRandomValues)throw new Error("randomness_unavailable");const random=crypto.getRandomValues(new Uint8Array(24));return Array.from(random,x=>x.toString(16).padStart(2,"0")).join("");}
  handoffChannel?.addEventListener("message",event=>{if(!transferRequest||!S.validHandoffResult(event.data,handoff,transferRequest))return;if(transferTimer)clearTimeout(transferTimer);transferTimer=null;const accepted=event.data.accepted;transferRequest="";$("transfer-status").textContent=accepted?"Added to the editor’s local changes. Review and apply there; no server records have been saved by this transfer.":({handoff_reconciliation_required:"Editor kept its existing local work; explicitly clear or finish it before another transfer.",handoff_identity_conflict:"Editor refused the candidate because its ruleset ID differs.",invalid_draft_handoff:"Editor rejected an invalid or stale transfer. Nothing changed.",editor_unavailable:"Editor is busy or not connected to a fresh snapshot. Nothing changed."})[event.data.error];controls();});
  $("transfer").addEventListener("click",()=>{if(!handoffChannel||transferRequest||!result||resultOperation!=="exact"||!result.compiled)return;try{transferRequest=randomID();handoffChannel.postMessage(S.draftHandoffMessage(result,handoff,transferRequest,location.pathname,Date.now()));$("transfer-status").textContent="Waiting for the originating editor to accept this candidate…";transferTimer=setTimeout(()=>{if(!transferRequest)return;transferRequest="";transferTimer=null;$("transfer-status").textContent="Transfer outcome unconfirmed. Inspect the originating editor draft before trying again.";controls();},5000);controls();}catch{$("transfer-status").textContent="Candidate could not be transferred. Nothing changed.";transferRequest="";controls();}});
  $("previous").addEventListener("click",()=>{if(result&&page>0){page--;render();}});$("next").addEventListener("click",()=>{const preview=resultOperation==="exact"?result?.source:result;if(preview&&(page+1)*S.PAGE<preview.entries.length){page++;render();}});
  window.addEventListener("pagehide",()=>{handoffChannel?.close();disconnect(false);$("source").value="";$("file").value="";});
  window.addEventListener("pageshow",event=>{if(event.persisted)disconnect();});
  render();controls();
})();
