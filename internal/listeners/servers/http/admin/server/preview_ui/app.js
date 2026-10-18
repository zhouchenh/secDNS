(() => {
  "use strict";
  const S=globalThis.RouterOSPreview, $=id=>document.getElementById(id), gate=new S.Gate();
  const endpoint=new URL("../../import/routeros/preview",document.currentScript.src);
  if(endpoint.origin!==location.origin)throw new Error("Invalid preview origin");
  $("endpoint").textContent=endpoint.origin+endpoint.pathname;
  let token="",verified=false,controller=null,result=null,page=0,provenance="";
  const status=(text,kind="")=>{$("status").textContent=text;$("status").className=kind;};
  const bytes=n=>n>=1024?(n/1024).toFixed(2)+" KiB":n+" B";
  function controls(){
    $("preview").disabled=gate.busy;
    $("authentication").textContent=verified?"Last preview authenticated":token?"Token held · not verified":"Token not verified";
    $("paste-source").hidden=$("mode").value!=="paste";$("file-source").hidden=$("mode").value!=="file";
    try{const file=$("file").files[0], size=$("mode").value==="file"?(file?S.fileSize(file):0):S.encodeText($("source").value).length;
      $("source-info").textContent=($("mode").value==="file"?(file?file.name+" · ":"No file selected · "):"Pasted text · submitted UTF-8 · ")+bytes(size)+" / 1 MiB maximum";
    }catch{$("source-info").textContent="Source exceeds 1 MiB or contains invalid text. It cannot be submitted.";}
  }
  function invalidate(session=false){
    if(session)gate.session();else gate.change();controller?.abort();controller=null;result=null;provenance="";page=0;render();controls();
  }
  function disconnect(show=true){token="";verified=false;$("token").value="";invalidate(true);if(show)status("Disconnected. Source retained locally; no automatic submission.");}
  function diagnostics(items){
    const list=document.createElement("ul");list.className="diagnostics";
    for(const item of items){const li=document.createElement("li");li.textContent=item.line===0?"Preview notice: "+item.code:"Line "+item.line+", byte column "+item.column+": "+item.code;list.append(li);}return list;
  }
  function render(){
    $("results").hidden=!result;$("entries").replaceChildren();$("global-diagnostics").replaceChildren();
    if(!result){$("summary").textContent=$("provenance").textContent=$("hash").textContent="";return;}
    const candidates=result.entries.filter(e=>e.classification==="exact_record_candidate").length;
    $("summary").textContent="Entries: "+result.entries.length+" · Structural candidates: "+candidates+" · Unsupported semantics: "+(result.entries.length-candidates)+". No entries can be applied here.";
    $("provenance").textContent=provenance;$("hash").textContent="Submitted bytes SHA-256 · "+result.source_sha256;
    $("global-diagnostics").append(diagnostics(result.diagnostics));
    const start=page*S.PAGE,end=Math.min(start+S.PAGE,result.entries.length);
    $("page-info").textContent=result.entries.length?"Entries "+(start+1)+"–"+end+" of "+result.entries.length:"0 entries";
    $("previous").disabled=page===0;$("next").disabled=end>=result.entries.length;$("empty").hidden=result.entries.length!==0;
    for(const entry of result.entries.slice(start,end)){
      const card=document.createElement("article"),heading=document.createElement("div"),title=document.createElement("h3"),classification=document.createElement("span"),fields=document.createElement("dl");
      card.className="entry";card.dataset.ordinal=String(entry.ordinal);heading.className="entry-heading";title.textContent="Entry "+entry.ordinal+" · source line "+entry.line;
      classification.className="classification "+entry.classification;classification.textContent=entry.classification==="exact_record_candidate"?"Structural exact-record candidate":"Unsupported semantics";heading.append(title,classification);fields.className="fields";
      for(const key of [...new Set([...Object.keys(entry.fields),"type","ttl","disabled","match-subdomain"])].sort()){
        const term=document.createElement("dt"),detail=document.createElement("dd");term.textContent=key;
        if(Object.hasOwn(entry.fields,key)){const text=document.createElement("code");text.textContent=JSON.stringify(entry.fields[key]);detail.append(text);}else{detail.className="missing";detail.textContent="Not supplied · source defaults not established";}
        fields.append(term,detail);
      }
      card.append(heading,fields);if(entry.diagnostics?.length)card.append(diagnostics(entry.diagnostics));$("entries").append(card);
    }
  }
  function httpMessage(code,data){
    if(code===400&&data?.error==="routeros_preview_parse_error"&&S.parseDiagnostic(data.diagnostic)){const d=data.diagnostic;return "Complete input rejected: "+d.code+" (line "+d.line+", byte column "+d.column+"). No partial preview.";}
    const allowed={400:["routeros_preview_read_failed"],413:["routeros_preview_too_large"],415:["routeros_preview_media_type","routeros_preview_encoding"],503:["routeros_preview_unavailable"]};
    return allowed[code]?.includes(data?.error)?({400:"Input could not be read. Source retained.",413:"Input exceeds 1 MiB. Source retained.",415:"The preview request format was rejected. Source retained.",503:"Preview unavailable. Source retained; retry explicitly."})[code]:"Unexpected response. Source retained; no preview accepted.";
  }
  $("preview-form").addEventListener("submit",async event=>{
    event.preventDefault();if(gate.busy)return;
    const entered=$("token").value.trim();if(entered){token=entered;verified=false;$("token").value="";invalidate(true);}
    if(!token){status("Enter an admin token before submitting.","error");return;}
    const captured=gate.begin(),capturedToken=token,mode=$("mode").value,file=$("file").files[0],text=$("source").value;
    result=null;render();controls();status("Preparing the selected bytes…");
    try{
      let data;
      if(mode==="file"){if(!file)throw new Error("file_required");S.fileSize(file);const buffer=await file.arrayBuffer();if(!gate.current(captured))return;if(buffer.byteLength>S.INPUT||buffer.byteLength!==file.size)throw new Error("input_limit");data=new Uint8Array(buffer);}else data=S.encodeText(text);
      if(!gate.current(captured))return;
      const active=new AbortController();controller=active;status("Requesting a preview. No records will be changed…");
      const response=await fetch(endpoint.href,{method:"POST",headers:{Authorization:"Bearer "+capturedToken,"Content-Type":"application/octet-stream"},body:data,credentials:"omit",redirect:"error",cache:"no-store",signal:active.signal});
      if(!gate.current(captured))return;
      if(response.status===401||response.status===403){void response.body?.cancel().catch(()=>{});disconnect(false);status("Authentication rejected. Re-enter a token; source retained without automatic retry.","error");return;}
      if(response.redirected||response.type==="opaqueredirect")throw new Error("invalid_response");
      const payload=await S.readJSON(response);if(!gate.current(captured))return;
      if(!response.ok){status(httpMessage(response.status,payload),"error");return;}
      if(!S.validPreview(payload))throw new Error("invalid_response");
      result=payload;page=0;provenance=(mode==="file"?"Original file bytes: "+file.name:"Pasted text: submitted UTF-8 bytes")+" · "+bytes(data.byteLength);verified=true;render();status("Complete preview loaded. Nothing applied.","success");
    }catch(error){if(gate.current(captured))status(({input_limit:"Source exceeds 1 MiB or file bytes changed. No preview sent.",invalid_text:"Pasted text contains invalid Unicode. No preview sent.",file_required:"Choose a local export file.",response_limit:"Response exceeds the preview limit. No preview accepted.",invalid_response:"Invalid preview response. No preview accepted."})[error.message]||"Preview failed or was interrupted. Source retained; retry explicitly.","error");}
    finally{if(gate.current(captured)){gate.finish(captured);controller=null;controls();}}
  });
  for(const id of ["source","file","mode"])$(id).addEventListener(id==="source"?"input":"change",()=>{invalidate();status("Source changed locally. Click Preview to submit these bytes.");});
  $("token").addEventListener("input",()=>{token="";verified=false;invalidate(true);status("Token changed locally; not yet verified.");});
  $("clear").addEventListener("click",()=>{$("source").value="";$("file").value="";invalidate();status("Source and preview cleared from this page.");});
  $("disconnect").addEventListener("click",()=>disconnect());
  $("previous").addEventListener("click",()=>{if(result&&page>0){page--;render();}});$("next").addEventListener("click",()=>{if(result&&(page+1)*S.PAGE<result.entries.length){page++;render();}});
  window.addEventListener("pagehide",()=>{disconnect(false);$("source").value="";$("file").value="";});
  window.addEventListener("pageshow",event=>{if(event.persisted)disconnect();});
  render();controls();
})();
