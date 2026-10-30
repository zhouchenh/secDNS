(() => {
 "use strict";
 const $=id=>document.getElementById(id), endpoint=new URL("../../followers",document.currentScript.src);
 let token="",epoch=0,accessEpoch=0,switching=false,controller=null,connected=false,busy=false;
 const note=text=>{$("status").textContent=text;};
 function controls(){ $("refresh").disabled=busy||!connected||(window.secDNSAgent&&!window.secDNSAgent.allows("records:read"));$("disconnect").hidden=!connected||!!window.secDNSAgent?.active;$("login").hidden=connected||!!window.secDNSAgent?.active; }
 function clear(){epoch++;controller?.abort();controller=null;token="";connected=false;busy=false;$("token").value="";$("rows").replaceChildren();$("sample").textContent="";controls();}
 const time=value=>value===null?"Not observed in this process":(window.secDNSI18n?.date(value)||new Date(value).toLocaleString());
 // Go emits UTC RFC3339Nano: reject JS's permissive locale/numeric date parsing.
 function timestamp(value){
  if(typeof value!=="string"||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{0,8}[1-9])?Z$/.test(value))return false;
  const ms=Date.parse(value);if(!Number.isFinite(ms))return false;
  return new Date(ms).toISOString().slice(0,19)===value.slice(0,19);
 }
 function revision(value){return typeof value==="string"&&/^(0|[1-9]\d{0,19})$/.test(value)&&(value.length<20||value<="18446744073709551615");}
 function validate(data){
  if(data?.scope!=="local_follower_workers"||data.stale_after_seconds!==90||!timestamp(data.observed_at)||!Array.isArray(data.followers)||data.followers.length>64)throw Error("Invalid status response.");
  for(const row of data.followers){
   for(const key of ["store","node_id","ruleset_id","lineage_id","authority_epoch","content_sha256"]){if(typeof row[key]!=="string"||row[key].length>1024)throw Error("Invalid status response.");}
   if(typeof row.accepted!=="boolean"||!revision(row.revision)||!["available","not_ready","unavailable"].includes(row.store_state)||!["unknown","recent","stale"].includes(row.contact_freshness)||!["starting","fetching","current","streaming","backoff","stopped"].includes(row.connection)||!["","authentication","canceled","protocol","snapshot","storage","transport"].includes(row.error_category))throw Error("Invalid status response.");
   for(const key of ["last_accepted_at","last_contact_at"]){if(row[key]!==null&&!timestamp(row[key]))throw Error("Invalid status response.");}
   if(row.accepted){if(row.revision==="0"||! /^[a-f0-9]{64}$/.test(row.content_sha256))throw Error("Invalid status response.");}
   else if(row.revision!=="0"||row.content_sha256!==""||row.last_accepted_at!==null)throw Error("Invalid status response.");
   if(row.last_accepted_at!==null&&row.last_contact_at===null)throw Error("Invalid status response.");
   if(row.last_contact_at===null&&row.contact_freshness!=="unknown")throw Error("Invalid status response.");
  }
  return data;
 }
 function render(data){
  const cards=[];
  for(const row of data.followers){
   const card=document.createElement("section"),title=document.createElement("h2"),list=document.createElement("dl");card.className="card";title.textContent=row.store;
   const fields={"Enrolled node":row.node_id,"Ruleset":row.ruleset_id,"Lineage":row.lineage_id,"Authority epoch":row.authority_epoch,"Local store":row.store_state,"Accepted revision":row.accepted?String(row.revision):"None accepted","Content digest":row.accepted?row.content_sha256:"None","Last accepted response":time(row.last_accepted_at),"Last validated contact":time(row.last_contact_at),"Contact freshness":row.contact_freshness,"Worker state":row.connection,"Last error category":row.error_category||"None"};
   const stamped={"Last accepted response":row.last_accepted_at,"Last validated contact":row.last_contact_at};
   for(const [key,value] of Object.entries(fields)){const dt=document.createElement("dt"),dd=document.createElement("dd");dt.textContent=key;dd.textContent=value;if(stamped[key]!==undefined&&stamped[key]!==null&&Number.isFinite(Date.parse(stamped[key]))){dd.dataset.i18nAt=stamped[key];dd.dataset.i18nTemplate="{time}";}list.append(dt,dd);}const readable=value=>value.replaceAll("_"," ").replace(/^./,c=>c.toUpperCase());const overview=document.createElement("p");overview.className="follower-summary";overview.textContent="Records: "+readable(row.store_state)+" / Contact: "+readable(row.contact_freshness)+" / Connection: "+readable(row.connection)+(row.error_category?" / Error: "+row.error_category:"");const detail=document.createElement("details"),summary=document.createElement("summary");summary.textContent="Replication details";detail.append(summary,list);card.append(title,overview,detail);cards.push(card);
  }
  $("rows").replaceChildren(...cards);$("sample").textContent="Last checked "+time(data.observed_at)+". This sample does not update automatically.";if(Number.isFinite(Date.parse(data.observed_at))){$("sample").dataset.i18nAt=data.observed_at;$("sample").dataset.i18nTemplate="Last checked {time}. This sample does not update automatically.";window.secDNSI18n?.stamp?.($("sample"));}
 }
 async function refresh(){
  controller?.abort();const captured=++epoch;const current=new AbortController();controller=current;busy=true;controls();note("Reading local worker status...");const timeout=setTimeout(()=>current.abort(),10000);
  try{
   const response=await fetch(endpoint,{headers:window.secDNSAgent?.headers(token,"GET")||{Authorization:"Bearer "+token},credentials:window.secDNSAgent?.credentials()||"omit",cache:"no-store",redirect:"error",signal:current.signal});
   if(!response.ok){void response.body?.cancel();const error=Error(response.status===404?"Local follower status is not configured on this listener.":response.status===401||response.status===403?"Sign in with an account or token that can view replication status.":"Local status is unavailable.");error.auth=response.status===401||response.status===403;error.status=response.status;throw error;}
   const reader=response.body.getReader();const chunks=[];let size=0;
   for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>1048576){await reader.cancel();throw Error("Status response exceeds its bound.");}chunks.push(value);}
   const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
   const data=validate(JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)));if(captured!==epoch)return;render(data);note(data.followers.length?"Read-only local worker sample received.":"No configured local follower workers.");
  }catch(error){if(captured!==epoch)return;if(error.auth){const session=!!window.secDNSAgent?.active;if(error.status===401&&session)window.secDNSAgent.expire();else clear();note(error.message);if(!session)$("token").focus();}else note((error.name==="AbortError"?"Status request timed out.":error.message)+" Any displayed sample is from the previous successful request; current state is unknown.");}
  finally{clearTimeout(timeout);if(captured===epoch){busy=false;controller=null;controls();}}
 }
 $("connect-form").addEventListener("submit",async event=>{event.preventDefault();if(switching)return;let value=$("token").value;$("token").value="";if(!value)return;const access=++accessEpoch;clear();switching=true;try{await window.secDNSAgent?.switchToLegacy();if(access!==accessEpoch)return;token=value;value="";connected=true;controls();await refresh();}catch{value="";if(access===accessEpoch)note("Could not switch authentication mode.");}finally{value="";switching=false;}});
 $("refresh").addEventListener("click",refresh);
 $("disconnect").addEventListener("click",()=>{const active=window.secDNSAgent?.active;accessEpoch++;clear();note("Disconnected. Status sample cleared.");if(active)void window.secDNSAgent.logout().catch(()=>{});});
 window.addEventListener("agentexpired",()=>{if(!switching)accessEpoch++;clear();note("Authentication session ended. Status sample cleared.");});
 window.addEventListener("agentconnected",()=>{accessEpoch++;clear();connected=true;controls();void refresh();});
 window.addEventListener("pagehide",()=>{accessEpoch++;clear();});
})();
