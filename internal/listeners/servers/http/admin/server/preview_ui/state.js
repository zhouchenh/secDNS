/* Bounded preview validation and request identity; no credentials or network destinations. */
(function(root){
  "use strict";
  const INPUT=1<<20, OUTPUT=32<<20, HANDOFF=4<<20, ENTRIES=4096, VALUE=16<<10, PAGE=50, EXACT_PROFILE="secdns.routeros-exact-explicit.v1";
  const HANDOFF_KIND="secdns.routeros-exact-draft.v1", HANDOFF_RESULT_KIND="secdns.routeros-exact-draft-result.v1";
  const fields=new Set(["name","address","cname","type","ttl","disabled","comment","regexp","match-subdomain","forward-to","address-list","mx-exchange","mx-preference","ns","srv-port","srv-priority","srv-target","srv-weight","text"]);
  const semantic=new Set(["unsupported_property","invalid_boolean","unsupported_ttl","omitted_ttl_requires_source_defaults","regexp_semantics_not_compiled","subdomain_semantics_not_compiled","omitted_disabled_requires_source_defaults","omitted_match_subdomain_requires_source_defaults","omitted_type_requires_source_defaults","conflicting_record_fields","invalid_address_family","missing_match","missing_cname_fields","forward_semantics_not_compiled","negative_semantics_not_compiled","unsupported_record_type","disabled_entry_retained"]);
  const syntax=new Set(["input_read_failed","input_limit","invalid_text","dns_static_section_required","unsupported_command","entry_limit","invalid_property","duplicate_property","unknown_property","invalid_decoded_text","logical_line_limit","invalid_continuation","invalid_quoted_value","unterminated_string","interpolation_not_allowed","unterminated_escape","unsupported_escape","value_limit","expression_not_allowed","value_concatenation_not_allowed","empty_token"]);
  const blockerCodes=new Set(["empty_source","defaults_missing","unsupported_type","disabled_not_enabled","matching_policy_not_exact","fields_not_exact","ttl_not_exact","record_invalid","parser_semantics_not_exact","duplicate_owner_type","cname_owner_conflict","cname_cycle","target_limit"]);
  const object=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
  const keys=(x,required,optional=[])=>object(x)&&required.every(k=>Object.hasOwn(x,k))&&Object.keys(x).every(k=>required.includes(k)||optional.includes(k));
  const whole=(x,min,max)=>Number.isSafeInteger(x)&&x>=min&&x<=max;
  function wellFormed(s){
    for(let i=0;i<s.length;i++){const c=s.charCodeAt(i);if(c>=0xd800&&c<=0xdbff){const next=s.charCodeAt(++i);if(!(next>=0xdc00&&next<=0xdfff))return false;}else if(c>=0xdc00&&c<=0xdfff)return false;}return true;
  }
  function encodeText(s){if(typeof s!=="string"||!wellFormed(s))throw new Error("invalid_text");if(s.length>INPUT)throw new Error("input_limit");const data=new TextEncoder().encode(s);if(data.length>INPUT)throw new Error("input_limit");return data;}
  function fileSize(file){if(!file||!whole(file.size,0,INPUT))throw new Error("input_limit");return file.size;}
  function diagnostic(d,codes,global=false){return keys(d,["line","column","code"])&&codes.has(d.code)&&whole(d.line,global?0:1,INPUT+1)&&whole(d.column,global?0:1,INPUT+1);}
  function validPreview(p){
    if(!keys(p,["source_sha256","entries","can_apply"],["diagnostics"])||p.can_apply!==false||typeof p.source_sha256!=="string"||!(/^[a-f0-9]{64}$/).test(p.source_sha256)||!Array.isArray(p.entries)||p.entries.length>ENTRIES)return false;
    if(!Array.isArray(p.diagnostics)||p.diagnostics.length!==1||!diagnostic(p.diagnostics[0],new Set(["preview_only_no_apply"]),true)||p.diagnostics[0].line!==0||p.diagnostics[0].column!==0)return false;
    return p.entries.every((e,i)=>keys(e,["ordinal","line","fields","classification"],["diagnostics"])&&e.ordinal===i+1&&whole(e.line,1,INPUT+1)&&["exact_record_candidate","unsupported"].includes(e.classification)&&object(e.fields)&&Object.keys(e.fields).every(k=>fields.has(k)&&typeof e.fields[k]==="string"&&wellFormed(e.fields[k])&&!e.fields[k].includes("\0")&&e.fields[k].length<=VALUE&&new TextEncoder().encode(e.fields[k]).length<=VALUE)&&(!Object.hasOwn(e,"diagnostics")||Array.isArray(e.diagnostics)&&e.diagnostics.length<=64&&e.diagnostics.every(d=>diagnostic(d,semantic)&&d.line===e.line&&d.column===1)));
  }
  function parseDiagnostic(d){return diagnostic(d,syntax);}
  function validRulesetID(s){return typeof s==="string"&&s.length>0&&s.length<=128&&/^[A-Za-z0-9._-]+$/.test(s);}
  const handoffID=s=>typeof s==="string"&&/^[a-f0-9]{48}$/.test(s);
  function handoffConfig(hash,expectedTarget){
    if(typeof hash!=="string"||!hash.startsWith("#"))return null;let p;try{p=new URLSearchParams(hash.slice(1));}catch{return null;}
    if(![2,3].includes([...p.keys()].length)||p.getAll("draft_handoff").length!==1||p.getAll("target").length!==1||!handoffID(p.get("draft_handoff"))||p.get("target")!==expectedTarget||([...p.keys()].length===3&&(p.getAll("ruleset").length!==1||!validRulesetID(p.get("ruleset")))))return null;
    return Object.freeze({channelID:p.get("draft_handoff"),targetPath:expectedTarget,...(p.has("ruleset")?{rulesetID:p.get("ruleset")}:{})});
  }
  function exactBlocker(b,entries){return keys(b,["ordinal","line","code"],["related_ordinal"])&&blockerCodes.has(b.code)&&whole(b.ordinal,0,entries)&&whole(b.line,b.ordinal===0?0:1,INPUT+1)&&(b.ordinal!==0||b.line===0)&&(!Object.hasOwn(b,"related_ordinal")||whole(b.related_ordinal,1,entries));}
  function exactRecord(r){return keys(r,["name","type","values","ttl_seconds"])&&typeof r.name==="string"&&wellFormed(r.name)&&!r.name.includes("\0")&&r.name.length>0&&r.name.length<=255&&["A","AAAA","CNAME"].includes(r.type)&&Array.isArray(r.values)&&r.values.length>0&&r.values.length<=64&&r.values.every(v=>typeof v==="string"&&wellFormed(v)&&!v.includes("\0")&&v.length>0&&v.length<=255)&&whole(r.ttl_seconds,0,0xffffffff);}
  function exactContent(c,ruleset){return keys(c,["schema","ruleset_id","records"])&&c.schema==="secdns.exact-record-set.v1"&&c.ruleset_id===ruleset&&Array.isArray(c.records)&&c.records.length<=ENTRIES&&c.records.every(exactRecord);}
  function exactBinding(b,entries){return keys(b,["ordinal","name","type"])&&whole(b.ordinal,1,entries)&&typeof b.name==="string"&&wellFormed(b.name)&&b.name.length>0&&b.name.length<=255&&["A","AAAA","CNAME"].includes(b.type);}
  function validExact(x,expectedRuleset){
    if(!keys(x,["profile","ruleset_id","compiled","can_apply","source_sha256","source"],["blockers","content_sha256","bindings","content"])||x.profile!==EXACT_PROFILE||!validRulesetID(x.ruleset_id)||x.ruleset_id!==expectedRuleset||typeof x.compiled!=="boolean"||x.can_apply!==false||!validPreview(x.source)||x.source_sha256!==x.source.source_sha256)return false;
    const blockers=Object.hasOwn(x,"blockers")?x.blockers:[];
    if(!Array.isArray(blockers)||blockers.length>2*ENTRIES+1||!blockers.every(b=>exactBlocker(b,x.source.entries.length)))return false;
    if(!x.compiled)return blockers.length>0&&!Object.hasOwn(x,"content_sha256")&&!Object.hasOwn(x,"bindings")&&!Object.hasOwn(x,"content");
    return blockers.length===0&&x.source.entries.every(e=>e.classification==="exact_record_candidate"&&!Object.hasOwn(e,"diagnostics")&&["A","AAAA","CNAME"].includes(e.fields.type)&&Object.hasOwn(e.fields,"ttl")&&e.fields.disabled==="no"&&e.fields["match-subdomain"]==="no")&&typeof x.content_sha256==="string"&&/^[a-f0-9]{64}$/.test(x.content_sha256)&&Array.isArray(x.bindings)&&exactContent(x.content,x.ruleset_id)&&x.content.records.length===x.source.entries.length&&x.bindings.length===x.content.records.length&&x.bindings.every((b,i)=>exactBinding(b,x.source.entries.length)&&b.name===x.content.records[i].name&&b.type===x.content.records[i].type)&&new Set(x.bindings.map(b=>b.ordinal)).size===x.bindings.length;
  }
  function draftHandoffMessage(result,config,requestID,sourcePath,now){
    if(!config||!handoffID(config.channelID)||!handoffID(requestID)||typeof sourcePath!=="string"||!sourcePath.startsWith("/")||!Number.isSafeInteger(now)||!validExact(result,result?.ruleset_id)||!result.compiled)throw new Error("invalid_handoff");
    const message={kind:HANDOFF_KIND,channel_id:config.channelID,request_id:requestID,issued_at_ms:now,source_path:sourcePath,target_path:config.targetPath,profile:result.profile,source_sha256:result.source_sha256,content_sha256:result.content_sha256,content:result.content};
    if(new TextEncoder().encode(JSON.stringify(message)).length>HANDOFF)throw new Error("handoff_limit");return message;
  }
  function validHandoffResult(x,config,requestID){return keys(x,["kind","channel_id","request_id","accepted"],["error"])&&x.kind===HANDOFF_RESULT_KIND&&x.channel_id===config?.channelID&&x.request_id===requestID&&typeof x.accepted==="boolean"&&(x.accepted?!Object.hasOwn(x,"error"):new Set(["handoff_reconciliation_required","handoff_identity_conflict","invalid_draft_handoff","editor_unavailable"]).has(x.error));}
  async function readJSON(response,limit=OUTPUT){
    const length=response.headers.get("content-length");if(length!==null&&(!/^\d+$/.test(length)||Number(length)>limit)){await response.body?.cancel();throw new Error("response_limit");}
    if(!response.body)throw new Error("invalid_response");
    const reader=response.body.getReader(), chunks=[];let total=0;
    try{while(true){const {done,value}=await reader.read();if(done)break;if(!(value instanceof Uint8Array)||value.byteLength>limit-total){await reader.cancel();throw new Error("response_limit");}total+=value.byteLength;chunks.push(value);}}
    finally{reader.releaseLock();}
    const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
    try{return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}catch{throw new Error("invalid_response");}
  }
  class Gate{
    constructor(){this.generation=0;this.epoch=0;this.busy=false;}
    change(){this.generation++;this.busy=false;}
    session(){this.epoch++;this.change();}
    begin(){if(this.busy)throw new Error("busy");this.busy=true;return Object.freeze({generation:this.generation,epoch:this.epoch});}
    current(c){return c.generation===this.generation&&c.epoch===this.epoch;}
    finish(c){if(this.current(c))this.busy=false;}
  }
  const api={INPUT,OUTPUT,HANDOFF,ENTRIES,VALUE,PAGE,EXACT_PROFILE,HANDOFF_KIND,HANDOFF_RESULT_KIND,encodeText,fileSize,validPreview,validRulesetID,validExact,handoffConfig,draftHandoffMessage,validHandoffResult,parseDiagnostic,readJSON,Gate};
  if(typeof module!=="undefined"&&module.exports)module.exports=api;else root.RouterOSPreview=api;
})(globalThis);
