/* Bounded preview validation and request identity; no credentials or network destinations. */
(function(root){
  "use strict";
  const INPUT=1<<20, OUTPUT=32<<20, ENTRIES=4096, VALUE=16<<10, PAGE=50;
  const fields=new Set(["name","address","cname","type","ttl","disabled","comment","regexp","match-subdomain","forward-to","address-list","mx-exchange","mx-preference","ns","srv-port","srv-priority","srv-target","srv-weight","text"]);
  const semantic=new Set(["unsupported_property","invalid_boolean","unsupported_ttl","omitted_ttl_requires_source_defaults","regexp_semantics_not_compiled","subdomain_semantics_not_compiled","omitted_disabled_requires_source_defaults","omitted_match_subdomain_requires_source_defaults","omitted_type_requires_source_defaults","conflicting_record_fields","invalid_address_family","missing_match","missing_cname_fields","forward_semantics_not_compiled","negative_semantics_not_compiled","unsupported_record_type","disabled_entry_retained"]);
  const syntax=new Set(["input_read_failed","input_limit","invalid_text","dns_static_section_required","unsupported_command","entry_limit","invalid_property","duplicate_property","unknown_property","invalid_decoded_text","logical_line_limit","invalid_continuation","invalid_quoted_value","unterminated_string","interpolation_not_allowed","unterminated_escape","unsupported_escape","value_limit","expression_not_allowed","value_concatenation_not_allowed","empty_token"]);
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
  const api={INPUT,OUTPUT,ENTRIES,VALUE,PAGE,encodeText,fileSize,validPreview,parseDiagnostic,readJSON,Gate};
  if(typeof module!=="undefined"&&module.exports)module.exports=api;else root.RouterOSPreview=api;
})(globalThis);
