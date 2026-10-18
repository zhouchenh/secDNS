const assert=require('node:assert/strict');
const S=require('../internal/listeners/servers/http/admin/server/preview_ui/state.js');
const preview=()=>({source_sha256:'a'.repeat(64),entries:[{ordinal:1,line:2,fields:{type:'A',disabled:'yes',ttl:'0',comment:' <img> '},classification:'exact_record_candidate',diagnostics:[{line:2,column:1,code:'disabled_entry_retained'}]}],diagnostics:[{line:0,column:0,code:'preview_only_no_apply'}],can_apply:false});
assert.equal(S.validPreview(preview()),true);assert.equal(S.validPreview({...preview(),entries:[]}),true);
for(const change of [{can_apply:true},{can_apply:null},{can_apply:undefined},{source_sha256:'A'.repeat(64)},{entries:null},{diagnostics:[]},{extra:1}])assert.equal(S.validPreview({...preview(),...change}),false);
for(const change of [{ordinal:2},{line:0},{classification:'ready'},{fields:{unknown:'x'}},{fields:{comment:3}},{fields:{comment:'\ud800'}},{fields:{comment:'\0'}},{fields:{comment:'字'.repeat(6000)}},{diagnostics:[{line:2,column:1,code:'fake'}]},{diagnostics:[{line:1,column:1,code:'disabled_entry_retained'}]}]){const p=preview();Object.assign(p.entries[0],change);assert.equal(S.validPreview(p),false);}
assert.deepEqual([...S.encodeText(' \r\n字 ')],[32,13,10,229,173,151,32]);
assert.throws(()=>S.encodeText('\udc00'),/invalid_text/);assert.throws(()=>S.encodeText('x'.repeat(S.INPUT+1)),/input_limit/);assert.throws(()=>S.encodeText('字'.repeat(Math.floor(S.INPUT/3)+1)),/input_limit/);
assert.equal(S.fileSize({size:S.INPUT}),S.INPUT);assert.throws(()=>S.fileSize({size:S.INPUT+1}),/input_limit/);assert.throws(()=>S.fileSize({size:-1}),/input_limit/);
const gate=new S.Gate(),old=gate.begin();assert.throws(()=>gate.begin(),/busy/);gate.change();const current=gate.begin();assert.equal(gate.current(old),false);gate.finish(old);assert.equal(gate.busy,true);gate.session();assert.equal(gate.current(current),false);assert.equal(gate.busy,false);const latest=gate.begin();gate.finish(latest);assert.equal(gate.busy,false);
assert.equal(S.parseDiagnostic({line:2,column:7,code:'unknown_property'}),true);assert.equal(S.parseDiagnostic({line:0,column:0,code:'preview_only_no_apply'}),false);
(async()=>{
  const data=preview();assert.deepEqual(await S.readJSON(new Response(JSON.stringify(data))),data);
  let reads=0,cancelled=false,released=false;const response={headers:{get:()=>null},body:{getReader:()=>({read:async()=>({done:false,value:new Uint8Array(++reads===1?3:4)}),cancel:async()=>{cancelled=true;},releaseLock:()=>{released=true;}})}};
  await assert.rejects(S.readJSON(response,5),/response_limit/);assert.equal(reads,2);assert.equal(cancelled,true);assert.equal(released,true);
  await assert.rejects(S.readJSON(new Response('123456',{headers:{'content-length':'6'}}),5),/response_limit/);
  await assert.rejects(S.readJSON(new Response(Uint8Array.of(0xff))),/invalid_response/);
  await assert.rejects(S.readJSON(new Response('{')),/invalid_response/);
  console.log('RouterOS preview state/stream tests passed.');
})().catch(e=>{console.error(e);process.exitCode=1;});
