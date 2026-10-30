const assert = require('node:assert/strict');
const S = require('../internal/listeners/servers/http/admin/server/versioned_ui/state.js');
const snapshot = (revision='1', records=[]) => ({schema:'secdns.exact-record-set.v1',ruleset_id:'r',lineage_id:'l',revision,content_sha256:'a'.repeat(64),records});
const record = {name:'text.invalid.',type:'TXT',values:['','same','same'],ttl_seconds:0,expires_at:'2000-01-01T00:00:00.123456789Z'};
const receipt = (id, revision) => ({operation_id:id,revision,content_sha256:'b'.repeat(64),committed_at:'2026-01-01T00:00:00.123456789Z'});
assert.equal(S.increment('9007199254740993'),'9007199254740994');
assert.equal(S.compare('9007199254740993','9007199254740992'),1);
for(const bad of ['0','01',1,'18446744073709551616','+1']) assert.equal(S.revision(bad),false);
assert.equal(S.revision('18446744073709551615'),true);
assert.throws(()=>S.increment('18446744073709551615'));
const m=new S.Model();m.accept(snapshot('9007199254740993',[record]));m.touch();
m.accept(snapshot('9007199254740994',[record,{...record,name:'remote.invalid.'}]));
assert.equal(m.base.revision,'9007199254740993');assert.equal(m.formDirty,true);assert.equal(m.draft.length,1);
m.formDirty=false;m.stage({...record,values:['changed']},S.key(record));
const pending=m.freeze('op','http://127.0.0.1/snapshot'), body=pending.body;
assert.equal(JSON.parse(body).expected.revision,'9007199254740993');assert.equal(JSON.parse(body).records[0].ttl_seconds,0);
m.uncertain();m.accept(snapshot('9007199254740995',[record]));
assert.equal(m.pending.body,body);assert.throws(()=>m.adopt());assert.throws(()=>m.freeze('other','x'));
m.acknowledge(receipt('op','9007199254740994'));m.accept(snapshot('9007199254740995',[record]));
assert.equal(m.base.revision,'9007199254740995');assert.equal(m.receipt.revision,'9007199254740994');assert.equal(m.pending,null);
assert.deepEqual(m.draft[0],record);assert.throws(()=>m.accept(snapshot('9007199254740994')));
m.stage({...record,values:['new']},S.key(record));m.freeze('next','local');m.touch();
m.acknowledge(receipt('next','9007199254740996'));m.accept(snapshot('9007199254740996',[record]));
assert.equal(m.formDirty,true);assert.equal(m.draft[0].values[0],'new');assert.ok(m.pending);
assert.throws(()=>m.accept({...snapshot('9007199254740997'),lineage_id:'other'}));
assert.equal(m.identityBlocked,true);assert.throws(()=>m.adopt());
for(const change of [{operation_id:'wrong'}, {revision:2}, {revision:'9007199254740997'}, {content_sha256:'wrong'}, {committed_at:'bad'}]) assert.throws(()=>m.acknowledge({...receipt('next','9007199254740996'),...change}));
assert.equal(S.recordsValid([{...record,values:['x'.repeat(256)]}]),false);
assert.equal(S.recordsValid([{...record,values:['\u5b57'.repeat(86)]}]),false);
assert.equal(S.recordsValid([{...record,values:Array(65).fill('x')}]),false);
assert.equal(S.recordsValid(Array(10001).fill(record)),false);
assert.equal(S.recordsValid(Array(10000).fill({...record,values:Array(11).fill('x')})),false);
assert.equal(S.recordsValid([{...record,values:[]}]),false);
const now=Date.UTC(2026,9,18), channel='c'.repeat(48), request='d'.repeat(48), sourcePath='/admin/ui/import-preview/', targetPath='/admin/ui/';
const candidateRecord={name:'imported.invalid.',type:'A',values:['192.0.2.10'],ttl_seconds:60};
const transfer=(fields={})=>({kind:S.HANDOFF_KIND,channel_id:channel,request_id:request,issued_at_ms:now,source_path:sourcePath,target_path:targetPath,profile:S.HANDOFF_PROFILE,source_sha256:'1'.repeat(64),content_sha256:'2'.repeat(64),content:{schema:'secdns.exact-record-set.v1',ruleset_id:'r',records:[candidateRecord]},...fields});
assert.equal(S.exactDraftHandoff(transfer(),channel,sourcePath,targetPath,now),true);
for(const change of [{kind:'wrong'},{channel_id:'e'.repeat(48)},{request_id:'short'},{issued_at_ms:now-S.HANDOFF_AGE_MS-1},{issued_at_ms:now+5001},{source_path:'/other/'},{target_path:'/other/'},{profile:'wrong'},{source_sha256:'A'.repeat(64)},{content_sha256:'x'},{extra:true},{content:{...transfer().content,records:[]}},{content:{...transfer().content,records:[{...candidateRecord,type:'TXT'}]}},{content:{...transfer().content,records:[{...candidateRecord,values:['192.0.2.10','192.0.2.11']}]}},{content:{...transfer().content,records:[{...candidateRecord,expires_at:'2030-01-01T00:00:00Z'}]}},{content:{...transfer().content,records:Array(4097).fill(candidateRecord)}}])assert.equal(S.exactDraftHandoff(transfer(change),channel,sourcePath,targetPath,now),false);
const cyclic=transfer();cyclic.loop=cyclic;assert.equal(S.exactDraftHandoff(cyclic,channel,sourcePath,targetPath,now),false);
const imported=new S.Model();imported.accept(snapshot());imported.importCandidate(transfer(),channel,sourcePath,targetPath,now);
assert.deepEqual(imported.draft,[candidateRecord]);assert.equal(imported.dirty(),true);assert.equal(imported.draftProvenance.sourceSHA256,'1'.repeat(64));assert.equal(imported.draftProvenance.contentSHA256,'2'.repeat(64));assert.equal(imported.draftProvenance.editCounter,imported.edits);
assert.throws(()=>imported.importCandidate(transfer(),channel,sourcePath,targetPath,now),/handoff_reconciliation_required/);
imported.adopt();assert.equal(imported.draftProvenance,null);
const unchangedImport=new S.Model();unchangedImport.accept(snapshot());unchangedImport.importCandidate(transfer(),channel,sourcePath,targetPath,now);
const importedPending=unchangedImport.freeze('import-op','local'),importedBody=JSON.parse(importedPending.body);
assert.deepEqual(importedBody.operator_supplied_provenance,{profile:S.HANDOFF_PROFILE,source_sha256:'1'.repeat(64),content_sha256:'2'.repeat(64)});
assert.deepEqual(importedPending.operatorSuppliedProvenance,importedBody.operator_supplied_provenance);
unchangedImport.uncertain();assert.equal(unchangedImport.pending.body,importedPending.body,'uncertain retry preserves tuple bytes');
const importedReceipt={...receipt('import-op','2'),content_sha256:'2'.repeat(64)},importedProvenance=importedBody.operator_supplied_provenance;
assert.throws(()=>unchangedImport.acknowledge(importedReceipt),/invalid_receipt/,'tuple-bearing request requires matching receipt headers');
unchangedImport.acknowledge(importedReceipt,importedProvenance);assert.deepEqual(unchangedImport.receiptProvenance,importedProvenance);
const editedImport=new S.Model();editedImport.accept(snapshot());editedImport.importCandidate(transfer(),channel,sourcePath,targetPath,now);
editedImport.stage({...candidateRecord,values:['192.0.2.11']},S.key(candidateRecord));editedImport.stage(candidateRecord,S.key(candidateRecord));
assert.equal(Object.hasOwn(JSON.parse(editedImport.freeze('edited-import','local').body),'operator_supplied_provenance'),false,'edit then revert omits original tuple');
assert.equal(S.operatorProvenance(importedProvenance,'2'.repeat(64)),true);assert.equal(S.operatorProvenance(importedProvenance,'3'.repeat(64)),false);
const responseModel=new S.Model();responseModel.accept({...snapshot(),content_sha256:'2'.repeat(64)},importedProvenance);assert.deepEqual(responseModel.currentProvenance,importedProvenance);
assert.throws(()=>new S.Model().accept(snapshot(),importedProvenance),/invalid_snapshot_response/);
assert.throws(()=>unchangedImport.acknowledge(importedReceipt,{...importedProvenance,source_sha256:'x'}),/invalid_receipt/);
const unfinished=new S.Model();unfinished.accept(snapshot());unfinished.touch();assert.throws(()=>unfinished.importCandidate(transfer(),channel,sourcePath,targetPath,now),/handoff_reconciliation_required/);assert.deepEqual(unfinished.draft,[]);
const mismatch=new S.Model();mismatch.accept(snapshot());assert.throws(()=>mismatch.importCandidate(transfer({content:{...transfer().content,ruleset_id:'other'}}),channel,sourcePath,targetPath,now),/handoff_identity_conflict/);assert.deepEqual(mismatch.draft,[]);
const huge=new S.Model();huge.accept(snapshot());
for(let i=0;i<270;i++)huge.draft.push({...record,name:`r${i}.invalid.`,values:Array(64).fill('x'.repeat(255))});
assert.throws(()=>huge.freeze('large','local'),/snapshot_too_large/);
// A display union distinguishes local and observed-server changes without adopting either.
const rr = (name, fields={}) => ({name,type:'TXT',values:['original'],ttl_seconds:60,...fields});
const base = [rr('unchanged.invalid.'),rr('local-remove.invalid.'),rr('server-remove.invalid.'),rr('ttl-expiry.invalid.'),rr('values.invalid.'),rr('local-change.invalid.'),rr('server-change.invalid.'),rr('same-change.invalid.')];
const draft = [base[0],base[2],rr('ttl-expiry.invalid.',{ttl_seconds:0}),rr('values.invalid.',{values:['','same','same']}),rr('local-add.invalid.'),rr('local-change.invalid.',{values:['  '+ 'x'.repeat(200)+'  ']}),base[6],rr('same-change.invalid.',{values:['identical']})];
const current = [base[0],base[1],rr('ttl-expiry.invalid.',{expires_at:'2030-01-01T00:00:00.123456789+00:00'}),rr('values.invalid.',{values:['same','','same']}),rr('server-add.invalid.'),base[5],rr('server-change.invalid.',{values:['remote']}),rr('same-change.invalid.',{values:['identical']})];
const before = JSON.stringify({base,draft,current}), compared = S.comparisonRows(base,draft,current);
const row = name => compared.find(r=>r.key===S.key(rr(name)));
assert.deepEqual(compared.map(r=>r.key),compared.map(r=>r.key).sort());
assert.deepEqual([row('local-add.invalid.').localChange,row('local-add.invalid.').serverChange],['added','unchanged']);
assert.deepEqual([row('server-add.invalid.').localChange,row('server-add.invalid.').serverChange],['unchanged','added']);
assert.deepEqual([row('local-remove.invalid.').localChange,row('local-remove.invalid.').serverChange],['removed','unchanged']);
assert.deepEqual([row('server-remove.invalid.').localChange,row('server-remove.invalid.').serverChange],['unchanged','removed']);
assert.deepEqual([row('local-change.invalid.').localChange,row('local-change.invalid.').serverChange],['changed','unchanged']);
assert.deepEqual([row('server-change.invalid.').localChange,row('server-change.invalid.').serverChange],['unchanged','changed']);
assert.deepEqual([row('same-change.invalid.').localChange,row('same-change.invalid.').serverChange],['changed','changed']);assert.deepEqual(row('same-change.invalid.').draft,row('same-change.invalid.').current);
assert.equal(row('local-change.invalid.').draft.values[0],'  '+'x'.repeat(200)+'  ');
assert.equal(row('ttl-expiry.invalid.').draft.ttl_seconds,0);assert.equal(row('ttl-expiry.invalid.').base.ttl_seconds,60);
assert.equal(Object.hasOwn(row('ttl-expiry.invalid.').draft,'expires_at'),false);assert.equal(row('ttl-expiry.invalid.').current.expires_at,'2030-01-01T00:00:00.123456789+00:00');
assert.deepEqual(row('values.invalid.').draft.values,['','same','same']);assert.deepEqual(row('values.invalid.').current.values,['same','','same']);
assert.equal(row('unchanged.invalid.').changed,false);
for(const [scope,records] of [['local',draft],['server',current]]){
  const counts = {added:0,changed:0,removed:0};for(const r of compared)if(Object.hasOwn(counts,r[scope+'Change']))counts[r[scope+'Change']]++;
  assert.deepEqual(counts,S.changes(base,records));
}
assert.ok(S.comparisonRows(base,draft).every(r=>r.serverChange==='unavailable'&&r.current===null));
assert.ok(S.comparisonRows(base,base,null).every(r=>!r.changed));
assert.ok(S.comparisonRows(base,base,[]).every(r=>r.serverChange==='removed'&&r.changed));
assert.equal(S.comparisonRows([rr('Case.invalid.')],[rr('case.invalid')],[]).length,1,'existing canonical key semantics');
row('values.invalid.').draft.values.reverse();row('ttl-expiry.invalid.').current.expires_at='display-only';
assert.equal(JSON.stringify({base,draft,current}),before,'display copies never alias snapshots');
// Rendering/filtering copies must leave exact retry identity, receipt, edit counter and dirty form untouched.
const protectedState = JSON.stringify(m);
S.comparisonRows(m.base.records,m.draft,m.current.records).filter(r=>r.changed).reverse().forEach(r=>{if(r.draft)r.draft.values.push('display-only');});
assert.equal(JSON.stringify(m),protectedState);
console.log('Versioned editor state tests passed.');

// Capability-driven one-RRset review and frozen transport semantics.
for(const capability of [null,'unknown','v1']) {
 const x=new S.Model();x.accept(snapshot('9007199254740993',[record]),null,capability);
 x.stage({...record,values:['new','new']},S.key(record));
 const review=x.review('http://127.0.0.1/snapshot');const p=x.freeze('single','http://127.0.0.1/snapshot',review),wire=JSON.parse(p.body);
 assert.equal(p.mode,capability==='v1'?'rrset':'replacement');
 if(capability==='v1'){assert.equal(p.endpoint,'http://127.0.0.1/snapshot/rrset');assert.equal(wire.action,'upsert');assert.equal(wire.record.ttl_seconds,0);assert.deepEqual(wire.record.values,['new','new']);assert.equal(wire.record.expires_at,record.expires_at);assert.equal(wire.records,undefined);}
 x.uncertain();x.accept(snapshot('9007199254740994',[record]),null,null);assert.equal(x.pending,p);assert.equal(x.pending.body,p.body);assert.equal(x.pending.endpoint,p.endpoint);assert.equal(x.pending.operationID,'single');
}
for(const operation of ['add','delete','multi','zero']) {
 const x=new S.Model();x.accept(snapshot('1',[record]),null,'v1');
 if(operation==='add'||operation==='multi')x.stage({...record,name:'other.invalid.'});
 if(operation==='delete'||operation==='multi')x.remove(S.key(record));
 const proposal=x.proposal('/snapshot');assert.equal(proposal.mode,['add','delete'].includes(operation)?'rrset':'replacement');
 if(operation==='delete')assert.deepEqual(proposal.payload,{action:'delete',key:{name:record.name,type:record.type},confirm_removals:1});
}
{
 const x=new S.Model();x.accept(snapshot('1',[record]),null,'v1');x.stage({...record,values:['new']},S.key(record));const review=x.review('/snapshot');x.rrsetCapability=null;assert.throws(()=>x.freeze('reviewed','/snapshot',review),/review_changed/);assert.equal(x.pending,null);
 x.rrsetCapability='v1';x.draftProvenance={editCounter:-1};assert.equal(x.proposal('/snapshot').mode,'replacement','edited import remains full atomic proposal');
}
console.log('Conditional RRset editor state tests passed.');

// Typed draft assistance must reject before mutating the draft, retaining unfinished fields.
const typed={name:'files.invalid.',type:'AAAA',values:['2001:db8::1'],ttl_seconds:0};
const validationModel=new S.Model();validationModel.accept(snapshot('1',[typed]));validationModel.touch();
const typedBefore=JSON.stringify(validationModel.draft);
assert.throws(()=>validationModel.stage({...typed,values:['invalid-ipv6']},S.key(typed)),e=>e.issue.field==='values');
assert.equal(JSON.stringify(validationModel.draft),typedBefore);assert.equal(validationModel.formDirty,true);assert.equal(validationModel.pending,null);
for(const value of ['::','::1','2001:db8::1','1:2:3:4:5:6:7:8','::192.0.2.1'])assert.equal(S.draftIssue({...typed,values:[value]}),null,value);
for(const value of ['invalid-ipv6','1::2::3','1:2:3:4:5:6:7','::ffff:192.0.2.1','fe80::1%eth0','[::1]'])assert.ok(S.draftIssue({...typed,values:[value]}),value);
for(const value of ['192.0.2.1','::ffff:192.0.2.1'])assert.equal(S.draftIssue({...typed,type:'A',values:[value]}),null,value);
for(const value of ['192.168.001.1','999.1.2.3','1.2.3','0x7f000001','::1'])assert.ok(S.draftIssue({...typed,type:'A',values:[value]}),value);
assert.ok(S.draftIssue({...typed,values:['::1','0:0:0:0:0:0:0:1']}));
assert.ok(S.draftIssue({...typed,type:'CNAME',values:['target.invalid.']},[typed]));
assert.ok(S.draftIssue({...typed,name:'other.invalid.'},[typed,{...typed,name:'other.invalid.'}],S.key(typed)));
assert.equal(S.draftIssue({...typed,type:'TXT',values:['','same','same'],ttl_seconds:0}),null);
for(const name of ['_service._tcp.invalid.','*.invalid.','.'])assert.equal(S.draftIssue({...typed,name}),null);
for(const name of ['x..invalid','a'.repeat(64)+'.invalid','bad name.invalid','escaped\\.invalid'])assert.ok(S.draftIssue({...typed,name}));
console.log('Typed draft validation and unchanged-draft tests passed.');
{
  // Slice 2: row Undo, and drafts kept across a WithMy ID round trip (exportDraft/importDraft).
  const a={name:'a.invalid.',type:'A',values:['192.0.2.1'],ttl_seconds:60},b={name:'b.invalid.',type:'A',values:['192.0.2.2'],ttl_seconds:60};
  const m=new S.Model();m.accept(snapshot('5',[a,b]));
  assert.equal(m.exportDraft(),null);
  m.remove(S.key(a));m.stage({...b,values:['192.0.2.3']},S.key(b));m.stage({name:'c.invalid.',type:'A',values:['192.0.2.4'],ttl_seconds:60});
  assert.deepEqual(S.changes(m.base.records,m.draft),{added:1,changed:1,removed:1});
  assert.equal(m.undo(S.key(a)),true);assert.deepEqual(S.changes(m.base.records,m.draft),{added:1,changed:1,removed:0});
  assert.equal(m.undo('c.invalid/A'),true);assert.equal(m.undo(S.key(b)),true);assert.equal(m.dirty(),false);assert.equal(m.undo('none.invalid/A'),false);
  m.remove(S.key(a));const kept=JSON.parse(JSON.stringify(m.exportDraft()));
  assert.equal(kept.base.revision,'5');assert.equal(kept.draft.length,1);assert.equal(kept.pending,null);
  // the server moved on meanwhile: the kept base stays the base, the newer state is the comparison
  const n=new S.Model();n.accept(snapshot('7',[a,b,{name:'d.invalid.',type:'A',values:['192.0.2.9'],ttl_seconds:60}]));
  n.importDraft(kept,['https://x/snapshot','https://x/snapshot/rrset']);
  assert.equal(n.base.revision,'5');assert.equal(n.current.revision,'7');assert.deepEqual(S.changes(n.base.records,n.draft),{added:0,changed:0,removed:1});
  assert.equal(n.proposal('https://x/snapshot').payload.confirm_removals,1);
  // refused: dirty target, another ruleset, a base newer than the server, a forged pending endpoint
  assert.throws(()=>n.importDraft(kept,[]),/draft_restore_refused/);
  const other=new S.Model();other.accept({...snapshot('9',[a]),ruleset_id:'other'});assert.throws(()=>other.importDraft(kept,[]),/draft_restore_refused/);
  const older=new S.Model();older.accept(snapshot('4',[a]));assert.throws(()=>older.importDraft(kept,[]),/draft_restore_refused/);
  // an uncertain submitted change keeps its frozen request
  const u=new S.Model();u.accept(snapshot('5',[a,b]));u.remove(S.key(a));u.remove(S.key(b));const frozen=u.freeze('op-kept','https://x/snapshot');u.uncertain();
  const keptU=JSON.parse(JSON.stringify(u.exportDraft()));assert.equal(keptU.pending.body,frozen.body);assert.equal(JSON.parse(frozen.body).confirm_removals,2);
  const v=new S.Model();v.accept(snapshot('5',[a,b]));assert.throws(()=>v.importDraft(keptU,['https://evil/snapshot']),/draft_restore_refused/);
  const w=new S.Model();w.accept(snapshot('5',[a,b]));w.importDraft(keptU,['https://x/snapshot']);assert.equal(w.pending.status,'uncertain');assert.equal(w.pending.body,frozen.body);assert.equal(w.pending.operationID,'op-kept');
  console.log('Slice-2 Undo and kept-draft tests passed.');
}
