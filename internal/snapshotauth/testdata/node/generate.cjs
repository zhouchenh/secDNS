'use strict';
// PUBLIC RFC8032 TEST KEY ONLY. Never use this published seed for real signing.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const seedHex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const publicHex = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const privateKey = crypto.createPrivateKey({key: Buffer.from('302e020100300506032b657004220420' + seedHex, 'hex'), format: 'der', type: 'pkcs8'});
const publicKey = crypto.createPublicKey(privateKey);
assert.equal(publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex'), publicHex);
assert.equal(crypto.sign(null, Buffer.alloc(0), privateKey).toString('hex'), 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
const hash = b => crypto.createHash('sha256').update(b).digest('hex');
const b64 = b => Buffer.from(b).toString('base64url');
const clone = x => JSON.parse(JSON.stringify(x));
// Only the pre-normalized synthetic fixture subset; not a replacement for recordset.New.
// Go encoding/json's HTML and separator escapes are required for embedded byte equality.
const json = x => JSON.stringify(x).replace(/[<>&\u2028\u2029]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
const records = [
  {name:'a.example.',type:'AAAA',values:['2001:db8::1'],ttl_seconds:300,expires_at:'2026-10-18T00:30:00.123456789Z'},
  {name:'z.example.',type:'TXT',values:['<safe>','','repeat','repeat'],ttl_seconds:0}
];
function snapshot(revision, useRecords = records) {
  const content = {schema:'secdns.exact-record-set.v1',ruleset_id:'synthetic-rules',records:useRecords};
  return {schema:content.schema,ruleset_id:content.ruleset_id,lineage_id:'synthetic-lineage',revision,content_sha256:hash(json(content)),records:useRecords};
}
const baseSnapshot = snapshot('9007199254740993');
const header = {alg:'Ed25519',typ:'application/vnd.secdns.snapshot-generation.v1+jws',kid:'rfc8032-test-1'};
function payload(s = baseSnapshot) {
  return {schema:'secdns.signed-snapshot-generation.v1',cluster_id:'synthetic-cluster',kind:'exact-records',ruleset_id:s.ruleset_id,lineage_id:s.lineage_id,authority_epoch:'synthetic-epoch',trust_generation:'7',revision:s.revision,content_sha256:s.content_sha256,issued_at:'2026-10-17T23:59:00Z',expires_at:'2026-10-18T01:00:00Z',snapshot:s};
}
const context = {
  expected_enrollment:{cluster_id:'synthetic-cluster',kind:'exact-records',ruleset_id:'synthetic-rules',lineage_id:'synthetic-lineage',authority_epoch:'synthetic-epoch'},
  trust:{enrollment:{cluster_id:'synthetic-cluster',kind:'exact-records',ruleset_id:'synthetic-rules',lineage_id:'synthetic-lineage',authority_epoch:'synthetic-epoch'},generation:'7',not_before:'2026-10-17T12:00:00Z',not_after:'2026-10-18T12:00:00Z',keys:[{kid:header.kid,public_key_hex:publicHex,not_before:'2026-10-17T12:00:00Z',not_after:'2026-10-18T12:00:00Z'}]},
  clock:{status:'trusted',now:'2026-10-18T00:00:00Z'},
  policy:{max_trust_window_seconds:86400,max_attestation_lifetime_seconds:86400,allowed_future_skew_seconds:30}
};
const vectors = [];
function add(id, expect, reason, h = json(header), p = json(payload()), overrides = null) {
  const hbytes = Buffer.isBuffer(h) ? h : Buffer.from(h);
  const pbytes = Buffer.isBuffer(p) ? p : Buffer.from(p);
  const hs = b64(hbytes), ps = b64(pbytes), signingInput = hs + '.' + ps;
  const sig = crypto.sign(null, Buffer.from(signingInput, 'ascii'), privateKey);
  const v = {id,expect,reason,header_utf8:hbytes.toString('utf8'),payload_utf8:pbytes.toString('utf8'),header_bytes_base64:hbytes.toString('base64'),payload_bytes_base64:pbytes.toString('base64'),signing_input_ascii:signingInput,signature_hex:sig.toString('hex'),compact:signingInput+'.'+b64(sig)};
  if (overrides) v.context = overrides;
  vectors.push(v);
  return v;
}
function changed(id, reason, mutate, expected = 'reject') {
  const p = clone(payload()); mutate(p); return add(id,expected,reason,json(header),json(p));
}
const valid = add('valid-high-revision','accept','Exact >2^53 revision; TTL0, nanosecond record expiry, escaped HTML, ordered duplicate and empty TXT chunks');
add('valid-max-revision','accept','Exact max uint64 revision',json(header),json(payload(snapshot('18446744073709551615'))));
add('valid-lower-revision','accept','Pure authenticity verifier has no persistent rollback floor',json(header),json(payload(snapshot('1'))));
add('valid-outer-reordered','accept','Original signed outer field order may vary; embedded snapshot stays canonical',json(header),json(Object.fromEntries(Object.entries(payload()).reverse())));
add('valid-header-reordered','accept','Protected-header field order may vary',json(Object.fromEntries(Object.entries(header).reverse())));
changed('valid-renewed-attestation','Same snapshot/revision under a later attestation',p=>{p.issued_at='2026-10-17T23:59:30Z';p.expires_at='2026-10-18T02:00:00Z';},'accept');
changed('valid-future-skew-boundary','Issuance exactly now+30 seconds is allowed by explicit fixture policy',p=>{p.issued_at='2026-10-18T00:00:30Z';p.expires_at='2026-10-18T00:01:00Z';},'accept');
for (const field of ['cluster_id','kind','ruleset_id','lineage_id','authority_epoch','trust_generation','revision','content_sha256']) {
  const p = clone(payload()); p[field] = field === 'revision' ? '9007199254740994' : field === 'trust_generation' ? '8' : field === 'content_sha256' ? '0'.repeat(64) : 'different';
  const ps = b64(json(p));
  const v = {...valid,id:'unsigned-tamper-'+field,expect:'reject',reason:'Payload '+field+' changed without resigning',payload_utf8:json(p),payload_bytes_base64:Buffer.from(json(p)).toString('base64'),signing_input_ascii:valid.compact.split('.')[0]+'.'+ps,compact:valid.compact.split('.')[0]+'.'+ps+'.'+valid.compact.split('.')[2]}; vectors.push(v);
}
for (const field of ['cluster_id','kind','ruleset_id','lineage_id','authority_epoch']) changed('signed-wrong-'+field,'Mathematically valid signature cannot change expected enrollment',p=>{p[field]='different';});
for (const generation of ['6','8','07','0','18446744073709551616']) changed('signed-trust-generation-'+generation,'Trust generation must be canonical positive uint64 and equal installed generation',p=>{p.trust_generation=generation;});
changed('signed-inner-revision-mismatch','Outer and canonical inner revision must match',p=>{p.revision='9007199254740994';});
changed('signed-inner-digest-mismatch','Outer and canonical inner digest must match',p=>{p.content_sha256='0'.repeat(64);});
changed('signed-inner-content-digest-invalid','Inner content digest must authenticate canonical content',p=>{p.snapshot.records[0].values[0]='2001:db8::2';});
const changedRecords=clone(records);changedRecords[0].values[0]='2001:db8::2';
add('valid-same-revision-different-content','accept','Pure verification accepts independently authentic content; persistent follower must detect equivocation',json(header),json(payload(snapshot(baseSnapshot.revision,changedRecords))));
const canonicalSnapshot=json(baseSnapshot);
add('signed-noncanonical-inner-whitespace','reject','Embedded raw bytes must equal recordset canonical MarshalJSON',json(header),json(payload()).replace(canonicalSnapshot,'{ '+canonicalSnapshot.slice(1)));
add('signed-noncanonical-inner-record-order','reject','Digest-valid semantic record reordering is not canonical',json(header),json(payload()).replace(canonicalSnapshot,json({...baseSnapshot,records:[...records].reverse()})));
add('signed-noncanonical-inner-html-escape','reject','Semantically identical literal HTML is not canonical Go JSON',json(header),json(payload()).replace('\\u003csafe\\u003e','<safe>'));
for (const [alg, id] of [['none','none'],['HS256','hs256'],['EdDSA','eddsa'],['Ed448','ed448']]) add('header-alg-'+id,'reject','No alternate algorithm allowed',json({...header,alg}));
add('header-wrong-typ','reject','Exact profile type required',json({...header,typ:'JWT'}));
add('header-jku','reject','Unknown remote key discovery member forbidden',json({...header,jku:'https://example.invalid/keys'}));
add('header-unknown-kid','reject','Only locally supplied authorized key selector allowed',json({...header,kid:'unknown'}));
add('header-duplicate-decoded-kid','reject','Escape-equivalent duplicate decoded field names',json(header).slice(0,-1)+',"k\\u0069d":"rfc8032-test-1"}');
add('header-case-variant','reject','Case-variant unknown field',json({...header,Kid:header.kid}));
add('payload-duplicate-decoded-revision','reject','Escape-equivalent duplicate payload name',json(header),json(payload()).slice(0,-1)+',"revis\\u0069on":"9007199254740993"}');
add('payload-null','reject','Required value cannot be null',json(header),json({...payload(),snapshot:null}));
add('payload-unknown','reject','Unknown payload field',json(header),json({...payload(),extra:true}));
add('payload-invalid-utf8','reject','Correctly signed raw invalid UTF8 must not be replaced and accepted',json(header),Buffer.concat([Buffer.from(json(payload()).slice(0,-1)+',"'),Buffer.from([0xff]),Buffer.from('":1}')]));
add('payload-lone-surrogate','reject','JSON escaped surrogate is invalid Unicode scalar',json(header),json(payload()).replace('synthetic-cluster','\\ud800'));
add('payload-trailing-value','reject','No trailing JSON value',json(header),json(payload())+'{}');
changed('time-expiry-at-now','now == expires_at fails half-open window',p=>{p.expires_at='2026-10-18T00:00:00Z';});
changed('time-future-skew-exceeded','now+31 seconds exceeds explicit fixture skew',p=>{p.issued_at='2026-10-18T00:00:31Z';});
changed('time-zero-lifetime','Issued and expiry cannot be equal',p=>{p.expires_at=p.issued_at;});
changed('time-before-key-window','Full signed interval must lie inside key/trust windows',p=>{p.issued_at='2026-10-17T11:59:59Z';});
changed('time-after-key-window','Full signed interval must lie inside key/trust windows',p=>{p.expires_at='2026-10-18T12:00:01Z';});
changed('time-noncanonical-offset','Equivalent offset does not equal canonical UTC Z spelling',p=>{p.issued_at='2026-10-18T07:59:00+08:00';});
changed('time-noncanonical-fraction','Attestation timestamps require whole seconds',p=>{p.issued_at='2026-10-17T23:59:00.000Z';});
add('clock-unknown','reject','Explicit unknown clock cannot verify',json(header),json(payload()),{clock:{status:'unknown',now:context.clock.now}});
add('trust-expired-now','reject','now == trust not_after fails',json(header),json(payload()),{clock:{status:'trusted',now:context.trust.not_after}});
add('key-revoked-absent','reject','Revoked key absent from enabled trust set cannot authorize even old issuance',json(header),json(payload()),{trust:{...context.trust,keys:[]}});
const parts=valid.compact.split('.');
function wire(id, reason, compact) {vectors.push({...valid,id,expect:'reject',reason,compact});}
wire('wire-whitespace','No whitespace wrapper',' '+valid.compact);
wire('wire-padding','Unpadded canonical base64url only',parts[0]+'=.'+parts[1]+'.'+parts[2]);
wire('wire-detached','Payload segment must be nonempty',parts[0]+'..'+parts[2]);
wire('wire-extra-segment','Exactly two periods',valid.compact+'.AA');
wire('wire-short-signature','Decoded signature must be exactly64 bytes',parts[0]+'.'+parts[1]+'.'+b64(Buffer.from(valid.signature_hex,'hex').subarray(1)));
const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';const final=parts[2].at(-1),alias=alphabet[alphabet.indexOf(final)+1];
assert.deepEqual(Buffer.from(parts[2],'base64url'),Buffer.from(parts[2].slice(0,-1)+alias,'base64url'));
wire('wire-nonzero-unused-bits','Decoded signature alias must fail canonical base64url re-encoding',parts[0]+'.'+parts[1]+'.'+parts[2].slice(0,-1)+alias);
const signature=Buffer.from(valid.signature_hex,'hex');signature[0]^=1;
wire('wire-signature-tamper','One signature bit changed',parts[0]+'.'+parts[1]+'.'+b64(signature));
for (const v of vectors) {
  const seg=v.compact.split('.');
  v.node_raw_signature_valid=seg.length===3 && crypto.verify(null,Buffer.from(seg[0]+'.'+seg[1],'ascii'),publicKey,Buffer.from(seg[2],'base64url'));
  v.compact_sha256=hash(v.compact);
}
const out={format:'operator-local synthetic interoperability fixtures; context fields are test-harness data, not new wire/API fields',key_provenance:'PUBLIC RFC8032 section7.1 test1; never deploy published seed',public_key_hex:publicHex,context,vectors};
fs.writeFileSync(path.join(__dirname,'vectors.json'),JSON.stringify(out,null,2)+'\n');
fs.writeFileSync(path.join(__dirname,'valid-high-revision.jws'),valid.compact);
fs.writeFileSync(path.join(__dirname,'valid-high-revision.header.json'),valid.header_utf8);
fs.writeFileSync(path.join(__dirname,'valid-high-revision.payload.json'),valid.payload_utf8);
fs.writeFileSync(path.join(__dirname,'valid-high-revision.signing-input.txt'),valid.signing_input_ascii);
fs.writeFileSync(path.join(__dirname,'canonical-snapshot.json'),canonicalSnapshot);
const provenance={node:process.version,openssl:process.versions.openssl,contractSHA256:hash(fs.readFileSync(path.join(__dirname,'..','authenticated-snapshot-next-proposal.md'))),generatorSHA256:hash(fs.readFileSync(__filename)),vectorsSHA256:hash(fs.readFileSync(path.join(__dirname,'vectors.json'))),keySource:'https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1',framingSource:'https://www.rfc-editor.org/rfc/rfc7515.html#section-3.1',rfcEmptyMessageSelfCheck:'PASS',public_key_hex:publicHex,canonicalContentSHA256:baseSnapshot.content_sha256,vectorCount:vectors.length,acceptCount:vectors.filter(v=>v.expect==='accept').length,byteFiles:['valid-high-revision.jws','valid-high-revision.header.json','valid-high-revision.payload.json','valid-high-revision.signing-input.txt','canonical-snapshot.json'].map(file=>({file,sha256:hash(fs.readFileSync(path.join(__dirname,file)))}))};
assert.equal(provenance.contractSHA256,'e5125bbcdc7dba1b63b8e8ae1f782f7823526dc1327472661938768de53b2f07');
fs.writeFileSync(path.join(__dirname,'provenance.json'),JSON.stringify(provenance,null,2)+'\n');
console.log(JSON.stringify({vectors:provenance.vectorCount,accept:provenance.acceptCount,node:provenance.node,generatorSHA256:provenance.generatorSHA256,vectorsSHA256:provenance.vectorsSHA256,provenanceSHA256:hash(fs.readFileSync(path.join(__dirname,'provenance.json')))},null,2));
