/* Pure snapshot/editor state; credentials and network operations live elsewhere. */
(function (root) {
  "use strict";
  const MAX = "18446744073709551615", LIMIT = 4 * 1024 * 1024, HANDOFF_AGE_MS = 30000;
  const HANDOFF_KIND = "secdns.routeros-exact-draft.v1", HANDOFF_PROFILE = "secdns.routeros-exact-explicit.v1";
  const clone = value => JSON.parse(JSON.stringify(value));
  const compare = (a, b) => a.length === b.length ? (a < b ? -1 : a > b ? 1 : 0) : (a.length < b.length ? -1 : 1);
  const revision = x => typeof x === "string" && /^[1-9][0-9]*$/.test(x) && compare(x, MAX) <= 0;
  function increment(value) {
    if (!revision(value) || value === MAX) throw new Error("revision_exhausted");
    const digits = value.split(""); let carry = true;
    for (let i = digits.length - 1; i >= 0 && carry; i--) { if (digits[i] === "9") digits[i] = "0"; else { digits[i] = String.fromCharCode(digits[i].charCodeAt(0) + 1); carry = false; } }
    if (carry) digits.unshift("1"); return digits.join("");
  }
  const identity = s => s.ruleset_id + "/" + s.lineage_id;
  const exactKeys = (obj, required, optional = []) => obj && typeof obj === "object" && !Array.isArray(obj) && required.every(k => Object.hasOwn(obj, k)) && Object.keys(obj).every(k => required.includes(k) || optional.includes(k));
  const stamp = s => typeof s === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/.test(s) && Number.isFinite(Date.parse(s));
  const bytes = s => new TextEncoder().encode(s).length;
  function boundedJSON(value) { try { return bytes(JSON.stringify(value)) <= LIMIT; } catch { return false; } }
  function recordsValid(records) {
    let values = 0;
    return Array.isArray(records) && records.length <= 10000 && records.every(r => {
      if (!exactKeys(r, ["name", "type", "values", "ttl_seconds"], ["expires_at"]) || typeof r.name !== "string" || !r.name || !["A", "AAAA", "CNAME", "TXT"].includes(r.type) || !Number.isInteger(r.ttl_seconds) || r.ttl_seconds < 0 || r.ttl_seconds > 4294967295 || !Array.isArray(r.values) || !r.values.length || r.values.length > 64) return false;
      values += r.values.length;
      return values <= 100000 && r.values.every(v => typeof v === "string" && bytes(v) <= 255) && (r.expires_at === undefined || stamp(r.expires_at));
    });
  }
  const idValid = s => typeof s === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(s);
  const hashValid = s => typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
  const operatorProvenance = (p, content = null) => exactKeys(p,["profile","source_sha256","content_sha256"]) && p.profile === HANDOFF_PROFILE && hashValid(p.source_sha256) && hashValid(p.content_sha256) && (content === null || p.content_sha256 === content);
  const handoffID = s => typeof s === "string" && /^[a-f0-9]{48}$/.test(s);
  function envelope(s) { return exactKeys(s, ["schema", "ruleset_id", "lineage_id", "revision", "content_sha256", "records"]) && s.schema === "secdns.exact-record-set.v1" && idValid(s.ruleset_id) && idValid(s.lineage_id) && revision(s.revision) && hashValid(s.content_sha256) && recordsValid(s.records) && bytes(JSON.stringify(s)) <= LIMIT; }
  function exactDraftHandoff(x, channelID, sourcePath, targetPath, now) {
    if (!exactKeys(x,["kind","channel_id","request_id","issued_at_ms","source_path","target_path","profile","source_sha256","content_sha256","content"]) || x.kind !== HANDOFF_KIND || x.channel_id !== channelID || !handoffID(channelID) || !handoffID(x.request_id) || !Number.isSafeInteger(x.issued_at_ms) || x.issued_at_ms > now + 5000 || now - x.issued_at_ms > HANDOFF_AGE_MS || x.source_path !== sourcePath || x.target_path !== targetPath || !sourcePath.startsWith("/") || !targetPath.startsWith("/") || x.profile !== HANDOFF_PROFILE || !hashValid(x.source_sha256) || !hashValid(x.content_sha256)) return false;
    const c=x.content;
    return exactKeys(c,["schema","ruleset_id","records"]) && c.schema === "secdns.exact-record-set.v1" && idValid(c.ruleset_id) && Array.isArray(c.records) && c.records.length > 0 && c.records.length <= 4096 && recordsValid(c.records) && c.records.every(r=>["A","AAAA","CNAME"].includes(r.type)&&r.values.length===1&&!Object.hasOwn(r,"expires_at")) && boundedJSON(x);
  }
  const key = r => r.name.toLowerCase().replace(/\.$/, "") + "/" + r.type;
  function changes(before, after) {
    const a = new Map(before.map(r => [key(r), r])), b = new Map(after.map(r => [key(r), r]));
    let added = 0, changed = 0, removed = 0;
    for (const [k, r] of b) { if (!a.has(k)) added++; else if (JSON.stringify(a.get(k)) !== JSON.stringify(r)) changed++; }
    for (const k of a.keys()) if (!b.has(k)) removed++;
    return {added, changed, removed};
  }
  // Display-only copies; null current means unavailable, never an empty snapshot.
  function comparisonRows(base, draft, current = null) {
    const a = new Map(base.map(r => [key(r), r])), b = new Map(draft.map(r => [key(r), r]));
    const c = current === null ? null : new Map(current.map(r => [key(r), r]));
    const kind = (before, after) => !before ? (after ? "added" : "unchanged") : !after ? "removed" : JSON.stringify(before) === JSON.stringify(after) ? "unchanged" : "changed";
    return [...new Set([...a.keys(), ...b.keys(), ...(c?.keys() || [])])].sort().map(k => {
      const before = a.get(k), local = b.get(k), observed = c?.get(k), localChange = kind(before, local), serverChange = c === null ? "unavailable" : kind(before, observed);
      return {key:k, base:before ? clone(before) : null, draft:local ? clone(local) : null, current:observed ? clone(observed) : null, localChange, serverChange,
        changed:localChange !== "unchanged" || serverChange !== "unavailable" && serverChange !== "unchanged"};
    });
  }
  // Draft assistance only: the server remains the canonical DNS parser and commit authority.
  function dnsName(value) {
    const name = value.trim().toLowerCase();
    if (!name || /[^\x21-\x7e]|\\/.test(name)) return null;
    const fqdn = name.endsWith(".") ? name : name + ".";
    if (fqdn.length > 255) return null;
    if (fqdn !== "." && fqdn.slice(0,-1).split(".").some(label => !label.length || label.length > 63)) return null;
    return fqdn;
  }
  function ipv4(value) {
    const parts=value.split(".");
    return parts.length===4 && parts.every(p=>/^(0|[1-9][0-9]{0,2})$/.test(p)&&Number(p)<=255) ? parts.map(Number) : null;
  }
  function ipValue(value) {
    value=value.trim(); const v4=ipv4(value); if(v4)return {family:4,key:v4.join(".")};
    if(!value.includes(":") || /[^0-9a-fA-F:.]/.test(value))return null;
    if(value.includes(".")) { const at=value.lastIndexOf(":"),tail=ipv4(value.slice(at+1));if(!tail)return null;value=value.slice(0,at+1)+((tail[0]<<8)|tail[1]).toString(16)+":"+((tail[2]<<8)|tail[3]).toString(16); }
    const halves=value.split("::");if(halves.length>2)return null;
    const left=halves[0]?halves[0].split(":"):[],right=halves.length===2&&halves[1]?halves[1].split(":"):[];
    if([...left,...right].some(p=>! /^[0-9a-fA-F]{1,4}$/.test(p)))return null;
    const n=left.length+right.length;if(halves.length===1?n!==8:n>=8)return null;
    const words=[...left.map(p=>parseInt(p,16)),...Array(halves.length===2?8-n:0).fill(0),...right.map(p=>parseInt(p,16))];
    if(words.slice(0,5).every(n=>n===0)&&words[5]===65535)return {family:4,key:[words[6]>>8,words[6]&255,words[7]>>8,words[7]&255].join(".")};
    return {family:6,key:words.join(":")};
  }
  function draftIssue(record, records=[], oldKey=null) {
    const issue=(field,text,index)=>({field,text,index});
    if(!recordsValid([record]))return issue("name","Check the record fields, value limits, TTL and expiration.");
    const name=dnsName(record.name);if(!name)return issue("name","Enter a DNS name with labels of at most 63 characters, using unescaped ASCII.");
    const seen=new Set();
    if(record.type==="CNAME"&&record.values.length!==1)return issue("values","A CNAME record must have exactly one destination.",0);
    for(let i=0;i<record.values.length;i++){
      const value=record.values[i];let canonical=value;
      if(record.type==="A"||record.type==="AAAA") {const ip=ipValue(value);if(!ip||ip.family!==(record.type==="A"?4:6))return issue("values",record.type==="A"?"Enter a valid IPv4 address (for example, 192.0.2.10).":"Enter a valid IPv6 address (for example, 2001:db8::10). IPv4-mapped addresses belong in A records.",i);canonical=ip.key;}
      if(record.type==="CNAME"){canonical=dnsName(value);if(!canonical)return issue("values","Enter a valid DNS destination name.",i);}
      if(record.type!=="TXT"&&seen.has(canonical))return issue("values","Remove the duplicate value.",i);seen.add(canonical);
    }
    for(const other of records){if(oldKey&&key(other)===oldKey)continue;if(dnsName(other.name)!==name)continue;if(other.type===record.type)return issue("name","That name and type already exist. Edit the existing record.");if(other.type==="CNAME"||record.type==="CNAME")return issue("name","A CNAME cannot share its name with another record. Remove the conflicting record first.");}
    return null;
  }
  class Model {
    constructor() { this.clear(); }
    clear() { this.base = this.current = this.pending = this.receipt = this.draftProvenance = this.currentProvenance = this.receiptProvenance = null; this.rrsetCapability = null; this.draft = []; this.edits = 0; this.formDirty = false; this.fresh = false; this.identityBlocked = false; this.observed = null; }
    dirty() { const d = this.base && changes(this.base.records, this.draft); return this.formDirty || !!(d && (d.added || d.changed || d.removed)); }
    touch() { this.edits++; this.formDirty = true; }
    stage(record, oldKey = null) {
      if (this.pending) throw new Error("pending_operation");
      const found = this.draft.findIndex(r => key(r) === (oldKey || key(record)));
      if (found >= 0 && !oldKey) throw new Error("duplicate_record");
      const issue = draftIssue(record,this.draft,oldKey); if(issue) throw Object.assign(new Error("invalid_record"),{issue});
      if (found >= 0) this.draft[found] = clone(record); else this.draft.push(clone(record));
      this.edits++; this.formDirty = false;
    }
    remove(k) { if (this.pending) throw new Error("pending_operation"); this.draft = this.draft.filter(r => key(r) !== k); this.edits++; }
    // Undo one pending row: the record returns to its saved (base) version, or an added
    // record leaves the draft.
    undo(k) {
      if (this.pending) throw new Error("pending_operation");
      const saved = this.base?.records.find(r => key(r) === k), at = this.draft.findIndex(r => key(r) === k);
      if (saved && at >= 0) this.draft[at] = clone(saved); else if (saved) this.draft.push(clone(saved)); else if (at >= 0) this.draft.splice(at, 1); else return false;
      this.edits++; return true;
    }
    // Unsaved work to keep across a WithMy ID round trip (session-scoped storage): the base it
    // was made against, the draft, the import provenance and an uncertain submitted change.
    exportDraft() {
      const uncertain = this.pending?.status === "uncertain";
      if (!this.base || this.identityBlocked || !(this.dirty() || uncertain)) return null;
      const p = this.pending, provenance = this.draftProvenance;
      return {v:1, base:clone(this.base), draft:clone(this.draft),
        provenance: provenance ? {profile:provenance.profile, rulesetID:provenance.rulesetID, sourceSHA256:provenance.sourceSHA256, contentSHA256:provenance.contentSHA256, transferredAt:provenance.transferredAt, intact:this.edits === provenance.editCounter} : null,
        pending: uncertain ? {endpoint:p.endpoint, mode:p.mode, expected:clone(p.expected), operationID:p.operationID, body:p.body, operatorSuppliedProvenance:p.operatorSuppliedProvenance ? clone(p.operatorSuppliedProvenance) : null} : null};
    }
    // Restores kept work over a freshly accepted, clean snapshot of the same ruleset/lineage.
    // The kept base stays the base: a server that moved on meanwhile shows as server changes
    // and a write still needs the reviewed, revision-checked apply (no merge, no auto-send).
    importDraft(saved, endpoints) {
      const base = saved?.base, prov = saved?.provenance, p = saved?.pending;
      if (!saved || saved.v !== 1 || !envelope(base) || !recordsValid(saved.draft) || !this.base || !this.current || this.dirty() || this.pending || this.identityBlocked || identity(base) !== identity(this.base) || compare(base.revision, this.current.revision) > 0) throw new Error("draft_restore_refused");
      if (prov !== null && !(exactKeys(prov,["profile","rulesetID","sourceSHA256","contentSHA256","transferredAt","intact"]) && prov.profile === HANDOFF_PROFILE && prov.rulesetID === base.ruleset_id && hashValid(prov.sourceSHA256) && hashValid(prov.contentSHA256) && Number.isSafeInteger(prov.transferredAt) && typeof prov.intact === "boolean")) throw new Error("draft_restore_refused");
      if (p !== null && !(exactKeys(p,["endpoint","mode","expected","operationID","body","operatorSuppliedProvenance"]) && Array.isArray(endpoints) && endpoints.includes(p.endpoint) && ["rrset","replacement"].includes(p.mode) && exactKeys(p.expected,["ruleset_id","lineage_id","revision"]) && p.expected.ruleset_id === base.ruleset_id && p.expected.lineage_id === base.lineage_id && revision(p.expected.revision) && idValid(p.operationID) && typeof p.body === "string" && bytes(p.body) <= LIMIT && (p.operatorSuppliedProvenance === null || operatorProvenance(p.operatorSuppliedProvenance)))) throw new Error("draft_restore_refused");
      if (p !== null) { let body; try { body = JSON.parse(p.body); } catch { throw new Error("draft_restore_refused"); } if (body?.operation_id !== p.operationID || JSON.stringify(body.expected) !== JSON.stringify(p.expected)) throw new Error("draft_restore_refused"); }
      this.base = clone(base); this.draft = clone(saved.draft); this.formDirty = false; this.edits++;
      this.draftProvenance = prov ? Object.freeze({profile:prov.profile,rulesetID:prov.rulesetID,sourceSHA256:prov.sourceSHA256,contentSHA256:prov.contentSHA256,transferredAt:prov.transferredAt,editCounter:prov.intact ? this.edits : -1}) : null;
      if (p !== null) {
        this.pending = {status:"uncertain"};
        for (const [k,v] of Object.entries({endpoint:p.endpoint, mode:p.mode, expected:Object.freeze(clone(p.expected)), operationID:p.operationID, body:p.body, editCounter:this.edits, operatorSuppliedProvenance:p.operatorSuppliedProvenance ? Object.freeze(clone(p.operatorSuppliedProvenance)) : null})) Object.defineProperty(this.pending,k,{value:v,enumerable:true});
      }
      return true;
    }
    importCandidate(handoff, channelID, sourcePath, targetPath, now) {
      if (!exactDraftHandoff(handoff,channelID,sourcePath,targetPath,now)) throw new Error("invalid_draft_handoff");
      if (!this.base || !this.current || !this.fresh || this.pending || this.identityBlocked || this.dirty()) throw new Error("handoff_reconciliation_required");
      if (handoff.content.ruleset_id !== this.base.ruleset_id) throw new Error("handoff_identity_conflict");
      this.draft = clone(handoff.content.records); this.formDirty = false; this.edits++;
      this.draftProvenance = Object.freeze({profile:handoff.profile,rulesetID:handoff.content.ruleset_id,sourceSHA256:handoff.source_sha256,contentSHA256:handoff.content_sha256,transferredAt:handoff.issued_at_ms,editCounter:this.edits});
    }
    accept(s, provenance = null, rrsetCapability = null) {
      if (!envelope(s) || provenance !== null && !operatorProvenance(provenance,s.content_sha256)) throw new Error("invalid_snapshot_response");
      if (this.base && identity(s) !== identity(this.base)) { this.identityBlocked = true; this.fresh = false; throw new Error("identity_conflict"); }
      if (this.observed && compare(s.revision, this.observed) < 0) throw new Error("stale_snapshot_response");
      this.rrsetCapability = rrsetCapability === "v1" ? "v1" : null; this.current = clone(s); this.currentProvenance = provenance === null ? null : clone(provenance); this.observed = s.revision; this.fresh = true;
      if (!this.base) this.adopt();
      else if (this.pending?.status === "acknowledged" && this.receipt && compare(s.revision, this.receipt.revision) >= 0 && this.edits === this.pending.editCounter) this.adopt();
      return s;
    }
    adopt() {
      if (!this.current || this.identityBlocked || this.pending && ["sending", "uncertain"].includes(this.pending.status)) throw new Error("reconciliation_required");
      this.base = clone(this.current); this.draft = clone(this.current.records); this.pending = this.draftProvenance = null; this.formDirty = false; this.edits++; this.fresh = true;
    }
    proposal(endpoint) {
      const expected = this.base && {ruleset_id:this.base.ruleset_id,lineage_id:this.base.lineage_id,revision:this.base.revision};
      const changed = comparisonRows(this.base?.records || [],this.draft).filter(r => r.localChange !== "unchanged");
      if (this.rrsetCapability === "v1" && !this.draftProvenance && changed.length === 1) {
        const row=changed[0], record=row.draft || row.base;
        return {mode:"rrset",endpoint:endpoint+"/rrset",expected,editCounter:this.edits,change:row.localChange,name:record.name,type:record.type,
          payload:row.draft ? {action:"upsert",record:clone(row.draft)} : {action:"delete",key:{name:row.base.name,type:row.base.type},confirm_removals:1}};
      }
      const payload={records:clone(this.draft)};
      // A replacement that removes records carries the removal count the operator confirmed;
      // the server rejects an exact import whose count does not match its own computation.
      const removed=changes(this.base?.records || [],this.draft).removed;if(removed>0)payload.confirm_removals=removed;
      if(this.draftProvenance && this.edits===this.draftProvenance.editCounter) payload.operator_supplied_provenance={profile:this.draftProvenance.profile,source_sha256:this.draftProvenance.sourceSHA256,content_sha256:this.draftProvenance.contentSHA256};
      return {mode:"replacement",endpoint,expected,editCounter:this.edits,payload};
    }
    review(endpoint) { return JSON.stringify(this.proposal(endpoint)); }
    freeze(operationID, endpoint, reviewed = null) {
      if (!this.base || !this.fresh || this.identityBlocked || this.pending || this.formDirty || !this.dirty() || !idValid(operationID)) throw new Error("reconciliation_required");
      if (!recordsValid(this.draft)) throw new Error("invalid_snapshot_request");
      increment(this.base.revision);
      const proposal=this.proposal(endpoint);
      if(reviewed !== null && reviewed !== JSON.stringify(proposal)) throw new Error("review_changed");
      const expected=proposal.expected;
      const replacement={expected,operation_id:operationID,...proposal.payload};
      endpoint=proposal.endpoint;
      const body = JSON.stringify(replacement);
      if (bytes(body) > LIMIT) throw new Error("snapshot_too_large");
      this.pending = {status:"sending"};
      const submittedProvenance = replacement.operator_supplied_provenance ? Object.freeze(clone(replacement.operator_supplied_provenance)) : null;
      for (const [k,v] of Object.entries({endpoint, mode:proposal.mode, expected:Object.freeze(expected), operationID, body, editCounter:this.edits,operatorSuppliedProvenance:submittedProvenance})) Object.defineProperty(this.pending,k,{value:v,enumerable:true});
      return this.pending;
    }
    acknowledge(r, provenance = null) {
      const p = this.pending;
      const provenanceMismatch = !p || (p.operatorSuppliedProvenance === null) !== (provenance === null) || p.operatorSuppliedProvenance !== null && JSON.stringify(p.operatorSuppliedProvenance) !== JSON.stringify(provenance);
      if (!p || !exactKeys(r, ["operation_id", "revision", "content_sha256", "committed_at"]) || r.operation_id !== p.operationID || !revision(r.revision) || r.revision !== increment(p.expected.revision) || !hashValid(r.content_sha256) || !stamp(r.committed_at) || provenance !== null && !operatorProvenance(provenance,r.content_sha256) || provenanceMismatch) throw new Error("invalid_receipt");
      this.receipt = clone(r); this.receiptProvenance = provenance === null ? null : clone(provenance); p.status = "acknowledged";
      if (!this.observed || compare(r.revision, this.observed) > 0) this.observed = r.revision;
      this.fresh = false;
    }
    uncertain() { if (this.pending && this.pending.status !== "acknowledged") this.pending.status = "uncertain"; this.fresh = false; }
  }
  const api = {draftIssue, Model, compare, revision, increment, recordsValid, envelope, operatorProvenance, exactDraftHandoff, changes, comparisonRows, key, clone, bytes, LIMIT, HANDOFF_AGE_MS, HANDOFF_KIND, HANDOFF_PROFILE};
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.SnapshotEditor = api;
})(globalThis);
