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
  class Model {
    constructor() { this.clear(); }
    clear() { this.base = this.current = this.pending = this.receipt = this.draftProvenance = this.currentProvenance = this.receiptProvenance = null; this.rrsetCapability = null; this.draft = []; this.edits = 0; this.formDirty = false; this.fresh = false; this.identityBlocked = false; this.observed = null; }
    dirty() { const d = this.base && changes(this.base.records, this.draft); return this.formDirty || !!(d && (d.added || d.changed || d.removed)); }
    touch() { this.edits++; this.formDirty = true; }
    stage(record, oldKey = null) {
      if (this.pending) throw new Error("pending_operation");
      const found = this.draft.findIndex(r => key(r) === (oldKey || key(record)));
      if (found >= 0 && !oldKey) throw new Error("duplicate_record");
      if (!recordsValid([record])) throw new Error("invalid_snapshot_request");
      if (found >= 0) this.draft[found] = clone(record); else this.draft.push(clone(record));
      this.edits++; this.formDirty = false;
    }
    remove(k) { if (this.pending) throw new Error("pending_operation"); this.draft = this.draft.filter(r => key(r) !== k); this.edits++; }
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
          payload:row.draft ? {action:"upsert",record:clone(row.draft)} : {action:"delete",key:{name:row.base.name,type:row.base.type}}};
      }
      const payload={records:clone(this.draft)};
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
  const api = {Model, compare, revision, increment, recordsValid, envelope, operatorProvenance, exactDraftHandoff, changes, comparisonRows, key, clone, bytes, LIMIT, HANDOFF_AGE_MS, HANDOFF_KIND, HANDOFF_PROFILE};
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.SnapshotEditor = api;
})(globalThis);
