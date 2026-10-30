// secDNS console UI language: catalogue lookup, DOM translation and locale-correct
// formatting. Page scripts keep building their DOM in English; this file is the last
// deferred script and starts at DOMContentLoaded, after every page and shell script has
// run, so they all read English sources. The document is then translated once and kept
// translated by a MutationObserver. The English source of every translated node is remembered, so the
// language can be switched in place without reloading (a reload would lose drafts).
// User data (record names and values, code, hashes, identities) is never translated.
(() => {
  "use strict";
  const LANGS = ["en", "zh-Hant"];
  const root = document.documentElement;
  const exact = new Map(), patterns = [], target = { en: new Map(), "zh-Hant": new Map() };
  const load = cat => {
    if (!cat || typeof cat !== "object" || !cat.en || !cat["zh-Hant"]) return;
    for (const [key, en] of Object.entries(cat.en)) {
      const zh = cat["zh-Hant"][key];
      if (typeof en !== "string" || typeof zh !== "string") continue;
      target.en.set(key, en); target["zh-Hant"].set(key, zh);
      if (/\{[a-zA-Z0-9_]+\}/.test(en)) {
        const names = [];
        const source = en.split(/(\{[a-zA-Z0-9_]+\})/).map(part => {
          const m = /^\{([a-zA-Z0-9_]+)\}$/.exec(part);
          if (m) { names.push(m[1]); return "(.+?)"; }
          return part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        }).join("");
        patterns.push({ key, names, re: new RegExp("^" + source + "$", "s"), weight: en.replace(/\{[a-zA-Z0-9_]+\}/g, "").length });
      } else exact.set(en, key);
    }
  };
  for (const cat of window.secDNSCatalogue || []) load(cat);
  // Most specific pattern first (most literal text), so a shorter variant never wins.
  patterns.sort((a, b) => b.weight - a.weight);

  const pick = value => {
    const v = String(value || "").toLowerCase();
    if (v === "en" || v.startsWith("en-")) return "en";
    if (v === "zh-hant" || v.startsWith("zh-hant") || v === "zh-tw" || v === "zh-hk" || v === "zh-mo") return "zh-Hant";
    return "";
  };
  const store = {
    get(key) { try { return window.localStorage.getItem(key); } catch { return null; } },
    set(key, value) { try { if (value === null) window.localStorage.removeItem(key); else window.localStorage.setItem(key, value); } catch { /* private mode */ } }
  };
  let lang = LANGS.includes(root.dataset.uiLang) ? root.dataset.uiLang : "en";

  // Placeholders whose captured text is itself UI wording (never user or server data) and may
  // be localized. Every other captured value (names, values, ids, paths, revisions, server
  // text) is inserted verbatim into the translated sentence.
  const LOCALIZED = new Set(["state", "page", "note", "message", "kind", "access", "change"]);
  // Translate one English string into the current language; unknown text is returned as is.
  const translate = (text, into = lang) => {
    if (into === "en" || typeof text !== "string") return text;
    const lead = /^\s*/.exec(text)[0], trail = /\s*$/.exec(text)[0];
    const core = text.trim().replace(/\s+/g, " ");
    if (!core) return text;
    const key = exact.get(core);
    if (key !== undefined) return lead + target[into].get(key) + trail;
    for (const p of patterns) {
      const m = p.re.exec(core);
      if (!m) continue;
      const captured = {};
      p.names.forEach((name, i) => { captured[name] = m[i + 1]; });
      // One pass over the template: inserted data is never re-scanned or translated.
      const out = target[into].get(p.key).replace(/\{([a-zA-Z0-9_]+)\}/g, (all, name) =>
        !Object.hasOwn(captured, name) ? all : LOCALIZED.has(name) ? translate(captured[name], into) : captured[name]);
      return lead + out + trail;
    }
    return text;
  };
  const english = key => target.en.get(key) ?? key;
  const t = (textOrKey, vars) => {
    let s = target.en.has(textOrKey) ? english(textOrKey) : String(textOrKey);
    if (vars) for (const [k, v] of Object.entries(vars)) s = s.split("{" + k + "}").join(String(v));
    return translate(s);
  };

  // --- DOM translation -------------------------------------------------------------
  const SKIP = "script,style,textarea,pre,code,svg,[translate=no],[data-i18n-skip],.notranslate,.record-name,.record-value,.record-fqdn,.record-ip,.hash,#candidate,#agent-identity,#endpoint,.node-observation-address,.comparison-values,.fields dt,#human-seed,[data-i18n-at]";
  const ATTRS = ["placeholder", "aria-label", "title", "alt"];
  const textSource = new WeakMap(), attrSource = new WeakMap();
  let writing = false;
  const skipped = el => !el || el.closest(SKIP);
  const doText = node => {
    const parent = node.parentElement;
    if (!parent || skipped(parent)) return;
    const current = node.nodeValue;
    const known = textSource.get(node);
    // A script wrote new English text into this node: it becomes the new source.
    const source = known && (current === known.out) ? known.src : current;
    const out = translate(source);
    textSource.set(node, { src: source, out });
    if (out !== current) node.nodeValue = out;
  };
  const doAttrs = el => {
    if (el.nodeType !== 1 || el.closest(SKIP)) return;
    let map = attrSource.get(el);
    for (const name of ATTRS) {
      if (!el.hasAttribute(name)) continue;
      const current = el.getAttribute(name), known = map?.[name];
      const source = known && current === known.out ? known.src : current;
      const out = translate(source);
      if (!map) { map = {}; attrSource.set(el, map); }
      map[name] = { src: source, out };
      if (out !== current) el.setAttribute(name, out);
    }
  };
  const walk = start => {
    if (!start) return;
    if (start.nodeType === 3) { doText(start); return; }
    if (start.nodeType !== 1 && start.nodeType !== 9 && start.nodeType !== 11) return;
    if (start.nodeType === 1) { if (start.closest(SKIP)) return; doAttrs(start); }
    const tw = document.createTreeWalker(start, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
      acceptNode: n => n.nodeType === 1 && n.matches(SKIP) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT
    });
    for (let n = tw.nextNode(); n; n = tw.nextNode()) { if (n.nodeType === 3) doText(n); else doAttrs(n); }
  };
  const run = fn => { writing = true; try { fn(); } finally { writing = false; observer.takeRecords(); } };
  const observer = new MutationObserver(records => {
    if (writing) return;
    run(() => {
      for (const r of records) {
        if (r.type === "characterData") doText(r.target);
        else if (r.type === "attributes") doAttrs(r.target);
        else for (const n of r.addedNodes) { walk(n); stamps(n); }
      }
    });
  });
  const observe = () => observer.observe(root, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS });

  // --- formatting --------------------------------------------------------------------
  const intlLocale = () => (lang === "zh-Hant" ? "zh-Hant-TW" : "en-US");
  const date = (value, options = { dateStyle: "medium", timeStyle: "short" }) => {
    const d = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(d.getTime())) return null;
    return new Intl.DateTimeFormat(intlLocale(), options).format(d);
  };
  const relative = value => {
    const d = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(d.getTime())) return null;
    const s = Math.round((d.getTime() - Date.now()) / 1000), a = Math.abs(s);
    const rtf = new Intl.RelativeTimeFormat(intlLocale(), { numeric: "auto" });
    if (a < 60) return rtf.format(s, "second");
    if (a < 3600) return rtf.format(Math.round(s / 60), "minute");
    if (a < 86400) return rtf.format(Math.round(s / 3600), "hour");
    return rtf.format(Math.round(s / 86400), "day");
  };
  const number = (value, options) => new Intl.NumberFormat(intlLocale(), options).format(value);
  // <time datetime> elements marked data-i18n-date are re-formatted when the language changes.
  const refreshTimes = () => {
    for (const el of document.querySelectorAll("time[data-i18n-date][datetime]")) {
      const text = date(el.getAttribute("datetime"), el.dataset.i18nDate === "long" ? { dateStyle: "medium", timeStyle: "long" } : undefined);
      if (text) el.textContent = text;
    }
  };

  // A date inside a sentence (data-i18n-at = ISO time, data-i18n-template = English sentence with
  // {time}, data-i18n-format = short | long | time | date): the whole sentence is rendered in the
  // current language, and rendered again on an in-place language switch, so no date is left in
  // the previous language's format. The date is data: it is inserted as formatted, never translated.
  const FORMATS = { long: { dateStyle: "medium", timeStyle: "long" }, time: { timeStyle: "short" }, date: { dateStyle: "medium" } };
  const stamp = el => {
    if (!el || el.nodeType !== 1 || !el.dataset.i18nAt) return el;
    const at = el.dataset.i18nAt, formatted = date(at, FORMATS[el.dataset.i18nFormat]) ?? at;
    const text = translate((el.dataset.i18nTemplate || "{time}").split("{time}").join(formatted));
    if (el.textContent !== text) el.textContent = text;
    if (!el.title) el.title = at;
    return el;
  };
  const stamps = start => {
    if (!start || start.nodeType !== 1 && start.nodeType !== 9) return;
    if (start.nodeType === 1 && start.matches("[data-i18n-at]")) stamp(start);
    for (const el of start.querySelectorAll("[data-i18n-at]")) stamp(el);
  };

  // Browser dialogs and validity messages are not part of the DOM: translate them on the way out.
  const nativeConfirm = window.confirm.bind(window), nativeAlert = window.alert.bind(window);
  window.confirm = message => nativeConfirm(translate(String(message)));
  window.alert = message => nativeAlert(translate(String(message)));
  for (const proto of [HTMLInputElement.prototype, HTMLSelectElement.prototype, HTMLTextAreaElement.prototype]) {
    const native = proto.setCustomValidity;
    proto.setCustomValidity = function (message) { return native.call(this, message ? translate(String(message)) : message); };
  }

  const setLanguage = next => {
    next = LANGS.includes(next) ? next : "en";
    store.set("secdns.lang", next);
    if (next === lang) return;
    lang = next;
    root.lang = next; root.dataset.uiLang = next;
    run(() => { walk(document); stamps(document); });
    refreshTimes();
    window.dispatchEvent(new CustomEvent("secdns:language", { detail: { lang } }));
  };

  // Theme: "system" (default, follows prefers-color-scheme), "light" or "dark".
  const getTheme = () => { const v = store.get("secdns.theme"); return v === "light" || v === "dark" ? v : "system"; };
  const setTheme = value => {
    const v = value === "light" || value === "dark" ? value : "system";
    store.set("secdns.theme", v === "system" ? null : v);
    if (v === "system") delete root.dataset.theme; else root.dataset.theme = v;
    window.dispatchEvent(new CustomEvent("secdns:theme", { detail: { theme: v } }));
  };

  window.secDNSI18n = Object.freeze({
    get lang() { return lang; },
    get locale() { return intlLocale(); },
    languages: LANGS,
    t, translate, date, relative, number, setLanguage, getTheme, setTheme, pick,
    stamp: el => { run(() => stamp(el)); return el; },
    // The English source behind a (possibly translated) visible string; test harnesses use it.
    source(text) {
      const core = String(text).trim().replace(/\s+/g, " ");
      if (lang === "en") return core;
      for (const [key, value] of target[lang]) if (value === core) return english(key);
      return core;
    },
    has(text) { return exact.has(String(text).trim().replace(/\s+/g, " ")); }
  });

  const start = () => {
    run(() => { walk(document); stamps(document); });
    refreshTimes();
    observe();
    root.classList.remove("i18n-pending");
  };
  let started = false;
  const once = () => { if (!started) { started = true; start(); } };
  if (document.readyState === "complete") once();
  else document.addEventListener("DOMContentLoaded", once, { once: true });
})();
