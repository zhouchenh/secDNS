// Applied synchronously in <head>, before the stylesheets and the body: the saved
// theme and UI language take effect before the first paint (no light flash, no
// wrong-language <html lang>). Storage can be unavailable; every access is guarded.
(() => {
  "use strict";
  const root = document.documentElement;
  const read = key => { try { return window.localStorage.getItem(key); } catch { return null; } };
  const theme = read("secdns.theme");
  if (theme === "light" || theme === "dark") root.dataset.theme = theme; else delete root.dataset.theme;
  const pick = value => {
    const v = String(value || "").toLowerCase();
    if (v === "en" || v.startsWith("en-")) return "en";
    if (v === "zh-hant" || v.startsWith("zh-hant") || v === "zh-tw" || v === "zh-hk" || v === "zh-mo") return "zh-Hant";
    return "";
  };
  let lang = pick(read("secdns.lang"));
  if (!lang) for (const candidate of navigator.languages || [navigator.language]) { lang = pick(candidate); if (lang) break; }
  lang = lang || "en";
  root.lang = lang;
  root.dataset.uiLang = lang;
  // Text is translated after the page scripts build the DOM; until then non-English
  // pages stay invisible (with a CSS time-out so a script failure never hides the page).
  if (lang !== "en") root.classList.add("i18n-pending");
})();
