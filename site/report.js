// The script for /report (spec-v53 §4). Served as a static file, loaded by
// that page alone. It shares nothing with the app: a different document, no
// storage, and no code in common — it cannot see a contract even by mistake.
//
// It reads the page's URL fragment, which a browser never sends to a server,
// shows the reader exactly what a report would contain, and — until the
// endpoint exists — sends nothing. There is no network call in this file.

/** Fragment keys, in display order. Anything else in the fragment is ignored. */
export const FIELDS = ["kind", "rule", "rv", "engine", "dkb", "type", "near"];

// An id is letters, digits, dots and dashes: nothing that is prose fits.
// Kept identical to `src/report/report-link.ts`; a test holds the two together.
const SHAPE = {
  kind: /^(?:wrong-finding|missed|wrong-type|site)$/,
  rule: /^[A-Z][A-Z0-9]{1,9}(?:-[A-Z0-9]{1,6}){1,3}$/,
  rv: /^\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  engine: /^\d{1,3}\.\d{1,5}\.\d{1,3}$/,
  dkb: /^v[0-9A-Za-z.-]{1,40}$/,
  type: /^(?![0-9a-f]{32,}$)[a-z0-9][a-z0-9-]{1,59}$/,
  near: /^(?![0-9a-f]{32,}$)[a-z0-9][a-z0-9-]{1,59}$/,
};

export const LABELS = {
  rule: "Rule",
  rv: "Rule version",
  engine: "Engine version",
  dkb: "Knowledge base version",
  type: "Document type",
  near: "Closest document type",
};

export const NOTE_MAX = 280;

/** Read a fragment. Unknown keys and malformed values are dropped, never shown. */
export function parseFragment(hash) {
  const out = {};
  for (const pair of String(hash).replace(/^#/, "").split("&")) {
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const key = pair.slice(0, eq);
    const value = pair.slice(eq + 1);
    if (FIELDS.includes(key) && SHAPE[key].test(value)) out[key] = value;
  }
  return out;
}

/** The kind a link implies when it does not say: a rule means a wrong finding. */
export function impliedKind(ctx) {
  if (ctx.kind) return ctx.kind;
  if (ctx.rule) return "wrong-finding";
  if (ctx.near) return "wrong-type";
  return "";
}

/** Exactly what a report would hold: the kind, the ids from the link, the note. */
export function reportPreview(ctx, kind, note) {
  const rows = [];
  if (kind) rows.push(["Kind of problem", kind]);
  for (const key of FIELDS) {
    if (key !== "kind" && ctx[key]) rows.push([LABELS[key], ctx[key]]);
  }
  const trimmed = String(note).slice(0, NOTE_MAX).trim();
  if (trimmed) rows.push(["Your note", trimmed]);
  return rows;
}

export function init(doc, hash) {
  const list = doc.getElementById("report-preview");
  const note = doc.getElementById("report-note");
  const count = doc.getElementById("report-note-count");
  if (!list || !note) return;
  const ctx = parseFragment(hash);
  const implied = impliedKind(ctx);
  for (const radio of doc.querySelectorAll('input[name="report-kind"]')) {
    radio.checked = radio.value === implied;
    radio.addEventListener("change", render);
  }
  note.addEventListener("input", render);
  render();

  function render() {
    const chosen = doc.querySelector('input[name="report-kind"]:checked');
    const rows = reportPreview(ctx, chosen ? chosen.value : "", note.value);
    list.textContent = "";
    if (rows.length === 0) {
      const empty = doc.createElement("li");
      empty.textContent = "Nothing yet. Choose a kind of problem above.";
      list.appendChild(empty);
    }
    for (const [label, value] of rows) {
      const item = doc.createElement("li");
      const name = doc.createElement("strong");
      name.textContent = `${label}: `;
      item.appendChild(name);
      // textContent, never innerHTML: the note is the reader's own typing.
      item.appendChild(doc.createTextNode(value));
      list.appendChild(item);
    }
    if (count) count.textContent = `${note.value.length} / ${NOTE_MAX}`;
  }
}

if (typeof document !== "undefined" && typeof location !== "undefined") {
  const start = () => init(document, location.hash);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
}
