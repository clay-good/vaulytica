/**
 * The standalone negotiation sheet (spec-v10 Thrust B, Step 170).
 *
 * A self-contained, print-clean single-file HTML worksheet a negotiator works
 * down before a call. Where the in-report "Negotiation Posture" section is a
 * *status table* (one row per dimension, in dimension order), this sheet is an
 * *action* view: it regroups the same positions by what the negotiator should
 * do — **escalate** (below the floor), **push here** (at the floor, room to
 * reach ideal), **verify** (the dimension is not stated), and **hold** (already
 * ideal) — in that priority order, so the most urgent fronts are at the top.
 *
 * Posture (spec-v10 §3): a pure, render-side function of the `NegotiationPosture`
 * — no clock, no network, no script. All author-supplied strings are
 * HTML-escaped (a `dimension`/`guidance`/`detail` can contain arbitrary text),
 * so the shared sheet can never carry live markup. Mobile-safe: `overflow-wrap`
 * on the body means every cell wraps; no horizontal scroll at any width.
 */

import type {
  NegotiationPosture,
  NegotiationTier,
  NegotiationPositionResult,
} from "../playbooks/custom-interpreter.js";

/** Escape text for safe inclusion in HTML content. Mirrors `html.ts`. */
function esc(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const STYLE = `
  :root { --mint:#00a883; --hold:#1a8f5a; --push:#2d6cdf; --verify:#a86700; --escalate:#b00020; }
  * { box-sizing: border-box; }
  body { font-family: Arial, Helvetica, sans-serif; color:#1a1a1a; line-height:1.5;
    max-width: 52rem; margin: 0 auto; padding: 1.25rem; overflow-wrap: anywhere; }
  h1 { font-size: 1.6rem; color: var(--mint); border-bottom: 2px solid var(--mint); padding-bottom:.3rem; }
  h2 { font-size: 1.15rem; margin-top: 1.6rem; }
  .counts { background:#f6f8f7; border:1px solid #dde3e1; border-radius:6px; padding:.6rem .9rem; margin:1rem 0; font-size:.9rem; }
  .group { margin-top: 1rem; }
  ul.positions { list-style: none; padding: 0; margin:.5rem 0; }
  ul.positions li { border:1px solid #dde3e1; border-left-width:4px; border-radius:6px;
    padding:.55rem .75rem; margin-bottom:.55rem; overflow-wrap: anywhere; }
  li.escalate { border-left-color: var(--escalate); }
  li.push { border-left-color: var(--push); }
  li.verify { border-left-color: var(--verify); }
  li.hold { border-left-color: var(--hold); }
  .dim { font-weight: bold; }
  .found { font-size:.85rem; color:#444; margin-top:.15rem; }
  .guide { font-size:.85rem; color:#333; margin-top:.15rem; }
  .sec { font-size:.8rem; color:#6b6b6b; }
  .note { margin-top:1.4rem; font-size:.85rem; color:#333; font-style: italic; }
  @media print { body { max-width:none; } }
  @media (max-width: 32rem) { body { padding:.75rem; } h1 { font-size:1.35rem; } }
`;

/** The four action buckets, in negotiator priority order (most urgent first). */
type Action = "escalate" | "push" | "verify" | "hold";

const ACTION_OF: Record<NegotiationTier, Action> = {
  "below-acceptable": "escalate",
  acceptable: "push",
  unevaluable: "verify",
  ideal: "hold",
};

const ACTION_ORDER: Action[] = ["escalate", "push", "verify", "hold"];

const ACTION_HEADING: Record<Action, string> = {
  escalate: "Escalate — below your floor",
  push: "Push here — at your floor, room to reach ideal",
  verify: "Verify — the draft does not state this",
  hold: "Hold — already at your ideal",
};

function renderPosition(p: NegotiationPositionResult, action: Action): string {
  const found = (p.detail ?? p.reason ?? "").trim();
  const guide = p.guidance?.trim();
  const sec = p.section_id ? ` <span class="sec">§${esc(p.section_id)}</span>` : "";
  // The team's own pre-approved fallback language, quoted verbatim and clearly
  // attributed to the playbook (never generated). Carried only on below-floor
  // rows (add-negotiation-ladder-playbooks).
  const approved = p.approved_language?.trim();
  return `<li class="${action}">
    <div class="dim">${esc(p.dimension)}${sec}</div>
    ${found ? `<div class="found">${esc(found)}</div>` : ""}
    ${guide ? `<div class="guide">${esc(guide)}</div>` : ""}
    ${approved ? `<blockquote class="approved-language"><div class="approved-label">Your playbook's approved fallback language:</div>${esc(approved)}</blockquote>` : ""}
  </li>`;
}

/**
 * Build the standalone negotiation sheet as a single-file HTML string.
 * `title` is an optional document/playbook label for the header.
 */
export function buildNegotiationSheet(posture: NegotiationPosture, title?: string): string {
  const c = posture.counts;
  const body: string[] = [];
  body.push(`<h1>Negotiation sheet${title ? ` — ${esc(title)}` : ""}</h1>`);
  body.push(
    `<div class="counts">${c.below_acceptable} to escalate · ${c.acceptable} to push · ${c.unevaluable} to verify · ${c.ideal} holding</div>`,
  );

  if (posture.positions.length === 0) {
    body.push("<p><em>No negotiation positions were defined in the active playbook.</em></p>");
  } else {
    const byAction = new Map<Action, NegotiationPositionResult[]>();
    for (const p of posture.positions) {
      const a = ACTION_OF[p.tier];
      const list = byAction.get(a) ?? [];
      list.push(p);
      byAction.set(a, list);
    }
    for (const action of ACTION_ORDER) {
      const group = byAction.get(action);
      if (!group || group.length === 0) continue;
      body.push(`<div class="group">`);
      body.push(`<h2>${esc(ACTION_HEADING[action])} (${group.length})</h2>`);
      body.push(`<ul class="positions">`);
      for (const p of group) body.push(renderPosition(p, action));
      body.push(`</ul></div>`);
    }
  }

  body.push(
    `<div class="note">This sheet is computed deterministically from your playbook's positions and the document's own terms. It shows where the draft sits on your team's ladder — it is not legal advice and does not assert any term is enforceable, adequate, or market.</div>`,
  );

  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>Negotiation sheet${title ? ` — ${esc(title)}` : ""}</title>`,
    `<style>${STYLE}</style>`,
    "</head>",
    "<body>",
    body.join("\n"),
    "</body>",
    "</html>",
    "",
  ].join("\n");
}

export function negotiationSheetBlob(posture: NegotiationPosture, title?: string): Blob {
  return new Blob([buildNegotiationSheet(posture, title)], { type: "text/html" });
}
