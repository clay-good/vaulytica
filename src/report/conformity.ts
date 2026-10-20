/**
 * Does the signed copy match the final draft? (add-executed-copy-conformity)
 *
 * The clause redline between a final draft and its executed copy, with the
 * differences execution is SUPPOSED to introduce set aside and listed:
 *
 *   - signature-block lines (`By:`, `Name:`, `Title:`, `Date:`, `/s/`,
 *     initials, witness and notary lines), on either side;
 *   - a short entry under the signature block — the printed name a signer
 *     writes on its own line — in the executed copy only;
 *   - a blank the final left for execution (`____`, `[●]`, `[DATE]`) filled
 *     in, where nothing else in the paragraph changed;
 *   - a page legend or watermark word ("FINAL", "EXECUTION VERSION",
 *     "EXECUTED", "Page 2 of 9") alone on its line.
 *
 * What remains is reported as differences, with a verdict. Nothing here says
 * whether a difference matters: a changed figure and a changed comma are both
 * differences, and the redline shows which is which.
 *
 * `conformity_hash` covers the verdict, the differences and the set-aside
 * list, namespaced apart from every `result_hash`; the comparison's own hash
 * is untouched.
 */
import type { DocumentTree } from "../ingest/types.js";
import { sha256Hex } from "../ingest/hash.js";
import { buildClauseDiff, flattenClauses, type Clause, type ClauseDiff } from "./clause-diff.js";

export const CONFORMITY_VERSION = "1";

/**
 * A signature-block line: the label a signer fills in, on its own line. Ingest
 * joins a signature rule with the printed name under it ("____ Jordan Lee"),
 * so an underline followed by a short name is one too.
 */
const SIGNATURE_LINE =
  /^(?:by|name|print(?:ed)? name|title|its|date|dated|signature|signed|witness|witnessed by|attest|initials?|address|email)\s*:|^\/s\/|^[_\s.]{6,}$|^_{4,}\s{1,3}[^.;:_]{1,60}$|^(?:notary public|my commission expires|subscribed and sworn|acknowledged before me|state of [a-z ]+\)|county of [a-z ]+\))/i;

/** A legend or watermark alone on its line. */
const LEGEND =
  /^(?:(?:final|execution|executed|execution version|execution copy|conformed copy|draft|signature page(?: follows)?|\[signature page follows\]|\[remainder of page intentionally left blank\]|page \d{1,3}(?: of \d{1,3})?)[\s.:—–-]*)+$/i;

/** A blank the final leaves for execution to fill. */
const BLANK = /_{3,}|\[\s*[●•]\s*\]|\[\s*(?:date|name|title|amount|insert[^\]]{0,40})\s*\]/gi;

const MAX_BLANKS = 6;
const OPERATIVE =
  /\b(?:shall|must|will|agrees?|waives?|releases?|indemnif\w*|notwithstanding|except|provided that|unless)\b/i;
const MAX_FILL_CHARS = 2000;

/** Where a signature block begins: the first signature-block line. */
function signatureStart(clauses: readonly Clause[]): number {
  const i = clauses.findIndex(
    (c) => SIGNATURE_LINE.test(c.text) || /^in witness whereof\b/i.test(c.text),
  );
  return i < 0 ? clauses.length : i;
}

/** The executed copy's short, sentence-less entries under the signature block. */
function isSignerEntry(c: Clause): boolean {
  const words = c.text.split(/\s+/).length;
  return (
    words <= 8 && !/[.;:]\s+\S/.test(c.text) && !/\b(?:shall|will|agrees?|must)\b/i.test(c.text)
  );
}

/** Why execution introduces this line, or undefined. */
export function executionAllowance(text: string): string | undefined {
  const t = text.trim();
  if (SIGNATURE_LINE.test(t)) return "signature-block line";
  // A signature rule that opens a short paragraph: ingest joins the rule with
  // what is printed under it — a name, a title, "Notary Public, My commission
  // expires", a date — and the whole block arrives as one paragraph.
  if (/^_{4,}/.test(t) && t.split(/\s+/).length <= 25) return "signature-block line";
  if (LEGEND.test(t)) return "legend or watermark";
  return undefined;
}

/** True when `executed` is `final` with its blanks filled and nothing else changed. */
export function fillsBlanks(final: string, executed: string): boolean {
  const norm = (s: string): string => s.replace(/\s+/g, " ").trim();
  const f = norm(final);
  // One lazy gap per blank: bounded so a long form with many blanks cannot
  // make the match backtrack without limit. Past the bound the paragraph is
  // simply compared as written.
  const blanks = f.match(BLANK)?.length ?? 0;
  if (blanks === 0 || blanks > MAX_BLANKS || f.length > MAX_FILL_CHARS) return false;
  const pattern = f
    .split(BLANK)
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("(.{1,80}?)");
  const m = new RegExp(`^${pattern}$`).exec(norm(executed));
  // A blank holds a date, a name, a figure. A fill that carries an operative
  // word is new terms typed into the blank, and is a difference.
  return m !== null && !m.slice(1).some((fill) => OPERATIVE.test(fill));
}

export type SetAside = { side: "final" | "executed"; text: string; reason: string };

export type Conformity = {
  version: string;
  /** `identical` outside the execution allowance, or how many differences remain. */
  verdict: "identical" | "differences";
  differences: Pick<ClauseDiff, "added" | "removed" | "changed">;
  /** `By:` lines on each side; unequal counts are one difference. */
  signature_blocks: { final: number; executed: number };
  difference_count: number;
  set_aside: SetAside[];
  conformity_hash: string;
};

/** Compare a final draft with its executed copy. */
export async function checkConformity(
  final: DocumentTree,
  executed: DocumentTree,
): Promise<Conformity> {
  const finalClauses = flattenClauses(final);
  const executedClauses = flattenClauses(executed);
  const signerFrom = signatureStart(executedClauses);
  // An entry the final's own text already has is compared, not set aside:
  // the party name over its signature line is the draft's, not the signer's.
  const finalKeys = new Set(finalClauses.map((c) => c.key));
  const set_aside: SetAside[] = [];
  // Set aside before aligning, so a signature line is never paired with a
  // clause it does not correspond to.
  const diff = buildClauseDiff(final, executed, {
    exclude: (c, side, index) => {
      const reason =
        executionAllowance(c.text) ??
        (side === "revised" && index >= signerFrom && isSignerEntry(c) && !finalKeys.has(c.key)
          ? "signer's entry under the signature block"
          : undefined);
      if (!reason) return false;
      set_aside.push({ side: side === "base" ? "final" : "executed", text: c.text, reason });
      return true;
    },
  });
  // A form's signature rule with its label under it ("____ ____ Signature of
  // applicant Date") is set aside on the final side, and its filled copy
  // ("/s/ Ana Ruiz 06/03/2026 Signature of applicant Date") arrives as an
  // added paragraph. Filling that rule's blanks is what signing it is.
  const setAsideFinal = set_aside.filter((x) => x.side === "final").map((x) => x.text);
  const added = diff.added.filter((c) => {
    if (!setAsideFinal.some((f) => fillsBlanks(f, c.text))) return true;
    set_aside.push({ side: "executed", text: c.text, reason: "blank filled in" });
    return false;
  });
  // A line of the final that the executed copy still carries, joined into a
  // line set aside above: filling a blank can change where ingest breaks
  // paragraphs, so "FOR OFFICE USE ONLY" arrives inside the signed line under
  // it. The text is there; it is not a difference.
  const norm = (t: string): string => t.replace(/\s+/g, " ").trim().toLowerCase();
  const setAsideExecuted = set_aside.filter((x) => x.side === "executed").map((x) => norm(x.text));
  const removed = diff.removed.filter((c) => {
    const key = norm(c.text);
    if (key.length < 4 || !setAsideExecuted.some((t) => t.includes(key))) return true;
    set_aside.push({
      side: "final",
      text: c.text,
      reason: "carried inside a signature-block line",
    });
    return false;
  });
  const changed = diff.changed.filter((pair) => {
    if (!fillsBlanks(pair.base.text, pair.revised.text)) return true;
    set_aside.push({ side: "executed", text: pair.revised.text, reason: "blank filled in" });
    return false;
  });

  // Every line of an added signatory's block is an allowance on its own, so
  // the blocks are counted: a party who signs and was not in the final, or a
  // block the signed copy lacks, is a difference whatever its lines say.
  const blocks = (cs: readonly Clause[]): number =>
    cs.filter((c) => /^by\s*:/i.test(c.text)).length;
  const signature_blocks = { final: blocks(finalClauses), executed: blocks(executedClauses) };
  const blockDifference = signature_blocks.final !== signature_blocks.executed ? 1 : 0;

  const difference_count = removed.length + added.length + changed.length + blockDifference;
  const verdict = difference_count === 0 ? "identical" : "differences";
  const canonical = JSON.stringify({
    namespace: "vaulytica-conformity",
    version: CONFORMITY_VERSION,
    verdict,
    removed: removed.map((c) => c.text),
    added: added.map((c) => c.text),
    changed: changed.map((p) => [p.base.text, p.revised.text]),
    signature_blocks,
    set_aside: set_aside.map((s) => [s.side, s.reason, s.text]),
  });
  return {
    version: CONFORMITY_VERSION,
    verdict,
    differences: { added, removed, changed },
    signature_blocks,
    difference_count,
    set_aside,
    conformity_hash: await sha256Hex(canonical),
  };
}

/** The verdict as one line a reader can act on. */
export function conformityLine(c: Conformity): string {
  return c.verdict === "identical"
    ? "Identical to the final outside the execution allowance."
    : `${c.difference_count} difference${c.difference_count === 1 ? "" : "s"} from the final outside the execution allowance.`;
}
