import type { EngineRun, Finding } from "../engine/finding.js";

/**
 * Links to the one report page, `/report` (spec-v53 §4).
 *
 * The project learns about a wrong finding only when a maintainer happens to
 * write the document that draws it. This is the way a reader says so — and it
 * is built so that a contract cannot travel with it:
 *
 *  - context rides in the URL **fragment**, which a browser never sends to a
 *    server, so even opening the link tells the site nothing;
 *  - the context is five identifiers the tool itself chose — a rule id and
 *    version, the engine and knowledge-base versions, a document-type id — and
 *    there is no field for an excerpt, a file name, or a hash of the document;
 *  - a finding from a user's own playbook gets NO link, and neither does
 *    anything while a custom playbook is loaded: those ids are theirs.
 *
 * The page is a separate document from the app and shares no memory with the
 * tab that analyzed a contract. Nothing here calls an endpoint.
 */
export const REPORT_PAGE_URL = "https://vaulytica.com/report";

/** What kind of problem is being reported. */
export type ReportKind = "wrong-finding" | "missed" | "wrong-type" | "site";

/** Everything a link may carry. Every value is an id the tool generated. */
export type ReportContext = {
  kind?: ReportKind;
  /** The rule a finding came from, and its version. */
  rule?: string;
  rv?: string;
  engine?: string;
  dkb?: string;
  /** The matched document-type id. */
  type?: string;
  /** For an unmatched document: the closest type's id. Never its score. */
  near?: string;
};

/** Fragment keys in the order they are written — and the only ones read back. */
export const REPORT_FIELDS = ["kind", "rule", "rv", "engine", "dkb", "type", "near"] as const;

/**
 * What each field may look like. An id is letters, digits, dots and dashes —
 * no spaces, no punctuation a sentence would need — so nothing that is prose
 * can be carried in one, by this code or by a hand-edited link. A document
 * type id is also not a long run of hex: a file's hash has that shape, and a
 * hash of the document is one of the things a report must never hold.
 */
const SHAPE: Record<(typeof REPORT_FIELDS)[number], RegExp> = {
  kind: /^(?:wrong-finding|missed|wrong-type|site)$/,
  rule: /^[A-Z][A-Z0-9]{1,9}(?:-[A-Z0-9]{1,6}){1,3}$/,
  rv: /^\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  engine: /^\d{1,3}\.\d{1,5}\.\d{1,3}$/,
  dkb: /^v[0-9A-Za-z.-]{1,40}$/,
  type: /^(?![0-9a-f]{32,}$)[a-z0-9][a-z0-9-]{1,59}$/,
  near: /^(?![0-9a-f]{32,}$)[a-z0-9][a-z0-9-]{1,59}$/,
};

/** A link to the report page carrying `ctx` in its fragment. Malformed values are dropped. */
export function reportLink(ctx: ReportContext): string {
  const parts: string[] = [];
  for (const key of REPORT_FIELDS) {
    const value = ctx[key];
    if (value !== undefined && SHAPE[key].test(value)) parts.push(`${key}=${value}`);
  }
  return parts.length > 0 ? `${REPORT_PAGE_URL}#${parts.join("&")}` : REPORT_PAGE_URL;
}

/** Read a fragment back. Unknown keys and malformed values are ignored, never echoed. */
export function parseReportFragment(hash: string): ReportContext {
  const out: ReportContext = {};
  for (const pair of hash.replace(/^#/, "").split("&")) {
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const key = pair.slice(0, eq) as (typeof REPORT_FIELDS)[number];
    const value = pair.slice(eq + 1);
    if (!REPORT_FIELDS.includes(key) || !SHAPE[key].test(value)) continue;
    (out as Record<string, string>)[key] = value;
  }
  return out;
}

/** Whether any part of this run came from a user's own playbook. */
function usesCustomPlaybook(run: Pick<EngineRun, "findings">): boolean {
  return run.findings.some((f) => f.source === "custom-playbook");
}

type RunIds = Pick<EngineRun, "version" | "dkb_version" | "playbook_id" | "findings">;

/**
 * The link a report carries once: this engine, this knowledge base, this
 * document type. `null` when the run used a custom playbook — nothing about a
 * user's own rules is offered up.
 */
export function reportLinkForRun(
  run: RunIds,
  opts: { customPlaybook?: boolean } = {},
): string | null {
  if (opts.customPlaybook || usesCustomPlaybook(run)) return null;
  return reportLink({ engine: run.version, dkb: run.dkb_version, type: run.playbook_id });
}

/** The link for one finding. `null` for a custom-playbook finding or run. */
export function reportLinkForFinding(
  run: RunIds,
  finding: Pick<Finding, "rule_id" | "rule_version" | "source">,
  opts: { customPlaybook?: boolean } = {},
): string | null {
  if (opts.customPlaybook || finding.source === "custom-playbook" || usesCustomPlaybook(run)) {
    return null;
  }
  return reportLink({
    kind: "wrong-finding",
    rule: finding.rule_id,
    rv: finding.rule_version,
    engine: run.version,
    dkb: run.dkb_version,
    type: run.playbook_id,
  });
}

/**
 * From the unmatched notice: "What kind of document is this?" Carries the
 * closest type's id when there is one, and never its score.
 */
export function reportLinkForUnmatched(
  run: Pick<EngineRun, "version" | "dkb_version">,
  nearType?: string,
  opts: { customPlaybook?: boolean } = {},
): string | null {
  if (opts.customPlaybook) return null;
  return reportLink({
    kind: "wrong-type",
    engine: run.version,
    dkb: run.dkb_version,
    ...(nearType ? { near: nearType } : {}),
  });
}
