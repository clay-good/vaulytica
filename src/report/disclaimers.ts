/**
 * The posture statements every report surface prints — in ONE place.
 *
 * 🚨 **It was wrong on the headless surfaces.** Four files each declared their
 * own `PRIVACY_STATEMENT`, all four opening "This analysis was performed
 * entirely inside the user's web browser", and the `vaulytica` CLI and the
 * GitHub Action render the same reports in a Node process on a build machine.
 * A report produced in CI told its reader it had run in a browser tab, and
 * described Vaulytica as "a static web page hosted on Cloudflare Pages" —
 * true of the web app, and not of the run that produced that file.
 *
 * The substance was never in doubt: no surface transmits document content
 * anywhere. What was wrong was the MECHANISM the report asserted, in the one
 * section a reader consults precisely because they want the mechanism.
 *
 * 🚨 **And the four copies had already drifted.** The bundle's dropped the
 * independent-verification sentence; the comparison's dropped the developer's
 * "no record of this analysis" as well. A claim that exists four times will
 * disagree with itself — which is why this file exists and why
 * `shared-vocabulary.test.ts` names it as the single owner.
 */

/** What the report is about, for the one clause that differs. */
export type PrivacySubject = "document" | "bundle" | "comparison" | "review";

const SUBJECT: Record<PrivacySubject, string> = {
  document: "No portion of the input document was transmitted to any server.",
  // The anchored-comments copy: the caller's own file, commented in place.
  review: "No portion of the input document was transmitted to any server.",
  bundle: "No portion of any input document was transmitted to any server.",
  comparison: "Neither file, nor any portion of either, was transmitted to any server.",
};

/**
 * True on every surface: the browser tab, the CLI, and the Action.
 *
 * "the machine that ran it" rather than "the user's browser" is the whole
 * repair — it is the claim a reader can check, and it is checkable whichever
 * surface produced the file.
 */
export function privacyStatement(subject: PrivacySubject): string {
  return (
    `${SUBJECT[subject]} In the web app the analysis runs entirely inside the browser tab; ` +
    "from the vaulytica CLI or the GitHub Action it runs entirely in the local process. " +
    "Neither path sends document content over the network. Vaulytica has no backend, no " +
    "database, no analytics, and no telemetry — the web app is a static page hosted on " +
    "Cloudflare Pages, and the CLI reads its rule data and writes its reports as files. " +
    "The developer of Vaulytica has no record of this analysis, no ability to recover it, " +
    "and no way to identify the user who performed it. The network logs of the machine " +
    "that ran it can independently confirm this."
  );
}

/**
 * The not-legal-advice statement.
 *
 * 🚨 **This had drifted the same four ways the privacy statement had**, and
 * for the same reason: `html.ts`, `docx.ts`, `bundle.ts` and `compare-docx.ts`
 * each declared their own. The bundle's copy had dropped "The decision to act
 * on any finding, or not, is yours and your counsel's" — the sentence that
 * puts the decision where it belongs — and the comparison's had dropped the
 * "may be incorrect, incomplete, or inapplicable" qualifier.
 *
 * 🚨 And the ANCHORED-COMMENTS DOCX printed none of it. That artifact is a
 * byte-copy of the client's own contract with review comments inserted, and
 * its comments quote Chancery practice and the Restatement — the surface most
 * likely to be forwarded to someone who did not run the tool, and the only one
 * that said nothing about what it is.
 */
export function nonAdviceStatement(subject: PrivacySubject): string {
  const WHAT: Record<PrivacySubject, string> = {
    document:
      "This report is a checklist of mechanical findings produced by a deterministic rule engine against a contract you provided.",
    bundle:
      "This report is a checklist of mechanical findings produced by a deterministic rule engine against documents you provided.",
    comparison:
      "This comparison is a mechanical diff of two rule-engine runs over documents you provided.",
    review:
      "These comments are a checklist of mechanical findings produced by a deterministic rule engine against the contract they are attached to.",
  };
  const what = WHAT[subject];
  return (
    `Vaulytica is a software tool, not a lawyer. ${what} It is not legal advice, and using ` +
    "Vaulytica does not create an attorney-client relationship with anyone. The findings may be " +
    "incorrect, incomplete, or inapplicable to your situation. The decision to act on any " +
    "finding, or not, is yours and your counsel's. If something here matters to a transaction " +
    "or a dispute, consult a licensed attorney in the relevant jurisdiction."
  );
}

/**
 * What a report says where its own timestamp would go.
 *
 * 🚨 `docx.ts` already carries the diagnosis — "One artifact contradicting
 * itself about its own provenance, on the page a reader looks at first" — and
 * the repair landed on the COVER only. The same DOCX's audit trail, a thousand
 * paragraphs later, still said the terse "(omitted from hash)", as did the
 * HTML report's provenance list and the bundle cover. Four sites, two
 * wordings, two of them inside one file.
 *
 * The terse form reads like a missing value. The long form says why the blank
 * is the point: the timestamp is left out so the same input reproduces the
 * same bytes on any machine, which is the whole determinism claim.
 */
export const EXECUTED_AT_OMITTED =
  "(omitted from hash — this report is reproducible on any machine)";
