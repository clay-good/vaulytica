/**
 * The privacy statement every report surface prints — in ONE place.
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
export type PrivacySubject = "document" | "bundle" | "comparison";

const SUBJECT: Record<PrivacySubject, string> = {
  document: "No portion of the input document was transmitted to any server.",
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
