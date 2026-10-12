/**
 * 🚨 THE SUITE SILENTLY TESTED A DIFFERENT APPLICATION.
 *
 * `playwright.config.ts` sets `reuseExistingServer: !process.env.CI`, so a
 * local run attaches to whatever already holds the port. On 2026-10-12 another
 * project's `vite preview` held 4173, and this suite ran against it: **17
 * failed and 39 PASSED**. The failures were loud but misdiagnosed as flake —
 * and the 39 passes were worse, because axe, keyboard and responsiveness
 * checks pass on any well-formed page, so a third of the suite reported green
 * against an app this repo has never seen.
 *
 * Wall time is not the tell. The foreign page loaded instantly, so the run
 * took a normal 33 seconds; only reading the captured DOM showed a heading
 * from someone else's site where the dropzone should have been.
 *
 * So before any test runs, the served page is asked to identify itself. A
 * foreign server now fails the run on the first line of output, naming what it
 * found, instead of producing a mix of red and meaningless green.
 */
const MARKER = "Vaulytica";

export default async function assertOurApp(): Promise<void> {
  const base =
    process.env.VAULYTICA_E2E_BASE_URL ??
    `http://127.0.0.1:${process.env.VAULYTICA_E2E_PORT ?? 4173}`;
  const res = await fetch(base, { redirect: "follow" });
  const html = await res.text();
  if (html.includes(MARKER)) return;

  const title = /<title>([^<]*)<\/title>/i.exec(html)?.[1]?.trim() ?? "(no <title>)";
  throw new Error(
    [
      `${base} is not serving this application.`,
      `Its <title> is ${JSON.stringify(title)}, which does not mention ${JSON.stringify(MARKER)}.`,
      "",
      "Playwright reuses an existing server locally, so another project's dev",
      "server on this port would be tested instead of yours — and most of the",
      "accessibility and layout specs pass against any well-formed page, so the",
      "run would report green for work that was never exercised.",
      "",
      "Free the port, or set VAULYTICA_E2E_PORT to one that is free.",
    ].join("\n"),
  );
}
