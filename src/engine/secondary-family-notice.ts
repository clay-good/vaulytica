/**
 * The sentence the per-document secondary-family cap owes the reader.
 *
 * One owner because three surfaces say it (the report DOCX, the report HTML,
 * and the browser tab), and a caveat two surfaces state differently is worse
 * than one they both omit: the reader cannot tell which number to believe.
 *
 * 🚨 **This is a LEAF module on purpose — it imports nothing, and must not.**
 * It first lived in `secondary-families.ts` beside the runner that uses it,
 * which meant `src/ui/states.ts` — part of the eagerly-loaded entry chunk —
 * reached `runEngine` through it. The entry went **84 KB → 151 KB raw**, first
 * contentful paint went 1.6s → 2.1s, and the 4G Lighthouse budget failed on a
 * one-line import. The engine belongs in the lazy pipeline chunk; a string
 * this small must never be the thing that drags it forward.
 *
 * The count of families actually scanned is passed in rather than read from
 * `MAX_SECONDARY_FAMILIES` so this module needs no import for that either —
 * and so the sentence stays true if a caller ever shows fewer than the cap.
 */
export function cappedFamiliesNotice(omitted: number, scanned: number): string {
  const one = omitted === 1;
  return (
    `This document clearly contains ${omitted} further ${one ? "family" : "families"} ` +
    `that ${one ? "was" : "were"} NOT scanned — only the ${scanned} strongest-signal ` +
    `families are run per document. The list below is therefore incomplete, and a clause ` +
    `these unscanned families would have checked for is neither reported present nor absent.`
  );
}
