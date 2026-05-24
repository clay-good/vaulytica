/**
 * Human-readable labels for the v3 family ids returned by
 * `detectV3Family` (`src/ui/v3/auto-detect.ts`).
 *
 * Pulled into its own tiny module so both the eager UI entry
 * (`main.ts`) and the dynamic-imported `pipeline.ts` chunk can reference
 * the same source of truth without `main.ts` pulling the pipeline's
 * heavy transitive deps (pdfjs, mammoth, docx).
 */

export const V3_FAMILY_LABELS: Record<string, string> = {
  baa: "Business Associate Agreement (BAA)",
  "dpa-eu": "EU Data Processing Agreement",
  "dpa-us-state": "US state DPA / Service Provider Addendum",
  "scc-module-2": "EU SCC Module 2 (controller → processor)",
  "scc-module-3": "EU SCC Module 3 (processor → processor)",
  "uk-idta": "UK International Data Transfer Addendum",
  "nda-deep": "NDA (deep)",
  "msa-deep": "MSA (deep)",
  coi: "Certificate of Insurance (ACORD 25)",
  "vendor-security": "Vendor Security Addendum",
  "ai-addendum": "AI Addendum",
};

/**
 * Resolve the display label for a v3 family. Falls back to a caller-
 * supplied default (typically the playbook name) when the detector
 * returned "unknown" or the family id is not in the table.
 */
export function familyDisplayLabel(family: string, fallback: string): string {
  if (family === "unknown") return fallback;
  return V3_FAMILY_LABELS[family] ?? fallback;
}
