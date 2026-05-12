/**
 * Report layer barrel. Consumers import the DOCX builder, the JSON
 * builder, the citation formatter, and the bibliography deduper from
 * a single place.
 */

export { buildDocxReport } from "./docx.js";
export { buildJsonReport, type JsonReport } from "./json.js";
export { formatCitation, formatBibliographyEntry } from "./citations.js";
export {
  buildBibliography,
  citationIndex,
  type BibliographyEntry,
} from "./bibliography.js";
