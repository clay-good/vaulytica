/**
 * Hand-authored regex pattern overlay for the clause classifier (spec
 * §13). Patterns fire at confidence 1.0 and short-circuit the TF-IDF
 * fallback. The orchestrator writes the resulting array to
 * `dkb-classifier-patterns.json`.
 *
 * Coverage matches spec §26 step 11: governing-law, indemnification,
 * limitation-of-liability, confidentiality-obligation, term,
 * termination-for-cause, termination-for-convenience, force-majeure,
 * assignment, entire-agreement, severability, waiver, notices,
 * counterparts.
 */

import type { ClassifierPatternEntry } from "../../../src/dkb/types.js";

export const PATTERNS: ClassifierPatternEntry[] = [
  {
    category: "governing-law",
    pattern: "governed\\s+by\\s+(?:and\\s+construed\\s+(?:in\\s+accordance\\s+)?with\\s+)?the\\s+laws\\s+of",
    flags: "i",
    confidence: 0.98,
  },
  {
    category: "governing-law",
    pattern: "this\\s+agreement\\s+shall\\s+be\\s+governed\\s+by",
    flags: "i",
    confidence: 0.97,
  },
  {
    category: "indemnification",
    pattern: "(?:shall|will|agrees?\\s+to)\\s+indemnify[\\s,]+(?:and\\s+)?(?:defend|hold\\s+harmless)",
    flags: "i",
    confidence: 0.98,
  },
  {
    category: "indemnification",
    pattern: "hold\\s+\\w+\\s+harmless\\s+from",
    flags: "i",
    confidence: 0.92,
  },
  {
    category: "limitation-of-liability",
    pattern: "(?:in\\s+no\\s+event|under\\s+no\\s+circumstances)\\s+(?:shall|will)",
    flags: "i",
    confidence: 0.95,
  },
  {
    category: "limitation-of-liability",
    pattern: "aggregate\\s+liability.*?(?:shall|will)?\\s*not\\s+exceed",
    flags: "i",
    confidence: 0.97,
  },
  {
    category: "consequential-damages-waiver",
    pattern: "(?:no|not|excluding)\\s+(?:indirect|consequential|incidental|special|punitive)\\s+damages",
    flags: "i",
    confidence: 0.94,
  },
  {
    category: "confidentiality-obligation",
    pattern: "confidential\\s+information",
    flags: "i",
    confidence: 0.86,
  },
  {
    category: "confidentiality-obligation",
    pattern: "shall\\s+(?:not\\s+disclose|maintain\\s+the\\s+confidentiality|treat\\s+as\\s+confidential)",
    flags: "i",
    confidence: 0.93,
  },
  {
    category: "permitted-disclosures",
    pattern: "may\\s+disclose.*?(?:employees|advisors|contractors|representatives)\\s+who",
    flags: "is",
    confidence: 0.9,
  },
  {
    category: "term",
    pattern: "term\\s+of\\s+this\\s+agreement\\s+(?:shall|will)\\s+(?:be|commence|begin)",
    flags: "i",
    confidence: 0.95,
  },
  {
    category: "renewal-term",
    pattern: "(?:shall|will)\\s+(?:automatically|auto-)?\\s*renew\\s+for",
    flags: "i",
    confidence: 0.95,
  },
  {
    category: "termination-for-cause",
    pattern: "may\\s+terminate\\s+this\\s+agreement.*?(?:for\\s+cause|material\\s+breach)",
    flags: "is",
    confidence: 0.96,
  },
  {
    category: "termination-for-convenience",
    pattern: "may\\s+terminate.*?(?:for\\s+(?:any|convenience))",
    flags: "is",
    confidence: 0.94,
  },
  {
    category: "force-majeure",
    pattern: "force\\s+majeure",
    flags: "i",
    confidence: 0.98,
  },
  {
    category: "force-majeure",
    pattern: "neither\\s+party\\s+(?:shall|will)\\s+be\\s+liable.*?(?:beyond\\s+(?:its|their)\\s+reasonable\\s+control)",
    flags: "is",
    confidence: 0.9,
  },
  {
    category: "assignment",
    pattern: "(?:may\\s+not|shall\\s+not)\\s+assign(?:\\s+this\\s+agreement)?\\s+without",
    flags: "i",
    confidence: 0.96,
  },
  {
    category: "entire-agreement",
    pattern: "entire\\s+agreement\\s+(?:of|between)\\s+the\\s+parties",
    flags: "i",
    confidence: 0.97,
  },
  {
    category: "entire-agreement",
    pattern: "supersedes\\s+all\\s+(?:prior|previous)\\s+(?:agreements|understandings|communications)",
    flags: "i",
    confidence: 0.95,
  },
  {
    category: "severability",
    pattern: "if\\s+any\\s+(?:provision|portion|part).*?(?:invalid|unenforceable|illegal)",
    flags: "is",
    confidence: 0.94,
  },
  {
    category: "waiver",
    pattern: "no\\s+waiver\\s+of\\s+any\\s+(?:provision|term|right)",
    flags: "i",
    confidence: 0.94,
  },
  {
    category: "notices",
    pattern: "(?:all\\s+)?notices?\\s+(?:under|required\\s+by|pursuant\\s+to)\\s+this\\s+agreement\\s+(?:shall|must)\\s+be\\s+in\\s+writing",
    flags: "i",
    confidence: 0.96,
  },
  {
    category: "counterparts",
    pattern: "may\\s+be\\s+executed\\s+in\\s+(?:one\\s+or\\s+more\\s+)?counterparts",
    flags: "i",
    confidence: 0.97,
  },
  {
    category: "jury-trial-waiver",
    pattern: "(?:waives?|waiv(?:er|ing))\\s+(?:any\\s+)?right\\s+to\\s+(?:a\\s+)?trial\\s+by\\s+jury",
    flags: "i",
    confidence: 0.98,
  },
  {
    category: "arbitration",
    pattern: "shall\\s+be\\s+(?:finally\\s+)?(?:settled|resolved|determined)\\s+by\\s+(?:binding\\s+)?arbitration",
    flags: "i",
    confidence: 0.97,
  },
  {
    category: "venue",
    pattern: "exclusive\\s+(?:jurisdiction|venue)\\s+(?:of|in)\\s+the\\s+(?:state|federal)\\s+courts",
    flags: "i",
    confidence: 0.96,
  },
  {
    category: "ip-ownership",
    pattern: "(?:all\\s+)?(?:work\\s+product|deliverables)\\s+(?:shall|will)\\s+be\\s+(?:owned\\s+by|the\\s+(?:sole\\s+)?property\\s+of)",
    flags: "i",
    confidence: 0.94,
  },
];
