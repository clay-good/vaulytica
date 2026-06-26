/**
 * v3 PHI / personal-data category detector (spec-v3.md §19).
 *
 * Maps detected categories to a controlled vocabulary covering HIPAA's 18
 * identifiers, GDPR Article 9 special categories, GDPR Article 10 criminal
 * convictions, CCPA "sensitive personal information", and a residual "other"
 * bucket. Pure / deterministic.
 */

import type { DocumentTree } from "../../ingest/types.js";
import type { DataCategory, DataCategoryGroup } from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";

type CategoryDef = {
  slug: string;
  label: string;
  group: DataCategoryGroup;
  rx: RegExp;
};

/** Controlled vocabulary; longest-first ordering kept by hand. */
export const CATEGORY_CATALOG: CategoryDef[] = [
  // HIPAA 18 identifiers (45 C.F.R. § 164.514(b)(2)).
  { slug: "hipaa-names", label: "names", group: "hipaa-identifier", rx: /\bnames?\b/i },
  {
    slug: "hipaa-geo-subdivisions",
    label: "geographic subdivisions smaller than state",
    group: "hipaa-identifier",
    rx: /\bgeographic\s+(?:subdivision|location|identifier)/i,
  },
  {
    slug: "hipaa-dates",
    label: "dates related to an individual",
    group: "hipaa-identifier",
    rx: /\b(?:dates? of (?:birth|death|admission|discharge)|date elements)/i,
  },
  {
    slug: "hipaa-phone",
    label: "telephone numbers",
    group: "hipaa-identifier",
    rx: /\btelephone numbers?\b/i,
  },
  { slug: "hipaa-fax", label: "fax numbers", group: "hipaa-identifier", rx: /\bfax numbers?\b/i },
  {
    slug: "hipaa-email",
    label: "email addresses",
    group: "hipaa-identifier",
    rx: /\b(?:e-?mail addresses?|electronic mail)\b/i,
  },
  {
    slug: "hipaa-ssn",
    label: "social security numbers",
    group: "hipaa-identifier",
    rx: /\bsocial security numbers?\b|\bSSN\b/i,
  },
  {
    slug: "hipaa-medical-record-numbers",
    label: "medical record numbers",
    group: "hipaa-identifier",
    rx: /\bmedical record numbers?\b/i,
  },
  {
    slug: "hipaa-health-plan-numbers",
    label: "health plan beneficiary numbers",
    group: "hipaa-identifier",
    rx: /\bhealth plan (?:beneficiary )?numbers?\b/i,
  },
  {
    slug: "hipaa-account-numbers",
    label: "account numbers",
    group: "hipaa-identifier",
    rx: /\baccount numbers?\b/i,
  },
  {
    slug: "hipaa-license-numbers",
    label: "certificate / license numbers",
    group: "hipaa-identifier",
    rx: /\b(?:certificate|license)\s+numbers?\b/i,
  },
  {
    slug: "hipaa-vehicle-identifiers",
    label: "vehicle identifiers",
    group: "hipaa-identifier",
    rx: /\bvehicle identifiers?\b|\bVIN\b/i,
  },
  {
    slug: "hipaa-device-identifiers",
    label: "device identifiers and serial numbers",
    group: "hipaa-identifier",
    rx: /\bdevice (?:identifiers?|serial numbers?)/i,
  },
  {
    slug: "hipaa-urls",
    label: "web URLs",
    group: "hipaa-identifier",
    rx: /\bweb URLs?\b|\bweb addresses?\b/i,
  },
  {
    slug: "hipaa-ip",
    label: "IP addresses",
    group: "hipaa-identifier",
    rx: /\bIP addresses?\b|\binternet protocol addresses?\b/i,
  },
  {
    slug: "hipaa-biometric",
    label: "biometric identifiers",
    group: "hipaa-identifier",
    rx: /\bbiometric (?:identifiers?|data|information)/i,
  },
  {
    slug: "hipaa-photos",
    label: "full-face photographs",
    group: "hipaa-identifier",
    rx: /\b(?:full-?face )?photographs?\b/i,
  },
  {
    slug: "hipaa-other-unique",
    label: "other unique identifying number, characteristic, or code",
    group: "hipaa-identifier",
    rx: /\bunique identifying (?:number|characteristic|code)/i,
  },

  // GDPR Art. 9 special categories.
  {
    slug: "gdpr-racial-ethnic",
    label: "racial or ethnic origin",
    group: "gdpr-special",
    rx: /\bracial or ethnic origin\b/i,
  },
  {
    slug: "gdpr-political",
    label: "political opinions",
    group: "gdpr-special",
    rx: /\bpolitical opinions\b/i,
  },
  {
    slug: "gdpr-religious",
    label: "religious or philosophical beliefs",
    group: "gdpr-special",
    rx: /\breligious or philosophical beliefs\b/i,
  },
  {
    slug: "gdpr-union-membership",
    label: "trade-union membership",
    group: "gdpr-special",
    rx: /\btrade[- ]?union membership\b/i,
  },
  { slug: "gdpr-genetic", label: "genetic data", group: "gdpr-special", rx: /\bgenetic data\b/i },
  {
    slug: "gdpr-biometric-id",
    label: "biometric data for unique identification",
    group: "gdpr-special",
    rx: /\bbiometric data\b/i,
  },
  {
    slug: "gdpr-health",
    label: "data concerning health",
    group: "gdpr-special",
    rx: /\b(?:data concerning )?health(?: data| information)?\b/i,
  },
  {
    slug: "gdpr-sex-life",
    label: "data concerning sex life or sexual orientation",
    group: "gdpr-special",
    rx: /\bsex(?:ual)? (?:life|orientation)\b/i,
  },

  // GDPR Art. 10.
  {
    slug: "gdpr-criminal",
    label: "personal data relating to criminal convictions and offences",
    group: "gdpr-criminal",
    rx: /\bcriminal (?:convictions?|offences?|records?|history)\b/i,
  },

  // CCPA sensitive personal information (Cal. Civ. Code § 1798.140(ae)).
  {
    slug: "ccpa-driver-license",
    label: "driver's license / state-id / passport",
    group: "ccpa-sensitive",
    rx: /\b(?:driver'?s? license|state identification|passport number)/i,
  },
  {
    slug: "ccpa-financial-account",
    label: "financial account / credit card / debit card with security or access code",
    group: "ccpa-sensitive",
    rx: /\b(?:financial account|credit card|debit card)\s+(?:number|information)/i,
  },
  {
    slug: "ccpa-precise-geolocation",
    label: "precise geolocation",
    group: "ccpa-sensitive",
    rx: /\bprecise geolocation\b/i,
  },
  {
    slug: "ccpa-mail-content",
    label: "contents of mail, email, and text messages",
    group: "ccpa-sensitive",
    rx: /\bcontents of (?:mail|email|text messages)/i,
  },
];

const SPECIAL_FLAG_RX =
  /\b(?:special categor(?:y|ies) of (?:personal )?data|sensitive personal information|article\s+9(?:\s+data)?)\b/i;

export function extractDataCategories(tree: DocumentTree): DataCategory[] {
  const seen = new Set<string>();
  const out: DataCategory[] = [];
  forEachParagraph(tree, (ctx) => {
    for (const cat of CATEGORY_CATALOG) {
      const m = cat.rx.exec(ctx.text);
      if (m) {
        const key = `${cat.slug}|${ctx.paragraph.id}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({
          slug: cat.slug,
          label: cat.label,
          group: cat.group,
          position: posInParagraph(ctx, m.index, m.index + m[0].length),
          raw_text: m[0],
        });
      }
    }
    // Always surface a generic "special categories" flag (groups it under "other"
    // when the catalog row didn't fire individually).
    const special = SPECIAL_FLAG_RX.exec(ctx.text);
    if (special) {
      const key = `flag-special|${ctx.paragraph.id}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({
          slug: "special-categories-flag",
          label: "special categories of personal data",
          group: "gdpr-special",
          position: posInParagraph(ctx, special.index, special.index + special[0].length),
          raw_text: special[0],
        });
      }
    }
  });
  out.sort((a, b) =>
    a.position.start !== b.position.start
      ? a.position.start - b.position.start
      : a.slug < b.slug
        ? -1
        : a.slug > b.slug
          ? 1
          : 0,
  );
  return out;
}
