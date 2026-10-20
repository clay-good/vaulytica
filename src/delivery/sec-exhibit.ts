/**
 * The document types an SEC exhibit is filed as — HANDOFF-008's scope.
 *
 * Reg. S-K Item 601(b)(10)(iv) lets a registrant omit information from a filed
 * material contract without a confidential-treatment request, provided the
 * exhibit marks each omission and carries a first-page statement. That rule is
 * about a filing, so the check applies only to a document that is one: routed
 * to a type the EDGAR routing sample's labels name for an Exhibit 10, or
 * asserted with `--sec-exhibit`.
 *
 * Held equal, by `sec-exhibit.test.ts`, to the exact and accepted types in
 * `corpus/routing/labels.json`, so a type the labels add is in scope here too.
 */
export const SEC_EXHIBIT_FAMILIES: ReadonlySet<string> = new Set([
  "advisor-agreement",
  "asset-purchase-agreement",
  "bonus-plan",
  "confidential-settlement",
  "consulting-agreement",
  "convertible-note",
  "copyright-license",
  "director-indemnification-agreement",
  "distribution-agreement",
  "employee-stock-purchase-plan",
  "employment-at-will-us",
  "employment-restrictive-covenant",
  "equipment-lease",
  "equity-incentive-plan",
  "escrow-agreement",
  "executive-employment",
  "forbearance-agreement",
  "guaranty",
  "indemnification-agreement",
  "independent-contractor",
  "joint-development-agreement",
  "lease-commercial-multitenant",
  "loan-agreement",
  "management-services-agreement",
  "manufacturing-supply-agreement",
  "master-purchase-agreement",
  "msa-customer-deep",
  "msa-general",
  "msa-vendor-deep",
  "mutual-release",
  "offer-letter",
  "operating-agreement-llc",
  "partnership-agreement",
  "patent-license",
  "physician-employment-agreement",
  "piia",
  "promissory-note",
  "purchase-order-terms",
  "revolving-credit-agreement",
  "rspa",
  "rsu-grant",
  "security-agreement",
  "separation-agreement",
  "software-license-enterprise",
  "stock-option-grant",
  "stock-purchase-agreement",
  "sublease-agreement",
  "subscription-agreement",
  "technology-transfer-agreement",
  "trademark-license",
  "transition-services-agreement",
  "venture-stock-purchase-agreement",
  "voting-agreement",
  "warrant-agreement",
]);
