/**
 * Does the document contemplate an international transfer of personal data?
 *
 * The precondition five rules state — DPA-032 ("where international transfers
 * occur"), DPA-054, DPA-055 and TRANSFER-020 ("where SCCs apply") and
 * TRANSFER-019 ("where SCCs / IDTA cover transfers") — and none tested. A DPA
 * that never mentions a transfer, a third country or the SCCs was told, at
 * CRITICAL, that it names no Chapter V mechanism, and four more findings about
 * clauses of an instrument it does not use. A DPA with no international
 * transfer has no Chapter V obligation to meet; one that contemplates a
 * transfer without naming its mechanism still reads every rule.
 */
export const INTERNATIONAL_TRANSFER =
  /standard\s+contractual\s+clauses|\bSCCs?\b|2021\/914|\bIDTA\b|international\s+data\s+transfer\s+(?:agreement|addendum)|third\s+countr|outside\s+(?:of\s+)?the\s+(?:EEA|European\s+Economic\s+Area|European\s+Union|EU|UK|United\s+Kingdom|country\s+of\s+origin)|international\s+(?:data\s+)?transfers?|cross-border\s+(?:transfer|movement|flow)|Chapter\s+V\b|transfer\w*\s+(?:(?:of\s+)?personal\s+data\s+)?(?:to|outside)\s+(?:any\s+)?(?:other\s+)?(?:country|jurisdiction)/i;
