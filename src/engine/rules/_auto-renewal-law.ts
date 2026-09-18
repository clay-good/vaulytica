/**
 * The law behind an automatic-renewal finding, stated once for the four rules
 * that read renewal clauses (TEMP-004, TEMP-005, TEMP-011, DARK-002).
 *
 * These rules used to cite 16 C.F.R. Part 425. Since the 2024 amendments were
 * vacated (Custom Communications, Inc. v. FTC, 8th Cir. 2025), Part 425 reaches
 * prenotification negative-option plans only — it never governed a renewal
 * notice window. The authorities that do are ROSCA and the state
 * automatic-renewal laws for consumers, and, for business contracts, New York
 * General Obligations Law § 5-903, which no rule mentioned: a customer-side
 * reviewer was never told that a missed window may not bind the customer.
 */

export const AUTO_RENEWAL_CITATIONS: readonly string[] = [
  "stat-15-usc-8403",
  "stat-ca-bp-17600",
  "stat-ny-gol-5-903",
];

export const AUTO_RENEWAL_LAW =
  "Whether the renewal binds depends on the contract and the state. For consumer subscriptions sold online, ROSCA (15 U.S.C. § 8403) and state automatic-renewal laws such as California's (Cal. Bus. & Prof. Code § 17600 et seq.) require clear disclosure of the renewal terms and a simple way to cancel. For business contracts, New York General Obligations Law § 5-903 makes an automatic-renewal clause in a contract for service, maintenance or repair to real or personal property unenforceable against the customer unless the provider serves written notice of the clause, personally or by certified mail, 15 to 30 days before the non-renewal deadline.";
