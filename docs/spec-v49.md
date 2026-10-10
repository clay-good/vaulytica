# Vaulytica v49 — The Documents People Actually Bring (Families the Catalog Returns Nothing For)

> **Status:** **Proposed (2026-10-10).** Not built. Continues after [`spec-v48.md`](spec-v48.md), beginning at **Step 308**.
> **Scope:** one idea — pick new families by **what a visitor drops and gets an empty report for**, not by what a law firm's practice list contains. Ten measured families now, a second tranche chosen by the same test.
> **Posture (unchanged):** deterministic, presence-only, citable. Every check names its authority and says plainly when that authority is customary practice rather than a rule that compels the clause.
> **Cousin docs:** [`spec-v45.md`](spec-v45.md) (the column-first discipline this reuses), [`adding-a-playbook.md`](adding-a-playbook.md), [`spec-v47.md`](spec-v47.md) (the currency guard every new citation joins), [`verticals.md`](verticals.md).

---

# Part 0 — The measurement

## §1. Ten ordinary documents, seven sent to the fallback

Ten short, correctly titled documents of types the 268-family catalog does not name, run through 9.853.0. They were written for this probe, so this is a signal, not a corpus measurement; Step 308 commits it as a test.

| Document                                     | Routed to                | Result                                                                     |
| -------------------------------------------- | ------------------------ | -------------------------------------------------------------------------- |
| Advisor agreement                            | `generic-fallback`       | 0 findings                                                                 |
| Exclusive buyer representation agreement     | `generic-fallback`       | 0 findings                                                                 |
| Pilot / evaluation agreement                 | `generic-fallback`       | 0 findings                                                                 |
| Training repayment ("stay-or-pay") agreement | `generic-fallback`       | 0 findings — though `PERS-008` exists to flag exactly this clause          |
| Merchant cash advance                        | `generic-fallback`       | 1 info — on a **confession of judgment** plus a personal guaranty          |
| Residential solar power purchase agreement   | `generic-fallback`       | 0 findings — on a 25-year term with a 2.9% annual escalator                |
| Roommate agreement                           | `generic-fallback`       | 0 findings                                                                 |
| Service level agreement                      | `saas-customer`          | **1 critical**, 5 warnings — "No indemnification clause", on an attachment |
| HIPAA limited-data-set data use agreement    | `data-sharing-agreement` | Generic sharing checks; none of the § 164.514(e) required terms            |
| Software development agreement               | `msa-general`            | Services checks; nothing on acceptance or the work-for-hire gap            |

The fallback is honest — it says no family matched. But an honest empty report on a merchant cash advance is still an empty report, and the SLA row is a confident false accusation.

**The existing corpus cannot see this.** All 327 specimens match a family; none falls to the fallback. The corpus was written from the catalog, so it contains only documents the catalog knows.

**One row is a recognizer miss, not a catalog gap.** `PERS-008` did not fire on "shall repay the Employer the full cost of the training" even with the employment playbook forced: its pattern wants "repay … training cost" in that order. That is fixed where it lives, before any new family is built on it.

## §2. What v49 is and is not

**It is** new playbooks and their gated checks in the open wave `src/playbooks/v7/`, each built column-first with the `v5/_pack.ts` shorthand, each with a clean specimen and a defective one.

**It is not** a new rule shape, a new jurisdiction (US only, as v45), or a claim of legal completeness. A family ships with the columns that could be verified and no others.

---

# Part I — The families

## §3. Tranche A — the ten measured above

A research pass on 2026-10-10 read the primary text where it could be reached. The last column says what was actually read. **"Mirror" and "secondary" are not verification**; §6 still applies to every row.

| Family id                        | What the checks read                                                                                                                                                                                            | Authority                                                                                                                                                    | Read on 2026-10-10                                                                                        |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| `hipaa-data-use-agreement`       | The seven required terms: permitted uses within the three allowed purposes; who may use or receive; no further use or disclosure; safeguards; reporting; agent flow-down; no re-identification or contact       | 45 C.F.R. § 164.514(e)(4)(ii)(A)–(C), purposes in (e)(3)                                                                                                     | Primary text                                                                                              |
| `software-development-agreement` | Specifications; acceptance and deemed acceptance; milestone payments; an **assignment**, not only a work-for-hire recital; pre-existing materials; open-source disclosure                                       | 17 U.S.C. § 101 — software is not one of the nine commissioned categories, so it _usually_ falls outside                                                     | Primary text                                                                                              |
| `merchant-cash-advance`          | Confession of judgment; reconciliation right; specified percentage; personal guaranty scope; auto-debit authorization                                                                                           | Tex. Fin. Code § 398.055 (confession of judgment void) and § 398.056, as a Texas overlay. Reconciliation, percentage, guaranty: **practice**                 | Enrolled bill text                                                                                        |
| `residential-solar-agreement`    | Three-business-day cancellation statement and Notice of Cancellation; no confession of judgment. Escalator, term, production guarantee, transfer on sale, fixture filing: **practice**                          | 16 C.F.R. § 429.1 — **only when the sale is a home solicitation**                                                                                            | Primary text                                                                                              |
| `buyer-representation-agreement` | Compensation as a specific amount or rate; objectively ascertainable, not open-ended; broker may not receive more; conspicuous "fully negotiable, not set by law" statement. Term and exclusivity: **practice** | 2024 NAR settlement practice changes (an industry settlement binding NAR members and MLS participants, **not law**); Tex. Occ. Code § 1101.563 as an overlay | NAR's published terms; Texas enrolled text                                                                |
| `training-repayment-agreement`   | Repayment trigger; proration; cap at employer's actual cost; no acceleration; wage-deduction authorization; carve-out for termination without misconduct                                                        | Cal. Bus. & Prof. Code § 16608 and Lab. Code § 926, as a California overlay                                                                                  | Mirror only. **Reported amended in Sept. 2026 to apply from 2027-01-01 — confirm at the official source** |
| `advisor-agreement`              | Equity amount; vesting and cliff; IP assignment; confidentiality; no-conflict; option priced at fair market value or by reference to the plan                                                                   | Practice (the FAST Agreement, cited by URL — **no license is stated; do not reproduce its text**); Treas. Reg. § 1.409A-1(b)(5) for pricing                  | Primary text for the regulation                                                                           |
| `service-level-agreement`        | Uptime commitment and measurement window; exclusions; credit schedule; claim deadline; sole-remedy clause; chronic-failure termination                                                                          | Practice                                                                                                                                                     | —                                                                                                         |
| `pilot-evaluation-agreement`     | Evaluation-only license; pilot length; conversion terms; feedback license; data return; as-is disclaimer                                                                                                        | Practice                                                                                                                                                     | —                                                                                                         |
| `roommate-agreement`             | Rent and utility shares; deposit split; early move-out; replacement; relationship to the master lease                                                                                                           | Practice                                                                                                                                                     | —                                                                                                         |

What the research pass **removed**, and why it matters:

- **N.Y. CPLR 3218**, as read, sets procedure and venue for confessions of judgment; it is not a general ban. It is not cited as a prohibition.
- **16 C.F.R. Part 444 is consumer-only.** `BNK-051` cites it correctly for consumer credit; it cannot be carried to a merchant cash advance, which is commercial.
- **California and New York commercial-financing laws** (Cal. Fin. Code § 22800 et seq.; N.Y. Fin. Serv. Law § 801 et seq.) require a separate **offer-stage disclosure**. They are mostly not readable in the contract itself, so they support a check only where the specimen includes the disclosure page.
- **29 C.F.R. § 531.35** does not mention training repayment. It is not cited as compelling any clause.

`service-level-agreement` and `hipaa-data-use-agreement` are the two where the win is a **removed** false accusation as much as an added check. An SLA is an attachment; its playbook expects no indemnity, payment, or governing-law clause of its own.

## §4. Tranche B — chosen by the same test, not listed in advance

Candidates, each with the best authority the research pass found. A candidate is built only if its titled specimen fails the §1 probe, and only with columns that pass §6. None of these authorities has been read at an official source; "Strong" describes how checkable the text looks, not that it was confirmed.

| Candidate                                                                                                                                       | Authority found                                                                     | Standing                                                        |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `student-data-privacy-agreement`                                                                                                                | 34 C.F.R. § 99.31(a)(1)(i)(B); Cal. Educ. Code § 49073.1 (nine contract provisions) | Strong — enumerated terms                                       |
| `home-improvement-contract`                                                                                                                     | Cal. Bus. & Prof. Code § 7159, California overlay; Part 429 as the federal floor    | Strong in California                                            |
| `founder-stock-purchase-agreement`                                                                                                              | IRC § 83(b); Treas. Reg. § 1.83-2                                                   | Check first whether `rspa` already routes it                    |
| `liability-waiver`                                                                                                                              | Cal. Civ. Code § 1668; _Tunkl_                                                      | Check first whether `hold-harmless-agreement` already routes it |
| `buy-sell-agreement`                                                                                                                            | IRC § 2703(b) is a facts test, not presence-checkable                               | Practice columns only                                           |
| `vehicle-purchase-agreement`                                                                                                                    | FTC Used Car Rule, 16 C.F.R. Part 455                                               | **Never cite the CARS Rule** — reported vacated in 2025         |
| `management-services-agreement`                                                                                                                 | 2025 Oregon and California corporate-practice statutes                              | In flux; read only through secondary sources. Not yet           |
| `support-maintenance-agreement`, `reseller-agreement`, `beta-test-agreement`, `board-observer-agreement`, `commercial-power-purchase-agreement` | Practice                                                                            | Practice columns only                                           |
| `short-term-rental-agreement`, `event-services-agreement`                                                                                       | None found                                                                          | Dropped unless a citable practice source is identified          |

---

# Part II — How a family ships

## §5. The definition of done, per family

1. **Columns first.** The compliance matrix is written before any rule; column count equals check count (the v45 guard).
2. **A clean specimen and a defective one.** The clean one draws **zero** absence findings (the clean-document method: on a complete document, every absence finding is a bug); the defective one fires exactly its intended checks.
3. **Routing margin.** The specimen wins its family outright. A tie means the catalog cannot tell two families apart, and the fix is in `negative_features`, not in the specimen. Three collisions are already predictable: `software-development-agreement` with `work-for-hire-agreement`, `founder-stock-purchase-agreement` with `rspa`, `liability-waiver` with `hold-harmless-agreement`.
4. **No collateral movement.** Zero primary-routing changes across the existing corpus, and `distinguishing-base-rate.test.ts` still holds at 0.15.
5. **Reuse before writing.** The confession-of-judgment patterns exist in `BNK-051`, the work-for-hire logic in the IP-licensing pack, the § 164.514 citation helper in the privacy pack. Lift the recognizer and re-cite; `duplicate-logic.test.ts` holds this.
6. **The site follows.** `npm run site:doc-types` and the build regenerate `/review/<id>`, the sitemap, and `llms.txt`; the "268 document types" count moves wherever a drift guard reads it.

## §6. The citation gate

No rule is written from the tables above. For each column: open the **official** primary source (not a mirror), record the URL and `retrieved_at` in the DKB, and write the rule from what the source says. A column whose authority cannot be confirmed ships as **practice** with a practice citation, or does not ship.

- **State law fires through `STATE_OVERLAYS` only** — when the document's governing law or a party's state selects it — never on every document of the family. Texas joins California as an overlay state for this wave.
- **Conditional authorities carry their condition.** Part 429 applies to a home solicitation; a contract-date-gated statute checks the date. A check that cannot read its own condition reports at `info` and names the condition.
- **An industry settlement is cited as one.** The buyer-agreement terms bind NAR members and MLS participants. The finding says "industry practice under the 2024 settlement," never "required by law."

## §7. Currency

Every statutory citation here joins the v47 review cadence. This wave adds a class that table lacks: **state statutes with delayed or amended effective dates.** One California statute in §3 was reported amended shortly before this spec was written, and a shipped rule (`PERS-008`) states the effective date as first enacted (January 1, 2026), which may no longer be right. Step 309 exists because of it.

## §8. Steps

| Step | Work                                                                                                                                                      | Verify                                                                                                    |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| 308  | Commit the §1 probe as a test: titled specimens of the ten types                                                                                          | Pinned as today's result: each of the ten routes as the §1 table says; a family's row flips when it ships |
| 309  | Repair before building: widen `PERS-008`'s recognizer; confirm its California and New York statements at the official sources and correct them if amended | The probe sentence fires; the release note records what was read and when                                 |
| 310  | The three practice-only families                                                                                                                          | §5                                                                                                        |
| 311  | The seven cited families, one release each                                                                                                                | §5 plus §6; each release names the source read                                                            |
| 312  | Run the probe over the tranche B candidates; build what fails it and passes §6                                                                            | The surviving list, committed with the measurement                                                        |

---

# Part III — Open questions

1. **Attorney review.** These are the documents non-lawyers bring, so a wrong check here reaches the reader least able to discount it. The v5 ground-truth process is still blocked on sign-offs; v49 does not unblock it.
2. **Outside the US.** UK tenancy and employment documents are the most likely next request. That is a jurisdiction decision (v45 chose depth in one), not a catalog one.
3. **Entertainment and creator contracts.** Real demand, thin public practice sources to cite. Deferred until a citable source set is identified.
4. **Demand evidence.** The probe was the author's guess at what people bring. [`spec-v53.md`](spec-v53.md) §4 adds the "what kind of document is this?" link that would replace the guess with reports.
