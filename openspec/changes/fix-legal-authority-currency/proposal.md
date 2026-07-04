# fix-legal-authority-currency

## Why

The fastest way to lose an attorney is to be confidently wrong about current law. The audit confirmed three instances: (1) `PERS-001` and the v4 employment citation helper describe the FTC Non-Compete Rule (16 C.F.R. Part 910) as "pending"/operative and the DKB node cites the "current" eCFR — but the rule was set aside nationwide in *Ryan LLC v. FTC* (N.D. Tex. 2024) and never took effect; (2) `FIN-009` annualizes any late fee with an unspecified period by assuming "monthly" ×12, so a benign one-time "late fee of 5% of the overdue amount" is reported as ~60%/year usury — a confident false accusation in the tested-only-for-periodic-rates blind spot; (3) headline claims overstate authority: "35 state-law overlays" covers exactly three topics (non-compete, security deposit, usury), and "every finding traces to a pinned public source" while sampled launch rules carry `dkb_citations: []`.

## What Changes

- Correct the FTC non-compete language everywhere it appears (rule text, citation helper, DKB statute node): the rule was vacated and never took effect; the FTC dismissed its appeals in September 2025 and acceded to vacatur, so the current federal posture is case-by-case FTC Act § 5 enforcement, and the enforceability point rests on state law (e.g., Cal. Bus. & Prof. Code § 16600).
- Bring the non-compete state overlay current through the 2025 legislative wave: Florida's CHOICE Act (effective July 2025 — the pro-enforcement outlier, permitting up to 4-year covenants for high earners), Wyoming SF 107 and Virginia's SB 1218 expansion (both effective July 1, 2025), and Arkansas's healthcare-worker ban (effective August 3, 2025).
- Fix `FIN-009`: never annualize a rate whose period is unstated; recognize one-time late-fee phrasing as a distinct, lower-severity drafting note; add the flat-fee regression test; sweep other numeric rules for the same assume-the-worst-unit pattern.
- Add citation-currency metadata discipline: every DKB statute node carries `retrieved_at`; findings citing nodes older than a configured horizon render a "verify currency as of <date>" label; extend the existing `dkb-staleness-ack.yml` gate to fail CI on unacknowledged stale nodes.
- Scope the headline claims to match reality: state-overlay copy names the three covered topics; the citation claim distinguishes rules with pinned authority from rules resting on drafting-practice rationale.

## Impact

- Affected specs: `legal-authority` (new capability spec)
- Affected code: `src/engine/rules/personnel/PERS-001.ts`, `src/engine/rules/v4/employment/_helpers.ts`, DKB statutes source + rebuild, `src/engine/rules/financial/FIN-009.ts` + tests, README + `site/index.html` copy, staleness gate
- Risk: wording changes alter finding text → golden re-baselines; severity of the flat-fee case drops by design.
