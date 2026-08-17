# The express-denial sweep

A `presence` rule reads a document for the words the required clause would use.
A single `present_patterns` match short-circuits it as compliant. So a document
that **affirmatively refuses** the clause — using the very same words — scores
clean, while a document that merely stays **silent** gets flagged.

That is backwards. An express refusal is strictly worse than an omission: the
omission leaves the position arguable, the refusal settles it against you.

An earlier pass added `denied_if` to 27 rules and the class was believed
closed. It was not. This document records the full sweep of the v4 packs, so
nobody has to rediscover which rules were judged and why.

## How to find candidates

```bash
node -e '
const {readdirSync,readFileSync,statSync}=require("fs");const {join}=require("path");
const root="src/engine/rules/v4";
const VERB=/\b(waiv(e|es|ed|er)|releases?|forfeits?|indemnif(y|ies)|assigns?|terminates?|discloses?|consents?|permits?|grants?|reserves?|appoints?|authoriz(e|es))\b/i;
for (const pack of readdirSync(root)) {
  const f=join(root,pack,"rules.ts"); try{statSync(f)}catch{continue}
  for (const b of readFileSync(f,"utf8").split(/\n  (?:presence|language|compound)\(\{/).slice(1)) {
    const id=(/id: "([A-Z]+-\d+)"/.exec(b)||[])[1]; if(!id) continue;
    const body=b.split(/\n  \}\)/)[0];
    if(!/present_patterns:/.test(body)||/denied_if:/.test(body)) continue;
    const pp=(/present_patterns:\s*\[([\s\S]*?)\n    \]/.exec(body)||[])[1]||"";
    if(VERB.test(pp) && !/\(\?<!/.test(pp)) console.log(pack, id);
  }
}'
```

It over-reports. It is a starting list, not a defect list.

## The procedure, per rule

1. Probe the **real** rule through `runEngine` under **its own playbook** (from
   `applies_to_playbooks`). Using the wrong playbook makes the rule
   inapplicable, and inapplicable looks exactly like the bug.
2. Assert on the finding **title**, never "did anything fire".
3. Three cases, always: **DENIAL** must report the denial title, **OMISSION**
   must still report the missing title, **COMPLIANT** must stay silent.
4. It is a bug only when DENIAL is silent while OMISSION fires.
5. Fix with `denied_if` / `denied_title` / `denied_description`, bump the rule
   `version`, regenerate goldens
   (`VAULYTICA_REGEN_GOLDEN=1 npx vitest run tests/golden/ --testTimeout=180000`)
   and confirm the diff is `result_hash`-only.

### `expressDenial()` usually will not reach these

Its frames put the negation on the **topic** ("subrogation shall not be
waived") and it deliberately treats waive/grant as scope verbs that end its
gap. Real drafting negates the **verb** ("shall not waive its rights of
recovery"). Write explicit frames, and include the **reservation** forms, which
deny without negating anything: "reserves all rights of subrogation",
"Nothing in this Assignment creates a power of attorney".

### Always test the compliant case

Three separate times in this sweep a denial pattern accused the compliant
drafting. The sharpest: EST-004's "and no bond **shall be required**" is the
*waiver*, and a pattern looking for "bond … shall be required" matched it,
because the negation sits on the noun rather than the verb.

## Fixed (18)

| Rule | Pack | The refusal that used to read as compliance |
|---|---|---|
| INS-012 | insurance | insurer "shall not waive its rights of recovery" |
| CON-030 | construction | contractor "does not waive any further claims" |
| IPL-005 | ip-licensing | "does not appoint Assignee as attorney-in-fact" |
| BNK-023 | banking | guarantor "does not waive any suretyship defenses" |
| SET-002 | settlement | "does not release any and all claims" |
| IPL-026 | ip-licensing | "grants no copyright license" (CLA) |
| IPL-027 | ip-licensing | "no patent license is granted" (CLA) |
| BNK-006 | banking | maker "does not waive presentment / notice of dishonor" |
| BNK-025 | banking | guarantor keeps subrogation / contribution rights |
| EMP-033 | employment | employee "does not assign any inventions" |
| IPL-012 | ip-licensing | "no grant-back license" |
| EST-004 | trust-estate | will **requires** bond instead of waiving it |
| IPL-037 | ip-licensing | backup assignment refused when work-for-hire fails |
| COMM-036 | commercial | agency "not required to keep information in confidence" |
| RE-003 | real-estate | tenant "not required to carry insurance" (net lease) |
| IPL-028 | ip-licensing | contributor "makes no representation" of originality |
| COMM-035 | commercial | agency does not clear third-party rights |
| COMM-039 | commercial | supplier does not pass through the warranty |

## Judged and deliberately NOT changed

Adding a denial guard to these would manufacture false accusations.

**The required clause is itself a negation, waiver, or prohibition.** Guarding
it inverts the rule: RE-052 (no lease modification without lender consent),
POL-009 (facilitating-payments prohibition recital), SET-014 (reservation of
rights), CON-014 (waiver type label).

**An alternative already satisfies the rule, so the "denial" is a lawful
choice.** EMP-012 (equity "if offered" — no equity offered makes the rule
inapplicable, not violated), RE-057 (release *or* continuing liability),
EST-041 and EST-050 (spousal support waiver *or* terms), COMM-022 (ownership of
deliverables is an allocation either way).

**Structural or informational: no one drafts a denial of it.** Grant dates and
share counts (EQT-019, EQT-029), consent and meeting recitals (GOV-030,
GOV-032, GOV-039, GOV-043, GOV-044, GOV-045, GOV-053, EQT-057), deal mechanics
(MNA-026, MNA-032, MNA-035, MNA-048, MNA-049, MNA-053, SET-022, SET-024),
instrument structure (BNK-032, BNK-041, BNK-050, COMM-008, COMM-034, IPL-024,
POL-003, INS-017, INS-018), and estate recitals (EST-003, EST-012, EST-025,
EST-042, EST-043).

**Already guarded another way.** GOV-008 carries an inline
`(?<!\bno\s)(?<!\bnot\s)` lookbehind rather than a `denied_if`. The candidate
script skips these.

**Checked and not reproducible.** CON-016 stays silent on omission too, because
a bare "release" anywhere satisfies its gate. That is a loose gate — a separate
judgement about what CON-016 should require — not this bug. SET-001's patterns
are noun forms ("releasor", "releasing party") that a denial sentence does not
match.

## What does not work

Do not try to automate the screen by negating each rule's own `recommendation`
text. Recommendations are imperative fragments naming clauses in quotes, so
negation yields gibberish — "Add 'not grant Date' and 'Number of Shares'
lines". A rule staying silent on gibberish says nothing, and the screen
"confirmed" 19 rules on that basis. Generating drafting a lawyer would
recognise is the part that needs a person.
