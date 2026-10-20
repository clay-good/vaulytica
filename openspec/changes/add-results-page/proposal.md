# add-results-page

## Why

Measured on vaulytica.com at 9.965.0 by pasting a mutual NDA: the result shows "0 critical · 4 warnings · 4 informational," a calendar panel, two coverage sentences, twenty compliance-regime buttons, and sixteen download buttons, 36 buttons in all. Not one finding's title appears on the page. To learn what the four warnings are, the user has to download and open the Word report. Most visitors come to answer one question: **what do I need to raise before I sign this, and why?** Today the page does not answer it.

The answer is short enough to show. On ten specimen contracts (an NDA, an MSA, a SaaS subscription, a DPA, a lease and others) the engine returns 4–17 findings, of which 1–9 carry a recommendation (`isActionable`, spec-v51 §4). Those recommendations already include the suggested wording ("Add: 'Receiving Party shall provide a written certification…'"), so the page can show what to ask for without generating anything new.

## What Changes

The single-document result becomes a page that is read top to bottom, with three levels:

1. **Glance.** A headline and the to-do list.
2. **Click a row.** It opens in place to show why the item is there and what to ask for.
3. **Download.** Only when the user wants a file (see `simplify-result-downloads`). Nothing downloads on its own.

The example below is the real output for the NDA pasted above (`tests/fixtures/specimens/legend-nda.txt`):

```
Mutual NDA — Deep Analysis                         [Why this type?]

6 things to raise before you sign
  Worth raising   Return-or-destruction attestation missing                   ▸
  Worth raising   Waiver-of-bond language missing                             ▸
  Worth raising   Authority / no-conflicting-obligation representation missing ▸
  Worth raising   Successors-and-assigns / consent-to-assignment missing      ▸
      Not in the document: (clause absent from the document)
      Why: Without a consent-to-assignment clause, an acquirer of the
           receiving party could inherit access to Confidential Information…
      Suggested change: Add: 'This Agreement shall bind and inure to the
           benefit of the parties and their successors and permitted assigns…'
      Source: [citation]  ·  NDA-D-023
      [Copy suggested change]  [Not a problem? Tell us]
  Optional        No-precedent / no-MFN clause missing                        ▸
  Optional        No indemnification clause detected                          ▸

Key terms
  Parties          Northgate Instrument Company (Ohio) · Cardinal Metrology, Inc (Delaware)
  Effective date   2026-09-02
  Governing law    Delaware                                            § 12
  Forum            Delaware                                            § 12
  Liability cap    Not found in the text
  Renewal          Not found in the text
  Assignment       Not found in the text

Dates to verify (1)                                                    ▸
Also noted (2)                                                         ▸
What this review covered                                               ▸
Download                                                               ▸
```

- **Headline.** "N things to raise before you sign." N counts the actionable findings plus the delivery items at critical or warning (metadata, tracked changes, and other HANDOFF checks). When N is zero, the headline reuses the existing clean-result line (`LOOP_CLEAN_STATEMENT`): the named checks found nothing to raise, and that does not mean the document is complete, balanced or enforceable.
- **The to-do list.** Items appear in the report's existing order. Severity is shown in plain words: critical is "Fix before signing," warning is "Worth raising," and info is "Optional." Delivery items form a short group, "Before you send this file," above the rest, and open to their description and evidence. An opened finding shows:
  - **The quote, only when there is one.** It is shown in quotation marks with its section heading only when the finding pinned a real span (the existing `hasQuotedExcerpt` test). An absence or pattern finding shows its placeholder (for example, "(clause absent from the document)") under the label "Not in the document," never in quotation marks. None of this NDA's six to-do rows has a quote (its only two quoted findings are observations), so this is the common case.
  - **Why:** the finding's explanation.
  - **Suggested change:** the rule's recommendation, verbatim. It is fixed text from the rule. The page generates nothing and never edits the user's document.
  - **Source:** the citations, as links, and the rule id.
  - **Copy suggested change** copies the recommendation as plain text, followed by a line naming the rule. **Not a problem? Tell us** is the existing per-finding `/report` link (`reportLinkForFinding`).
- **Key terms.** Rows come from the existing abstract (`src/report/abstract.ts`): parties, effective date, governing law, forum, liability cap, renewal and assignment. A section is shown when the abstract has one. A blank reads "Not found in the text" and is never a guess. There is no "standard" column and no score: this block reports what the document says, and the to-do list says what to do about it.
- **Everything else is folded.** "Dates to verify" (the critical-dates register), "Also noted" (findings without a recommendation) and "What this review covered" are collapsed. The covered section holds one line each for the type and playbook, the attorney-review and quoted-evidence sentences, other detected families, jurisdiction overlays and hashes. The twenty regime buttons move into it under "Adjust this review." Three notices stay at the top because they change how far the page can be trusted: the input notice ("Read as plain text…"), a misread type, and a rule that errored.
- **Print.** A print stylesheet opens every row and hides the controls, so the browser's Save as PDF gives a clean copy with no PDF generator.
- **The landing page** replaces the six "What you get back" cards with three: "A page that says what to raise and why," "Your draft back with comments," and "Everything else, if you want it." `/sample-report` is rebuilt at build time from this same renderer, so the sample shows the page a user will actually get.

## Not in this change

Generated contract language or tracked-change redlines. A balance score or "market standard" values. Saving results anywhere: the page lives in the tab and says "This page is not saved. Download to keep a copy." Per-row "handled" checkboxes.

## Impact

- Affected specs: `results-page` (new)
- Affected code: `src/ui/states.ts` (the `complete` template and renderers), a new `src/ui/results-page.ts`, styles, `site/index.html`, `tools/site/sample-report.ts`, and e2e tests
- Hashes: none. The change only affects how results render; it reads the same `EngineRun`, abstract, delivery and critical-dates data the exports already read.
