# add-court-certification-receipt

## Why

Court directives on generative-AI use in filings now number 300+ per the Ropes & Gray AI Court Order Tracker (the stricter Legal AI Governance tracker counts ~113 orders that bind attorney filings — 73 requiring disclosure, 86 verification — and 2026 brought the first system-wide rules, e.g. New York's 22 NYCRR Part 161, effective June 1, 2026), requiring filers to disclose AI use, verify AI output, or certify neither occurred. 2026 privilege rulings diverge on consumer-AI use — *United States v. Heppner* (S.D.N.Y. Feb. 2026) held materials run through a public generative-AI tool protected by neither privilege nor work product, while *Warner v. Gilbarco* (E.D. Mich. Feb. 2026) found no waiver — and ABA Formal Opinion 512 pushes the same direction. Vaulytica is one of the few review tools that can make the certification *provable*: deterministic rule engine, no AI, no server, hash-fingerprinted output. Today that story lives in the README; nothing an attorney can attach to a filing or a client file states it. One page turns the product's core posture into a compliance artifact no LLM-based competitor can copy.

## What Changes

- New export: "Verification certificate" — a one-page DOCX/PDF + JSON companion generated with any report, stating: the tool and engine version; the DKB version; the input file's SHA-256 and name; the `result_hash`; that the analysis is a deterministic rule evaluation involving no generative-AI, machine-learning, or probabilistic component and no network transmission; and the exact reproduction command (`vaulytica verify <report> <file>`).
- The certificate is factual and self-limiting: it certifies what the tool did, never the filer's overall compliance; it carries the standing disclaimer and states the attorney remains responsible for verification (mirroring Op. 512's competence/supervision duties).
- The JSON companion carries its own namespaced `certificate_hash` so the certificate itself is tamper-evident and re-derivable.
- The site gains a short "For court and ethics compliance" section explaining the standing-order landscape and how the certificate + `verify` fit it.

## Impact

- Affected specs: `report-exports`
- Affected code: new `src/report/certificate.ts`, export wiring (tab + CLI `--certificate`), site copy section; tests for content, determinism, and hash namespacing
- Risk: wording must not overclaim ("no AI was used *by this tool*" — not "in this filing"); legal-review pass on the template text before ship.
