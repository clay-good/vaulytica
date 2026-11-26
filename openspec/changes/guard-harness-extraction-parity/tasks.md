# guard-harness-extraction-parity — tasks

- [x] 1. Enumerate the harnesses whose output is committed, compared, or rendered — measured, not
      guessed. *(5 REGEN-gated files + their pipelines; the render class from the builder names.)*
- [x] 2. Wire the four committed-output harnesses. *(Inert: 820 golden tests passed unchanged. Real
      divergence, latent consequence — recorded as such.)*
- [x] 3. Wire the render class. *(8 sites across 6 files; also inert. The honest result.)*
- [x] 4. 🥇 Fix the live one. *(`extraction-format-invariance` asserted `jurisdiction_id` survives a
      format transform while every value in the projection was `""`. Invariance holds once wired,
      so a dead assertion, not a behavioural bug. Added a `resolvedIds` floor so the vacuity is
      detectable; proved it reports 0 and names itself.)*
- [x] 5. One shared scanner in `_extract-all-sites.ts`; refactor the product guard onto it.
      *(Skips a string literal so it can read itself, a comment, the declaration, and a member call
      — but NOT a spread, which the member-call rule had been swallowing.)*
- [x] 6. Harness sweep with the three reasons, plus three vacuity assertions.
- [x] 7. Prove every reason bites. *(🚨 Found a hole: the REGEN gate is in `golden.test.ts` while
      the extraction is in `_pipeline.ts`, so unwiring the helper left the sweep GREEN. The reason
      now propagates one level through local imports, and all three golden helpers were re-proved.
      The sweep also caught `critical-dates-no-wallclock.test.ts`, which my hand survey missed.)*
- [ ] 8. Full gate, then push and confirm the deploy.
