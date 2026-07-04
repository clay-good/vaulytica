# Tasks

- [ ] 1. Build the offset→document.xml anchor mapper as a pure function; property-test the round-trip (commented span text == finding excerpt text) over the fixture corpus.
- [ ] 2. Implement `src/report/docx-comments.ts`: deterministic container rewrite (comments part, anchors, rels, content types; fixed dates; stable zip entry order).
- [ ] 3. Unanchorable-findings aggregation comment + count invariant test.
- [ ] 4. Invariant tests: body byte-parity, determinism, no `w:ins`/`w:del` ever, masked HANDOFF values, tracked-changes fixture round-trip.
- [ ] 5. Tab wiring: "Reviewed copy (.docx)" download card, enabled only for DOCX uploads; disabled-state explains why for PDF/paste.
- [ ] 6. CLI wiring: `--format docx-comments` writes `<name>.reviewed.docx`; stream contract respected (binary to file via `--out`, never stdout).
- [ ] 7. Open the output in Word/LibreOffice manually once per OS family; screenshot into docs.
- [ ] 8. README + site copy: "findings as Word comments in your own draft — never a generated redline."
- [ ] 9. Full gate green.
