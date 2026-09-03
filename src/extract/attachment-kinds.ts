/**
 * What a contract calls the thing it staples to the back.
 *
 * An American agreement attaches an Exhibit, an English one a Schedule, an EU
 * instrument an Annex, and Indian and South African drafting an Annexure. They
 * are the same object under six names, and every part of this engine that
 * reconciles "referenced" against "present" — the cross-reference extractor,
 * STRUCT-007, STRUCT-018, and the four subordinate-document recitals in
 * `rules/_helpers.ts` — has to know all six or it reports an attachment as
 * missing because of the noun in front of the letter.
 *
 * Six lists had drifted to five different answers. This is the one, and the
 * guard in `tests/integration/attachment-kinds.test.ts` keeps it that way.
 *
 * Regex SOURCE, not a `RegExp`: the callers embed it in larger patterns with
 * their own anchors, flags and capture groups.
 */
// SINGULAR only. A caller that lowercases the matched kind to build a key —
// STRUCT-018 reconciles "appendix:a" against "appendix:a" — would read
// "Appendices" as a SEVENTH kind and report the attachment it just found as
// missing. Plurals live in {@link ATTACHMENT_KIND_PLURAL}, for the callers that
// read a reference rather than a key.
export const ATTACHMENT_KIND = "Exhibit|Schedule|Annexure|Annex|Appendix|Attachment|Addendum";

/**
 * The same set with the plurals a reference actually uses. "Schedules 1 and 2",
 * "the Annexes hereto" — a singular-only list reads the first designator and
 * nothing else.
 */
export const ATTACHMENT_KIND_PLURAL =
  "Exhibits|Exhibit|Schedules|Schedule|Annexures|Annexure|Annexes|Annex|Appendices|Appendix|Attachments|Attachment|Addenda|Addendum";
