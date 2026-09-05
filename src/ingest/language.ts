import { flattenText, type DocumentTree } from "./types.js";

/**
 * A language screen for ingested text.
 *
 * Every rule, extractor, and playbook in this engine is written against
 * English legal prose. Handed a Spanish or German contract, the engine does
 * not fail — it simply matches almost nothing and returns a short, quiet
 * findings list that reads exactly like a clean document. A translated NDA
 * measured 3 findings against the English original's 23, with no warning of
 * any kind. That silent near-empty result is the failure this module exists
 * to make loud.
 *
 * The question asked here is deliberately binary and narrow: *can the English
 * rule corpus read this document?* It is not general language identification.
 * When the answer is no, a best-effort name for the language is offered
 * because "this looks like Spanish" is more actionable than "this is not
 * English" — but naming is a courtesy, and an unrecognized language still
 * gets the warning.
 *
 * The method is function-word density. Function words are the highest-
 * frequency, most style-independent tokens in any language, so their share of
 * a sample separates languages far more reliably than content vocabulary,
 * which in legal prose is full of Latin and shared proper nouns. Scoring is a
 * pure count over a bounded prefix of the text: deterministic, allocation-
 * light, and independent of document length.
 */

/**
 * Words scored per document. Language does not change partway through a
 * contract, so a bounded prefix answers the question as well as the whole
 * document does and keeps the screen O(1) in document size. Large enough that
 * a long English title page cannot dominate the sample.
 */
const SAMPLE_WORDS = 2000;

/**
 * Below this share of function words, the sample is not English prose. Set
 * from the measured distribution over the 312-specimen corpus, whose minimum
 * is far above it — see `language.test.ts`, which pins the whole corpus as
 * English so a future tightening of this constant cannot silently start
 * warning on real documents.
 */
const ENGLISH_FLOOR = 0.12;

/**
 * A named language must both clear this share and beat English to be named.
 * A document can be non-English without any candidate clearing it (a language
 * not in the table, or a non-Latin script that does not tokenize into these
 * words at all) — that document still gets the warning, just without a name.
 */
const NAMED_FLOOR = 0.12;

/**
 * Function words by language. These are closed-class words — articles,
 * prepositions, conjunctions, auxiliaries, pronouns — not legal vocabulary.
 * Overlap between the Romance sets is expected and harmless: the winner is
 * the argmax, and a tie names nothing.
 */
const FUNCTION_WORDS: ReadonlyArray<
  readonly [code: string, name: string, words: readonly string[]]
> = [
  [
    "en",
    "English",
    // prettier-ignore
    ["the","of","and","to","in","that","is","be","for","with","as","by","or","this","not",
       "any","on","at","from","which","such","will","are","has","have","it","if","an","all",
       "may","no","other","than","upon","its","been","were","was","but","into","under","shall"],
  ],
  [
    "es",
    "Spanish",
    // prettier-ignore
    ["de","la","que","el","en","y","los","del","se","las","por","un","para","con","no","una",
       "su","al","es","lo","como","más","o","pero","sus","le","ha","esta","entre","cuando",
       "muy","sin","sobre","también","hasta","este","son","ser","cualquier"],
  ],
  [
    "fr",
    "French",
    // prettier-ignore
    ["de","la","le","et","les","des","en","un","du","une","que","est","pour","qui","dans",
       "par","sur","au","ne","pas","se","plus","ou","aux","avec","son","sont","cette","ses",
       "être","comme","tout","entre","leur","ont","toute","sans"],
  ],
  [
    "de",
    "German",
    // prettier-ignore
    ["der","die","und","den","von","zu","das","mit","sich","des","auf","für","ist","im","dem",
       "nicht","ein","eine","als","auch","an","werden","aus","hat","dass","sie","nach","bei",
       "oder","um","sind","wie","einem","über","einen","zum","haben","nur","durch","wird"],
  ],
  [
    "it",
    "Italian",
    // prettier-ignore
    ["di","il","la","che","in","un","per","non","una","del","con","da","le","si","dei","come",
       "più","sono","al","della","nel","alla","o","ma","se","gli","delle","anche","alle","dal",
       "essere","sulla","nella","questo"],
  ],
  [
    "pt",
    "Portuguese",
    // prettier-ignore
    ["de","que","do","da","em","um","para","com","não","uma","os","no","se","na","por","mais",
       "as","dos","como","ao","das","seu","sua","ou","quando","nos","também","pelo","pela",
       "ser","são","este","qualquer","sobre","entre"],
  ],
  [
    "nl",
    "Dutch",
    // prettier-ignore
    ["de","van","het","een","en","in","is","dat","op","te","met","voor","zijn","er","maar",
       "om","aan","of","als","uit","bij","ook","tot","door","over","dan","deze","niet","worden",
       "wordt","aan","heeft","zal","bepaling"],
  ],
];

export type LanguageScreen = {
  /**
   * ISO 639-1 code for the language the sample scores as, or `undefined` when
   * no candidate clears its floor. `"en"` means the engine's rules apply.
   */
  code?: string;
  /**
   * A warning to surface to the reader, or `null` when the document reads as
   * English and every rule therefore applies as written.
   */
  notice: string | null;
};

const WORD = /[\p{L}\p{M}']+/gu;

/** Lowercased words from the head of `text`, capped at {@link SAMPLE_WORDS}. */
function sampleWords(text: string): string[] {
  const words: string[] = [];
  WORD.lastIndex = 0;
  for (let m = WORD.exec(text); m !== null; m = WORD.exec(text)) {
    words.push(m[0].toLowerCase());
    if (words.length === SAMPLE_WORDS) break;
  }
  return words;
}

/**
 * Screen `text` for the language the engine can read.
 *
 * A sample too short to score (fewer than 30 words — a caption, a stub, an
 * empty paste) returns no code and no notice: there is not enough evidence to
 * accuse a document of being foreign, and a false warning on a one-line
 * document is worse than a missing one.
 */
export function screenLanguage(text: string): LanguageScreen {
  const words = sampleWords(text);
  if (words.length < 30) return { notice: null };

  const counts = new Map<string, number>();
  for (const w of words) counts.set(w, (counts.get(w) ?? 0) + 1);

  let best: { code: string; name: string; ratio: number } | null = null;
  let tied = false;
  let englishRatio = 0;
  for (const [code, name, list] of FUNCTION_WORDS) {
    let hits = 0;
    for (const w of list) hits += counts.get(w) ?? 0;
    const ratio = hits / words.length;
    if (code === "en") englishRatio = ratio;
    if (best === null || ratio > best.ratio) {
      best = { code, name, ratio };
      tied = false;
    } else if (ratio === best.ratio) {
      tied = true;
    }
  }

  if (englishRatio >= ENGLISH_FLOOR && best !== null && best.code === "en") {
    return { code: "en", notice: null };
  }

  const named =
    best !== null && !tied && best.code !== "en" && best.ratio >= NAMED_FLOOR ? best : null;
  const notice = named
    ? `This document does not read as English — it appears to be ${named.name}. Every rule in this engine is written against English legal prose, so the checks below did not read most of this document. A short findings list here means the text could not be analyzed, NOT that the document is sound.`
    : `This document does not read as English. Every rule in this engine is written against English legal prose, so the checks below did not read most of this document. A short findings list here means the text could not be analyzed, NOT that the document is sound.`;
  return { ...(named ? { code: named.code } : {}), notice };
}

/**
 * Screen a normalized tree and produce the `language` field of an
 * {@link IngestResult}, pushing any notice onto `warnings`.
 *
 * The notice is **unshifted**, not pushed. A reader who is told the engine
 * could not read their document needs that before anything else in the list:
 * it reframes every other warning and the entire findings list below it.
 *
 * An English document adds nothing to `warnings` and sets `language: "en"`,
 * so a run that was clean before this screen existed produces the same
 * warnings it always did.
 */
export function languageFields(tree: DocumentTree, warnings: string[]): { language?: string } {
  const screen = screenLanguage(flattenText(tree));
  if (screen.notice) warnings.unshift(screen.notice);
  return screen.code ? { language: screen.code } : {};
}
