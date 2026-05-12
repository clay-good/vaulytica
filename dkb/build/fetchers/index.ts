/**
 * Registry mapping `ParserId` → concrete fetcher. The build orchestrator
 * (`dkb/build/build.ts`, lands in Step 11) imports this map.
 */

import type { Fetcher, ParserId } from "../types.js";
import { edgarFetcher } from "./edgar.js";
import { uscodeFetcher } from "./uscode.js";
import { ecfrFetcher } from "./ecfr.js";
import { govinfoFetcher } from "./govinfo.js";
import { commonpaperFetcher } from "./commonpaper.js";
import { cuadFetcher } from "./cuad.js";
import { ledgarFetcher } from "./ledgar.js";
import { ulcFetcher } from "./ulc.js";

export const FETCHERS: Record<ParserId, Fetcher> = {
  edgar: edgarFetcher,
  uscode: uscodeFetcher,
  ecfr: ecfrFetcher,
  govinfo: govinfoFetcher,
  commonpaper: commonpaperFetcher,
  cuad: cuadFetcher,
  ledgar: ledgarFetcher,
  ulc: ulcFetcher,
};

export {
  edgarFetcher,
  uscodeFetcher,
  ecfrFetcher,
  govinfoFetcher,
  commonpaperFetcher,
  cuadFetcher,
  ledgarFetcher,
  ulcFetcher,
};

export { parseEdgarSearchHits } from "./edgar.js";
export { parseUslmXml } from "./uscode.js";
export { parseEcfrXml } from "./ecfr.js";
export { parsePublicLawXml } from "./govinfo.js";
export { parseCommonPaperMarkdown } from "./commonpaper.js";
export { parseCuadRows } from "./cuad.js";
export { parseLedgarRows } from "./ledgar.js";
export { ulcActToStatute, ULC_ACTS } from "./ulc.js";
