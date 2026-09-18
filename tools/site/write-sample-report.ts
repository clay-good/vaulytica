/** Build step: write `dist/sample-report.html` (see `sample-report.ts`). */
import { resolve } from "node:path";
import { writeSampleReport } from "./sample-report.js";

writeSampleReport(process.cwd(), resolve("dist", "sample-report.html"));
console.log("Wrote dist/sample-report.html");
