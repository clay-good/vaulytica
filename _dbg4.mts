import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { analyzeText } from "./tools/cli/api.js";
import { loadAccuracyDeps } from "./tools/accuracy/pipeline.js";
function hardWrap(text: string, width = 62): string {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (line.trim().length === 0) { out.push(""); continue; }
    let rest = line.trim();
    while (rest.length > width) {
      const slice = rest.slice(0, width + 1);
      const cut = Math.max(slice.lastIndexOf(" "), slice.lastIndexOf("-"));
      if (cut <= 0) break;
      out.push(rest.slice(0, cut + (slice[cut] === "-" ? 1 : 0)).trimEnd());
      rest = rest.slice(cut + 1).trimStart();
    }
    out.push(rest);
  }
  return out.join("\n");
}
const mutate = (t: string): string => {
  const lines = hardWrap(t).split("\n");
  const pages = Math.ceil(lines.length / 45);
  const out: string[] = [];
  for (let i = 0; i < lines.length; i += 1) { out.push(lines[i]!); if ((i + 1) % 45 === 0) out.push("", `Page ${Math.ceil((i + 1) / 45)} of ${pages}`, ""); }
  return out.join("\n");
};
const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const deps = await loadAccuracyDeps({});
const broken: string[] = [];
for (const name of readdirSync(DIR).filter((f) => f.endsWith(".txt"))) {
  const text = readFileSync(join(DIR, name), "utf8");
  const m = mutate(text); if (m === text) continue;
  const before = await analyzeText(text, name, { deps });
  const after = await analyzeText(m, name, { deps });
  const ids = (r: typeof before) => [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
  const lost = ids(before).filter((id) => !ids(after).includes(id));
  const gained = ids(after).filter((id) => !ids(before).includes(id));
  if (lost.length || gained.length) broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
}
console.log(broken.join("\n")); console.log(`${broken.length} diverged`);
