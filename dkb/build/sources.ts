/**
 * Loader and validator for `dkb/build/sources.yaml`. The schema is
 * intentionally narrow — the build orchestrator is the only consumer
 * and it shouldn't have to second-guess the input.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import * as YAML from "js-yaml";
import type { SourceDeclaration, SourcesFile } from "./types.js";

export const SourceDeclarationSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  url: z.string().url(),
  fetch_method: z.enum(["http", "github-clone", "huggingface-download"]),
  parser: z.enum(["edgar", "uscode", "ecfr", "govinfo", "commonpaper", "cuad", "ledgar", "ulc"]),
  license: z.string().min(1),
  license_url: z.string().url(),
  rate_limit_rps: z.number().positive(),
  user_agent: z.string().min(1),
  notes: z.string().optional(),
});

export const SourcesFileSchema = z.object({
  sources: z.array(SourceDeclarationSchema),
});

export function parseSourcesYaml(text: string): SourcesFile {
  const raw = YAML.load(text);
  return SourcesFileSchema.parse(raw);
}

export async function loadSourcesYaml(path?: string): Promise<SourcesFile> {
  const p = path ?? join(process.cwd(), "dkb", "build", "sources.yaml");
  const text = await readFile(p, "utf8");
  return parseSourcesYaml(text);
}

export function findSource(file: SourcesFile, id: string): SourceDeclaration | undefined {
  return file.sources.find((s) => s.id === id);
}
