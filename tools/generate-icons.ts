#!/usr/bin/env tsx
/**
 * Generate PNG icon assets from `site/favicon.svg`. The output is
 * committed under `site/` so production builds don't need a runtime
 * SVG rasterizer.
 *
 *   npm run icons
 *
 * The maskable variant keeps the artwork inside the central 80% of the
 * canvas — 410x410 inset by 51px on a 512x512 ground, i.e. 10% padding
 * per side. That is the maskable-icon safe zone: a circle whose diameter
 * is 80% of the icon, which is what a launcher may crop to.
 *
 * `apple-touch-icon.png` is 180x180 and deliberately opaque: iOS renders
 * an alpha channel as black, and it applies its own rounded-rect mask, so
 * the artwork is composited on the theme background with only a small
 * margin rather than the maskable safe area.
 */

import sharp from "sharp";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const SITE = join(process.cwd(), "site");

async function main(): Promise<void> {
  const svg = await readFile(join(SITE, "favicon.svg"));

  await sharp(svg).resize(192, 192).png().toFile(join(SITE, "icon-192.png"));
  await sharp(svg).resize(512, 512).png().toFile(join(SITE, "icon-512.png"));

  // Maskable: rasterize at 80% of the canvas, dark background fill.
  const maskable = await sharp({
    create: {
      width: 512,
      height: 512,
      channels: 4,
      background: { r: 14, g: 17, b: 25, alpha: 1 },
    },
  })
    .composite([
      {
        input: await sharp(svg).resize(410, 410).png().toBuffer(),
        top: 51,
        left: 51,
      },
    ])
    .png()
    .toBuffer();
  await writeFile(join(SITE, "icon-maskable-512.png"), maskable);

  // Apple touch icon: opaque, 180x180, artwork at ~84% of the canvas.
  const appleTouch = await sharp({
    create: {
      width: 180,
      height: 180,
      channels: 4,
      background: { r: 14, g: 17, b: 25, alpha: 1 },
    },
  })
    .composite([
      {
        input: await sharp(svg).resize(152, 152).png().toBuffer(),
        top: 14,
        left: 14,
      },
    ])
    .png()
    .toBuffer();
  await writeFile(join(SITE, "apple-touch-icon.png"), appleTouch);

  process.stdout.write("icons regenerated\n");
}

void main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exit(1);
});
