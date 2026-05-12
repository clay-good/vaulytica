import { describe, expect, it } from "vitest";
import { sha256Hex } from "./hash.js";

describe("sha256Hex", () => {
  it("hashes the empty string to the known constant", async () => {
    expect(await sha256Hex("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("hashes 'abc' to the known constant", async () => {
    expect(await sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("matches for ArrayBuffer, Uint8Array, and string of the same bytes", async () => {
    const text = "vaulytica";
    const bytes = new TextEncoder().encode(text);
    const a = await sha256Hex(text);
    const b = await sha256Hex(bytes);
    const c = await sha256Hex(bytes.buffer.slice(0));
    expect(a).toEqual(b);
    expect(a).toEqual(c);
  });
});
