/**
 * SHA-256 over arbitrary bytes, returning lowercase hex. Uses the standard
 * Web Crypto API, which is available in modern browsers, Node ≥ 19, and
 * the test environment (happy-dom / jsdom / Node).
 */
export async function sha256Hex(bytes: ArrayBuffer | Uint8Array | string): Promise<string> {
  const data =
    typeof bytes === "string"
      ? new TextEncoder().encode(bytes)
      : bytes instanceof Uint8Array
        ? bytes
        : new Uint8Array(bytes);
  // `crypto.subtle.digest` accepts any BufferSource; the TS lib types
  // tightened in v5+ around shared-buffer disambiguation, so we cast
  // through `BufferSource` to keep the cross-environment signature.
  const buf = await crypto.subtle.digest("SHA-256", data as unknown as BufferSource);
  const arr = new Uint8Array(buf);
  let hex = "";
  for (let i = 0; i < arr.length; i += 1) {
    hex += arr[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}
