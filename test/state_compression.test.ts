import { describe, expect, it } from "vitest";
import { decodeState } from "../src/state_compression";

async function gzipBase64(text: string): Promise<string> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
  return btoa(String.fromCharCode(...bytes));
}

describe("State Compression", () => {
  it("test encoded cookies can be decoded by decodeState", async () => {
    const cookies = "A=123; B=456";
    expect(await decodeState(await gzipBase64(cookies))).toBe(cookies);
  });
});
