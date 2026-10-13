export async function decodeState(encodedCookies: string): Promise<string> {
  const binaryString = atob(encodedCookies);
  const bytes = Uint8Array.from(binaryString, (c) => c.charCodeAt(0));
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Response(stream).text();
}
