import { describe, expect, it } from "vitest";
import { relayPathToBlobUrl, sasUrlToRelayPath } from "../src/azure";
import { isTakeoutUrl } from "../src/takeout";
import { deriveKey, fromBase64Url, open, seal, TICKET_TTL_SECONDS, TicketError, toBase64Url } from "../src/ticket";
import vectors from "./vectors.json";

const { secret, iv, now, payload, expectedTicket } = vectors.ticket;

async function expectTicketError(promise: Promise<unknown>, code: string) {
  const error = await promise.then(
    () => null,
    (reason: unknown) => reason,
  );
  expect(error).toBeInstanceOf(TicketError);
  expect((error as TicketError).code).toBe(code);
}

describe("ticket", () => {
  it("seals to the expected vector", async () => {
    expect(await seal(secret, payload, { now, iv: fromBase64Url(iv) })).toBe(expectedTicket);
  });

  it("opens the vector", async () => {
    expect(await open(secret, expectedTicket, now)).toEqual(payload);
  });

  it("round-trips with a random iv", async () => {
    const ticket = await seal(secret, payload);
    expect(ticket).not.toBe(await seal(secret, payload));
    expect(await open(secret, ticket)).toEqual(payload);
  });

  it("rejects the wrong secret", async () => {
    await expectTicketError(open(toBase64Url(new Uint8Array(32)), expectedTicket, now), "invalid");
  });

  it("rejects a tampered body and a tampered iv", async () => {
    const body = fromBase64Url(expectedTicket);
    body[body.length - 1] ^= 1;
    await expectTicketError(open(secret, toBase64Url(body), now), "invalid");
    const header = fromBase64Url(expectedTicket);
    header[0] ^= 1;
    await expectTicketError(open(secret, toBase64Url(header), now), "invalid");
  });

  it.each([0, 5, 12, 20])("rejects a ticket truncated to %i bytes", async (length) => {
    const truncated = toBase64Url(fromBase64Url(expectedTicket).slice(0, length));
    await expectTicketError(open(secret, truncated, now), "invalid");
  });

  it.each(["", "!!!", "a b", "not+base64/url="])("rejects non-base64url input %j", async (ticket) => {
    await expectTicketError(open(secret, ticket, now), "invalid");
  });

  it("expires at exp", async () => {
    const exp = now + TICKET_TTL_SECONDS;
    expect(await open(secret, expectedTicket, exp - 1)).toEqual(payload);
    await expectTicketError(open(secret, expectedTicket, exp), "expired");
    await expectTicketError(open(secret, expectedTicket, exp + 1), "expired");
  });

  it("rejects an authentic ticket whose payload is malformed", async () => {
    const key = await deriveKey(secret);
    const stream = new Blob([JSON.stringify({ u: 1 })]).stream().pipeThrough(new CompressionStream("deflate-raw"));
    const compressed = await new Response(stream).arrayBuffer();
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12) }, key, compressed);
    const ticket = new Uint8Array(12 + encrypted.byteLength);
    ticket.set(new Uint8Array(encrypted), 12);
    await expectTicketError(open(secret, toBase64Url(ticket), now), "invalid");
  });
});

describe("isTakeoutUrl", () => {
  it.each(vectors.takeoutUrls.accept)("accepts %s", (url) => {
    expect(isTakeoutUrl(url)).toBe(true);
  });

  it.each(vectors.takeoutUrls.reject)("rejects %j", (url) => {
    expect(isTakeoutUrl(url)).toBe(false);
  });
});

describe("azure paths", () => {
  it.each(vectors.azurePaths)("maps $relayPath", ({ sasUrl, relayPath }) => {
    expect(sasUrlToRelayPath(sasUrl)).toBe(relayPath);
    const relay = new URL(relayPath, "https://proxy.example");
    expect(relayPathToBlobUrl(relay.pathname, relay.search)?.toString()).toBe(sasUrl);
  });

  it("rejects non-Azure SAS URLs", () => {
    expect(() => sasUrlToRelayPath("https://example.com/c/b?sig=x")).toThrow();
    expect(() => sasUrlToRelayPath("http://acct.blob.core.windows.net/c/b")).toThrow();
    expect(() => sasUrlToRelayPath("https://evil.example/.blob.core.windows.net/c/b")).toThrow();
  });

  it.each(["/azure/", "/azure/acct", "/azure/acct/c", "/azure/acct/c/", "/azure/AB/c/b", "/azure/a.b.c/c/b", "/azure/acct//b", "/other/acct/c/b"])("rejects relay path %s", (path) => {
    expect(relayPathToBlobUrl(path, "?sig=x")).toBeNull();
  });
});
