export interface TicketPayload {
  u: string;
  c: string;
}

export type TicketErrorCode = "invalid" | "expired";

export class TicketError extends Error {
  constructor(readonly code: TicketErrorCode) {
    super(code);
  }
}

export const TICKET_TTL_SECONDS = 6 * 60 * 60;

const IV_BYTES = 12;
const HKDF_SALT = "gtr-proxy";
const HKDF_INFO = "ticket v1";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function fromBase64Url(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new TicketError("invalid");
  }
  const binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export async function deriveKey(secret: string): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: encoder.encode(HKDF_SALT), info: encoder.encode(HKDF_INFO) }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function transform(bytes: Uint8Array, stream: CompressionStream | DecompressionStream): Promise<Uint8Array> {
  const output = new Response(new Response(bytes).body!.pipeThrough(stream));
  return new Uint8Array(await output.arrayBuffer());
}

export interface SealOptions {
  now?: number;
  iv?: Uint8Array;
}

export async function seal(secret: string, payload: TicketPayload, options: SealOptions = {}): Promise<string> {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const iv = options.iv ?? crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const json = JSON.stringify({ u: payload.u, c: payload.c, exp: now + TICKET_TTL_SECONDS });
  const compressed = await transform(encoder.encode(json), new CompressionStream("deflate-raw"));
  const key = await deriveKey(secret);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, compressed);
  const ticket = new Uint8Array(IV_BYTES + encrypted.byteLength);
  ticket.set(iv);
  ticket.set(new Uint8Array(encrypted), IV_BYTES);
  return toBase64Url(ticket);
}

async function decrypt(secret: string, ticket: string): Promise<Uint8Array> {
  const bytes = fromBase64Url(ticket);
  if (bytes.length <= IV_BYTES) {
    throw new TicketError("invalid");
  }
  const key = await deriveKey(secret);
  const compressed = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, IV_BYTES) }, key, bytes.slice(IV_BYTES));
  return transform(new Uint8Array(compressed), new DecompressionStream("deflate-raw"));
}

function parsePayload(json: string): TicketPayload & { exp: number } {
  const value: unknown = JSON.parse(json);
  if (typeof value !== "object" || value === null) {
    throw new TicketError("invalid");
  }
  const { u, c, exp } = value as Record<string, unknown>;
  if (typeof u !== "string" || typeof c !== "string" || typeof exp !== "number") {
    throw new TicketError("invalid");
  }
  return { u, c, exp };
}

export async function open(secret: string, ticket: string, now = Math.floor(Date.now() / 1000)): Promise<TicketPayload> {
  let payload: TicketPayload & { exp: number };
  try {
    payload = parsePayload(decoder.decode(await decrypt(secret, ticket)));
  } catch {
    throw new TicketError("invalid");
  }
  if (payload.exp <= now) {
    throw new TicketError("expired");
  }
  return { u: payload.u, c: payload.c };
}
