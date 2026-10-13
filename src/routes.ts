import { relayPathToBlobUrl } from "./azure";
import { errorResponse, filterHeaders } from "./http";
import { isTakeoutUrl } from "./takeout";
import { open, TicketError, type TicketPayload } from "./ticket";

export const VERSION = "3.0.0";
export const TICKET_PREFIX = "/t/";

const MAX_TAKEOUT_REDIRECTS = 5;
const TAKEOUT_RESPONSE_HEADERS = new Set(["content-type", "content-length", "content-range", "content-disposition", "accept-ranges", "etag", "last-modified"]);
const AZURE_RESPONSE_HEADERS = new Set(["content-type", "content-length", "content-range", "content-encoding", "content-md5", "content-language", "etag", "last-modified", "date"]);

export function health(): Response {
  return Response.json({ version: VERSION });
}

function takeoutRequestHeaders(request: Request, payload: TicketPayload): Headers {
  const headers = new Headers({ Cookie: payload.c });
  const range = request.headers.get("range");
  if (range) {
    headers.set("Range", range);
  }
  return headers;
}

function redirectTarget(response: Response, from: string): string | null {
  const location = response.headers.get("location");
  if (response.status < 300 || response.status >= 400 || !location) {
    return null;
  }
  try {
    return new URL(location, from).toString();
  } catch {
    return null;
  }
}

// Redirects are followed by hand so a 3xx can never carry the cookie to a non-Takeout host.
async function fetchTakeout(url: string, headers: Headers): Promise<Response | null> {
  let target = url;
  for (let hops = 0; hops <= MAX_TAKEOUT_REDIRECTS; hops++) {
    const response = await fetch(target, { method: "GET", headers, redirect: "manual" });
    if (response.status < 300 || response.status >= 400) {
      return response;
    }
    await response.body?.cancel();
    const next = redirectTarget(response, target);
    if (!next || !isTakeoutUrl(next)) {
      return null;
    }
    target = next;
  }
  return null;
}

async function openTicket(secret: string, ticket: string): Promise<TicketPayload | Response> {
  try {
    const payload = await open(secret, ticket);
    if (!isTakeoutUrl(payload.u)) {
      return errorResponse(403, "forbidden_url", "The ticket does not point at a Google Takeout download.");
    }
    return payload;
  } catch (error) {
    if (error instanceof TicketError && error.code === "expired") {
      return errorResponse(410, "ticket_expired", "The ticket has expired. Start the download again.");
    }
    return errorResponse(403, "invalid_ticket", "The ticket could not be verified.");
  }
}

export async function takeout(request: Request, env: Env, url: URL): Promise<Response> {
  const payload = await openTicket(env.GTR_SECRET, url.pathname.slice(TICKET_PREFIX.length));
  if (payload instanceof Response) {
    return payload;
  }
  let upstream: Response | null;
  try {
    upstream = await fetchTakeout(payload.u, takeoutRequestHeaders(request, payload));
  } catch {
    return errorResponse(502, "upstream_unreachable", "Google Takeout could not be reached.");
  }
  if (!upstream) {
    return errorResponse(502, "upstream_redirect", "Google Takeout redirected to an unexpected location.");
  }
  if (request.method === "HEAD") {
    await upstream.body?.cancel();
    return new Response(null, { status: upstream.status, headers: filterHeaders(upstream.headers, (name) => TAKEOUT_RESPONSE_HEADERS.has(name)) });
  }
  return new Response(upstream.body, { status: upstream.status, headers: filterHeaders(upstream.headers, (name) => TAKEOUT_RESPONSE_HEADERS.has(name)) });
}

function azureRequestHeaders(request: Request): Headers {
  return filterHeaders(request.headers, (name) => name.startsWith("x-ms-") || name === "content-length" || name === "content-type");
}

function isAzureResponseHeader(name: string): boolean {
  return name.startsWith("x-ms-") || AZURE_RESPONSE_HEADERS.has(name);
}

export async function azure(request: Request, _env: Env, url: URL): Promise<Response> {
  const blobUrl = relayPathToBlobUrl(url.pathname, url.search);
  if (!blobUrl) {
    return errorResponse(400, "invalid_path", "Expected /azure/<account>/<container>/<blob>.");
  }
  let upstream: Response;
  try {
    upstream = await fetch(blobUrl, { method: request.method, headers: azureRequestHeaders(request), body: request.body, redirect: "manual" });
  } catch {
    return errorResponse(502, "upstream_unreachable", "Azure Blob Storage could not be reached.");
  }
  return new Response(upstream.body, { status: upstream.status, headers: filterHeaders(upstream.headers, isAzureResponseHeader) });
}
