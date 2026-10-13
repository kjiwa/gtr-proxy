import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { seal, TICKET_TTL_SECONDS } from "../src/ticket";
import vectors from "./vectors.json";

const SECRET = env.GTR_SECRET;
const TAKEOUT_URL = vectors.takeoutUrls.accept[0]!;
const ORIGIN = "https://proxy.example";
const BEARER = { Authorization: `Bearer ${SECRET}` };
const AZURE_PATH = "/azure/gtrtest/takeouts/dir/a%2Fb.bin?comp=block&blockid=YQ%3D%3D&sig=x%2By%3D";

const fetchSpy = vi.spyOn(globalThis, "fetch");

afterEach(() => {
  fetchSpy.mockReset();
});

function call(path: string, init: RequestInit = {}) {
  return exports.default.fetch(new Request(ORIGIN + path, init));
}

function stubUpstream(response: () => Response) {
  fetchSpy.mockImplementation(async () => response());
}

function upstreamCall(index = 0) {
  const [input, init] = fetchSpy.mock.calls[index]!;
  return { url: String(input), init: init as RequestInit, headers: new Headers(init?.headers) };
}

async function json(response: Response) {
  return (await response.json()) as { error?: string; message?: string; version?: string };
}

async function ticketFor(url: string, options: { now?: number; cookie?: string } = {}) {
  return seal(SECRET, { u: url, c: options.cookie ?? "SID=abc" }, options.now === undefined ? {} : { now: options.now });
}

describe("routing", () => {
  it.each(["/", "/nope", "/t", "/t/", "/azure", "/health/x", "/p/x"])("404s %s without redirecting", async (path) => {
    const response = await call(path);
    expect(response.status).toBe(404);
    expect(response.headers.get("location")).toBeNull();
    expect((await json(response)).error).toBe("not_found");
  });

  it.each([
    ["/health", "POST", "GET", BEARER],
    ["/t/abc", "POST", "GET, HEAD", {}],
    ["/azure/gtrtest/c/b", "GET", "PUT", BEARER],
  ])("405s %s %s with Allow", async (path, method, allow, headers) => {
    const response = await call(path, { method, headers });
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe(allow);
    expect((await json(response)).error).toBe("method_not_allowed");
  });

  it("returns 503 on every route when the secret is missing", async () => {
    const unset = { ...env, GTR_SECRET: "" };
    for (const path of ["/health", "/t/abc", "/azure/a/b/c", "/nope"]) {
      const response = await worker.fetch(new Request(ORIGIN + path, { headers: BEARER }), unset);
      expect(response.status).toBe(503);
      expect((await json(response)).error).toBe("not_configured");
    }
  });
});

describe("/health", () => {
  it("returns the version with a valid bearer", async () => {
    const response = await call("/health", { headers: BEARER });
    expect(response.status).toBe(200);
    expect(await json(response)).toEqual({ version: "3.0.0" });
  });

  it.each([
    ["no header", {}],
    ["wrong secret", { Authorization: "Bearer wrong" }],
    ["empty bearer", { Authorization: "Bearer " }],
    ["wrong scheme", { Authorization: `Basic ${SECRET}` }],
    ["bare secret", { Authorization: SECRET }],
  ])("401s with %s", async (_label, headers) => {
    const response = await call("/health", { headers });
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe("Bearer");
    expect((await json(response)).error).toBe("unauthorized");
  });
});

describe("/t/<ticket>", () => {
  it("fetches Takeout with only the cookie and Range, and strips response headers", async () => {
    stubUpstream(
      () =>
        new Response("0123456789", {
          status: 206,
          headers: {
            "content-type": "application/zip",
            "content-length": "10",
            "content-range": "bytes 0-9/100",
            "content-disposition": 'attachment; filename="a.zip"',
            "accept-ranges": "bytes",
            etag: '"e"',
            "last-modified": "Wed, 01 Jan 2026 00:00:00 GMT",
            "set-cookie": "NID=secret; Path=/",
            "x-guploader-uploadid": "id",
            server: "UploadServer",
          },
        }),
    );
    const ticket = await ticketFor(TAKEOUT_URL, { cookie: "SID=abc; HSID=def" });
    const response = await call(`/t/${ticket}`, {
      headers: { Range: "bytes=0-9", Authorization: "Bearer leak", "X-Forwarded-For": "1.2.3.4", "User-Agent": "x", Cookie: "browser=1" },
    });
    expect(response.status).toBe(206);
    expect(await response.text()).toBe("0123456789");
    expect([...response.headers.keys()].sort()).toEqual(["accept-ranges", "content-disposition", "content-length", "content-range", "content-type", "etag", "last-modified"].sort());
    const upstream = upstreamCall();
    expect(upstream.url).toBe(TAKEOUT_URL);
    expect(upstream.init.method).toBe("GET");
    expect(upstream.init.redirect).toBe("manual");
    expect([...upstream.headers.keys()].sort()).toEqual(["cookie", "range"]);
    expect(upstream.headers.get("cookie")).toBe("SID=abc; HSID=def");
    expect(upstream.headers.get("range")).toBe("bytes=0-9");
  });

  it("sends no Range when the client sent none", async () => {
    stubUpstream(() => new Response("x"));
    await call(`/t/${await ticketFor(TAKEOUT_URL)}`);
    expect([...upstreamCall().headers.keys()]).toEqual(["cookie"]);
  });

  it("does not read the body on HEAD", async () => {
    const cancel = vi.fn();
    const body = new ReadableStream({ pull: (controller) => controller.enqueue(new Uint8Array(4)), cancel });
    stubUpstream(() => new Response(body, { headers: { "content-length": "999", "content-type": "application/zip" } }));
    const response = await call(`/t/${await ticketFor(TAKEOUT_URL)}`, { method: "HEAD" });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-length")).toBe("999");
    expect(await response.text()).toBe("");
    expect(cancel).toHaveBeenCalled();
    expect(upstreamCall().init.method).toBe("GET");
  });

  it("passes through upstream error statuses", async () => {
    stubUpstream(() => new Response("denied", { status: 401, headers: { "www-authenticate": "x" } }));
    const response = await call(`/t/${await ticketFor(TAKEOUT_URL)}`);
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBeNull();
  });

  it("403s on a bogus, tampered or wrong-secret ticket without fetching", async () => {
    const good = await ticketFor(TAKEOUT_URL);
    const wrongSecret = await seal("another-secret", { u: TAKEOUT_URL, c: "SID=abc" });
    for (const ticket of ["bogus", good.slice(0, -2) + "AA", good.slice(0, 10), wrongSecret]) {
      const response = await call(`/t/${ticket}`);
      expect(response.status).toBe(403);
      expect((await json(response)).error).toBe("invalid_ticket");
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("410s on an expired ticket", async () => {
    const now = Math.floor(Date.now() / 1000) - TICKET_TTL_SECONDS - 1;
    const response = await call(`/t/${await ticketFor(TAKEOUT_URL, { now })}`);
    expect(response.status).toBe(410);
    expect((await json(response)).error).toBe("ticket_expired");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each(["https://example.com/takeout/download", "http://takeout.google.com/takeout/download", "https://evilapidata.googleusercontent.com/download/storage/v1/b/takeout/o/a"])("403s when the ticket targets %s", async (url) => {
    const response = await call(`/t/${await ticketFor(url)}`);
    expect(response.status).toBe(403);
    expect((await json(response)).error).toBe("forbidden_url");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("follows a redirect to another Takeout host", async () => {
    const next = "https://takeout-download.usercontent.google.com/download/a.zip";
    fetchSpy.mockImplementationOnce(async () => new Response(null, { status: 302, headers: { location: next } }));
    fetchSpy.mockImplementationOnce(async () => new Response("ok"));
    const response = await call(`/t/${await ticketFor(TAKEOUT_URL)}`);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("ok");
    expect(upstreamCall(1).url).toBe(next);
  });

  it("502s on a redirect to a non-Takeout host without following it", async () => {
    stubUpstream(() => new Response(null, { status: 302, headers: { location: "https://evil.example/x" } }));
    const response = await call(`/t/${await ticketFor(TAKEOUT_URL)}`);
    expect(response.status).toBe(502);
    expect((await json(response)).error).toBe("upstream_redirect");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("502s when the upstream fetch throws", async () => {
    fetchSpy.mockRejectedValue(new TypeError("network"));
    const response = await call(`/t/${await ticketFor(TAKEOUT_URL)}`);
    expect(response.status).toBe(502);
    expect((await json(response)).error).toBe("upstream_unreachable");
  });
});

describe("/azure/*", () => {
  it("401s without a valid bearer and does not fetch", async () => {
    for (const headers of [{}, { Authorization: "Bearer wrong" }] as Record<string, string>[]) {
      const response = await call(AZURE_PATH, { method: "PUT", headers });
      expect(response.status).toBe(401);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("400s on a malformed relay path", async () => {
    for (const path of ["/azure/", "/azure/gtrtest", "/azure/gtrtest/c", "/azure/BAD_ACCOUNT/c/b"]) {
      const response = await call(path, { method: "PUT", headers: BEARER });
      expect(response.status).toBe(400);
      expect((await json(response)).error).toBe("invalid_path");
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("relays only allowed headers and streams the PUT body unchanged", async () => {
    let received = new Uint8Array();
    fetchSpy.mockImplementation(async (_input, init) => {
      received = new Uint8Array(await new Response(init?.body).arrayBuffer());
      return new Response(null, {
        status: 201,
        headers: {
          etag: '"abc"',
          "x-ms-request-id": "rid",
          "x-ms-version": "2022-11-02",
          date: "Wed, 01 Jan 2026 00:00:00 GMT",
          "content-length": "0",
          "set-cookie": "a=b",
          server: "Windows-Azure-Blob/1.0",
        },
      });
    });
    const payload = new Uint8Array(1024).map((_, index) => index % 251);
    const response = await call(AZURE_PATH, {
      method: "PUT",
      headers: {
        ...BEARER,
        "Content-Type": "application/octet-stream",
        "x-ms-copy-source": "https://proxy.example/t/abc",
        "x-ms-version": "2022-11-02",
        Cookie: "SID=leak",
        "X-Forwarded-For": "1.2.3.4",
      },
      body: payload,
    });
    expect(response.status).toBe(201);
    expect([...response.headers.keys()].sort()).toEqual(["content-length", "date", "etag", "x-ms-request-id", "x-ms-version"]);

    const upstream = upstreamCall();
    expect(upstream.url).toBe("https://gtrtest.blob.core.windows.net/takeouts/dir/a%2Fb.bin?comp=block&blockid=YQ%3D%3D&sig=x%2By%3D");
    expect(upstream.init.method).toBe("PUT");
    expect(upstream.init.redirect).toBe("manual");
    expect([...upstream.headers.keys()].sort()).toEqual(["content-length", "content-type", "x-ms-copy-source", "x-ms-version"]);
    expect(upstream.headers.get("content-length")).toBe("1024");
    expect(received).toEqual(payload);
  });

  it("relays Azure error statuses and bodies", async () => {
    stubUpstream(() => new Response("<Error/>", { status: 403, headers: { "content-type": "application/xml", "x-ms-error-code": "AuthenticationFailed" } }));
    const response = await call(AZURE_PATH, { method: "PUT", headers: BEARER });
    expect(response.status).toBe(403);
    expect(response.headers.get("x-ms-error-code")).toBe("AuthenticationFailed");
    expect(await response.text()).toBe("<Error/>");
  });

  it("502s when the upstream fetch throws", async () => {
    fetchSpy.mockRejectedValue(new TypeError("network"));
    const response = await call(AZURE_PATH, { method: "PUT", headers: BEARER });
    expect(response.status).toBe(502);
    expect((await json(response)).error).toBe("upstream_unreachable");
  });
});

describe("logging", () => {
  it("logs only route and status", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    stubUpstream(() => new Response("x"));
    await call(`/t/${await ticketFor(TAKEOUT_URL, { cookie: "SID=topsecret" })}`);
    await call("/health", { headers: BEARER });
    expect(log.mock.calls).toEqual([["takeout 200"], ["health 200"]]);
    log.mockRestore();
  });
});
