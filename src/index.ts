import { errorResponse } from "./http";
import { RELAY_PREFIX } from "./azure";
import { azure, health, takeout, TICKET_PREFIX } from "./routes";

type Handler = (request: Request, env: Env, url: URL) => Response | Promise<Response>;

interface Route {
  name: string;
  matches: (pathname: string) => boolean;
  methods: string[];
  bearer: boolean;
  handler: Handler;
}

const ROUTES: Route[] = [
  { name: "health", matches: (path) => path === "/health", methods: ["GET"], bearer: true, handler: health },
  { name: "takeout", matches: (path) => path.startsWith(TICKET_PREFIX) && path.length > TICKET_PREFIX.length, methods: ["GET", "HEAD"], bearer: false, handler: takeout },
  { name: "azure", matches: (path) => path.startsWith(RELAY_PREFIX), methods: ["PUT"], bearer: true, handler: azure },
];

const encoder = new TextEncoder();

async function digest(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

async function hasValidBearer(request: Request, secret: string): Promise<boolean> {
  const header = request.headers.get("authorization") ?? "";
  const provided = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  return crypto.subtle.timingSafeEqual(await digest(provided), await digest(secret));
}

async function dispatch(request: Request, env: Env): Promise<{ route: string; response: Response }> {
  if (!env.GTR_SECRET) {
    return { route: "-", response: errorResponse(503, "not_configured", "GTR_SECRET is not set on this Worker.") };
  }
  const url = new URL(request.url);
  const route = ROUTES.find((candidate) => candidate.matches(url.pathname));
  if (!route) {
    return { route: "-", response: errorResponse(404, "not_found", "No such route.") };
  }
  if (!route.methods.includes(request.method)) {
    return { route: route.name, response: errorResponse(405, "method_not_allowed", `Use ${route.methods.join(", ")}.`, { Allow: route.methods.join(", ") }) };
  }
  if (route.bearer && !(await hasValidBearer(request, env.GTR_SECRET))) {
    return { route: route.name, response: errorResponse(401, "unauthorized", "A valid bearer token is required.", { "WWW-Authenticate": "Bearer" }) };
  }
  return { route: route.name, response: await route.handler(request, env, url) };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { route, response } = await dispatch(request, env);
    console.log(`${route} ${response.status}`);
    return response;
  },
} satisfies ExportedHandler<Env>;
