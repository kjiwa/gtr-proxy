export function errorResponse(status: number, code: string, message: string, headers: HeadersInit = {}): Response {
  return Response.json({ error: code, message }, { status, headers });
}

export function filterHeaders(source: Headers, allowed: (name: string) => boolean): Headers {
  const result = new Headers();
  for (const [name, value] of source) {
    if (allowed(name)) {
      result.set(name, value);
    }
  }
  return result;
}
