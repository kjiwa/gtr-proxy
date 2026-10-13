interface TakeoutRule {
  host: RegExp;
  pathPrefixes: string[];
}

const SUBDOMAINS = "(?:[a-z0-9-]+\\.)*";

// Takeout download hosts carry a hash prefix joined by a hyphen, e.g. <hex>-apidata.googleusercontent.com.
const RULES: TakeoutRule[] = [
  {
    host: new RegExp(`^${SUBDOMAINS}(?:[a-z0-9]+-)?apidata\\.googleusercontent\\.com$`),
    pathPrefixes: ["/download/storage/v1/b/dataliberation/o/", "/download/storage/v1/b/takeout"],
  },
  {
    host: new RegExp(`^${SUBDOMAINS}storage\\.googleapis\\.com$`),
    pathPrefixes: ["/takeout-"],
  },
  {
    host: new RegExp(`^${SUBDOMAINS}(?:takeout\\.google\\.com|takeout-download\\.usercontent\\.google\\.com)$`),
    pathPrefixes: ["/takeout/download", "/download"],
  },
];

export function isTakeoutUrl(value: string | URL): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.port !== "" || url.username !== "" || url.password !== "") {
    return false;
  }
  return RULES.some((rule) => rule.host.test(url.hostname) && rule.pathPrefixes.some((prefix) => url.pathname.startsWith(prefix)));
}
