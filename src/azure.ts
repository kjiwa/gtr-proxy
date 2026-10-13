export const RELAY_PREFIX = "/azure/";

const ACCOUNT_NAME = /^[a-z0-9]{3,24}$/;

// Pathname and query are carried verbatim so percent-escapes in blob names and SAS signatures survive.
export function sasUrlToRelayPath(sasUrl: string): string {
  const url = new URL(sasUrl);
  const suffix = ".blob.core.windows.net";
  if (url.protocol !== "https:" || !url.hostname.endsWith(suffix)) {
    throw new Error("not an Azure blob URL");
  }
  const account = url.hostname.slice(0, -suffix.length);
  if (!ACCOUNT_NAME.test(account)) {
    throw new Error("invalid storage account name");
  }
  return `${RELAY_PREFIX}${account}${url.pathname}${url.search}`;
}

export function relayPathToBlobUrl(pathname: string, search: string): URL | null {
  if (!pathname.startsWith(RELAY_PREFIX)) {
    return null;
  }
  const rest = pathname.slice(RELAY_PREFIX.length);
  const slash = rest.indexOf("/");
  const account = slash === -1 ? rest : rest.slice(0, slash);
  const blobPath = slash === -1 ? "" : rest.slice(slash);
  const [, container, blob] = blobPath.split("/");
  if (!ACCOUNT_NAME.test(account) || !container || !blob) {
    return null;
  }
  return new URL(`https://${account}.blob.core.windows.net${blobPath}${search}`);
}
