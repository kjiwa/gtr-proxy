import { proxyPathnameToAzBlobSASUrl } from './azb'
import { decodeState } from './state_compression';

// Query parameter carrying an optional pre-shared auth token. Present on
// every request once a client (e.g. the GTR extension) is configured with a
// token; stripped before any request is forwarded upstream so it never
// reaches Google or Azure.
export const PROXY_TOKEN_PARAM = 'gtr_token'

// Compares two strings in constant time relative to their (equal) length, so
// a mismatching token can't be distinguished by how many leading characters
// happened to match.
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false
  }
  let mismatch = 0
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return mismatch === 0
}

// Rejects the request if this instance is configured to require a
// pre-shared token (via the GTR_TOKEN binding) and the request doesn't carry
// a matching one. Returns null when the request may proceed: either no
// token is configured (the proxy is open, as it was before this feature
// existed) or the caller supplied the right one.
export function checkProxyToken(url: URL): Response | null {
  const requiredToken = (globalThis as { GTR_TOKEN?: string }).GTR_TOKEN
  if (!requiredToken) {
    return null
  }
  const provided = url.searchParams.get(PROXY_TOKEN_PARAM)
  if (!provided || !timingSafeEqual(provided, requiredToken)) {
    return new Response('forbidden', { status: 403 })
  }
  return null
}

export async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url)

  const tokenRejection = checkProxyToken(url)
  if (tokenRejection) {
    return tokenRejection
  }

  if (url.pathname.startsWith('/p/')) {
    return handleProxyToGoogleTakeoutRequest(request)
  }

  if (url.pathname.startsWith('/p-azb/')) {
    return handleProxyToAzStorageRequest(request)
  }

  if (url.pathname.startsWith('/version/')) {
    return new Response(
      JSON.stringify(
        {
          apiVersion: '2.0.0',
        },
        null,
        2,
      ),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      },
    )
  }

  // Check if the URL matches the path desired. If not, just redirect to GitHub
  // for project information
  return new Response(null, {
    status: 302,
    headers: {
      Location: 'https://github.com/nelsonjchen/gtr-proxy#readme',
    },
  })
}

export async function handleProxyToGoogleTakeoutRequest(
  request: Request,
): Promise<Response> {
  // Extracted URL is after the /p/ in the path with https:// prepended to it
  const original_url_segment = `https://${request.url.substring(request.url.indexOf('/p/') + 3)}`

  // Strip off "/dummy.bin" from the end of the URL if it is there.
  // This allows testing with azcopy which requires a nice filename at the end.
  const original_url_segment_stripped = original_url_segment.replace(/\/dummy.bin$/, '')

  // Replace %25 with % to get the original URL
  const original_url_segment_stripped_processed = original_url_segment_stripped.replace(/%25/g, '%')

  let extracted_url: URL
  try {
    // Replace %25 with % to get the original URL
    extracted_url = new URL(original_url_segment_stripped_processed)
  } catch (_) {
    return new Response('invalid URL', {
      status: 500,
    })
  }

  // Extract cookies from request
  const encodedCookies = new URL(request.url).searchParams.get('a');
  const headersWithCookies = new Headers(request.headers);
  if (encodedCookies) {
    try {
      // Create a new Headers object since request.headers is immutable
      headersWithCookies.set('Cookie', decodeState(encodedCookies));
    } catch (error) {
      console.error('Failed to decode state:', error);
      return new Response('Failed to decode cookies from request', { status: 400 });
    }
  } else {
    console.error('No cookies found in request.');
    return new Response('No cookies found in request.', { status: 400 });
  }
  // Remove the 'a' parameter from the URL before fetching
  extracted_url.searchParams.delete('a');
  // Also remove the proxy auth token, if present, so it isn't leaked to
  // Google as part of the forwarded URL.
  extracted_url.searchParams.delete(PROXY_TOKEN_PARAM);

  if (
    !(validGoogleTakeoutUrl(extracted_url) || validTestServerURL(extracted_url))
  ) {
    console.log("Not a valid Takeout URL");
    return new Response(
      'encoded url was not a google takeout or test server url',
      {
        status: 403,
      },
    )
  }

  // For HEAD requests to retrieve the content-length of the Takeout archive,
  // actually send as GET, since Google Takeout will sometimes not return
  // the content-length for HEAD requests. The fetch API resolves its
  // promise after the response headers arrive.
  const fetchMethod = request.method === 'HEAD' ? 'GET' : request.method;

  // Pass the original URL processed. A URL object will malform the `%2B` to `+`.
  const originalResponse = await fetch(extracted_url, {
    method: fetchMethod,
    headers: headersWithCookies
  })

  console.log("Response Headers:", JSON.stringify(Object.fromEntries(originalResponse.headers.entries())));

  if (request.method === 'HEAD') {
    // For HEAD requests, we sent a GET, but only return the headers and no body.
    return new Response(null, {
      status: originalResponse.status,
      headers: originalResponse.headers,
    });
  } else {
    // For non-HEAD requests, return the original body.
    return new Response(originalResponse.body, {
      status: originalResponse.status,
      headers: originalResponse.headers,
    });
  }
}

export async function handleProxyToAzStorageRequest(request: Request): Promise<Response> {
  const url = new URL(request.url)
  // Remove the proxy auth token, if present, so it isn't leaked to Azure as
  // part of the forwarded query string.
  url.searchParams.delete(PROXY_TOKEN_PARAM);
  try {
    const azUrl = proxyPathnameToAzBlobSASUrl(url)

    // If this instance is locked to a specific storage account (via the
    // GTR_ALLOWED_AZ_ACCOUNT binding), reject anything else. Without this,
    // any caller who can reach this proxy -- and, absent a proxy token,
    // that's anyone -- can relay to an Azure storage account of their own
    // choosing, using a SAS token they supply themselves.
    const allowedAccount = (globalThis as { GTR_ALLOWED_AZ_ACCOUNT?: string }).GTR_ALLOWED_AZ_ACCOUNT
    if (allowedAccount && azUrl.hostname !== `${allowedAccount}.blob.core.windows.net`) {
      console.log('Azure storage account not allowed')
      return new Response('azure storage account not allowed', {
        status: 403,
      })
    }

    const originalResponse = await fetch(azUrl.toString(), {
      method: request.method,
      headers: request.headers,
    })

    const response = new Response(originalResponse.body, {
      status: originalResponse.status,
      headers: originalResponse.headers,
    })
    console.log(`response: ${JSON.stringify(response)}`)

    return response
  } catch {
    return new Response('invalid URL', {
      status: 500,
    })
  }
}

export function validTestServerURL(url: URL): boolean {
  return (
    // Cloudflare Bucket test server with unlimited download bandwidth
    url.hostname.endsWith('gtr-test.677472.xyz') ||
    // https://github.com/nelsonjchen/put-block-from-url-esc-issue-demo-server/
    url.hostname.endsWith('3vngqvvpoq-uc.a.run.app')
  )
}

export function validGoogleTakeoutUrl(url: URL): boolean {
  return (
    (
      url.hostname.endsWith('apidata.googleusercontent.com') &&
      (
        url.pathname.startsWith('/download/storage/v1/b/dataliberation/o/') ||
        url.pathname.startsWith('/download/storage/v1/b/takeout')
      )
    ) ||
    (
      url.hostname.endsWith('storage.googleapis.com') &&
      url.pathname.startsWith('/takeout-')
    ) ||
    (
      (url.hostname.endsWith('takeout.google.com') ||
        url.hostname.endsWith('takeout-download.usercontent.google.com')) &&
      (url.pathname.startsWith('/takeout/download') ||
        url.pathname.startsWith('/download')
      )
    )
  )
}
