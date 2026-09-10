import type { AuthClientOptions, AuthFetch, CsrfTokenResponse } from './types.js'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE'])

/**
 * Builds a `fetch` that carries the session and recovers from an expired access token.
 *
 * ⚠ **This holds no credential, and neither does the page.** The access and refresh tokens live in
 * HttpOnly cookies the browser attaches on its own, which is the whole point: script that cannot
 * read a credential cannot exfiltrate one. Nothing here touches `localStorage`, and there is no
 * token to pass around.
 *
 * The consequence is that the browser attaches those cookies to *any* request it is tricked into
 * making, so every state-changing call carries a CSRF token as well.
 */
export function createAuthClient(options: AuthClientOptions): AuthFetch {
  const baseUrl = options.baseUrl.replace(/\/$/, '')
  const csrfPath = options.csrfPath ?? '/auth/csrf'
  const refreshPath = options.refreshPath ?? '/auth/refresh'

  let csrfToken: string | null = null

  /*
   * ⚠ Single-flight, both of them.
   *
   * Without this, a page that fires six requests on load gets six 401s and sends six refreshes.
   * Because refresh tokens are single-use with replay detection, the first would succeed and the
   * other five would look exactly like a stolen token being replayed — which revokes every session
   * for the account and signs the user out. Concurrency here is not an optimisation; it is the
   * difference between working and logging everyone out on a slow connection.
   */
  let refreshing: Promise<boolean> | null = null
  let fetchingCsrf: Promise<string> | null = null

  async function getCsrfToken(): Promise<string> {
    if (csrfToken !== null) return csrfToken

    fetchingCsrf ??= (async () => {
      const response = await fetch(`${baseUrl}${csrfPath}`, { credentials: 'include' })
      if (!response.ok) throw new Error(`Could not fetch a CSRF token: ${response.status}`)
      const body = (await response.json()) as CsrfTokenResponse
      csrfToken = body.token
      return body.token
    })().finally(() => {
      fetchingCsrf = null
    })

    return fetchingCsrf
  }

  async function refresh(): Promise<boolean> {
    refreshing ??= (async () => {
      const token = await getCsrfToken().catch(() => null)

      const response = await fetch(`${baseUrl}${refreshPath}`, {
        method: 'POST',
        credentials: 'include',
        headers: token === null ? {} : { 'X-CSRF-TOKEN': token },
      })

      // Rotation issues a new antiforgery token alongside the new session, so the cached one is
      // stale whatever the outcome.
      csrfToken = null

      return response.ok
    })().finally(() => {
      refreshing = null
    })

    return refreshing
  }

  async function send(path: string, init: RequestInit): Promise<Response> {
    const method = (init.method ?? 'GET').toUpperCase()
    const headers = new Headers(init.headers)

    if (!SAFE_METHODS.has(method)) {
      headers.set('X-CSRF-TOKEN', await getCsrfToken())
    }

    // ⚠ credentials: 'include' on every call. The cookies are the session, and a cross-origin
    // fetch omits them by default — so leaving this off makes every authenticated request look
    // like an anonymous one, which surfaces as a 401 that no amount of signing in fixes.
    return fetch(`${baseUrl}${path}`, { ...init, headers, credentials: 'include' })
  }

  return async function authFetch(path: string, init: RequestInit = {}): Promise<Response> {
    let response = await send(path, init)

    if (response.status === 401) {
      if (await refresh()) {
        response = await send(path, init)
      } else {
        options.onSignedOut?.()
      }
    } else if (response.status === 400) {
      /*
       * A 400 may be a rejected CSRF token rather than a bad request — the token is rotated on
       * refresh and on sign-in, so a cached one goes stale during an ordinary session. Retried
       * exactly once with a fresh token; if it is still a 400, it was a real bad request and the
       * caller sees it.
       */
      const stale = csrfToken
      csrfToken = null
      if (stale !== null && !SAFE_METHODS.has((init.method ?? 'GET').toUpperCase())) {
        response = await send(path, init)
      }
    }

    return response
  }
}
