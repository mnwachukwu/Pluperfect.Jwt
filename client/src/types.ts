/**
 * How to reach one API.
 *
 * Every path is relative to `baseUrl`, and `baseUrl` is the API's own origin — not the client's.
 * The two are deliberately separate origins across this fleet, so that a CORS mistake surfaces the
 * first time a form is submitted rather than on deploy day.
 */
export interface AuthClientOptions {
  /** The API origin, e.g. `https://api.example.com`. No trailing slash. */
  baseUrl: string

  /**
   * Where a CSRF token is fetched.
   *
   * The antiforgery cookie stays HttpOnly and the request token comes back in the response body,
   * to be echoed as a header. A token the page could read from a cookie would protect nothing,
   * since anything able to read a cookie can also send it.
   */
  csrfPath?: string

  /** Where a refresh token is redeemed for a new session. */
  refreshPath?: string

  /**
   * Called when the session is gone for good — a refresh was attempted and refused.
   *
   * This is the signal to route to a sign-in page. It fires once per failed recovery, not once per
   * request, so it is safe to navigate from.
   */
  onSignedOut?: () => void
}

/** The shape returned by the CSRF endpoint. */
export interface CsrfTokenResponse {
  token: string
}

/** A `fetch` that carries the session and recovers from an expired access token. */
export type AuthFetch = (path: string, init?: RequestInit) => Promise<Response>
