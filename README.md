# Pluperfect.Jwt

Session tokens for the Pluperfect Development fleet: a signed JWT carried in an `HttpOnly` cookie,
an opaque refresh token that rotates and detects replay, and the CSRF layers that a cookie
transport makes mandatory.

Two libraries in one repository — a .NET one under `src/`, and a framework-agnostic TypeScript one
under `client/`. Neither is published to a registry; consumers take them by project reference and
by `file:` dependency.

## The shape, and why

**The JWT travels in a cookie, not an `Authorization` header.** That is the entire design decision
everything else follows from.

A bearer token has to be readable by script to be sent by script, which means any successful
injection on the page can read it and replay it from anywhere. A cookie marked `HttpOnly` cannot be
read by script at all — so the page holds no credential, and there is nothing to steal from it.

The cost is that the browser now attaches the credential automatically, to any request it is
tricked into making. That is CSRF, and it is why this library ships three overlapping defenses
rather than treating them as optional extras:

1. `SameSite=Lax` stops cross-site non-GET requests — but it is a browser default, and browsers
   have changed their defaults before.
2. `OriginFilter`, which is stateless and does not care what the browser decided.
3. ASP.NET antiforgery via `AntiforgeryFilter`, cookie-to-header.

If you take the cookie transport, you take all three. They are not independently optional.

**The access token is a JWT; the refresh token is not.** A refresh token carries no claims and
means nothing on its own — it is a lookup key into a table that says whether it is still live.
That is the point: it can be revoked, which a signed token cannot be without somewhere to write the
revocation. Only its SHA-256 hash is stored, so a reader of the database cannot present what they
find there.

**Refresh is single-use.** Redeeming one issues its replacement and kills the original, atomically.
A second redemption of the same value means two parties hold it and only one should — so it is
treated as theft, and every session for that account is revoked.

## What this does not do

- **No `IRefreshTokenStore` implementation.** The interface is here; the storage is not. Every
  consumer already has a database and an ORM, and shipping one implementation would pick for all of
  them. `RedeemAsync` must be one transaction — read, revoke, insert — because split across three
  calls, two concurrent refreshes interleave and either both succeed, defeating single-use, or both
  fail and sign a legitimate user out.
- **No password hashing, no sign-in service, no user store.** Those know what an account *is*,
  which is the application's business.
- **No claims vocabulary.** `Issue` writes exactly the claims it is given.
- **No bearer-header mode.** Adding one would reintroduce the exfiltration risk the cookie
  transport exists to remove, and having both available invites the wrong one being chosen.

## Consuming it

Both halves assume a **sibling checkout** — this repository cloned beside the consuming one.

```
D:\Repos\
  Pluperfect.Jwt\
  PokeStory\
  FortyLife\
```

Server, in the consuming `.csproj`:

```xml
<ProjectReference Include="../../../Pluperfect.Jwt/src/Pluperfect.Jwt/Pluperfect.Jwt.csproj" />
```

Client, in the consuming `package.json`:

```json
"dependencies": {
  "@pluperfect/jwt": "file:../../Pluperfect.Jwt/client"
}
```

`client/dist` is git-ignored, so a consumer's CI runs `npm ci && npm run build` in this directory
after checking it out.

## Server usage

```csharp
builder.Services.AddPluperfectJwt(
    builder.Configuration,
    allowDevelopmentKey: builder.Environment.IsDevelopment(),
    secureOrigin: !builder.Environment.IsDevelopment());
```

Both flags are parameters rather than environment checks inside the library, because a library that
reads its host behaves differently depending on who hosts it. Both default to the safe answer, so
forgetting them fails closed.

Register a store and the filters yourself:

```csharp
builder.Services.AddScoped<IRefreshTokenStore, MyEfRefreshTokenStore>();
builder.Services.AddSingleton(new AllowedOriginRegistry(allowedOrigins));
builder.Services.AddControllers(mvc =>
{
    mvc.Filters.Add<OriginFilter>();
    mvc.Filters.Add(new AntiforgeryFilter(antiforgery, "/auth/csrf"));
});
```

⚠ **CORS before authentication** in the middleware order. A rejected preflight must still carry CORS
headers, or the browser reports an opaque failure instead of the real one.

### Configuration

Bound from the `Jwt` section.

| Key | Default | Notes |
|---|---|---|
| `SigningKey` | — | **Secret.** At least 32 bytes. Changing it signs everybody out. |
| `Issuer` | — | Both issuer and audience: a service signs tokens for itself. |
| `AccessTokenMinutes` | 15 | ⚠ This is the revocation window. |
| `RefreshTokenDays` | 7 | Rotation resets it, so this is the *idle* limit, not a session cap. |
| `RevokedTokenGraceDays` | 30 | How long a dead row is kept so a late replay is still detected as one. |
| `AccessCookieName` | `sid` | `__Host-` is applied automatically on a secure origin. |
| `RefreshCookieName` | `rt` | |
| `RefreshCookiePath` | `/auth` | ⚠ Must match the clearing cookie exactly, or sign-out silently fails. |

In production, set the key as an environment variable — `Jwt__SigningKey` — never in a file.

## Client usage

```ts
import { createAuthClient } from '@pluperfect/jwt'

export const api = createAuthClient({
  baseUrl: import.meta.env.VITE_API_BASE_URL,
  onSignedOut: () => { window.location.href = '/sign-in' },
})

const response = await api('/campaigns', { method: 'POST', body: JSON.stringify(campaign) })
```

It holds no credential and touches no storage. What it does is attach `credentials: 'include'` to
every request, send `X-CSRF-TOKEN` on unsafe methods, and recover from an expired access token by
refreshing once and retrying.

⚠ **Refresh is single-flight, and that is load-bearing.** A page firing six requests on load gets
six 401s. Without single-flight it would send six refreshes; the first succeeds and the other five
look exactly like a stolen token being replayed — which revokes every session for the account.
Concurrency here is the difference between working and signing everyone out on a slow connection.

## Where this came from

Extracted from `PokéStory/Site/Server`, which is the reference implementation for this stack and
where the rationale in these comments was first worked out. Where this library and that codebase
disagree, that codebase is right and this is a bug.

## Licenses

Pluperfect.Jwt is MIT-licensed; see [LICENSE](LICENSE). It takes in the packages below directly, each under its own
license. The packages those bring in carry licenses of their own.

### The library (`src/Pluperfect.Jwt`)

| Package | Used for | License |
|---|---|---|
| [Microsoft.AspNetCore.Authentication.JwtBearer](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.JwtBearer) | Validating the access token each request carries | [MIT](https://spdx.org/licenses/MIT.html) |

### The tests (`tests/Pluperfect.Jwt.Tests`)

| Package | Used for | License |
|---|---|---|
| [Microsoft.NET.Test.Sdk](https://www.nuget.org/packages/Microsoft.NET.Test.Sdk) | Running the tests | [MIT](https://spdx.org/licenses/MIT.html) |
| [NUnit](https://www.nuget.org/packages/NUnit) | The test framework | [MIT](https://spdx.org/licenses/MIT.html) |
| [NUnit3TestAdapter](https://www.nuget.org/packages/NUnit3TestAdapter) | Running NUnit tests through `dotnet test` | [MIT](https://spdx.org/licenses/MIT.html) |
| [NUnit.Analyzers](https://www.nuget.org/packages/NUnit.Analyzers) | Catching test mistakes at build time | [MIT](https://spdx.org/licenses/MIT.html) |
| [Shouldly](https://www.nuget.org/packages/Shouldly) | Assertions | [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) |

### The client (`client/package.json`)

| Package | Used for | License |
|---|---|---|
| [TypeScript](https://www.npmjs.com/package/typescript) (`typescript`) | Compiling the client | [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) |
