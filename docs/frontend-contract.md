# PolyAuth — front-end (SPA) contract

PolyAuth owns the server side of auth. The SPA only has to do two things. This doc is self-contained; the
golden, compiling copy of every snippet below is [`sample/ui`](../sample/ui).

## 1. Runtime config (`/config.json`)
The API serves a non-secret config payload the SPA fetches at startup. Shape:

```json
{
  "firebase": { "apiKey": "…", "authDomain": "<project>.firebaseapp.com", "projectId": "<project>", "appId": "…" },
  "oauth":    { "clientId": "polyauth-ui", "tokenEndpoint": "/connect/token",
                "revocationEndpoint": "/connect/revocation",
                "scope": "openid profile email api.read api.write offline_access" }
}
```

Load it before bootstrapping and fail hard if it's missing (see `sample/ui/src/app/runtime-config.ts` +
`main.ts`).

## 2. Sign-in + the two flows

### a) Get the SPA's own API token (Firebase token-exchange)
After Firebase email/password login, exchange the Firebase **ID token** for an OAuth access token for your API:

```
POST /connect/token   (application/x-www-form-urlencoded)
  grant_type=urn:polyauth:firebase
  client_id=polyauth-ui                     # = oauth.clientId from /config.json
  firebase_id_token=<the Firebase ID token>
  scope=openid profile email api.read api.write offline_access
→ { access_token, refresh_token, expires_in, … }
```

Attach `Authorization: Bearer <access_token>` to `/api/*` calls (HTTP interceptor). Reference:
`sample/ui/src/app/auth/auth.service.ts` (`exchangeFirebaseToken`) and `auth/auth.interceptor.ts`.

### b) Establish the OAuth **session cookie** (only for connector logins)
When a connector (ChatGPT/Claude) starts the authorization-code flow, the library's `/connect/authorize`
redirects unauthenticated users to your **`/sign-in`** route (configurable via `PolyAuth:OAuth:SignInPath`,
default `/sign-in`) with a `returnUrl`. Your sign-in page must, after Firebase login:

```
POST /api/oauth/session   (application/json, Authorization: Bearer <Firebase ID token>)
  { "returnUrl": "<the returnUrl query param>" }
→ 200 { "returnUrl": "<normalized>" }   + Set-Cookie: __Host-polyauth-oauth=…
```

then **full-page navigate** to the returned `returnUrl` (back to `/connect/authorize`, which now issues the code).
Reference: `sample/ui/src/app/auth/auth.service.ts` (`createOAuthSession`) and `login/login.component.ts`
(the `returnUrl.startsWith('/connect/authorize')` branch).

> The cookie is `__Host-`/`Secure`, so this only works over **HTTPS** (App Service, or local `https`).

## 3. Session restore + route guard
Tokens are obtained per session. Subscribe to Firebase `onAuthStateChanged` on startup so a page refresh
re-obtains the API token before the route guard runs, and make the guard `await` that restore — otherwise a
refresh bounces a signed-in user to `/sign-in`. Reference: `auth/auth.service.ts` (`waitUntilReady`) +
`auth/auth.guard.ts`.

## Minimal Angular reference
Copy these from `sample/ui/src/app/` — they are standalone Angular 22, signals, zoneless, and depend only on
`firebase`:

| File | Responsibility |
|---|---|
| `runtime-config.ts` | fetch `/config.json` before bootstrap |
| `auth/auth.service.ts` | Firebase login, token-exchange, `createOAuthSession`, `waitUntilReady` (refresh restore) |
| `auth/auth.interceptor.ts` | attach the bearer to `/api/*` |
| `auth/auth.guard.ts` | `await auth.waitUntilReady()` before allowing protected routes |
| `login/login.component.ts` | email/password form + the `returnUrl` → `/connect/authorize` handoff |

The MCP widget UI (rendered inside ChatGPT/Claude) is a separate app on the widget host; see `sample/ui/projects/mcp-ui`
and `docs/mcpdocs.md`.
