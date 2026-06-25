# MCP + OAuth with PolyAuth

This document explains the flows PolyAuth implements and how a consuming app turns them on. It is the
"configure the library" counterpart to hand-writing OAuth/MCP code.

## The three flows

### 1. Human login → API (Firebase token exchange)
1. The Angular SPA logs the user in with Firebase email/password and gets a Firebase **ID token**.
2. The SPA POSTs that ID token to the token endpoint using the custom grant:
   ```
   POST /connect/token
   grant_type=urn:polyauth:firebase
   client_id=polyauth-ui
   firebase_id_token=<firebase id token>
   scope=openid profile email api.read api.write offline_access
   ```
3. PolyAuth verifies the ID token (`IFirebaseTokenVerifier`), and issues an OAuth **access + refresh token**
   whose subject is the Firebase uid. The grant is restricted to the configured first-party `UiClientId`.
4. The SPA calls `/api/*` with `Authorization: Bearer <access token>`; controllers enforce `AuthPolicies.ApiRead` /
   `ApiWrite` (scope-based).

### 2. MCP client via DCR-by-URL (ChatGPT)
ChatGPT identifies itself with an HTTPS **client-id metadata document** URL. On the authorization request,
PolyAuth fetches + validates that document and materializes an OpenIddict client on the fly
(`EnableUrlClientMetadata`, baseline ON). The discovery document advertises
`client_id_metadata_document_supported: true`. External clients are limited to the MCP scopes.

> **ChatGPT requires `EnableClientAssertion = true`.** ChatGPT's metadata declares
> `token_endpoint_auth_method: private_key_jwt` with a `jwks_uri`, so it authenticates the **token
> exchange** with a signed `client_assertion` JWT — not PKCE-only. Without the client-assertion handlers,
> OpenIddict rejects the assertion's token type and the code exchange fails with
> `invalid_client` / "The specified token is not of the expected type" (OpenIddict ID2089). The
> authorization step still succeeds, so the failure surfaces only at the final token call. Turn it on:
> `o.OAuth.EnableClientAssertion = true` (or `PolyAuth:OAuth:EnableClientAssertion=true`). The sample
> enables it. Claude Desktop, by contrast, uses public PKCE + a loopback redirect and does **not** need it.

### 3. MCP client via loopback redirect (Claude Desktop)
Claude Desktop uses a statically configured client (`OAuth.StaticClients`) with
`AllowLoopbackRedirectUris: true`. PolyAuth accepts `http://127.0.0.1:<port>/<allowed-path>` /
`http://localhost:<port>/<allowed-path>` redirect URIs and materializes them on the authorization request
(`EnableLoopbackRedirects`, baseline ON).

Both MCP clients then run **authorization code + PKCE**. The library's `/connect/authorize` endpoint (mapped by
`MapPolyAuthEndpoints`) redirects the user to the SPA `/sign-in` page (`OAuth.SignInPath`), which establishes the
`OAuthSession` cookie from a Firebase login via `POST /api/oauth/session`; third-party clients then get the
library's built-in consent screen (auto-consented for the first-party UI client). The client exchanges the code
for an `mcp.read` / `mcp.write` token at `/connect/token`, then calls `/mcp` with that bearer token;
`MapMcp("/mcp").RequireAuthorization(AuthPolicies.McpRead)` enforces the scope.

## Discovery / metadata endpoints (served by `UsePolyAuth`)
- `/.well-known/oauth-authorization-server` (+ `/openid-configuration`) — OpenIddict AS metadata, plus the
  `…/mcp` aliases for MCP clients that probe the resource-scoped path.
- `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp` — RFC 9728 protected
  resource metadata (resource, authorization server, supported scopes).
- A 401 on `/mcp` is answered with `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp"`
  so clients can discover the AS and register.

## Turning it on in a consuming app
1. Add the `PolyAuth` config section (see the README schema). Provide the Cosmos-for-Mongo connection string, the
   issuer, and signing/encryption certificates (or run in Development for dev certs).
2. `builder.Services.AddPolyAuth(config, o => { o.Firebase.Enabled = true; o.OAuth.Enabled = true; o.Mcp.Enabled = true; });`
   (set `o.OAuth.EnableClientAssertion = true` if you want ChatGPT connectors — see the note above).
3. `builder.Services.AddPolyAuthMcp(mcp => mcp.WithTools<YourTools>().WithResources<YourWidgets>());`
4. `app.UsePolyAuth(); app.MapControllers(); app.MapPolyAuthEndpoints(); app.MapMcp("/mcp").RequireAuthorization(AuthPolicies.McpRead);`
5. Write MCP tools as `[McpServerToolType]` classes; tool exceptions are mapped to user-facing errors by the
   library's tool-error filter (see `McpToolHelpers`). For ChatGPT/MCP-App widgets, host a small Angular widget app
   on a separate static host and build the resource HTML with `McpWidgetHtmlBuilder` keyed off
   `Mcp.WidgetHostBaseUrl`.
6. Add a thin SPA `/sign-in` page implementing the [front-end contract](frontend-contract.md) (Firebase login →
   token-exchange for the API, and the `POST /api/oauth/session` → `returnUrl` handoff for connector logins).

## Authorize / consent / session endpoints (library-owned)
`MapPolyAuthEndpoints()` maps the entire interactive surface — there is **no hand-written OAuth code in the app**:
- `/connect/authorize` — redirects unauthenticated users to `OAuth.SignInPath`, auto-consents the first-party UI
  client, and shows a built-in consent page for third-party clients (override it by registering an
  `IPolyAuthConsentRenderer` in DI), then issues the code via OpenIddict's passthrough.
- `/connect/logout` — clears the `OAuthSession` cookie and the OpenIddict session.
- `POST /api/oauth/session` — the Firebase ID-token → `OAuthSession` cookie bridge (mapped only when Firebase is
  enabled).

The only app-side responsibility is the SPA `/sign-in` page (see the [front-end contract](frontend-contract.md));
[`sample/web/Program.cs`](../sample/web/Program.cs) is the canonical, controller-free integration template.

## Connecting a real MCP client
- **ChatGPT** (developer mode / connectors): add a connector pointing at `https://<your-api>/mcp`. ChatGPT discovers
  the AS via the protected-resource metadata, registers by URL (DCR), runs auth-code + PKCE, and lists your tools.
- **Claude Desktop**: add a custom MCP server `https://<your-api>/mcp`; it registers the loopback client and runs
  auth-code + PKCE against the loopback redirect.
