# PolyAuth

A reusable **.NET 10** class library that encapsulates authentication + authorization for apps on the
ASP.NET Core + Angular + Cosmos + App Service stack. It lets a generated app turn on **Firebase email/password
login** and/or an **OAuth 2.1 Authorization Server** (so MCP clients such as ChatGPT and Claude Desktop can call
the app's MCP tools) with a few lines of config, instead of hand-writing security-critical OAuth code per project.

It owns the hard, near-identical parts:

- A **Firebase** bearer authentication scheme (verifies Firebase ID tokens).
- An **OpenIddict** OAuth 2.1 Authorization Server (Core + Server + Validation) backed by Mongo /
  **Azure Cosmos DB for MongoDB (RU serverless)**.
- A **Firebase → OAuth token-exchange** grant (`urn:polyauth:firebase`) so a Firebase-logged-in user obtains
  OAuth tokens for the app's own API.
- The load-bearing **MCP-client handlers**: ChatGPT DCR-by-URL (client-id metadata documents) and
  Claude Desktop loopback redirect URIs.
- Scope policies, the MCP authorization endpoints (`/.well-known/oauth-protected-resource`, the `/mcp`
  `WWW-Authenticate` challenge), the MCP server wiring + tool-error mapping, and a get-or-create test-user
  provisioner.

The consuming app supplies only configuration + its own MCP tool classes.

## Quick start (consumer surface)

```csharp
// Program.cs
builder.Services.AddPolyAuth(builder.Configuration, o =>
{
    o.Firebase.Enabled = true;                       // human login
    o.OAuth.Enabled = true;
    o.Mcp.Enabled = true;                            // OAuth AS + MCP auth
});
builder.Services.AddPolyAuthMcp(mcp => mcp.WithTools<MyAppTools>());   // your tool classes

app.UsePolyAuth();
app.MapControllers();
app.MapMcp("/mcp").RequireAuthorization(AuthPolicies.McpRead);
```

Protect controllers with the policies, and read the verified user id from the subject claim:

```csharp
[Authorize(Policy = AuthPolicies.ApiRead)]   // or ApiWrite / McpRead / McpWrite
public sealed class MyController : ControllerBase
{
    string UserId => User.FindFirstValue("sub")!;    // Firebase uid / OAuth subject
}
```

That is all the app writes — there is **no hand-written OpenIddict wiring** in the consuming app. The runnable
proof is [`sample/web`](sample/web) (see below).

## Public API

| Type | Purpose |
|---|---|
| `AddPolyAuth(IConfiguration, Action<PolyAuthOptions>?)` | Binds the `PolyAuth` config section, applies the delegate, and wires authentication + authorization + OpenIddict + the token-exchange grant + the baseline MCP-client handlers — only for providers whose `Enabled` is true. |
| `UsePolyAuth()` | Middleware in the correct order: OAuth discovery aliases → protected-resource metadata → MCP resource-metadata challenge → `UseAuthentication` → `UseAuthorization`. No-op for disabled providers. |
| `AddPolyAuthMcp(Action<IMcpServerBuilder>)` | `AddMcpServer().WithHttpTransport()` + a tool-error request filter; the app supplies tools/resources via the delegate. |
| `AuthScopes` | `api.read`, `api.write`, `mcp.read`, `mcp.write`. |
| `AuthPolicies` | `ApiRead`, `ApiWrite`, `McpRead`, `McpWrite`, `FirebaseUser` (used with `[Authorize(Policy = …)]`). |
| `AuthSchemes` | `Firebase`, `OAuthSession`, and the OpenIddict validation scheme. |
| `PolyAuthConstants.FirebaseTokenExchangeGrantType` | `urn:polyauth:firebase`. |
| `IAuthTestUserProvisioner` / `TestUser` | Get-or-create persistent E2E test user (never resets an existing password). |
| `IPolyAuthPrincipalEnricher` | Optional hook to add app claims (e.g. an account id) to issued tokens. Default registration is a no-op. |

Options shape: `PolyAuthOptions { Firebase, OAuth, Mcp }` — see [`src/PolyAuth/PolyAuthOptions.cs`](src/PolyAuth/PolyAuthOptions.cs).

## Configuration schema (`PolyAuth` section)

```jsonc
{
  "PolyAuth": {
    "Firebase": {
      "Enabled": true,
      "ProjectId": "<firebase-project-id>",
      "ServiceAccountJson": "<raw or base64 service-account JSON>"   // secret; outside Development this is required
    },
    "OAuth": {
      "Enabled": true,
      "Issuer": "https://your-api.example.com",                      // required outside Development
      "AccessTokenLifetimeMinutes": 60,
      "RefreshTokenLifetimeDays": 14,
      "UiClientId": "polyauth-ui",
      "EnableUrlClientMetadata": true,                               // ChatGPT DCR-by-URL (baseline ON)
      "EnableLoopbackRedirects": true,                               // Claude Desktop loopback (baseline ON)
      "EnableClientAssertion": false,                                // private_key_jwt — set true for ChatGPT (it uses private_key_jwt)
      "EnableDiagnostics": false,                                    // token-endpoint diagnostics (optional)
      "SigningCertificate":    { "Base64": "", "Path": "", "Password": "" },  // required outside Development
      "EncryptionCertificate": { "Base64": "", "Path": "", "Password": "" },  // required outside Development
      "Store": {
        "ConnectionString": "<Cosmos-for-Mongo RU connection string>",        // required when OAuth enabled
        "DatabaseName": "polyauth-openiddict"
      },
      "Scopes": { "Additional": [] },
      "StaticClients": [
        {
          "ClientId": "claude-desktop",
          "ClientName": "Claude Desktop",
          "AllowLoopbackRedirectUris": true,
          "AllowedLoopbackRedirectPaths": [ "/callback", "/oauth/callback" ],
          "Scopes": [ "openid", "profile", "email", "offline_access", "mcp.read", "mcp.write" ]
        }
      ]
    },
    "Mcp": {
      "Enabled": true,
      "McpBaseUrl": "https://your-api.example.com",   // resource indicator for /mcp; defaults to Issuer
      "WidgetHostBaseUrl": "https://your-mcp-ui.example.com"  // where the widget Angular app is hosted
    }
  }
}
```

**Fail-fast:** `AddPolyAuth` throws with a clear message when a required value is missing — `Store.ConnectionString`/
`DatabaseName` when OAuth is enabled, and (outside Development) `Issuer`, the signing/encryption certificates, and the
Firebase service account. In **Development**, OpenIddict development certificates are used automatically and the
transport-security requirement is relaxed.

## Store: Azure Cosmos DB for MongoDB (RU serverless) — verified

The OpenIddict store uses `OpenIddict.MongoDb` against **Azure Cosmos DB for MongoDB, RU-based serverless**
(`*.mongo.cosmos.azure.com`), chosen for zero idle cost. The RU Mongo API is an emulation with some feature limits,
so it was tested explicitly.

**Findings** (verified against a live `Microsoft.DocumentDB` account, `kind=MongoDB`, `EnableServerless`, server
version **7.0**, by `tests/PolyAuth.IntegrationTests/CosmosRuMongoStoreTests.cs`):

- ✅ **Unique index creation** on the OpenIddict collections (e.g. `applications.client_id`, `scopes.name`) succeeds.
- ✅ **CRUD** through `IOpenIddictApplicationManager` / `IOpenIddictScopeManager` (create / find-by-client-id /
  delete) works.
- ✅ **Persistence across a reconnect** (new `MongoClient`) — clients/tokens survive, i.e. they persist across an
  app restart.

No incompatibility was hit for the operations OpenIddict performs at runtime (client/scope/token CRUD + the unique
indexes). If a future need hits an RU limitation (multi-document transactions, certain index types, or unsupported
`$` operators), fall back to **Cosmos for MongoDB vCore** (`*.mongocluster.cosmos.azure.com`), which has a small
always-on cost but full feature support — switch only the connection string. The connection string is read from
config; provisioning the account is out of scope of the library.

To re-run the live RU test: set `POLYAUTH_COSMOS_MONGO` to the account's Mongo connection string and
`dotnet test tests/PolyAuth.IntegrationTests`. Without it, that test is a no-op.

## Build & test

```bash
dotnet build PolyAuth.slnx
# Unit tests need nothing extra; integration tests need a Mongo (local Docker or Cosmos RU):
docker run -d -p 27017:27017 mongo:7
dotnet test PolyAuth.slnx
```

Integration tests use `WebApplicationFactory<Program>` over `sample/web` with a stubbed Firebase verifier and a
Mongo store (`POLYAUTH_TEST_MONGO`, default `mongodb://localhost:27017`). Current status: **25 unit + 13 integration
tests pass**, covering token-exchange issuing a usable token, scope policies (403 on wrong scope / 200 on correct),
`/mcp` returning 401 without a token and serving a scripted MCP `initialize` + `tools/list` with an `mcp.read` token,
the discovery/metadata endpoints, the get-or-create provisioner, and the live RU store.

## Distribution

The library is self-contained (no feed dependency baked in) so it can ship either as a **private NuGet package**
(e.g. GitHub Packages, consumed via `PackageReference` + `nuget.config`) or as a **copied `ProjectReference`**
project. The sample consumes it via `ProjectReference`.

## Sample app

[`sample/`](sample) is a full reference app demonstrating the library end-to-end: the `web` API host (Firebase login
+ OAuth AS + MCP at `/mcp` + a Cosmos-backed `items` API), an Angular login UI, an MCP-UI host + Angular widget app,
and Bicep/azd infrastructure. See [`docs/mcpdocs.md`](docs/mcpdocs.md) for the MCP/OAuth flows and how to turn them on.
