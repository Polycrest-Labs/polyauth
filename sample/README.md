# PolyAuth sample — operations guide

The canonical reference app (web API + Angular SPA + MCP server + MCP-UI widget host) demonstrating
PolyAuth, deployed to Azure with `azd`. See the repo [README](../README.md) for the library/integration
contract and [docs/mcpdocs.md](../docs/mcpdocs.md) / [docs/frontend-contract.md](../docs/frontend-contract.md).

## Current deployment
| | URL |
|---|---|
| Web (API + SPA + `/mcp` + OAuth AS) | https://web-n2gf3l75dp2ng.azurewebsites.net |
| MCP-UI widget host | https://mcpui-n2gf3l75dp2ng.azurewebsites.net |
| ChatGPT / Claude connector URL | `https://web-n2gf3l75dp2ng.azurewebsites.net/mcp` |

Resource group: `rg-polyauth-sample` (azd env `polyauth-sample`, subscription `new`, region `centralus`).
The hostnames are **deterministic** — azd derives resource names from `uniqueString(subscription, envName, location)`,
so tearing down and redeploying the same env in the same subscription/region produces the **same URLs**.

## Test user (E2E only)
A persistent test user in the **`testagent-letsgo`** Firebase project (not an Azure resource — it survives
`azd down`). For sample/demo/E2E use only; not a production credential.

- **Email:** `e2e@polyauth.test`
- **Password:** `Passw0rd-polyauth-e2e!`

Provisioned via Firebase email/password sign-up; reused get-or-create (the password is never reset). To make a
fresh one, use `IAuthTestUserProvisioner` or the Identity Toolkit `accounts:signUp` REST call with the project's
Web API key.

## Prerequisites
.NET 10 SDK, Node 20+ / Angular CLI, Azure CLI (`az login`), Azure Developer CLI (`azd`), and Docker (only for
running the integration tests locally). Authenticate azd with `azd config set auth.useAzCliAuth true` (reuses `az login`).

## Delete the Azure resources (teardown)
From this `sample/` directory:

```bash
azd down --force --purge
```

This deletes everything in `rg-polyauth-sample` (both App Services, the App Service plan, both Cosmos accounts,
Log Analytics, App Insights). `--purge` also purges soft-deletable resources so the names are immediately reusable.

> There is a **separate** standalone RU-Mongo account used only by the live store test, in its own group:
> `az group delete --name rg-polyauth --yes --no-wait`. The Firebase project + test user are unaffected by either.

## Deploy again

### How `azd` works (mental model)
Run from this `sample/` folder, `azd` does two jobs: **provision** the Azure resources (from the Bicep in
`infra/`) and **deploy** the built app onto them.
- `azd up` — provision **and** deploy (use after a teardown or for a brand-new environment).
- `azd deploy` — just push new app builds to infra that already exists (the everyday case).
- `azd down` — delete the resources.

An **azd environment** is a named profile (stored locally in `sample/.azure/<name>/`) that remembers your
subscription, region, and config/secrets. `azd env set NAME value` writes one value into it; the Bicep reads
several of them (subscription, region, the Firebase config, the cert blobs) to configure the deployed app.

### Which path do I need?
| Situation | Command |
|---|---|
| Changed app code, resources still up | `azd deploy` (or `azd deploy web` / `azd deploy mcp-ui`) |
| Ran `azd down`, but `sample/.azure/` still exists | `azd up` — azd reuses the saved settings, no re-`set` needed |
| Brand-new machine / deleted `sample/.azure/` | Full setup below, then `azd up` |

### Full setup (only when the environment's settings are gone)
These `azd env set` lines hand azd the values the app needs (they're secret/environment-specific, so they
aren't in the repo). You run them **once**; azd remembers them for future `azd up`/`azd deploy`.

```bash
cd sample
azd env new polyauth-sample                       # create the named profile (or: azd env select polyauth-sample)
azd env set AZURE_SUBSCRIPTION_ID <sub-id>        # which subscription to deploy into
azd env set AZURE_LOCATION centralus              # which region (must match the URLs above to keep the same hostnames)

# Firebase — so the app can verify logins. The service account is base64-encoded to survive the azd→Bicep boundary:
azd env set FIREBASE_PROJECT_ID   testagent-letsgo
azd env set FIREBASE_AUTH_DOMAIN  testagent-letsgo.firebaseapp.com
azd env set FIREBASE_API_KEY      <web-api-key>
azd env set FIREBASE_APP_ID       <web-app-id>
azd env set FIREBASE_SERVICE_ACCOUNT_B64  "$(base64 -w0 ../testagent-letsgo-firebase-adminsdk.json)"

# OpenIddict signing + encryption certs. The helper PRINTS two ready-to-paste `azd env set` commands — run it,
# then paste its two output lines:
pwsh ../scripts/generate-certs.ps1                # or: ../scripts/generate-certs.sh
#   azd env set POLYAUTH_SIGNING_CERT_B64 MII...
#   azd env set POLYAUTH_ENCRYPTION_CERT_B64 MII...

azd up                                            # provision (Bicep) + deploy both services
azd env get-values | grep -i uri                  # prints WEB_URI / MCP_UI_URI
```

For ChatGPT connector support, `PolyAuth:OAuth:EnableClientAssertion` is already `true` in
[`web/appsettings.json`](web/appsettings.json) (ChatGPT uses `private_key_jwt`); Claude Desktop needs nothing extra.

## Verify a deployment
```bash
python ../scripts/remote_validation.py  https://<web-uri>
python ../scripts/mcp_oauth_flow.py     https://<web-uri> e2e@polyauth.test 'Passw0rd-polyauth-e2e!' ping list_items
```
