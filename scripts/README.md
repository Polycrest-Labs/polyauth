# Verification scripts

Helpers to verify a deployed PolyAuth sample end-to-end.

## Remote validation (definition of done)
```
python scripts/remote_validation.py https://<web-app>.azurewebsites.net
```
Checks: SPA shell loads, `/health`, `/config.json`, protected `/api/items` requires auth (401),
deep-link fallback, OAuth AS metadata, and the `/mcp` 401 + `WWW-Authenticate` resource-metadata challenge.

## Scripted MCP OAuth flow (Claude-style auth-code + PKCE + loopback)
```
python scripts/mcp_oauth_flow.py https://<web-app>.azurewebsites.net e2e@polyauth.test "Passw0rd-polyauth-e2e!"
```
Drives the full flow against the live app: Firebase sign-in → `/api/oauth/session` cookie →
`/connect/authorize` (PKCE + consent) → loopback redirect with code → `/connect/token`
(authorization_code + PKCE) → MCP `initialize` + `tools/list` with the issued `mcp.read`/`mcp.write`
token. Asserts the sample tools (`ping`, `list_items`) are listed.

## Browser / UI validation (Playwright)
Sign in at `https://<web-app>.azurewebsites.net/sign-in` with the persistent test user
(`e2e@polyauth.test` / `Passw0rd-polyauth-e2e!`), confirm the protected `/items` route renders and an
authed `GET /api/items` succeeds, and that signing out returns to `/sign-in`.

## Real MCP connectors (manual)
- **ChatGPT** (developer mode / connectors): add a connector for `https://<web-app>.azurewebsites.net/mcp`.
  It discovers the AS via protected-resource metadata, registers by URL (DCR), runs auth-code + PKCE, and
  lists the tools.
- **Claude Desktop**: add a custom MCP server `https://<web-app>.azurewebsites.net/mcp`; it registers the
  loopback client and runs auth-code + PKCE against the loopback redirect (the scripted flow above
  reproduces this exact sequence).
