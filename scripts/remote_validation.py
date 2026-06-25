#!/usr/bin/env python3
"""Remote validation (definition of done) for a deployed PolyAuth sample web app.

Usage: python remote_validation.py https://web-xxxx.azurewebsites.net
"""
import sys
import json
import urllib.request
import urllib.error


def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


def main():
    base = sys.argv[1].rstrip("/")
    failures = []

    # 1) SPA shell
    s, body, _ = get(f"{base}/")
    ok = s == 200 and "app-root" in body
    print(f"[{'PASS' if ok else 'FAIL'}] 1. SPA shell loads (GET / -> {s})")
    if not ok:
        failures.append("spa-shell")

    # 2) Health
    s, _, _ = get(f"{base}/health")
    ok = s == 200
    print(f"[{'PASS' if ok else 'FAIL'}] 2. Health (GET /health -> {s})")
    if not ok:
        failures.append("health")

    # 3) Runtime config
    s, body, _ = get(f"{base}/config.json")
    ok = s == 200
    try:
        cfg = json.loads(body)
        ok = ok and "firebase" in cfg and "oauth" in cfg
    except Exception:
        ok = False
    print(f"[{'PASS' if ok else 'FAIL'}] 3. Runtime config (GET /config.json -> {s})")
    if not ok:
        failures.append("config")

    # 4) Protected API returns 401 without a token (Cosmos-backed endpoint)
    s, _, _ = get(f"{base}/api/items")
    ok = s == 401
    print(f"[{'PASS' if ok else 'FAIL'}] 4. Protected API requires auth (GET /api/items -> {s}, expected 401)")
    if not ok:
        failures.append("protected-api")

    # 5) Deep-link fallback returns the SPA shell
    s, body, _ = get(f"{base}/items")
    ok = s == 200 and "app-root" in body
    print(f"[{'PASS' if ok else 'FAIL'}] 5. Deep-link fallback (GET /items -> {s})")
    if not ok:
        failures.append("deep-link")

    # Bonus) OAuth discovery + MCP challenge
    s, body, _ = get(f"{base}/.well-known/oauth-authorization-server")
    ok = s == 200 and "token_endpoint" in body
    print(f"[{'PASS' if ok else 'FAIL'}] +. OAuth AS metadata (GET /.well-known/oauth-authorization-server -> {s})")
    if not ok:
        failures.append("as-metadata")

    s, _, headers = get(f"{base}/mcp")
    challenge = headers.get("WWW-Authenticate", "")
    ok = s == 401 and "resource_metadata" in challenge
    print(f"[{'PASS' if ok else 'FAIL'}] +. MCP challenge (GET /mcp -> {s}; WWW-Authenticate has resource_metadata={('resource_metadata' in challenge)})")
    if not ok:
        failures.append("mcp-challenge")

    print()
    if failures:
        print(f"RESULT: FAILED ({', '.join(failures)})")
        sys.exit(1)
    print("RESULT: ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
