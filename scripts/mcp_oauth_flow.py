#!/usr/bin/env python3
"""Scripted MCP OAuth flow against a deployed PolyAuth sample.

Exercises the Claude-Desktop-style path end-to-end:
  Firebase sign-in -> /api/oauth/session (cookie) -> /connect/authorize (PKCE + consent)
  -> loopback redirect with code -> /connect/token (authorization_code + PKCE)
  -> MCP initialize + tools/list with the issued mcp.read/mcp.write token.

Usage:
  python mcp_oauth_flow.py https://web-xxxx.azurewebsites.net e2e@polyauth.test "Passw0rd!longenough"

The Firebase Web API key is read from {base}/config.json.
"""
import sys
import json
import base64
import hashlib
import os
import http.cookiejar
import urllib.request
import urllib.parse
import urllib.error


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class StopRedirect(urllib.request.HTTPRedirectHandler):
    location = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        StopRedirect.location = newurl
        return None  # do not follow


def make_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(StopRedirect, urllib.request.HTTPCookieProcessor(jar)), jar


def post_json(url, body, headers=None):
    data = json.dumps(body).encode()
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def main():
    base = sys.argv[1].rstrip("/")
    email = sys.argv[2]
    password = sys.argv[3]

    # 0) read firebase api key from /config.json
    with urllib.request.urlopen(f"{base}/config.json", timeout=30) as r:
        cfg = json.loads(r.read())
    api_key = cfg["firebase"]["apiKey"]

    # 1) Firebase sign-in (sign up first if the user does not exist)
    id_token = firebase_id_token(api_key, email, password)
    print("[1] obtained Firebase ID token")

    opener, _ = make_opener()

    # 2) Establish the OAuthSession cookie from the Firebase login
    req = urllib.request.Request(
        f"{base}/api/oauth/session",
        data=json.dumps({"returnUrl": "/"}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {id_token}"},
        method="POST",
    )
    with opener.open(req, timeout=30) as r:
        assert r.status == 200, f"session login failed: {r.status}"
    print("[2] established OAuthSession cookie")

    # 3) PKCE + authorization request for the loopback (Claude-style) client
    verifier = b64url(os.urandom(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    redirect_uri = "http://127.0.0.1:8765/callback"
    params = {
        "response_type": "code",
        "client_id": "claude-desktop",
        "redirect_uri": redirect_uri,
        "scope": "openid offline_access mcp.read mcp.write",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "xyz123",
    }
    authorize_url = f"{base}/connect/authorize?{urllib.parse.urlencode(params)}"

    # GET -> consent page (third-party client); then POST approve.
    with opener.open(authorize_url, timeout=30) as r:
        _ = r.read()
    StopRedirect.location = None
    approve = dict(params)
    approve["consent_action"] = "approve"
    req = urllib.request.Request(
        f"{base}/connect/authorize",
        data=urllib.parse.urlencode(approve).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with opener.open(req, timeout=30) as r:
            _ = r.read()
    except urllib.error.HTTPError:
        pass
    location = StopRedirect.location
    assert location and location.startswith(redirect_uri), f"expected loopback redirect, got {location}"
    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
    print(f"[3] authorization code issued to loopback redirect")

    # 4) Exchange the code (PKCE) for tokens
    token = post_form(f"{base}/connect/token", {
        "grant_type": "authorization_code",
        "client_id": "claude-desktop",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    })
    access_token = token["access_token"]
    print(f"[4] exchanged code for access token (scope={token.get('scope')})")

    # 5) MCP initialize + tools/list with the token
    tools = mcp_tools_list(f"{base}/mcp", access_token)
    print(f"[5] MCP tools/list -> {tools}")
    # Generic verifier: any consuming app has its own tools. Optionally pass expected tool names as
    # extra args (argv[4:]) that must be present.
    assert tools, "tools/list returned no tools"
    expected = sys.argv[4:]
    missing = [t for t in expected if t not in tools]
    assert not missing, f"missing expected tools: {missing}"
    print("\nRESULT: auth-code + PKCE + loopback + MCP tools/list SUCCEEDED")


def firebase_id_token(api_key, email, password):
    base = "https://identitytoolkit.googleapis.com/v1/accounts"
    body = {"email": email, "password": password, "returnSecureToken": True}
    try:
        return post_json(f"{base}:signInWithPassword?key={api_key}", body)["idToken"]
    except urllib.error.HTTPError:
        # Create the user, then sign in.
        try:
            return post_json(f"{base}:signUp?key={api_key}", body)["idToken"]
        except urllib.error.HTTPError:
            return post_json(f"{base}:signInWithPassword?key={api_key}", body)["idToken"]


def post_form(url, fields):
    req = urllib.request.Request(
        url, data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def mcp_tools_list(mcp_url, token):
    session = {"id": None}

    def call(payload, notify=False):
        req = urllib.request.Request(
            mcp_url, data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {token}",
                **({"Mcp-Session-Id": session["id"]} if session["id"] else {}),
            }, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            if "Mcp-Session-Id" in r.headers and not session["id"]:
                session["id"] = r.headers["Mcp-Session-Id"]
            body = r.read().decode()
        if notify:
            return None
        return extract_json(body)

    call({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                     "clientInfo": {"name": "polyauth-script", "version": "1.0"}}})
    call({"jsonrpc": "2.0", "method": "notifications/initialized"}, notify=True)
    result = call({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    return [t["name"] for t in result.get("result", {}).get("tools", [])]


def extract_json(body):
    s = body.lstrip()
    if s.startswith("{") or s.startswith("["):
        return json.loads(body)
    data = "".join(line[len("data:"):].strip() for line in body.splitlines() if line.startswith("data:"))
    return json.loads(data) if data else json.loads(body)


if __name__ == "__main__":
    main()
