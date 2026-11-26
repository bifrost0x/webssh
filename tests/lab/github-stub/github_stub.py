#!/usr/bin/env python3
"""Minimal stand-in for the GitHub OAuth and REST endpoints WebSSH calls.

Covers app/github_auth_service.py: authorize (PKCE S256), token exchange,
GET /user and GET /user/memberships/orgs/{org}. Users, organizations and the
client secret come from the per-run config. Lab use only.
"""

import base64
import hashlib
import hmac
import json
import secrets
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

CODE_TTL = 120
MAX_BODY = 16 * 1024


class State:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.codes = {}
        self.tokens = {}

    def issue_code(self, login, redirect_uri, challenge):
        code = secrets.token_urlsafe(24)
        with self.lock:
            self.codes[code] = (login, redirect_uri, challenge, time.monotonic() + CODE_TTL)
        return code

    def redeem(self, code, redirect_uri, verifier):
        with self.lock:
            entry = self.codes.pop(code, None)
        if entry is None:
            return None
        login, expected_uri, challenge, expires = entry
        if time.monotonic() > expires or redirect_uri != expected_uri:
            return None
        digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(digest, challenge):
            return None
        token = "gho_" + secrets.token_urlsafe(30)
        with self.lock:
            self.tokens[token] = login
        return token

    def login_for(self, header):
        if not header or not header.startswith("Bearer "):
            return None
        with self.lock:
            return self.tokens.get(header[len("Bearer "):])


class Handler(BaseHTTPRequestHandler):
    server_version = "lab-github-stub"
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @property
    def state(self):
        return self.server.state

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/login/oauth/authorize":
            return self.authorize(parse_qs(url.query))
        if url.path == "/healthz":
            return self.send_json(200, {"ok": True})
        login = self.state.login_for(self.headers.get("Authorization"))
        if login is None:
            return self.send_json(401, {"message": "Bad credentials"})
        user = self.state.config["users"][login]
        if url.path == "/user":
            return self.send_json(200, {"id": user["id"], "login": login, "name": user["name"]})
        prefix = "/user/memberships/orgs/"
        if url.path.startswith(prefix):
            org = url.path[len(prefix):]
            if org in self.state.config["unavailable_orgs"]:
                return self.send_json(502, {"message": "Server Error"})
            membership = user["orgs"].get(org)
            if membership is None:
                return self.send_json(404, {"message": "Not Found"})
            return self.send_json(200, {"state": membership, "role": "member",
                                        "organization": {"login": org}})
        return self.send_json(404, {"message": "Not Found"})

    def authorize(self, query):
        def one(name):
            values = query.get(name, [])
            return values[0] if len(values) == 1 else None
        cfg = self.state.config
        redirect_uri = one("redirect_uri")
        challenge = one("code_challenge")
        login = one("login") or cfg["default_login"]
        if (one("client_id") != cfg["client_id"] or not redirect_uri or not challenge
                or one("code_challenge_method") != "S256" or login not in cfg["users"]):
            return self.send_json(400, {"error": "invalid_request"})
        code = self.state.issue_code(login, redirect_uri, challenge)
        separator = "&" if "?" in redirect_uri else "?"
        params = {"code": code}
        if one("state") is not None:
            params["state"] = one("state")
        self.send_response(302)
        self.send_header("Location", redirect_uri + separator + urlencode(params))
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if urlsplit(self.path).path != "/login/oauth/access_token":
            return self.send_json(404, {"message": "Not Found"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self.send_json(413, {"error": "too_large"})
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items() if len(v) == 1}
        cfg = self.state.config
        if (form.get("client_id") != cfg["client_id"]
                or not hmac.compare_digest(form.get("client_secret", ""), cfg["client_secret"])):
            # GitHub answers 200 with an error body for bad client credentials.
            return self.send_json(200, {"error": "incorrect_client_credentials"})
        token = self.state.redeem(form.get("code", ""), form.get("redirect_uri", ""),
                                  form.get("code_verifier", ""))
        if token is None:
            return self.send_json(200, {"error": "bad_verification_code"})
        payload = {"access_token": token, "token_type": "bearer", "scope": ""}
        if "json" in (self.headers.get("Accept") or ""):
            return self.send_json(200, payload)
        body = urlencode(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-www-form-urlencoded")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    config_path, cert, key, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    with open(config_path, encoding="utf-8") as handle:
        config = json.load(handle)
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.state = State(config)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    # Handshake in the handler thread so one stalled client cannot block accept().
    server.socket = context.wrap_socket(server.socket, server_side=True,
                                        do_handshake_on_connect=False)
    server.serve_forever()


if __name__ == "__main__":
    main()
