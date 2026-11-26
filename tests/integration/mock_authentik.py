#!/usr/bin/env python3
"""Authentik as netportal sees it, for the integration test: OIDC provider (per-application
issuer, RS256 ID tokens with nonce and groups, PKCE checked, client secret basic or post) and
the users API (/api/v3/core/users/, uid = OIDC subject, groups_obj, is_active).

    mock_authentik.py --port P --client-id netportal --client-secret S
    POST /_test/users [{"sub", "username", "name", "groups", "active"}...]   (first one logs in)
"""

import argparse
import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class State:
    def __init__(self, port, client_id, client_secret):
        self.base = "http://127.0.0.1:%d" % port
        self.issuer = "%s/application/o/%s/" % (self.base, client_id)
        self.client_id, self.client_secret = client_id, client_secret
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.users = []
        self.codes = {}
        self.api_token = "mock-reader-token"

    def jwks(self):
        n = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
                          "n": b64url(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")),
                          "e": b64url(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big"))}]}

    def id_token(self, user, nonce):
        now = int(time.time())
        body = {"iss": self.issuer, "aud": self.client_id, "sub": user["sub"], "iat": now, "exp": now + 300,
                "nonce": nonce, "preferred_username": user["username"], "name": user["name"],
                "groups": user["groups"], "email": user["username"] + "@example.org"}
        head = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "k1"}).encode())
        signing = head + "." + b64url(json.dumps(body).encode())
        return signing + "." + b64url(self.key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256()))


def handler(st):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, data, ctype="application/json", headers=None):
            body = data if isinstance(data, bytes) else json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            q = dict(urllib.parse.parse_qsl(url.query))
            app = "/application/o/%s/" % st.client_id
            if url.path == app + ".well-known/openid-configuration":
                self.send(200, {
                    "issuer": st.issuer,
                    "authorization_endpoint": st.base + "/application/o/authorize/",
                    "token_endpoint": st.base + "/application/o/token/",
                    "userinfo_endpoint": st.base + "/application/o/userinfo/",
                    "jwks_uri": st.base + app + "jwks/",
                    "response_types_supported": ["code"], "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]})
            elif url.path == app + "jwks/":
                self.send(200, st.jwks())
            elif url.path == "/application/o/authorize/":
                if q.get("client_id") != st.client_id or not st.users or not q.get("nonce"):
                    self.send(400, {"error": "invalid_request"})
                    return
                code = secrets.token_urlsafe(16)
                st.codes[code] = {"user": dict(st.users[0]), "nonce": q["nonce"], "redirect_uri": q["redirect_uri"],
                                  "challenge": q.get("code_challenge")}
                target = q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": q.get("state", "")})
                self.send(302, b"", "text/plain", {"Location": target})
            elif url.path == "/api/v3/core/users/":
                if self.headers.get("Authorization") != "Bearer " + st.api_token:
                    self.send(403, {"detail": "no"})
                    return
                results = [{"pk": i + 1, "username": u["username"], "uid": u["sub"], "is_active": u.get("active", True),
                            "groups_obj": [{"name": g} for g in u["groups"]]} for i, u in enumerate(st.users)]
                self.send(200, {"pagination": {"next": 0, "current": 1, "count": len(results)}, "results": results})
            else:
                self.send(404, {"error": "not found"})

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if self.path == "/_test/users":
                st.users = json.loads(raw)
                self.send(200, {"ok": True})
                return
            if self.path != "/application/o/token/":
                self.send(404, {"error": "not found"})
                return
            form = dict(urllib.parse.parse_qsl(raw.decode()))
            cid, csec = form.get("client_id"), form.get("client_secret")
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Basic "):
                cid, _, csec = base64.b64decode(auth[6:]).decode().partition(":")
                cid, csec = urllib.parse.unquote(cid), urllib.parse.unquote(csec)
            if cid != st.client_id or csec != st.client_secret:
                self.send(401, {"error": "invalid_client"})
                return
            entry = st.codes.pop(form.get("code", ""), None)
            if not entry or form.get("redirect_uri") != entry["redirect_uri"]:
                self.send(400, {"error": "invalid_grant"})
                return
            if entry["challenge"]:
                verifier = form.get("code_verifier", "")
                if b64url(hashlib.sha256(verifier.encode()).digest()) != entry["challenge"]:
                    self.send(400, {"error": "invalid_grant", "error_description": "pkce"})
                    return
            self.send(200, {"access_token": secrets.token_urlsafe(16), "token_type": "Bearer", "expires_in": 300,
                            "id_token": st.id_token(entry["user"], entry["nonce"])})

    return H


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--client-secret", required=True)
    a = p.parse_args()
    ThreadingHTTPServer(("127.0.0.1", a.port), handler(State(a.port, a.client_id, a.client_secret))).serve_forever()


if __name__ == "__main__":
    main()
