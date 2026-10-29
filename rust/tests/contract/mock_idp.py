#!/usr/bin/env python3
"""tests/integration/mock_authentik.py (imported by path, unchanged) with what the contract
tests need on top; everything else is the integration test's mock.

    mock_idp.py --port P --client-id netportal --client-secret S

Additions:
- POST /_test/users also remembers every person it was given (`known`, latest definition per
  sub). The users API answers the DIRECTORY: by default every known person as last posted, so an
  offboarding round started by one test leaves the other tests' people alone.
- POST /_test/directory {"override": {sub: user | null}} changes (or, null, removes) people
  in the directory only; {"only": [users]} replaces the whole directory; {"reset": true} drops
  overrides and "only"; {"page_size": n} pages the users API (Authentik's pagination: `next`
  is the next page NUMBER, 0 on the last page); {"fail": status | null} makes the users API
  answer that HTTP status.
- GET /_test/api-requests: [{"path", "query", "authorized"}] of the users API calls since the
  last /_test/directory call.
- A user may carry "omit": ["sub", "preferred_username", "name", "groups"], claims left out of
  the ID token (the portal's fallbacks and refusals).
"""

import argparse
import importlib.util
import json
import time
import urllib.parse
from http.server import ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

_PATH = Path(__file__).resolve().parents[3] / "tests" / "integration" / "mock_authentik.py"
_spec = importlib.util.spec_from_file_location("mock_authentik", _PATH)
mock = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mock)


class State(mock.State):
    def __init__(self, port, client_id, client_secret):
        super().__init__(port, client_id, client_secret)
        self.known = {}            # sub -> user (as last posted)
        self.override = {}         # sub -> user or None (removed from the directory)
        self.only = None           # a whole directory instead of known + override
        self.page_size = 100
        self.fail = None
        self.api_requests = []

    def directory(self):
        if self.only is not None:
            return list(self.only)
        people = dict(self.known)
        for sub, user in self.override.items():
            if user is None:
                people.pop(sub, None)
            else:
                people[sub] = user
        return list(people.values())

    def id_token(self, user, nonce):
        omit = set(user.get("omit") or ())
        if not omit:
            return super().id_token(user, nonce)
        now = int(time.time())
        body = {"iss": self.issuer, "aud": self.client_id, "sub": user["sub"], "iat": now, "exp": now + 300,
                "nonce": nonce, "preferred_username": user["username"], "name": user["name"],
                "groups": user["groups"], "email": user["username"] + "@example.org"}
        for key in omit:
            body.pop(key, None)
        head = mock.b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "k1"}).encode())
        signing = head + "." + mock.b64url(json.dumps(body).encode())
        return signing + "." + mock.b64url(self.key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256()))


def handler(st):
    base = mock.handler(st)

    class H(base):
        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            if url.path == "/api/v3/core/users/":
                return self.users_api(url)
            if url.path == "/_test/api-requests":
                return self.send(200, st.api_requests)
            return super().do_GET()

        def users_api(self, url):
            authorized = self.headers.get("Authorization") == "Bearer " + st.api_token
            st.api_requests.append({"path": url.path, "query": url.query, "authorized": authorized})
            if not authorized:
                return self.send(403, {"detail": "no"})
            if st.fail:
                return self.send(st.fail, {"detail": "failing on purpose"})
            people = st.directory()
            q = dict(urllib.parse.parse_qsl(url.query))
            page = int(q.get("page") or 1)
            pages = max(1, -(-len(people) // st.page_size))
            chunk = people[(page - 1) * st.page_size:page * st.page_size]
            results = [{"pk": i + 1, "username": u["username"], "uid": u["sub"], "is_active": u.get("active", True),
                        "groups_obj": [{"name": g} for g in u["groups"]]} for i, u in enumerate(chunk)]
            self.send(200, {"pagination": {"next": page + 1 if page < pages else 0, "previous": page - 1,
                                           "count": len(people), "current": page, "total_pages": pages},
                            "results": results})

        def do_POST(self):
            if self.path not in ("/_test/users", "/_test/directory"):
                return super().do_POST()
            data = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
            if self.path == "/_test/users":
                st.users = data
                for user in data:
                    st.known[user["sub"]] = user
            else:
                if data.get("reset"):
                    st.override, st.only, st.page_size, st.fail = {}, None, 100, None
                st.override.update(data.get("override") or {})
                if "only" in data:
                    st.only = data["only"]
                if "page_size" in data:
                    st.page_size = data["page_size"]
                if "fail" in data:
                    st.fail = data["fail"]
                st.api_requests = []
            self.send(200, {"ok": True})

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
