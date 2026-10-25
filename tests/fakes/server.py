"""The shared part of the fakes: a threaded HTTP server that answers GET with JSON."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class FakeServer:
    """Subclasses implement answer(path, params) -> (status, body as JSON-able)."""

    def __init__(self):
        self.requests = []                  # [(path, {param: value})], in order
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 (http.server's name)
                url = urlsplit(self.path)
                params = {k: v[-1] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
                with owner.lock:
                    owner.requests.append((url.path, params))
                try:
                    status, body = owner.answer(url.path, params)
                except Exception as e:  # noqa: BLE001 (a bug in a test's data: answer 500)
                    status, body = 500, {"status": "error", "error": repr(e)}
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    def answer(self, path, params):
        raise NotImplementedError

    def paths(self):
        with self.lock:
            return [p for p, _ in self.requests]
