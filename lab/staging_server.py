"""lab-staging (172.28.0.12:443): Simulated HTTPS Staging/Dev USOS Test Portal with self-signed TLS."""

import json
import os
import ssl
import subprocess

from common import BaseLabHandler, ReusableThreadingHTTPServer, make_deterministic_ico

CERT_PATH = "/tmp/staging.crt"
KEY_PATH = "/tmp/staging.key"

FAVICON_BYTES = make_deterministic_ico((124, 58, 237), (250, 204, 21), seed=2103)

INDEX_HTML = """<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="generator" content="Flask/3.0.2 Werkzeug/3.0.1" />
  <title>Staging - USOS Test Portal</title>
  <link rel="icon" href="/favicon.ico" type="image/x-icon" />
</head>
<body>
  <div style="background:#fef3c7;padding:8px;border:1px solid #f59e0b">
    <strong>STAGING ENVIRONMENT — DEBUG MODE ACTIVE</strong>
  </div>
  <h1>Staging - USOS Test Portal (AGH)</h1>
  <p>Wewnętrzne środowisko testowe przed wdrożeniem produkcyjnym.</p>
  <ul>
    <li><a href="/version">Build Version Info</a></li>
    <li><a href="/login">Test Login</a></li>
  </ul>
  <footer>USOS Test Portal 2.1.0-rc3-staging | Werkzeug/3.0.1 Python/3.12</footer>
</body>
</html>
"""

VERSION_PAYLOAD = json.dumps(
    {
        "service": "usos-test-portal",
        "version": "2.1.0-rc3-staging",
        "environment": "staging",
        "debug": True,
        "git_sha": "9f8a7b6c",
    }
)


def ensure_self_signed_cert() -> None:
    if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        return
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        KEY_PATH,
        "-out",
        CERT_PATH,
        "-days",
        "21",
        "-subj",
        "/C=PL/ST=Malopolskie/L=Krakow/O=AGH University Staging/CN=staging.usos.agh.edu.pl",
        "-addext",
        "subjectAltName=DNS:staging.usos.agh.edu.pl,DNS:dev-usos.agh.local,IP:172.28.0.12",
    ]
    subprocess.run(cmd, check=True)
    print(f"[lab-staging] Generated self-signed TLS certificate at {CERT_PATH}", flush=True)


class StagingHandler(BaseLabHandler):
    server_banner = "Werkzeug/3.0.1 Python/3.12"

    def _base_headers(self) -> list[tuple[str, str]]:
        return [
            ("X-Debug-Token", "9f8a7b6c"),
            ("X-Environment", "staging"),
            ("Set-Cookie", "staging_session=dev_9f8a7b6c; Path=/"),
        ]

    def _handle(self, head_only: bool) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self.send_response_body(200, INDEX_HTML, headers=self._base_headers(), head_only=head_only)
        elif path == "/version":
            self.send_response_body(
                200,
                VERSION_PAYLOAD,
                content_type="application/json; charset=utf-8",
                headers=self._base_headers(),
                head_only=head_only,
            )
        elif path == "/login":
            self.send_response_body(
                200,
                "<html><head><title>Staging Login - USOS Test Portal</title></head><body><h1>USOS Staging Login</h1></body></html>",
                headers=self._base_headers(),
                head_only=head_only,
            )
        elif path == "/robots.txt":
            self.send_response_body(
                200,
                "User-agent: *\nDisallow: /\n",
                content_type="text/plain; charset=utf-8",
                headers=self._base_headers(),
                head_only=head_only,
            )
        elif path == "/favicon.ico":
            self.send_response_body(
                200, FAVICON_BYTES, content_type="image/x-icon", headers=[("Cache-Control", "public, max-age=86400")], head_only=head_only
            )
        else:
            self.send_response_body(404, "<h1>404 Not Found</h1>", headers=self._base_headers(), head_only=head_only)

    def do_GET(self) -> None:
        self._handle(head_only=False)

    def do_HEAD(self) -> None:
        self._handle(head_only=True)


if __name__ == "__main__":
    ensure_self_signed_cert()
    httpd = ReusableThreadingHTTPServer(("0.0.0.0", 443), StagingHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("[lab-staging] Listening on 0.0.0.0:443 (HTTPS self-signed Staging portal)", flush=True)
    httpd.serve_forever()
