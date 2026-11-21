"""lab-admin (172.28.0.11:80): Simulated CBI AGH Internal Admin Console / Grafana-style portal."""

from common import BaseLabHandler, ReusableThreadingHTTPServer, make_deterministic_ico

FAVICON_BYTES = make_deterministic_ico((244, 104, 0), (24, 27, 31), seed=1101)

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>CBI AGH Internal Admin Console</title>
  <link rel="icon" href="/favicon.ico" type="image/x-icon" />
</head>
<body>
  <h1>CBI AGH Internal Admin Console</h1>
  <p>Restricted Infrastructure &amp; Grafana Telemetry Operations Portal.</p>
  <ul>
    <li><a href="/admin">Admin Management Panel</a></li>
    <li><a href="/login">Grafana Operator Login</a></li>
  </ul>
  <footer>CBI AGH Operations Console v4.2.1 | Grafana UI / Express</footer>
</body>
</html>
"""

ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Admin Panel — CBI AGH Internal Admin Console</title>
</head>
<body>
  <h1>Internal Administration Dashboard</h1>
  <p>Cluster nodes: 14 | Active alerts: 3 | Role: restricted</p>
  <form action="/login" method="post">
    <input type="text" name="username" placeholder="Admin username" />
    <input type="password" name="password" placeholder="Password" />
  </form>
</body>
</html>
"""

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Grafana — CBI AGH Internal Admin Console</title>
</head>
<body>
  <script>window.grafanaBootData = { settings: { buildInfo: { version: "10.4.1" } } };</script>
  <h1>Welcome to Grafana (CBI AGH)</h1>
  <form action="/login" method="post">
    <label>Email or username</label><input type="text" name="user" />
    <label>Password</label><input type="password" name="password" />
  </form>
</body>
</html>
"""

ROBOTS_TXT = """User-agent: *
Disallow: /admin
Disallow: /login
Disallow: /metrics
"""


class AdminHandler(BaseLabHandler):
    server_banner = "nginx/1.25.3"

    def _base_headers(self) -> list[tuple[str, str]]:
        # Intentionally sets cookie without HttpOnly/Secure and exposes Express header
        return [
            ("X-Powered-By", "Express"),
            ("X-Admin-Node", "cbi-ops-01.agh.edu.pl"),
            ("Set-Cookie", "admin_session=demo_tok; Path=/"),
        ]

    def _handle(self, head_only: bool) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self.send_response_body(200, INDEX_HTML, headers=self._base_headers(), head_only=head_only)
        elif path in ("/admin", "/admin/"):
            self.send_response_body(200, ADMIN_HTML, headers=self._base_headers(), head_only=head_only)
        elif path in ("/login", "/login/"):
            self.send_response_body(200, LOGIN_HTML, headers=self._base_headers(), head_only=head_only)
        elif path == "/robots.txt":
            self.send_response_body(
                200, ROBOTS_TXT, content_type="text/plain; charset=utf-8", headers=self._base_headers(), head_only=head_only
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
    print("[lab-admin] Listening on 0.0.0.0:80 (CBI AGH Admin Console simulation)", flush=True)
    ReusableThreadingHTTPServer(("0.0.0.0", 80), AdminHandler).serve_forever()
