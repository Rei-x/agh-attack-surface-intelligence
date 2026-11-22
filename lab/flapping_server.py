"""lab-flapping (172.28.0.14:80 + control API :9999): Dynamic mutating & flapping host.

Control API (exposed on host :19999):
  GET  /status                         -> current mode and listener state
  POST /control?mode=normal|changed|down -> switches host behavior live between scans
  GET  /health                         -> healthcheck

Modes:
  - normal:  200 OK, title "AGH Moodle E-Learning", Server: nginx/1.24.0, MoodleSession cookie
  - changed: 200 OK, title "AGH Moodle Maintenance - Admin Exposed", /admin -> 200 OK,
             header X-Staging-Debug: true, changed Server banner (Apache/2.4.52)
  - down:    stops listening on TCP port 80 so nmap & HTTP probes observe host/service down!
"""

import json
import threading
from urllib.parse import parse_qs, urlparse

from common import BaseLabHandler, ReusableThreadingHTTPServer, make_deterministic_ico

VALID_MODES = ("normal", "changed", "down")

FAVICON_NORMAL = make_deterministic_ico((249, 128, 18), (255, 255, 255), seed=432)
FAVICON_CHANGED = make_deterministic_ico((220, 38, 38), (254, 240, 138), seed=999)

NORMAL_INDEX_HTML = """<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="keywords" content="moodle, AGH Moodle E-Learning" />
  <title>AGH Moodle E-Learning</title>
  <link rel="icon" href="/favicon.ico" type="image/x-icon" />
</head>
<body>
  <h1>AGH Moodle E-Learning</h1>
  <p>Platforma zdalnego nauczania Akademii Górniczo-Hutniczej.</p>
  <a href="/login/index.php">Zaloguj się</a>
  <footer>Powered by Moodle 4.3.2 (Build: 20240212)</footer>
</body>
</html>
"""

CHANGED_INDEX_HTML = """<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <title>AGH Moodle Maintenance - Admin Exposed</title>
  <link rel="icon" href="/favicon.ico" type="image/x-icon" />
</head>
<body>
  <div style="background:#fee2e2;padding:8px">MAINTENANCE MODE: DEBUG &amp; ADMIN EXPOSED</div>
  <h1>AGH Moodle Maintenance - Admin Exposed</h1>
  <p>Temporary maintenance interface active. <a href="/admin">Open Admin Console</a></p>
  <footer>Moodle 4.3.2-hotfix-staging | Apache/2.4.52</footer>
</body>
</html>
"""

CHANGED_ADMIN_HTML = """<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <title>Moodle Site Administration - Exposed Maintenance Panel</title>
</head>
<body>
  <h1>Moodle Site Administration</h1>
  <p>Exposed administrative endpoint during maintenance window.</p>
</body>
</html>
"""


class FlappingState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.mode: str = "normal"
        self.transitions: int = 0
        self._httpd: ReusableThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start_port80(self) -> None:
        if self._httpd is not None:
            return
        srv = ReusableThreadingHTTPServer(("0.0.0.0", 80), ServiceHandler)
        t = threading.Thread(target=srv.serve_forever, name="flapping-port80", daemon=True)
        t.start()
        self._httpd = srv
        self._thread = t
        print("[lab-flapping] Port 80 listener STARTED", flush=True)

    def stop_port80(self) -> None:
        srv = self._httpd
        t = self._thread
        self._httpd = None
        self._thread = None
        if srv is not None:
            srv.shutdown()
            srv.server_close()
            if t is not None:
                t.join(timeout=2.0)
            print("[lab-flapping] Port 80 listener STOPPED (mode=down)", flush=True)

    def set_mode(self, new_mode: str) -> tuple[str, str, bool]:
        with self._lock:
            prev = self.mode
            self.mode = new_mode
            if new_mode != prev:
                self.transitions += 1
            if new_mode == "down":
                self.stop_port80()
            else:
                self.start_port80()
            return prev, self.mode, self._httpd is not None

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "mode": self.mode,
                "transitions": self.transitions,
                "port80_listening": self._httpd is not None,
            }


STATE = FlappingState()


class ServiceHandler(BaseLabHandler):
    def version_string(self) -> str:
        if STATE.mode == "changed":
            return "Apache/2.4.52 (Ubuntu)"
        return "nginx/1.24.0"

    def _handle(self, head_only: bool) -> None:
        mode = STATE.mode
        if mode == "down":
            # Safety fallback if a request raced with listener shutdown
            self.close_connection = True
            return

        path = self.path.split("?", 1)[0]
        if mode == "normal":
            headers = [
                ("Set-Cookie", "MoodleSession=agh2026moodle001; Path=/; HttpOnly"),
                ("X-Frame-Options", "SAMEORIGIN"),
                ("X-Content-Type-Options", "nosniff"),
            ]
            if path == "/":
                self.send_response_body(200, NORMAL_INDEX_HTML, headers=headers, head_only=head_only)
            elif path == "/login/index.php":
                self.send_response_body(
                    200,
                    "<html><head><title>AGH Moodle E-Learning: Log in</title></head><body><h1>Moodle Login</h1></body></html>",
                    headers=headers,
                    head_only=head_only,
                )
            elif path in ("/admin", "/admin/"):
                self.send_response_body(403, "<h1>403 Forbidden</h1>", headers=headers, head_only=head_only)
            elif path == "/favicon.ico":
                self.send_response_body(200, FAVICON_NORMAL, content_type="image/x-icon", head_only=head_only)
            else:
                self.send_response_body(404, "<h1>404 Not Found</h1>", headers=headers, head_only=head_only)
        else:
            # mode == "changed"
            headers = [
                ("X-Staging-Debug", "true"),
                ("X-Maintenance-Bypass", "enabled"),
                ("Set-Cookie", "MoodleSession=agh2026debug999; Path=/"),
            ]
            if path == "/":
                self.send_response_body(200, CHANGED_INDEX_HTML, headers=headers, head_only=head_only)
            elif path in ("/admin", "/admin/"):
                self.send_response_body(200, CHANGED_ADMIN_HTML, headers=headers, head_only=head_only)
            elif path == "/version":
                self.send_response_body(
                    200,
                    json.dumps({"app": "moodle", "version": "4.3.2-hotfix-staging", "debug": True}),
                    content_type="application/json; charset=utf-8",
                    headers=headers,
                    head_only=head_only,
                )
            elif path == "/favicon.ico":
                self.send_response_body(200, FAVICON_CHANGED, content_type="image/x-icon", head_only=head_only)
            else:
                self.send_response_body(404, "<h1>404 Not Found</h1>", headers=headers, head_only=head_only)

    def do_GET(self) -> None:
        self._handle(head_only=False)

    def do_HEAD(self) -> None:
        self._handle(head_only=True)


class ControlHandler(BaseLabHandler):
    server_banner = "DzieciolLabControl/1.0"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in ("/health", "/status", "/control"):
            payload = {"status": "ok", **STATE.snapshot()}
            self.send_response_body(200, json.dumps(payload), content_type="application/json")
        else:
            self.send_response_body(404, json.dumps({"error": "not found"}), content_type="application/json")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/control":
            self.send_response_body(404, json.dumps({"error": "use POST /control?mode=normal|changed|down"}), content_type="application/json")
            return

        qs = parse_qs(parsed.query)
        mode = qs.get("mode", [""])[0].strip().lower()
        if not mode:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > 0:
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw.decode("utf-8"))
                    mode = str(body.get("mode", "")).strip().lower()
                except Exception:
                    pass

        if mode not in VALID_MODES:
            self.send_response_body(
                400,
                json.dumps({"error": f"invalid mode '{mode}', expected one of {list(VALID_MODES)}"}),
                content_type="application/json",
            )
            return

        prev, current, listening = STATE.set_mode(mode)
        self.send_response_body(
            200,
            json.dumps(
                {
                    "previous_mode": prev,
                    "mode": current,
                    "port80_listening": listening,
                    "transitions": STATE.snapshot()["transitions"],
                }
            ),
            content_type="application/json",
        )


if __name__ == "__main__":
    STATE.start_port80()
    print("[lab-flapping] Control API listening on 0.0.0.0:9999 (host :19999)", flush=True)
    ReusableThreadingHTTPServer(("0.0.0.0", 9999), ControlHandler).serve_forever()
