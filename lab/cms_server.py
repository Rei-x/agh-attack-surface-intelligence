"""lab-cms (172.28.0.10:80): Simulated AGH Faculty WordPress 6.4.2 CMS portal."""

from common import BaseLabHandler, ReusableThreadingHTTPServer, make_deterministic_ico

FAVICON_BYTES = make_deterministic_ico((33, 117, 155), (255, 255, 255), seed=642)

INDEX_HTML = """<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="generator" content="WordPress 6.4.2" />
  <title>Wydział Informatyki AGH — Portal Aktualności</title>
  <link rel="icon" href="/favicon.ico" type="image/x-icon" />
  <link rel="stylesheet" href="/wp-content/themes/agh-portal/style.css?ver=6.4.2" />
  <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</head>
<body>
  <header>
    <h1>Portal Aktualności Wydziału Informatyki AGH</h1>
    <nav>
      <a href="/">Strona główna</a> |
      <a href="/wp-login.php">Logowanie redakcji</a> |
      <a href="/readme.html">Informacje</a>
    </nav>
  </header>
  <main>
    <article>
      <h2>Ogłoszenia semestralne 2026</h2>
      <p>Witamy na testowym portalu CMS przygotowanym dla laboratorium AegisASI (CBI AGH).</p>
    </article>
  </main>
  <footer>
    <p>&copy; 2026 Akademia Górniczo-Hutnicza | Powered by WordPress 6.4.2</p>
  </footer>
</body>
</html>
"""

WP_LOGIN_HTML = """<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="generator" content="WordPress 6.4.2" />
  <title>Log In &lsaquo; Wydział Informatyki AGH &#8212; WordPress</title>
</head>
<body class="login wp-core-ui">
  <div id="login">
    <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
    <form name="loginform" id="loginform" action="/wp-login.php" method="post">
      <p><label for="user_login">Username or Email Address</label><input type="text" id="user_login" /></p>
      <p><label for="user_pass">Password</label><input type="password" id="user_pass" /></p>
    </form>
  </div>
</body>
</html>
"""

README_HTML = """<!DOCTYPE html>
<html><head><title>WordPress &rsaquo; ReadMe</title></head>
<body><h1>WordPress</h1><p>Version 6.4.2</p></body></html>
"""

ROBOTS_TXT = """User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
"""


class CMSHandler(BaseLabHandler):
    server_banner = "Apache/2.4.58 (Debian)"

    def _base_headers(self) -> list[tuple[str, str]]:
        return [
            ("X-Powered-By", "PHP/8.2.15"),
            ("Set-Cookie", "wp-settings-1=m5; Path=/"),
            ("Set-Cookie", "wp-settings-time-1=1700000000; Path=/"),
        ]

    def _handle(self, head_only: bool) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.php"):
            self.send_response_body(200, INDEX_HTML, headers=self._base_headers(), head_only=head_only)
        elif path == "/wp-login.php":
            self.send_response_body(200, WP_LOGIN_HTML, headers=self._base_headers(), head_only=head_only)
        elif path in ("/wp-admin", "/wp-admin/"):
            headers = self._base_headers() + [
                ("Location", "/wp-login.php?redirect_to=%2Fwp-admin%2F"),
            ]
            self.send_response_body(302, "", headers=headers, head_only=head_only)
        elif path == "/readme.html":
            self.send_response_body(200, README_HTML, headers=self._base_headers(), head_only=head_only)
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
    print("[lab-cms] Listening on 0.0.0.0:80 (WordPress 6.4.2 simulation)", flush=True)
    ReusableThreadingHTTPServer(("0.0.0.0", 80), CMSHandler).serve_forever()
