"""lab-iot (172.28.0.13:8080): Simulated AGH networked HP LaserJet Pro MFP M428fdw IoT printer."""

from common import BaseLabHandler, ReusableThreadingHTTPServer, make_deterministic_ico

FAVICON_BYTES = make_deterministic_ico((0, 150, 214), (255, 255, 255), seed=428)

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>HP LaserJet Pro MFP M428fdw</title>
  <link rel="icon" href="/favicon.ico" type="image/x-icon" />
</head>
<body>
  <header>
    <h1>HP LaserJet Pro MFP M428fdw</h1>
    <p>Embedded Web Server — AGH Pawilon C-2, Pokój 114</p>
  </header>
  <main>
    <table>
      <tr><th>Device Status</th><td>Ready</td></tr>
      <tr><th>Firmware Datecode</th><td>20240219 (002_2341A)</td></tr>
      <tr><th>IPv4 Address</th><td>172.28.0.13</td></tr>
      <tr><th>Black Cartridge</th><td>74%</td></tr>
    </table>
    <p><a href="/info_deviceStatus.html">Detailed Device Status</a></p>
  </main>
  <footer>HP Embedded Web Server | Virata-EmWeb/R6_2_1</footer>
</body>
</html>
"""

DEVICE_STATUS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Device Status — HP LaserJet Pro MFP M428fdw</title>
</head>
<body>
  <h2>HP LaserJet Pro MFP M428fdw — Device Status</h2>
  <ul>
    <li>State: Ready</li>
    <li>Serial Number: PHB8N01428</li>
    <li>Hostname: printer-c2-114.agh.local</li>
    <li>Supplies: Black Toner 74%</li>
  </ul>
</body>
</html>
"""


class IoTPrinterHandler(BaseLabHandler):
    server_banner = "Virata-EmWeb/R6_2_1"

    def _base_headers(self) -> list[tuple[str, str]]:
        return [
            ("X-Frame-Options", "SAMEORIGIN"),
        ]

    def _handle(self, head_only: bool) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self.send_response_body(200, INDEX_HTML, headers=self._base_headers(), head_only=head_only)
        elif path == "/info_deviceStatus.html":
            self.send_response_body(200, DEVICE_STATUS_HTML, headers=self._base_headers(), head_only=head_only)
        elif path == "/favicon.ico":
            self.send_response_body(
                200, FAVICON_BYTES, content_type="image/x-icon", headers=[("Cache-Control", "public, max-age=86400")], head_only=head_only
            )
        else:
            self.send_response_body(404, "<h1>404 Object Not Found</h1>", headers=self._base_headers(), head_only=head_only)

    def do_GET(self) -> None:
        self._handle(head_only=False)

    def do_HEAD(self) -> None:
        self._handle(head_only=True)


if __name__ == "__main__":
    print("[lab-iot] Listening on 0.0.0.0:8080 (HP LaserJet Pro MFP M428fdw simulation)", flush=True)
    ReusableThreadingHTTPServer(("0.0.0.0", 8080), IoTPrinterHandler).serve_forever()
