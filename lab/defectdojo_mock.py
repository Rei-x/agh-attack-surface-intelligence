"""lab-defectdojo-mock (172.28.0.20:8000, host :18000): DefectDojo API v2 mock + live HTML viewer.

Implements DefectDojo API v2 endpoints used by Dzięcioł:
  - GET  /api/v2/users/
  - GET  /api/v2/products/
  - GET  /api/v2/engagements/
  - GET  /api/v2/test_types/
  - GET  /api/v2/tests/
  - POST /api/v2/tests/
  - POST /api/v2/import-scan/   (multipart/form-data Nmap Scan XML)
  - POST /api/v2/reimport-scan/ (Nmap Scan / Generic Findings Import, auto_create_context)
  - GET  /api/v2/{engagements,products,product_types}/<id>/
  - GET  /api/v2/findings/
  - POST /api/v2/findings/
  - POST /api/v2/reset/
  - GET  /ui                    (live offline-capable HTML viewer for received scans & findings)
  - GET  /health
"""

import datetime
import html
import json
import os
import threading
import xml.etree.ElementTree as ET
from email.parser import BytesParser
from email.policy import default as email_policy_default
from urllib.parse import parse_qs, urlparse

from common import BaseLabHandler, ReusableThreadingHTTPServer

PUBLIC_BASE_URL = os.environ.get("DD_PUBLIC_BASE_URL", "http://localhost:18000").rstrip("/")


class DefectDojoStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.next_test_id = 100
            self.next_finding_id = 1000
            self.scans: list[dict[str, object]] = []
            self.findings: list[dict[str, object]] = []
            self.tests: list[dict[str, object]] = [
                {
                    "id": 1,
                    "engagement": 1,
                    "test_type": 1,
                    "title": "Dzięcioł Continuous Discovery",
                    "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
            ]

    def test_for_title(self, title: str) -> int:
        with self._lock:
            for t in self.tests:
                if t.get("title") == title:
                    return int(t["id"])
            self.next_test_id += 1
            self.tests.append({"id": self.next_test_id, "engagement": 1, "test_type": 1, "title": title,
                               "created": datetime.datetime.now(datetime.timezone.utc).isoformat()})
            return self.next_test_id

    def add_test(self, data: dict[str, object]) -> dict[str, object]:
        with self._lock:
            self.next_test_id += 1
            item = {
                "id": self.next_test_id,
                "engagement": int(data.get("engagement", 1) or 1),
                "test_type": int(data.get("test_type", 1) or 1),
                "title": str(data.get("title") or "Dzięcioł Findings"),
                "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self.tests.append(item)
            return item

    def add_scan(
        self,
        scan_type: str,
        engagement_id: int,
        scan_date: str,
        filename: str,
        raw_xml: str,
        tags: list[str],
    ) -> dict[str, object]:
        hosts_parsed = 0
        ports_parsed = 0
        try:
            root = ET.fromstring(raw_xml)
            hosts_parsed = len(root.findall(".//host"))
            ports_parsed = len(root.findall(".//port"))
        except ET.ParseError:
            pass

        with self._lock:
            self.next_test_id += 1
            test_id = self.next_test_id
            record = {
                "id": test_id,
                "test": test_id,
                "test_id": test_id,
                "product_id": 1,
                "engagement_id": engagement_id,
                "scan_type": scan_type,
                "scan_date": scan_date,
                "filename": filename,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "hosts_parsed": hosts_parsed,
                "ports_parsed": ports_parsed,
                "finding_count": max(ports_parsed, hosts_parsed),
                "tags": tags,
                "raw_xml": raw_xml,
                "received_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "url": f"{PUBLIC_BASE_URL}/ui#scan-{test_id}",
            }
            self.scans.insert(0, record)
            return record

    def add_finding(self, payload: dict[str, object]) -> tuple[dict[str, object], bool]:
        uid = str(payload.get("unique_id_from_tool") or "").strip()
        with self._lock:
            if uid:
                for existing in self.findings:
                    if existing.get("unique_id_from_tool") == uid:
                        existing["duplicate_updates"] = int(existing.get("duplicate_updates", 0)) + 1
                        existing["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        return existing, True

            self.next_finding_id += 1
            fid = self.next_finding_id
            item = {
                "id": fid,
                "title": str(payload.get("title") or "Untitled Dzięcioł Finding"),
                "description": str(payload.get("description") or ""),
                "severity": str(payload.get("severity") or "Medium"),
                "numerical_severity": str(payload.get("numerical_severity") or "S2"),
                "test": int(payload.get("test", 1) or 1),
                "engagement": int(payload.get("engagement", 1) or 1),
                "active": bool(payload.get("active", True)),
                "verified": bool(payload.get("verified", True)),
                "unique_id_from_tool": uid,
                "vuln_id_from_tool": str(payload.get("vuln_id_from_tool") or "dzieciol"),
                "mitigation": str(payload.get("mitigation") or ""),
                "references": str(payload.get("references") or ""),
                "tags": payload.get("tags") if isinstance(payload.get("tags"), list) else [],
                "endpoints": payload.get("endpoints") if isinstance(payload.get("endpoints"), list) else [],
                "received_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "duplicate_updates": 0,
                "url": f"{PUBLIC_BASE_URL}/ui#finding-{fid}",
            }
            self.findings.insert(0, item)
            return item, False

    def snapshot(self) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        with self._lock:
            return list(self.scans), list(self.findings)


STORE = DefectDojoStore()


def parse_multipart(content_type: str, body: bytes) -> tuple[dict[str, str], dict[str, tuple[str, bytes]]]:
    """Parse multipart/form-data using stdlib email.parser (Python 3.12+ safe)."""
    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
    msg = BytesParser(policy=email_policy_default).parsebytes(header + body)
    fields: dict[str, str] = {}
    files: dict[str, tuple[str, bytes]] = {}
    if not msg.is_multipart():
        return fields, files
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename:
            files[name] = (filename, payload)
        else:
            fields[name] = payload.decode("utf-8", errors="replace")
    return fields, files


def render_ui_html() -> str:
    scans, findings = STORE.snapshot()
    total_hosts = sum(int(s.get("hosts_parsed", 0)) for s in scans)
    total_ports = sum(int(s.get("ports_parsed", 0)) for s in scans)

    scan_rows = []
    for s in scans:
        sid = s["id"]
        xml_preview = html.escape(str(s.get("raw_xml", ""))[:6000])
        scan_rows.append(
            f"""<article class="card" id="scan-{sid}">
              <div class="card-head">
                <div>
                  <span class="badge badge-blue">Nmap Scan #{sid}</span>
                  <strong>{html.escape(str(s.get('filename', 'nmap.xml')))}</strong>
                  <span class="muted">Engagement #{s.get('engagement_id')} &middot; {html.escape(str(s.get('scan_type')))}</span>
                </div>
                <span class="muted">{html.escape(str(s.get('received_at')))}</span>
              </div>
              <div class="meta">
                Hosts parsed: <strong>{s.get('hosts_parsed')}</strong> &middot;
                Ports parsed: <strong>{s.get('ports_parsed')}</strong> &middot;
                Scan date: <strong>{html.escape(str(s.get('scan_date')))}</strong>
              </div>
              <details>
                <summary>View raw Nmap XML ({len(str(s.get('raw_xml', '')))} bytes)</summary>
                <pre>{xml_preview}</pre>
              </details>
            </article>"""
        )

    finding_rows = []
    sev_colors = {
        "critical": "badge-red",
        "high": "badge-red",
        "medium": "badge-amber",
        "low": "badge-blue",
        "info": "badge-slate",
    }
    for f in findings:
        fid = f["id"]
        sev = str(f.get("severity", "Medium"))
        cls = sev_colors.get(sev.lower(), "badge-slate")
        tags_html = " ".join(f'<span class="tag">{html.escape(str(t))}</span>' for t in (f.get("tags") or []))
        uid = html.escape(str(f.get("unique_id_from_tool") or "-"))
        desc = html.escape(str(f.get("description") or ""))
        dedup_note = (
            f' <span class="badge badge-slate">dedup hits: {f["duplicate_updates"]}</span>'
            if int(f.get("duplicate_updates", 0)) > 0
            else ""
        )
        finding_rows.append(
            f"""<article class="card" id="finding-{fid}">
              <div class="card-head">
                <div>
                  <span class="badge {cls}">{html.escape(sev)}</span>
                  <strong>#{fid} &mdash; {html.escape(str(f.get('title')))}</strong>{dedup_note}
                </div>
                <span class="muted">{html.escape(str(f.get('received_at')))}</span>
              </div>
              <div class="meta">
                Test #{f.get('test')} &middot; unique_id_from_tool: <code>{uid}</code> {tags_html}
              </div>
              <details open>
                <summary>Evidence &amp; Description</summary>
                <pre>{desc}</pre>
              </details>
            </article>"""
        )

    scans_html = "\n".join(scan_rows) if scan_rows else '<p class="empty">No Nmap XML scans received yet. Push a scan from Dzięcioł to see it here.</p>'
    findings_html = "\n".join(finding_rows) if finding_rows else '<p class="empty">No Findings pushed yet. Select a host/service in Dzięcioł and click "Push to DefectDojo".</p>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="refresh" content="10" />
  <title>DefectDojo v2 Mock Receiver — CBI AGH Demo</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#0b1120; color:#e2e8f0; margin:0; padding:24px; line-height:1.5; }}
    .wrap {{ max-width:1100px; margin:0 auto; }}
    header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #1e293b; padding-bottom:16px; margin-bottom:24px; }}
    h1 {{ margin:0; font-size:22px; color:#f8fafc; }}
    h2 {{ font-size:16px; text-transform:uppercase; letter-spacing:0.06em; color:#94a3b8; margin:28px 0 12px; }}
    .kpis {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:24px; }}
    .kpi {{ background:#111827; border:1px solid #1e293b; border-radius:10px; padding:14px 16px; }}
    .kpi .val {{ font-size:28px; font-weight:700; color:#38bdf8; }}
    .kpi .lbl {{ font-size:12px; color:#94a3b8; text-transform:uppercase; }}
    .card {{ background:#111827; border:1px solid #1e293b; border-radius:10px; padding:16px; margin-bottom:12px; }}
    .card-head {{ display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; }}
    .meta {{ font-size:13px; color:#94a3b8; margin:8px 0; }}
    .muted {{ color:#64748b; font-size:12px; }}
    .badge {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; margin-right:6px; }}
    .badge-red {{ background:#7f1d1d; color:#fecaca; }}
    .badge-amber {{ background:#78350f; color:#fde68a; }}
    .badge-blue {{ background:#0c4a6e; color:#bae6fd; }}
    .badge-slate {{ background:#1e293b; color:#cbd5e1; }}
    .tag {{ display:inline-block; background:#1e293b; color:#93c5fd; padding:1px 6px; border-radius:4px; font-size:11px; margin-left:4px; }}
    pre {{ background:#020617; border:1px solid #1e293b; border-radius:6px; padding:12px; overflow-x:auto; font-size:12px; white-space:pre-wrap; }}
    code {{ background:#1e293b; padding:1px 5px; border-radius:4px; font-size:12px; }}
    .empty {{ color:#64748b; background:#111827; border:1px dashed #334155; border-radius:10px; padding:20px; text-align:center; }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div>
        <h1>DefectDojo API v2 Mock Receiver</h1>
        <div class="muted">Offline-ready live viewer for Dzięcioł (CBI AGH) &middot; Auto-refreshes every 10s</div>
      </div>
      <div class="muted">API base: <code>http://172.28.0.20:8000/api/v2/</code></div>
    </header>
    <section class="kpis">
      <div class="kpi"><div class="val">{len(scans)}</div><div class="lbl">Nmap Scans Imported</div></div>
      <div class="kpi"><div class="val">{len(findings)}</div><div class="lbl">Findings Pushed</div></div>
      <div class="kpi"><div class="val">{total_hosts}</div><div class="lbl">Nmap Hosts Parsed</div></div>
      <div class="kpi"><div class="val">{total_ports}</div><div class="lbl">Nmap Ports Parsed</div></div>
    </section>
    <h2>Received Findings (POST /api/v2/findings/)</h2>
    {findings_html}
    <h2>Received Nmap Scans (POST /api/v2/import-scan/)</h2>
    {scans_html}
  </div>
</body>
</html>
"""


class DefectDojoHandler(BaseLabHandler):
    server_banner = "DefectDojo-Mock/2.38"

    def _check_auth(self) -> bool:
        auth = (self.headers.get("Authorization") or "").strip()
        if not auth:
            self.send_response_body(
                401,
                json.dumps({"detail": "Authentication credentials were not provided. Use 'Authorization: Token <token>'."}),
                content_type="application/json",
            )
            return False
        if auth.lower() in ("token invalid", "token bad"):
            self.send_response_body(
                401,
                json.dumps({"detail": "Invalid token."}),
                content_type="application/json",
            )
            return False
        return True

    def _read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            self.send_response_body(200, json.dumps({"status": "ok", "service": "defectdojo-v2-mock"}), content_type="application/json")
            return
        if path == "/":
            self.send_response_body(302, "", headers=[("Location", "/ui")])
            return
        if path in ("/ui", "/ui/"):
            self.send_response_body(200, render_ui_html(), content_type="text/html; charset=utf-8")
            return

        if path.startswith("/api/v2/"):
            if not self._check_auth():
                return

        detail = {
            "/api/v2/engagements/1/": {"id": 1, "name": "CBI AGH Continuous Attack Surface Discovery", "product": 1},
            "/api/v2/products/1/": {"id": 1, "name": "AGH University Campus Network", "prod_type": 1},
            "/api/v2/product_types/1/": {"id": 1, "name": "Dzięcioł"},
        }
        if path in detail:
            self.send_response_body(200, json.dumps(detail[path]), content_type="application/json")
            return

        if path in ("/api/v2/users/", "/api/v2/users"):
            self.send_response_body(
                200,
                json.dumps(
                    {
                        "count": 1,
                        "next": None,
                        "previous": None,
                        "results": [
                            {
                                "id": 1,
                                "username": "dzieciol-integrator",
                                "first_name": "Dzięcioł",
                                "last_name": "CBI AGH",
                                "email": "soc@agh.edu.pl",
                                "is_active": True,
                                "is_superuser": True,
                            }
                        ],
                    }
                ),
                content_type="application/json",
            )
        elif path in ("/api/v2/products/", "/api/v2/products"):
            self.send_response_body(
                200,
                json.dumps(
                    {
                        "count": 1,
                        "next": None,
                        "previous": None,
                        "results": [
                            {
                                "id": 1,
                                "name": "AGH University Campus Network",
                                "description": "CBI AGH Attack Surface Intelligence",
                            }
                        ],
                    }
                ),
                content_type="application/json",
            )
        elif path in ("/api/v2/engagements/", "/api/v2/engagements"):
            self.send_response_body(
                200,
                json.dumps(
                    {
                        "count": 1,
                        "next": None,
                        "previous": None,
                        "results": [
                            {
                                "id": 1,
                                "name": "CBI AGH Continuous Attack Surface Discovery",
                                "product": 1,
                                "status": "In Progress",
                                "target_start": "2026-01-01",
                                "target_end": "2026-12-31",
                            }
                        ],
                    }
                ),
                content_type="application/json",
            )
        elif path in ("/api/v2/test_types/", "/api/v2/test_types"):
            self.send_response_body(
                200,
                json.dumps(
                    {
                        "count": 2,
                        "results": [
                            {"id": 1, "name": "Dzięcioł Finding"},
                            {"id": 2, "name": "Nmap Scan"},
                        ],
                    }
                ),
                content_type="application/json",
            )
        elif path in ("/api/v2/tests/", "/api/v2/tests"):
            self.send_response_body(
                200,
                json.dumps({"count": len(STORE.tests), "results": STORE.tests}),
                content_type="application/json",
            )
        elif path in ("/api/v2/findings/", "/api/v2/findings"):
            _, findings = STORE.snapshot()
            qs = parse_qs(parsed.query)
            uid_filter = qs.get("unique_id_from_tool", [None])[0]
            test_filter = qs.get("test", [None])[0]
            if test_filter:
                findings = [f for f in findings if str(f.get("test")) == test_filter]
            if uid_filter:
                findings = [f for f in findings if f.get("unique_id_from_tool") == uid_filter]
            self.send_response_body(
                200,
                json.dumps({"count": len(findings), "next": None, "previous": None, "results": findings}),
                content_type="application/json",
            )
        else:
            self.send_response_body(404, json.dumps({"detail": "Not found."}), content_type="application/json")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/api/v2/reset/", "/api/v2/reset"):
            STORE.reset()
            self.send_response_body(200, json.dumps({"status": "reset"}), content_type="application/json")
            return

        if path.startswith("/api/v2/"):
            if not self._check_auth():
                return

        if path in ("/api/v2/tests/", "/api/v2/tests"):
            created = STORE.add_test(self._read_json())
            self.send_response_body(201, json.dumps(created), content_type="application/json")
        elif path in ("/api/v2/reimport-scan/", "/api/v2/reimport-scan"):
            ctype = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else b""
            if "multipart/form-data" not in ctype:
                self.send_response_body(400, json.dumps({"detail": "multipart/form-data required"}), content_type="application/json")
                return
            fields, files = parse_multipart(ctype, body)
            if fields.get("auto_create_context") != "true" and not fields.get("test"):
                self.send_response_body(400, json.dumps({"detail": "test or auto_create_context with names required"}), content_type="application/json")
                return
            scan_type = fields.get("scan_type") or "Nmap Scan"
            title = fields.get("test_title") or scan_type
            raw = files.get("file", ("", b""))[1].decode("utf-8", errors="replace")
            test_id = STORE.test_for_title(title)
            total = 0
            if scan_type == "Generic Findings Import":
                try:
                    doc = json.loads(raw or "{}")
                except ValueError:
                    doc = {}
                for f in doc.get("findings", []):
                    f["test"] = test_id
                    STORE.add_finding(f)
                    total += 1
            else:
                rec = STORE.add_scan(scan_type, 1, fields.get("scan_date") or datetime.date.today().isoformat(),
                                     files.get("file", ("nmap.xml", b""))[0], raw, ["dzieciol"])
                rec["test"] = rec["test_id"] = test_id
                total = int(rec.get("finding_count", 0))
            self.send_response_body(201, json.dumps({"test": test_id, "test_id": test_id, "engagement_id": 1, "product_id": 1,
                                                     "statistics": {"after": {"total": {"total": total}}}}), content_type="application/json")
        elif path in ("/api/v2/import-scan/", "/api/v2/import-scan"):
            ctype = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else b""
            if "multipart/form-data" in ctype:
                fields, files = parse_multipart(ctype, body)
                scan_type = fields.get("scan_type") or "Nmap Scan"
                engagement_id = int(fields.get("engagement") or "1")
                scan_date = fields.get("scan_date") or datetime.date.today().isoformat()
                tags = [t.strip() for t in (fields.get("tags") or "").split(",") if t.strip()]
                if "file" in files:
                    filename, raw_bytes = files["file"]
                    raw_xml = raw_bytes.decode("utf-8", errors="replace")
                else:
                    filename, raw_xml = "nmap.xml", fields.get("file", "")
            else:
                data = json.loads(body.decode("utf-8") or "{}") if body else {}
                scan_type = str(data.get("scan_type") or "Nmap Scan")
                engagement_id = int(data.get("engagement") or 1)
                scan_date = str(data.get("scan_date") or datetime.date.today().isoformat())
                tags = data.get("tags") if isinstance(data.get("tags"), list) else []
                filename, raw_xml = "nmap.xml", str(data.get("xml") or "")

            rec = STORE.add_scan(scan_type, engagement_id, scan_date, filename, raw_xml, tags)
            resp = {k: v for k, v in rec.items() if k != "raw_xml"}
            self.send_response_body(201, json.dumps(resp), content_type="application/json")
        elif path in ("/api/v2/findings/", "/api/v2/findings"):
            payload = self._read_json()
            item, is_dup = STORE.add_finding(payload)
            resp = {**item, "duplicate": is_dup}
            self.send_response_body(201, json.dumps(resp), content_type="application/json")
        else:
            self.send_response_body(404, json.dumps({"detail": "Not found."}), content_type="application/json")


if __name__ == "__main__":
    print(f"[lab-defectdojo-mock] Listening on 0.0.0.0:8000 (UI: {PUBLIC_BASE_URL}/ui)", flush=True)
    ReusableThreadingHTTPServer(("0.0.0.0", 8000), DefectDojoHandler).serve_forever()
