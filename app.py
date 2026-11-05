#!/usr/bin/env python3
import os, re, glob
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from flask import Flask, jsonify, render_template, request, Response, send_file
import io, zipfile
from xml.sax.saxutils import escape as xml_escape

APP = Flask(__name__)
LOG_DIR = os.environ.get("VPN_LOG_DIR", "/var/log/mikrotik-vpn")
TZ = ZoneInfo("Asia/Jakarta")
DASH_USER = os.environ.get("DASH_USER", "admin")
DASH_PASSWORD = os.environ.get("DASH_PASSWORD", "")

LINE_RE = re.compile(r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<body>.*)$")
LOGIN_RE = re.compile(r"\baccount\s+(?P<user>.+?)\s+logged in,\s*(?P<vpn_ip>\S+)\s+from\s+(?P<remote_ip>\S+)", re.I)
LOGOUT_RE = re.compile(r"\baccount\s+(?P<user>.+?)\s+logged out,\s*(?P<details>.*?)\s+from\s+(?P<remote_ip>\S+)", re.I)
FAIL_RE = re.compile(r"login failure|authentication failed|failed to authenticate|auth.*failed|invalid password", re.I)

@APP.before_request
def protect_dashboard():
    if request.endpoint == "health":
        return None
    if not DASH_PASSWORD:
        return Response("Dashboard password belum dikonfigurasi.", 503)
    auth = request.authorization
    if not (auth and auth.username == DASH_USER and auth.password == DASH_PASSWORD):
        return Response("Login diperlukan", 401,
                        {"WWW-Authenticate": 'Basic realm="VPN RIM Dashboard"'})

def parse_timestamp(value):
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(TZ)
    except Exception:
        return None

def read_events():
    events = []
    paths = sorted(glob.glob(os.path.join(LOG_DIR, "*.log")))
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    m = LINE_RE.match(line)
                    if not m:
                        continue
                    ts = parse_timestamp(m.group("ts"))
                    if not ts:
                        continue
                    body = m.group("body")
                    ev = {
                        "timestamp": ts.isoformat(timespec="seconds"),
                        "timestamp_display": ts.strftime("%d-%m-%Y %H:%M:%S"),
                        "host": m.group("host"), "raw": line,
                        "type": "log", "user": "", "vpn_ip": "",
                        "remote_ip": "", "message": body,
                    }
                    login = LOGIN_RE.search(body)
                    logout = LOGOUT_RE.search(body)
                    if login:
                        ev.update(type="login", user=login.group("user").strip(),
                                  vpn_ip=login.group("vpn_ip"), remote_ip=login.group("remote_ip"),
                                  message="VPN login berhasil")
                    elif logout:
                        ev.update(type="logout", user=logout.group("user").strip(),
                                  remote_ip=logout.group("remote_ip"), message="VPN logout")
                    elif FAIL_RE.search(body):
                        ev.update(type="failed", message=body)
                    events.append(ev)
        except OSError:
            continue
    events.sort(key=lambda e: e["timestamp"])
    return events

def build_sessions(events):
    active = {}
    for ev in events:
        if ev["type"] == "login":
            key = (ev["user"], ev["remote_ip"])
            active[key] = {
                "user": ev["user"], "vpn_ip": ev["vpn_ip"], "remote_ip": ev["remote_ip"],
                "login_at": ev["timestamp"], "login_display": ev["timestamp_display"],
                "status": "ONLINE"
            }
        elif ev["type"] == "logout":
            key = (ev["user"], ev["remote_ip"])
            match = key if key in active else next(
                (k for k in reversed(list(active.keys())) if k[0] == ev["user"]), None)
            if match:
                active.pop(match)
    return list(active.values())

@APP.get("/health")
def health():
    return jsonify(ok=True)

@APP.get("/")
def index():
    return render_template("index.html")

@APP.get("/api/events")
def events_data():
    start_value = request.args.get("start_date", "").strip()
    end_value = request.args.get("end_date", "").strip()
    try:
        start_date = datetime.strptime(start_value, "%Y-%m-%d").date() if start_value else None
        end_date = datetime.strptime(end_value, "%Y-%m-%d").date() if end_value else None
    except ValueError:
        return jsonify(error="Format tanggal tidak valid. Gunakan YYYY-MM-DD."), 400
    if start_date and end_date and start_date > end_date:
        return jsonify(error="Tanggal mulai tidak boleh melewati tanggal akhir."), 400

    events = read_events()
    filtered = []
    for event in events:
        event_date = datetime.fromisoformat(event["timestamp"]).date()
        if start_date and event_date < start_date:
            continue
        if end_date and event_date > end_date:
            continue
        filtered.append(event)
    filtered.reverse()
    total = len(filtered)
    return jsonify(total=total, events=filtered[:5000], limit=5000)



def make_xlsx(events):
    headers = ["Waktu (WIB)", "Username", "Aktivitas", "IP VPN", "IP Asal", "Pesan"]
    rows = [headers]
    labels = {"login": "LOGIN BERHASIL", "logout": "LOGOUT", "failed": "GAGAL AUTENTIKASI"}
    for e in events:
        rows.append([e.get("timestamp_display", ""), e.get("user", ""),
                     labels.get(e.get("type"), e.get("type", "LOG")),
                     e.get("vpn_ip", ""), e.get("remote_ip", ""), e.get("message", "")])

    def col_name(n):
        out = ""
        while n:
            n, rem = divmod(n - 1, 26)
            out = chr(65 + rem) + out
        return out

    sheet_rows = []
    for ri, row in enumerate(rows, 1):
        cells = []
        for ci, value in enumerate(row, 1):
            ref = f"{col_name(ci)}{ri}"
            val = xml_escape(str(value if value is not None else ""))
            style = ' s="1"' if ri == 1 else ""
            cells.append(f'<c r="{ref}" t="inlineStr"{style}><is><t xml:space="preserve">{val}</t></is></c>')
        sheet_rows.append(f'<row r="{ri}">{"".join(cells)}</row>')
    worksheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<cols><col min="1" max="1" width="22" customWidth="1"/>'
        '<col min="2" max="6" width="25" customWidth="1"/></cols>'
        f'<sheetData>{"".join(sheet_rows)}</sheetData></worksheet>')

    files = {
        "[Content_Types].xml": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>''',
        "_rels/.rels": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>''',
        "xl/workbook.xml": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="VPN Activity" sheetId="1" r:id="rId1"/></sheets></workbook>''',
        "xl/_rels/workbook.xml.rels": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>''',
        "xl/styles.xml": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>
<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF17365D"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="1" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs>
</styleSheet>''',
        "xl/worksheets/sheet1.xml": worksheet
    }
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as xlsx:
        for name, content in files.items():
            xlsx.writestr(name, content)
    bio.seek(0)
    return bio

@APP.get("/api/export.xlsx")
def export_events():
    start_value = request.args.get("start_date", "").strip()
    end_value = request.args.get("end_date", "").strip()
    event_type = request.args.get("type", "all").strip()
    query = request.args.get("q", "").strip().lower()
    try:
        start_date = datetime.strptime(start_value, "%Y-%m-%d").date() if start_value else None
        end_date = datetime.strptime(end_value, "%Y-%m-%d").date() if end_value else None
    except ValueError:
        return jsonify(error="Format tanggal tidak valid. Gunakan YYYY-MM-DD."), 400
    if start_date and end_date and start_date > end_date:
        return jsonify(error="Tanggal mulai tidak boleh melewati tanggal akhir."), 400
    events = []
    for event in read_events():
        event_date = datetime.fromisoformat(event["timestamp"]).date()
        if start_date and event_date < start_date:
            continue
        if end_date and event_date > end_date:
            continue
        if event_type != "all" and event["type"] != event_type:
            continue
        hay = " ".join(str(event.get(k, "")) for k in ("user", "vpn_ip", "remote_ip", "message", "raw")).lower()
        if query and query not in hay:
            continue
        events.append(event)
    events.reverse()
    workbook = make_xlsx(events)
    return send_file(workbook, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     as_attachment=True, download_name="office-vpn-activity.xlsx")

@APP.get("/api/dashboard")
def dashboard_data():
    events = read_events()
    active = build_sessions(events)
    today = datetime.now(TZ).date()
    today_events = [e for e in events if datetime.fromisoformat(e["timestamp"]).date() == today]
    recent = [e for e in reversed(events) if e["type"] in ("login", "logout", "failed")][:500]
    return jsonify({
        "server_time": datetime.now(TZ).strftime("%d-%m-%Y %H:%M:%S WIB"),
        "online_count": len(active),
        "logins_today": sum(e["type"] == "login" for e in today_events),
        "failures_today": sum(e["type"] == "failed" for e in today_events),
        "total_events": len(events),
        "active_sessions": active,
        "recent_events": recent,
        "log_dir": LOG_DIR,
    })

if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
