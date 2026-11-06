#!/usr/bin/env python3
import os, re, glob
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from flask import Flask, jsonify, render_template, request, Response, send_file, session, redirect, url_for
import io, zipfile, subprocess, threading, time, json, urllib.request, urllib.error, ipaddress
import sys, secrets
from functools import wraps

for _site in glob.glob("/opt/server-log-vpn-dashboard/venv/lib/python*/site-packages"):
    if _site not in sys.path:
        sys.path.insert(0, _site)

import mysql.connector
from werkzeug.security import check_password_hash, generate_password_hash
from xml.sax.saxutils import escape as xml_escape

APP = Flask(__name__)
APP.secret_key = os.environ.get("DASH_SESSION_SECRET")
if not APP.secret_key:
    raise RuntimeError("DASH_SESSION_SECRET belum dikonfigurasi")
APP.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=__import__("datetime").timedelta(hours=8)
)
LOG_DIR = os.environ.get("VPN_LOG_DIR", "/var/log/mikrotik-vpn")
TZ = ZoneInfo("Asia/Jakarta")
DASH_USER = os.environ.get("DASH_USER", "admin")
DASH_PASSWORD = os.environ.get("DASH_PASSWORD", "")


# GitHub update configuration
GITHUB_OWNER = "irfannjt"
GITHUB_REPO = "office-vpn-monitoring"
GITHUB_BRANCH = "main"
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
SERVICE_NAME = "server-log-vpn-dashboard"

def git_output(*args, timeout=20):
    result = subprocess.run(["git", *args], cwd=PROJECT_DIR, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stdout.strip() or "Perintah Git gagal")
    return result.stdout.strip()

def github_json(path):
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                           "User-Agent": "Office-VPN-Monitoring"})
    with urllib.request.urlopen(req, timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))

def restart_dashboard_later():
    # Restart after the HTTP response has had time to leave the server.
    time.sleep(2)
    subprocess.Popen(["/bin/systemctl", "restart", SERVICE_NAME],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)

LINE_RE = re.compile(r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<body>.*)$")
LOGIN_RE = re.compile(r"\baccount\s+(?P<user>.+?)\s+logged in,\s*(?P<vpn_ip>\S+)\s+from\s+(?P<remote_ip>\S+)", re.I)
LOGOUT_RE = re.compile(r"\baccount\s+(?P<user>.+?)\s+logged out,\s*(?P<details>.*?)\s+from\s+(?P<remote_ip>\S+)", re.I)
FAIL_RE = re.compile(r"login failure|authentication failed|failed to authenticate|auth.*failed|invalid password", re.I)


def db_connection():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "3306")),
        database=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        connection_timeout=5
    )


@APP.before_request
def protect_dashboard():
    if request.endpoint in ("health", "login", "static"):
        return None

    if not session.get("authenticated") or not session.get("user_id"):
        if request.path.startswith("/api/"):
            return jsonify(ok=False, error="Silakan login kembali."), 401
        return redirect(url_for("login"))

    if request.path.startswith("/api/users") and request.method in ("POST", "PATCH", "DELETE"):
        supplied = request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf_token", "")
        import hmac
        if not expected or not hmac.compare_digest(supplied, expected):
            return jsonify(ok=False, error="Token keamanan tidak valid."), 403


@APP.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = None
        cur = None
        try:
            db = db_connection()
            cur = db.cursor(dictionary=True)
            cur.execute("""
                SELECT id, username, password_hash, role, is_active
                FROM dashboard_users
                WHERE username = %s
                LIMIT 1
            """, (username,))
            user = cur.fetchone()

            if user and user["is_active"] and check_password_hash(user["password_hash"], password):
                cur.execute(
                    "UPDATE dashboard_users SET last_login = NOW() WHERE id = %s",
                    (user["id"],)
                )
                db.commit()

                session.clear()
                session["authenticated"] = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                session.permanent = True
                return redirect(url_for("index"))

            error = "Username atau password tidak sesuai."
        except Exception:
            APP.logger.exception("Login database gagal")
            error = "Login sementara tidak dapat diproses. Silakan coba kembali."
        finally:
            if cur:
                cur.close()
            if db:
                db.close()

    return render_template("login.html", error=error)


@APP.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify(ok=False, error="Akses khusus Admin."), 403
        return fn(*args, **kwargs)
    return wrapper


@APP.route("/api/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    db = None
    cur = None
    try:
        db = db_connection()
        cur = db.cursor(dictionary=True)

        if request.method == "GET":
            cur.execute("""
                SELECT id, username, role, is_active, created_at, updated_at, last_login
                FROM dashboard_users ORDER BY id
            """)
            users = cur.fetchall()
            for user in users:
                for field in ("created_at", "updated_at", "last_login"):
                    if user[field]:
                        user[field] = user[field].isoformat(sep=" ", timespec="seconds")
            return jsonify(ok=True, users=users)

        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        role = data.get("role", "operator")

        if not username or len(username) > 100:
            return jsonify(ok=False, error="Username wajib diisi (maksimal 100 karakter)."), 400
        if len(password) < 10:
            return jsonify(ok=False, error="Password minimal 10 karakter."), 400
        if role not in ("admin", "operator"):
            return jsonify(ok=False, error="Role tidak valid."), 400

        cur.execute("""
            INSERT INTO dashboard_users (username, password_hash, role, is_active)
            VALUES (%s, %s, %s, 1)
        """, (username, generate_password_hash(password), role))
        db.commit()
        return jsonify(ok=True, message="User berhasil ditambahkan."), 201

    except mysql.connector.IntegrityError:
        if db:
            db.rollback()
        return jsonify(ok=False, error="Username sudah digunakan."), 409
    except Exception:
        if db:
            db.rollback()
        APP.logger.exception("Manajemen user gagal")
        return jsonify(ok=False, error="Operasi database gagal."), 500
    finally:
        if cur:
            cur.close()
        if db:
            db.close()


@APP.route("/api/users/<int:user_id>", methods=["PATCH", "DELETE"])
@admin_required
def edit_user(user_id):
    db = None
    cur = None
    try:
        db = db_connection()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT id, username, role, is_active FROM dashboard_users WHERE id = %s",
            (user_id,)
        )
        target = cur.fetchone()
        if not target:
            return jsonify(ok=False, error="User tidak ditemukan."), 404

        current_id = int(session["user_id"])

        if request.method == "DELETE":
            if user_id == current_id:
                return jsonify(ok=False, error="Anda tidak dapat menghapus akun sendiri."), 400

            if target["role"] == "admin" and target["is_active"]:
                cur.execute("""
                    SELECT COUNT(*) AS total FROM dashboard_users
                    WHERE role = 'admin' AND is_active = 1
                """)
                if cur.fetchone()["total"] <= 1:
                    return jsonify(ok=False, error="Admin aktif terakhir tidak boleh dihapus."), 400

            cur.execute("DELETE FROM dashboard_users WHERE id = %s", (user_id,))
            db.commit()
            return jsonify(ok=True, message="User berhasil dihapus.")

        data = request.get_json(silent=True) or {}
        username = str(data.get("username", target["username"])).strip()
        role = data.get("role", target["role"])
        is_active = data.get("is_active", bool(target["is_active"]))
        password = data.get("password")

        if not username or len(username) > 100:
            return jsonify(ok=False, error="Username tidak valid."), 400
        if role not in ("admin", "operator"):
            return jsonify(ok=False, error="Role tidak valid."), 400
        if not isinstance(is_active, bool):
            return jsonify(ok=False, error="Status aktif tidak valid."), 400
        if password is not None and len(str(password)) < 10:
            return jsonify(ok=False, error="Password minimal 10 karakter."), 400

        if user_id == current_id and (role != "admin" or not is_active):
            return jsonify(ok=False, error="Anda tidak dapat menonaktifkan atau menurunkan role akun sendiri."), 400

        loses_admin = (
            target["role"] == "admin" and target["is_active"] and
            (role != "admin" or not is_active)
        )
        if loses_admin:
            cur.execute("""
                SELECT COUNT(*) AS total FROM dashboard_users
                WHERE role = 'admin' AND is_active = 1
            """)
            if cur.fetchone()["total"] <= 1:
                return jsonify(ok=False, error="Admin aktif terakhir tidak boleh dinonaktifkan atau diturunkan role-nya."), 400

        if password is not None:
            cur.execute("""
                UPDATE dashboard_users
                SET username=%s, role=%s, is_active=%s, password_hash=%s
                WHERE id=%s
            """, (username, role, int(is_active), generate_password_hash(str(password)), user_id))
        else:
            cur.execute("""
                UPDATE dashboard_users
                SET username=%s, role=%s, is_active=%s
                WHERE id=%s
            """, (username, role, int(is_active), user_id))

        db.commit()
        return jsonify(ok=True, message="Data user berhasil diperbarui.")

    except mysql.connector.IntegrityError:
        if db:
            db.rollback()
        return jsonify(ok=False, error="Username sudah digunakan."), 409
    except Exception:
        if db:
            db.rollback()
        APP.logger.exception("Edit user gagal")
        return jsonify(ok=False, error="Operasi database gagal."), 500
    finally:
        if cur:
            cur.close()
        if db:
            db.close()


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
    return render_template("index.html", csrf_token=session.get("csrf_token", ""))

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


# Public IP metadata lookup (cached in memory for 24 hours).
IP_INFO_CACHE = {}
IP_INFO_LOCK = threading.Lock()

@APP.get("/api/ip-info")
def ip_info():
    raw_ip = request.args.get("ip", "").strip()
    try:
        addr = ipaddress.ip_address(raw_ip)
    except ValueError:
        return jsonify(ok=False, error="Alamat IP tidak valid."), 400
    # Private, reserved, loopback and other non-global IPs have no public ISP metadata.
    if not addr.is_global:
        return jsonify(ok=True, ip=raw_ip, public=False, provider="IP privat/tidak publik", country="—", country_code="", flag="🏠")
    now = time.time()
    with IP_INFO_LOCK:
        cached = IP_INFO_CACHE.get(raw_ip)
        if cached and now - cached[0] < 86400:
            return jsonify(cached[1])
    try:
        url = "https://ipwho.is/" + raw_ip
        req = urllib.request.Request(url, headers={"User-Agent": "Office-VPN-Monitoring/1.2"})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
        if not data.get("success"):
            raise RuntimeError(data.get("message", "Metadata IP tidak tersedia"))
        conn = data.get("connection") or {}
        country_code = (data.get("country_code") or "").upper()
        flag = "".join(chr(127397 + ord(c)) for c in country_code) if len(country_code) == 2 else "🌐"
        result = {"ok": True, "ip": raw_ip, "public": True,
                  "provider": conn.get("isp") or conn.get("org") or "Provider tidak diketahui",
                  "country": data.get("country") or "Tidak diketahui",
                  "country_code": country_code, "flag": flag,
                  "asn": conn.get("asn") or ""}
        with IP_INFO_LOCK:
            IP_INFO_CACHE[raw_ip] = (now, result)
        return jsonify(result)
    except Exception:
        # Do not fail the monitoring dashboard if the metadata service is unavailable.
        return jsonify(ok=False, ip=raw_ip, provider="Tidak dapat dideteksi", country="—", country_code="", flag="🌐")

@APP.get("/api/system-info")
def system_info():
    try:
        local_sha = git_output("rev-parse", "--short", "HEAD")
        branch = git_output("branch", "--show-current")
        remote = git_output("remote", "get-url", "origin")
        if remote.rstrip("/").removesuffix(".git") != f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}":
            raise RuntimeError("Remote Git tidak sesuai repository resmi project")
        remote_data = github_json(f"commits/{GITHUB_BRANCH}")
        remote_sha = remote_data["sha"]
        updates = github_json("commits?per_page=5")
        clean = not bool(git_output("status", "--porcelain"))
        return jsonify(ok=True, version="1.2.0", branch=branch, local_commit=local_sha,
                       remote_commit=remote_sha[:7], update_available=local_sha != remote_sha[:7],
                       working_tree_clean=clean, commits=[{"sha": c["sha"][:7],
                       "message": c["commit"]["message"].split("\n")[0],
                       "date": c["commit"]["author"]["date"]} for c in updates])
    except Exception as exc:
        return jsonify(ok=False, error=str(exc)), 503

@APP.post("/api/update")
def update_from_github():
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        return jsonify(ok=False, error="Permintaan update tidak valid."), 400
    try:
        remote = git_output("remote", "get-url", "origin")
        if remote.rstrip("/").removesuffix(".git") != f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}":
            raise RuntimeError("Remote Git tidak sesuai repository resmi project")
        if git_output("status", "--porcelain"):
            return jsonify(ok=False, error="Ada perubahan lokal. Simpan/commit dahulu sebelum update."), 409
        git_output("fetch", "origin", GITHUB_BRANCH, timeout=60)
        before = git_output("rev-parse", "HEAD")
        target = git_output("rev-parse", f"origin/{GITHUB_BRANCH}")
        if before == target:
            return jsonify(ok=True, updated=False, message="Dashboard sudah menggunakan versi terbaru.")
        git_output("merge", "--ff-only", f"origin/{GITHUB_BRANCH}", timeout=60)
        threading.Thread(target=restart_dashboard_later, daemon=True).start()
        return jsonify(ok=True, updated=True, message="Pembaruan berhasil diunduh. Dashboard sedang dimulai ulang." )
    except Exception as exc:
        return jsonify(ok=False, error=str(exc)), 500

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


@APP.get("/api/routeros-active")
def routeros_active_data():
    try:
        result = subprocess.run(
            [os.path.join(PROJECT_DIR, "venv", "bin", "python"),
             os.path.join(PROJECT_DIR, "routeros_active.py")],
            cwd=PROJECT_DIR, capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            raise RuntimeError("Pembacaan RouterOS gagal")
        data = json.loads(result.stdout)
        if data.get("ok") is not True:
            raise RuntimeError("Data RouterOS tidak valid")
        return jsonify(data)
    except Exception:
        return jsonify(ok=False, error="Data VPN dari CCR1009 tidak dapat dibaca."), 503


@APP.get("/api/netflow-user")
def netflow_user_data():
    try:
        raw_ip = request.args.get("ip", "").strip()
        if not raw_ip:
            return jsonify(ok=False, error="Parameter IP VPN wajib diisi."), 400

        try:
            vpn_ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            return jsonify(ok=False, error="Format IP VPN tidak valid."), 400

        try:
            limit = int(request.args.get("limit", "2000"))
        except ValueError:
            limit = 2000
        limit = max(1, min(limit, 5000))

        result = subprocess.run(
            [
                "/usr/bin/nfdump",
                "-R", "/var/cache/nfdump/",
                "-o", "json",
                "-c", str(limit),
                f"src ip {vpn_ip} or dst ip {vpn_ip}"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise RuntimeError("nfdump gagal membaca data")

        records = json.loads(result.stdout)
        if not isinstance(records, list):
            raise RuntimeError("Format data NetFlow tidak valid")

        flows = []
        destinations = {}
        upload_bytes = download_bytes = 0
        upload_packets = download_packets = 0

        protocol_names = {
            1: "ICMP", 6: "TCP", 17: "UDP",
            47: "GRE", 50: "ESP", 58: "ICMPv6"
        }

        for item in records:
            if item.get("type") != "FLOW":
                continue

            src_ip = item.get("src4_addr") or item.get("src6_addr")
            dst_ip = item.get("dst4_addr") or item.get("dst6_addr")

            if src_ip == vpn_ip:
                direction = "UPLOAD"
                remote_ip = dst_ip
                remote_port = item.get("dst_port")
            elif dst_ip == vpn_ip:
                direction = "DOWNLOAD"
                remote_ip = src_ip
                remote_port = item.get("src_port")
            else:
                continue

            packets = int(item.get("in_packets") or 0)
            byte_count = int(item.get("in_bytes") or 0)
            proto = int(item.get("proto") or 0)
            protocol = protocol_names.get(proto, str(proto))

            first = item.get("first")
            last = item.get("last")

            duration = 0
            try:
                start = datetime.fromisoformat(first)
                end = datetime.fromisoformat(last)
                duration = max(0, (end - start).total_seconds())
            except (TypeError, ValueError):
                pass

            if direction == "UPLOAD":
                upload_bytes += byte_count
                upload_packets += packets
            else:
                download_bytes += byte_count
                download_packets += packets

            flows.append({
                "first": first,
                "last": last,
                "duration_seconds": duration,
                "direction": direction,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": protocol,
                "protocol_number": proto,
                "src_ip": src_ip,
                "src_port": item.get("src_port"),
                "dst_ip": dst_ip,
                "dst_port": item.get("dst_port"),
                "packets": packets,
                "bytes": byte_count,
                "tcp_flags": item.get("tcp_flags")
            })

            key = (remote_ip, str(remote_port or ""), protocol)
            if key not in destinations:
                destinations[key] = {
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "protocol": protocol,
                    "upload_bytes": 0,
                    "download_bytes": 0,
                    "upload_packets": 0,
                    "download_packets": 0
                }

            entry = destinations[key]
            if direction == "UPLOAD":
                entry["upload_bytes"] += byte_count
                entry["upload_packets"] += packets
            else:
                entry["download_bytes"] += byte_count
                entry["download_packets"] += packets

        return jsonify({
            "ok": True,
            "vpn_ip": vpn_ip,
            "flow_count": len(flows),
            "upload_bytes": upload_bytes,
            "download_bytes": download_bytes,
            "total_bytes": upload_bytes + download_bytes,
            "upload_packets": upload_packets,
            "download_packets": download_packets,
            "total_packets": upload_packets + download_packets,
            "limit": limit,
            "flows": flows,
            "destinations": list(destinations.values())
        })

    except subprocess.TimeoutExpired:
        return jsonify(ok=False, error="Pembacaan NetFlow melewati batas waktu."), 504
    except Exception:
        APP.logger.exception("NetFlow API gagal")
        return jsonify(ok=False, error="Data NetFlow tidak dapat dibaca."), 503


if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
