#!/usr/bin/env python3
import os, re, glob
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from flask import Flask, jsonify, render_template, request, Response, send_file, session, redirect, url_for
import io, zipfile, subprocess, threading, time, json, urllib.request, urllib.error, ipaddress
import sys, secrets, socket
from functools import wraps

for _site in glob.glob("/opt/server-log-vpn-dashboard/venv/lib/python*/site-packages"):
    if _site not in sys.path:
        sys.path.insert(0, _site)

import psutil
psutil.cpu_percent(interval=None)  # Inisialisasi sampling CPU
import mysql.connector
from werkzeug.security import check_password_hash, generate_password_hash
from xml.sax.saxutils import escape as xml_escape
from router_manager import test_router_connection
from router_credentials import encrypt_secret


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

    protected_mutation = (
        request.path.startswith("/api/users")
        or request.path.startswith("/api/routers")
    )

    if protected_mutation and request.method in ("POST", "PUT", "PATCH", "DELETE"):
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
        if len(password) < 6:
            return jsonify(ok=False, error="Password minimal 6 karakter."), 400
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
            return jsonify(ok=False, error="Password minimal 6 karakter."), 400

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




def router_audit(cur, router_id, action, details, status="SUCCESS"):
    cur.execute("""
        INSERT INTO router_audit_logs
            (router_id, user_id, action, details, status)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        router_id,
        session.get("user_id"),
        action,
        details,
        status
    ))


@APP.route("/api/routers", methods=["GET", "POST"])
@admin_required
def manage_routers():
    db = None
    cur = None
    try:
        db = db_connection()
        cur = db.cursor(dictionary=True)

        if request.method == "GET":
            cur.execute("""
                SELECT r.id, r.name, r.host, r.port,
                       r.connection_type, r.routeros_version,
                       r.description, r.is_active,
                       r.created_at, r.updated_at,
                       c.api_username
                FROM managed_routers r
                LEFT JOIN router_credentials c ON c.router_id = r.id
                ORDER BY r.id
            """)
            routers = cur.fetchall()
            for item in routers:
                for field in ("created_at", "updated_at"):
                    if item[field]:
                        item[field] = item[field].isoformat(
                            sep=" ", timespec="seconds"
                        )
                item["is_active"] = bool(item["is_active"])
            return jsonify(ok=True, routers=routers)

        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip()
        host = str(data.get("host", "")).strip()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        description = str(data.get("description", "")).strip()
        connection_type = str(
            data.get("connection_type", "VPN")
        ).upper()

        try:
            port = int(data.get("port", 8728))
        except (TypeError, ValueError):
            return jsonify(ok=False, error="Port API tidak valid."), 400

        if not name or len(name) > 100:
            return jsonify(ok=False, error="Nama router wajib diisi (maksimal 100 karakter)."), 400
        if not host or len(host) > 255:
            return jsonify(ok=False, error="Host/IP router tidak valid."), 400
        if not username or len(username) > 100 or not password:
            return jsonify(ok=False, error="Username dan password API wajib diisi."), 400
        if not 1 <= port <= 65535:
            return jsonify(ok=False, error="Port harus antara 1 sampai 65535."), 400
        if connection_type not in ("VPN", "PUBLIC_IP"):
            return jsonify(ok=False, error="Jenis koneksi tidak valid."), 400
        if len(description) > 255:
            return jsonify(ok=False, error="Keterangan maksimal 255 karakter."), 400

        # Pastikan router dapat diakses sebelum disimpan.
        test = test_router_connection(host, username, password, port)
        if test.get("ok") is not True:
            return jsonify(ok=False, error="Koneksi router gagal diuji."), 400

        encrypted_password = encrypt_secret(password)

        cur.execute("""
            INSERT INTO managed_routers
                (name, host, port, connection_type,
                 routeros_version, description, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, 0)
        """, (
            name, host, port, connection_type,
            test.get("version"), description or None
        ))
        router_id = cur.lastrowid

        cur.execute("""
            INSERT INTO router_credentials
                (router_id, api_username, encrypted_password)
            VALUES (%s, %s, %s)
        """, (router_id, username, encrypted_password))

        router_audit(
            cur, router_id, "ADD_ROUTER",
            "Router ditambahkan dan koneksi berhasil diuji."
        )
        db.commit()

        return jsonify(
            ok=True,
            message="Router berhasil diuji dan disimpan. Pilih Aktif untuk menggunakannya.",
            router_id=router_id,
            test=test
        ), 201

    except mysql.connector.IntegrityError:
        if db:
            db.rollback()
        return jsonify(ok=False, error="Nama router sudah digunakan."), 409
    except Exception:
        if db:
            db.rollback()
        APP.logger.exception("Pengelolaan router gagal")
        return jsonify(ok=False, error="Router gagal diproses. Periksa koneksi dan konfigurasi."), 500
    finally:
        if cur:
            cur.close()
        if db:
            db.close()


@APP.post("/api/routers/test")
@admin_required
def test_router_api():
    data = request.get_json(silent=True) or {}
    host = str(data.get("host", "")).strip()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    try:
        port = int(data.get("port", 8728))
        if not host or not username or not password or not 1 <= port <= 65535:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify(ok=False, error="Host, port, username, dan password harus valid."), 400

    try:
        result = test_router_connection(host, username, password, port)
        return jsonify(result), (200 if result.get("ok") else 400)
    except Exception:
        APP.logger.exception("Test koneksi router gagal")
        return jsonify(ok=False, error="Koneksi API RouterOS gagal. Periksa host, port, username, password, dan firewall."), 400


@APP.post("/api/routers/<int:router_id>/active")
@admin_required
def activate_router(router_id):
    db = None
    cur = None
    try:
        db = db_connection()
        cur = db.cursor(dictionary=True)

        cur.execute("""
            SELECT r.id, r.name, r.host, r.port,
                   c.api_username, c.encrypted_password
            FROM managed_routers r
            JOIN router_credentials c ON c.router_id = r.id
            WHERE r.id = %s
            LIMIT 1
        """, (router_id,))
        target = cur.fetchone()

        if not target:
            return jsonify(ok=False, error="Router tidak ditemukan atau kredensial belum tersedia."), 404

        # Uji koneksi lagi sebelum mengganti router aktif.
        from router_credentials import decrypt_secret
        password = decrypt_secret(target["encrypted_password"])
        test = test_router_connection(
            target["host"], target["api_username"],
            password, target["port"]
        )

        if test.get("ok") is not True:
            return jsonify(ok=False, error="Router gagal diuji. Router aktif tidak diubah."), 400

        cur.execute("UPDATE managed_routers SET is_active = 0")
        cur.execute(
            "UPDATE managed_routers SET is_active = 1, routeros_version = %s WHERE id = %s",
            (test.get("version"), router_id)
        )
        router_audit(
            cur, router_id, "ACTIVATE_ROUTER",
            "Router dipilih sebagai router aktif."
        )
        db.commit()

        return jsonify(
            ok=True,
            message="Router aktif berhasil diganti.",
            router={"id": router_id, "name": target["name"]},
            test=test
        )

    except Exception:
        if db:
            db.rollback()
        APP.logger.exception("Pergantian router aktif gagal")
        return jsonify(ok=False, error="Router aktif gagal diganti."), 500
    finally:
        if cur:
            cur.close()
        if db:
            db.close()


@APP.delete("/api/routers/<int:router_id>")
@admin_required
def delete_router(router_id):
    db = None
    cur = None
    try:
        db = db_connection()
        cur = db.cursor(dictionary=True)

        cur.execute(
            "SELECT id, name, is_active FROM managed_routers WHERE id = %s",
            (router_id,)
        )
        target = cur.fetchone()

        if not target:
            return jsonify(ok=False, error="Router tidak ditemukan."), 404

        router_audit(
            cur, router_id, "DELETE_ROUTER",
            "Router dihapus: " + target["name"]
        )
        cur.execute("DELETE FROM managed_routers WHERE id = %s", (router_id,))
        db.commit()

        return jsonify(
            ok=True,
            message="Router berhasil dihapus."
        )

    except Exception:
        if db:
            db.rollback()
        APP.logger.exception("Penghapusan router gagal")
        return jsonify(ok=False, error="Router gagal dihapus."), 500
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


# Pemetaan IP server lokal yang diakses oleh klien VPN berdasarkan NetFlow.
LOCAL_DEST_NETWORKS = [
    ipaddress.ip_network("192.168.5.0/24"),
    ipaddress.ip_network("192.168.6.0/24"),
    ipaddress.ip_network("172.16.0.0/22"),
]
VPN_CLIENT_NETWORKS = [
    ipaddress.ip_network("192.168.110.0/24"),
    ipaddress.ip_network("192.168.201.0/24"),
]
NETFLOW_DEST_CACHE = {"created": 0, "mapping": {}}
NETFLOW_DEST_LOCK = threading.Lock()


def get_local_destination_map():
    now = time.time()
    with NETFLOW_DEST_LOCK:
        if now - NETFLOW_DEST_CACHE["created"] < 30:
            return NETFLOW_DEST_CACHE["mapping"]

        mapping = {}
        archives = sorted(
            glob.glob("/var/cache/nfdump/nfcapd.*"),
            key=os.path.getmtime,
            reverse=True
        )[:10]

        for archive in archives:
            try:
                result = subprocess.run(
                    ["/usr/bin/nfdump", "-r", archive, "-o", "json", "-c", "2000"],
                    capture_output=True, text=True, timeout=8
                )
                if result.returncode != 0:
                    continue
                records = json.loads(result.stdout)
                if not isinstance(records, list):
                    continue
            except (OSError, subprocess.TimeoutExpired, ValueError):
                continue

            for flow in records:
                if flow.get("type") != "FLOW":
                    continue

                src_values = {
                    flow.get("src4_addr"),
                    flow.get("src4_xlt_ip"),
                }
                dst_values = {
                    flow.get("dst4_addr"),
                    flow.get("dst4_xlt_ip"),
                }

                src_vpn = []
                dst_vpn = []
                for value in src_values:
                    try:
                        addr = ipaddress.ip_address(value) if value else None
                        if addr and any(addr in net for net in VPN_CLIENT_NETWORKS):
                            src_vpn.append(str(addr))
                    except ValueError:
                        pass
                for value in dst_values:
                    try:
                        addr = ipaddress.ip_address(value) if value else None
                        if addr and any(addr in net for net in VPN_CLIENT_NETWORKS):
                            dst_vpn.append(str(addr))
                    except ValueError:
                        pass

                # Jika klien VPN berada di sisi sumber, server berada di sisi tujuan.
                for vpn_ip in src_vpn:
                    for value in dst_values:
                        try:
                            addr = ipaddress.ip_address(value) if value else None
                            if addr and any(addr in net for net in LOCAL_DEST_NETWORKS):
                                mapping.setdefault(vpn_ip, set()).add(str(addr))
                        except ValueError:
                            pass

                # Jika klien VPN berada di sisi tujuan (flow balasan/NAT),
                # server berada di sisi sumber.
                for vpn_ip in dst_vpn:
                    for value in src_values:
                        try:
                            addr = ipaddress.ip_address(value) if value else None
                            if addr and any(addr in net for net in LOCAL_DEST_NETWORKS):
                                mapping.setdefault(vpn_ip, set()).add(str(addr))
                        except ValueError:
                            pass

        clean_mapping = {
            vpn_ip: sorted(destinations)
            for vpn_ip, destinations in mapping.items()
        }
        NETFLOW_DEST_CACHE["mapping"] = clean_mapping
        NETFLOW_DEST_CACHE["created"] = now
        return clean_mapping


def attach_local_destinations(events):
    mapping = get_local_destination_map()
    for event in events:
        vpn_ip = event.get("vpn_ip", "")
        destinations = mapping.get(vpn_ip, []) if vpn_ip else []
        event["local_destinations"] = ", ".join(destinations) if destinations else "Belum ada data"
    return events


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
    filtered = attach_local_destinations(filtered[:5000])
    total = len(filtered)
    return jsonify(total=total, events=filtered, limit=5000)



def make_xlsx(events, analysis=None):
    if analysis is None:
        headers = ["Waktu (WIB)", "Username", "Aktivitas", "IP VPN", "IP Asal",
                   "IP Tujuan / Server yang Diakses", "Pesan"]
        rows = [headers]
        labels = {"login": "LOGIN BERHASIL", "logout": "LOGOUT", "failed": "GAGAL AUTENTIKASI"}
        for e in events:
            rows.append([e.get("timestamp_display", ""), e.get("user", ""),
                         labels.get(e.get("type"), e.get("type", "LOG")),
                         e.get("vpn_ip", ""), e.get("remote_ip", ""),
                         e.get("local_destinations", "Belum ada data"), e.get("message", "")])
    else:
        headers = [
            "Waktu Awal", "Waktu Akhir", "Username", "IP VPN",
            "Arah Trafik", "IP Asal", "Port Asal", "IP Tujuan",
            "Port Tujuan", "Protokol", "IP Tujuan / Server yang Diakses", "Byte"
        ]
        rows = [headers]
        for f in analysis.get("flows", []):
            rows.append([
                f.get("first", ""), f.get("last", ""),
                analysis.get("user", ""), analysis.get("vpn_ip", ""),
                f.get("direction", ""), f.get("src_ip", ""),
                f.get("src_port", ""), f.get("dst_ip", ""),
                f.get("dst_port", ""), f.get("protocol", ""),
                f.get("destination_ip", "Belum ada data"), f.get("bytes", 0)
            ])

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
        '<col min="2" max="12" width="22" customWidth="1"/></cols>'
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
    events = attach_local_destinations(events)
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
    recent = attach_local_destinations(recent)
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


@APP.get("/api/noc-monitoring")
def noc_monitoring_data():
    """Lightweight host telemetry for the NOC overview; no router credentials are returned."""
    try:
        interface = os.environ.get("NOC_INTERFACE", "eth0").strip() or "eth0"
        counters = psutil.net_io_counters(pernic=True).get(interface)
        if counters is None:
            return jsonify(ok=False, error=f"Interface {interface} tidak ditemukan."), 503

        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        boot_time = datetime.fromtimestamp(psutil.boot_time(), TZ)
        uptime_seconds = max(0, int(time.time() - psutil.boot_time()))

        router_status = {"reachable": False, "latency_ms": None}
        router_env = "/etc/office-vpn-router.env"
        try:
            cfg = {}
            with open(router_env, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        cfg[key.strip()] = value.strip().strip('"').strip("'")
            host = cfg.get("ROUTEROS_HOST", "")
            port = int(cfg.get("ROUTEROS_PORT", "8728"))
            if host:
                started = time.perf_counter()
                with socket.create_connection((host, port), timeout=1.5):
                    pass
                router_status = {
                    "reachable": True,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 1)
                }
        except Exception:
            pass

        return jsonify(
            ok=True,
            timestamp=datetime.now(TZ).strftime("%d-%m-%Y %H:%M:%S WIB"),
            hostname=__import__("socket").gethostname(),
            interface=interface,
            cpu_percent=round(psutil.cpu_percent(interval=None), 1),
            memory_percent=round(mem.percent, 1),
            memory_used=mem.used,
            memory_total=mem.total,
            disk_percent=round(disk.percent, 1),
            disk_used=disk.used,
            disk_total=disk.total,
            uptime_seconds=uptime_seconds,
            boot_time=boot_time.strftime("%d-%m-%Y %H:%M:%S WIB"),
            bytes_sent=counters.bytes_sent,
            bytes_recv=counters.bytes_recv,
            router=router_status
        )
    except Exception:
        APP.logger.exception("NOC monitoring gagal membaca metrik server")
        return jsonify(ok=False, error="Metrik server sementara tidak dapat dibaca."), 503


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


def get_flow_local_destination(item, vpn_ip, direction):
    local_networks = (
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("172.16.0.0/22"),
    )

    excluded_networks = (
        ipaddress.ip_network("192.168.110.0/24"),
        ipaddress.ip_network("192.168.201.0/24"),
    )

    if direction == "UPLOAD":
        candidates = (item.get("dst4_addr"), item.get("dst4_xlt_ip"))
    else:
        candidates = (item.get("src4_addr"), item.get("src4_xlt_ip"))

    endpoints = (
        item.get("src4_addr"), item.get("src4_xlt_ip"),
        item.get("dst4_addr"), item.get("dst4_xlt_ip"),
    )
    if vpn_ip not in endpoints:
        return "Belum ada data"

    found = set()
    for value in candidates:
        try:
            address = ipaddress.ip_address(str(value))
            if (
                address.version == 4
                and any(address in net for net in local_networks)
                and not any(address in net for net in excluded_networks)
            ):
                found.add(str(address))
        except ValueError:
            continue

    return ", ".join(sorted(found)) if found else "Belum ada data"



@APP.get("/api/l2tp-online")
def l2tp_online_data():
    try:
        router_result = subprocess.run(
            [
                os.path.join(PROJECT_DIR, "venv", "bin", "python"),
                os.path.join(PROJECT_DIR, "routeros_active.py")
            ],
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            timeout=15
        )

        if router_result.returncode != 0:
            raise RuntimeError("Pembacaan PPP Active gagal")

        router_data = json.loads(router_result.stdout)
        if router_data.get("ok") is not True:
            raise RuntimeError("Data RouterOS tidak valid")

        sessions = []
        for user in router_data.get("sessions", []):
            if str(user.get("service", "")).upper() != "L2TP":
                continue
            if str(user.get("status", "")).upper() != "ONLINE":
                continue

            vpn_ip = str(user.get("vpn_ip", "")).strip()
            try:
                vpn_ip = str(ipaddress.ip_address(vpn_ip))
            except ValueError:
                continue

            sessions.append({
                "user": user.get("user", "-"),
                "vpn_ip": vpn_ip,
                "remote_ip": user.get("remote_ip", "-"),
                "uptime": user.get("uptime", "-"),
                "destination_ip": set()
            })

        if sessions:
            filters = []
            for user in sessions:
                ip = user["vpn_ip"]
                filters.append(f"(src ip {ip} or dst ip {ip})")

            flow_result = subprocess.run(
                [
                    "/usr/bin/nfdump",
                    "-R", "/var/cache/nfdump/",
                    "-o", "json",
                    "-c", "5000",
                    " or ".join(filters)
                ],
                capture_output=True,
                text=True,
                timeout=30
            )

            if flow_result.returncode != 0:
                raise RuntimeError("Pembacaan NetFlow gagal")

            output = flow_result.stdout.strip()

            if "No matching flows" in output:
                records = []
            else:
                records = json.loads(output)

            if not isinstance(records, list):
                raise RuntimeError("Format NetFlow tidak valid")

            session_map = {u["vpn_ip"]: u for u in sessions}

            for item in records:
                if item.get("type") != "FLOW":
                    continue

                src_ip = item.get("src4_addr")
                dst_ip = item.get("dst4_addr")
                src_xlt = item.get("src4_xlt_ip")
                dst_xlt = item.get("dst4_xlt_ip")

                if src_ip in session_map or src_xlt in session_map:
                    vpn_ip = src_ip if src_ip in session_map else src_xlt
                    direction = "UPLOAD"
                elif dst_ip in session_map or dst_xlt in session_map:
                    vpn_ip = dst_ip if dst_ip in session_map else dst_xlt
                    direction = "DOWNLOAD"
                else:
                    continue

                destination = get_flow_local_destination(
                    item, vpn_ip, direction
                )

                if destination != "Belum ada data":
                    session_map[vpn_ip]["destination_ip"].update(
                        x.strip() for x in destination.split(",") if x.strip()
                    )

        for user in sessions:
            found = sorted(user["destination_ip"])
            user["destination_ip"] = (
                ", ".join(found) if found else "Belum ada data"
            )

        return jsonify(
            ok=True,
            online_count=len(sessions),
            sessions=sessions
        )

    except Exception:
        APP.logger.exception("L2TP online gagal dibaca")
        return jsonify(
            ok=False,
            error="Data user L2TP online tidak dapat dibaca."
        ), 503


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

        output = result.stdout.strip()

        if "No matching flows" in output:
            records = []
        else:
            records = json.loads(output)

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
                "destination_ip": get_flow_local_destination(item, vpn_ip, direction),
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




@APP.post("/api/netflow-user/export.xlsx")
def export_netflow_user_xlsx():
    import hmac

    expected = session.get("csrf_token", "")
    supplied = request.headers.get("X-CSRF-Token", "")
    if not expected or not hmac.compare_digest(supplied, expected):
        return jsonify(ok=False, error="Token keamanan tidak valid."), 403

    data = request.get_json(silent=True) or {}
    username = str(data.get("user", "")).strip()
    raw_ip = str(data.get("vpn_ip", "")).strip()
    flows = data.get("flows")

    if not username or len(username) > 100:
        return jsonify(ok=False, error="Username tidak valid."), 400

    try:
        vpn_ip = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        return jsonify(ok=False, error="IP VPN tidak valid."), 400

    if not isinstance(flows, list) or len(flows) > 5000:
        return jsonify(ok=False, error="Data flow tidak valid atau melebihi 5.000 baris."), 400

    allowed = (
        "first", "last", "direction", "src_ip", "src_port",
        "dst_ip", "dst_port", "protocol", "packets", "bytes", "destination_ip"
    )
    clean_flows = []

    for flow in flows:
        if not isinstance(flow, dict):
            return jsonify(ok=False, error="Format data flow tidak valid."), 400

        clean = {}
        for key in allowed:
            value = flow.get(key, "")
            if key in ("packets", "bytes", "src_port", "dst_port"):
                try:
                    value = max(0, int(value or 0))
                except (ValueError, TypeError):
                    value = 0
            else:
                value = str(value or "")[:200]
            clean[key] = value

        clean_flows.append(clean)

    try:
        output = make_xlsx([], analysis={
            "user": username,
            "vpn_ip": vpn_ip,
            "flows": clean_flows
        })
        filename = "VPN-Analysis-" + re.sub(r"[^A-Za-z0-9_-]", "_", username) + ".xlsx"

        return send_file(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=filename
        )
    except Exception:
        APP.logger.exception("Export Excel NetFlow gagal")
        return jsonify(ok=False, error="Gagal membuat laporan Excel."), 500

if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
