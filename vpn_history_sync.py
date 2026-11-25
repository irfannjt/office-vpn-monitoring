#!/usr/bin/env python3
import os
import re
import glob
import hashlib
import logging
import ipaddress

from datetime import datetime
import mysql.connector

LOG_FILE = "/var/log/ccr1009-vpn/ccr1009.log"
LOG_PATTERN = LOG_FILE + "*"

LINE_RE = re.compile(r"^(\S+)\s+(\S+)\s+(.*)$")
LOGIN_RE = re.compile(
    r"\baccount\s+(.+?)\s+logged in,\s*(\S+)\s+from\s+(\S+)", re.I
)
LOGOUT_RE = re.compile(
    r"\baccount\s+(.+?)\s+logged out,.*?\s+from\s+(\S+)", re.I
)
FAIL_RE = re.compile(
    r"login failure|authentication failed|failed to authenticate|auth.*failed|invalid password",
    re.I
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("vpn-history-sync")


def db_connect():
    return mysql.connector.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", "3306")),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
        connection_timeout=15
    )


def connection_type(vpn_ip):
    networks = [
        ("192.168.110.0/24", "L2TP"),
        ("192.168.201.0/24", "SSTP"),
        ("192.168.120.0/24", "PPTP"),
        ("192.168.200.0/24", "OpenVPN"),
    ]
    try:
        ip = ipaddress.ip_address(vpn_ip)
        for network, name in networks:
            if ip in ipaddress.ip_network(network):
                return name
    except (ValueError, TypeError):
        pass
    return "UNKNOWN"


def parse_event(raw):
    match = LINE_RE.match(raw)
    if not match:
        return None

    timestamp, hostname, body = match.groups()

    try:
        event_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if event_at.tzinfo:
            event_at = event_at.astimezone().replace(tzinfo=None)
    except ValueError:
        return None

    event = {
        "event_at": event_at,
        "event_type": "log",
        "username": None,
        "vpn_ip": None,
        "remote_ip": None,
        "hostname": hostname,
        "message": body,
        "raw_line": raw,
    }

    login = LOGIN_RE.search(body)
    logout = LOGOUT_RE.search(body)

    if login:
        event.update(
            event_type="login",
            username=login.group(1).strip(),
            vpn_ip=login.group(2),
            remote_ip=login.group(3),
            message="VPN login berhasil"
        )
    elif logout:
        event.update(
            event_type="logout",
            username=logout.group(1).strip(),
            remote_ip=logout.group(2),
            message="VPN logout"
        )
    elif FAIL_RE.search(body):
        event["event_type"] = "failed"

    if event["event_type"] not in ("login", "logout", "failed"):
        return None

    return event


def save_event(cur, event):
    event_hash = hashlib.sha256(
        event["raw_line"].encode("utf-8", errors="replace")
    ).hexdigest()

    cur.execute("""
        INSERT IGNORE INTO vpn_events
        (event_hash, event_at, event_type, username, vpn_ip,
         remote_ip, hostname, message, raw_line)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        event_hash, event["event_at"], event["event_type"],
        event["username"], event["vpn_ip"], event["remote_ip"],
        event["hostname"], event["message"], event["raw_line"]
    ))

    if cur.rowcount != 1:
        return 0

    if event["event_type"] == "login":
        cur.execute("""
            INSERT IGNORE INTO vpn_sessions
            (login_event_hash, username, vpn_ip, remote_ip,
             connection_type, login_at, status)
            VALUES (%s,%s,%s,%s,%s,%s,'ONLINE')
        """, (
            event_hash,
            event["username"],
            event["vpn_ip"],
            event["remote_ip"],
            connection_type(event["vpn_ip"]),
            event["event_at"]
        ))

    elif event["event_type"] == "logout":
        cur.execute("""
            SELECT id, login_at
            FROM vpn_sessions
            WHERE username=%s
              AND status='ONLINE'
              AND (%s IS NULL OR remote_ip=%s)
            ORDER BY login_at DESC
            LIMIT 1
            FOR UPDATE
        """, (
            event["username"],
            event["remote_ip"],
            event["remote_ip"]
        ))

        row = cur.fetchone()
        if row:
            session_id, login_at = row
            duration = max(
                0, int((event["event_at"] - login_at).total_seconds())
            )
            cur.execute("""
                UPDATE vpn_sessions
                SET logout_at=%s,
                    duration_seconds=%s,
                    status='OFFLINE'
                WHERE id=%s
            """, (event["event_at"], duration, session_id))

    return 1


def sync_file(conn, path):
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return

    inode = stat.st_ino
    size = stat.st_size

    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT inode, byte_offset
            FROM vpn_log_checkpoints
            WHERE filename=%s
            FOR UPDATE
        """, (path,))
        checkpoint = cur.fetchone()

        if checkpoint:
            old_inode, offset = checkpoint
            if old_inode != inode or size < offset:
                logger.warning(
                    "File berubah/terpotong, mulai dari awal: %s", path
                )
                offset = 0
        else:
            offset = 0

        imported = 0
        scanned = 0
        last_complete_offset = offset

        with open(path, "rb") as file:
            file.seek(offset)

            while True:
                raw_bytes = file.readline()
                if not raw_bytes:
                    break

                if not raw_bytes.endswith(b"\n"):
                    break

                last_complete_offset = file.tell()
                raw = raw_bytes.rstrip(b"\r\n").decode(
                    "utf-8", errors="replace"
                )

                event = parse_event(raw)
                if event:
                    scanned += 1
                    imported += save_event(cur, event)

        cur.execute("""
            INSERT INTO vpn_log_checkpoints
            (filename, inode, byte_offset)
            VALUES (%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                inode=VALUES(inode),
                byte_offset=VALUES(byte_offset)
        """, (path, inode, last_complete_offset))

        conn.commit()

        logger.info(
            "File %s: %s event baru, %s diperiksa, posisi %s/%s byte",
            os.path.basename(path),
            imported,
            scanned,
            last_complete_offset,
            size
        )

    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def main():
    paths = sorted(
        p for p in glob.glob(LOG_PATTERN)
        if os.path.isfile(p)
        and (
            p == LOG_FILE
            or p == LOG_FILE + ".1"
        )
    )

    conn = db_connect()
    try:
        for path in paths:
            sync_file(conn, path)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
