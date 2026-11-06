#!/usr/bin/env python3
import os
import re
import json
import glob
import hashlib
import argparse
import subprocess
import ipaddress
import logging

from datetime import datetime
from collections import defaultdict
from pathlib import Path

import mysql.connector

LOG_DIR = "/var/log/mikrotik-vpn"
FLOW_DIR = "/var/cache/nfdump"

VPN_NETWORKS = [
    ipaddress.ip_network("192.168.110.0/24"),
    ipaddress.ip_network("192.168.201.0/24"),
]

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

PROTOCOLS = {
    1: "ICMP", 6: "TCP", 17: "UDP",
    47: "GRE", 50: "ESP", 58: "ICMPv6"
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("/opt/server-log-vpn-dashboard/logs/sync.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("vpn-sync")


def db_connect():
    return mysql.connector.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", "3306")),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
        connection_timeout=10
    )


def to_mysql_datetime(value):
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def connection_type(vpn_ip):
    try:
        ip = ipaddress.ip_address(vpn_ip)
        if ip in ipaddress.ip_network("192.168.110.0/24"):
            return "L2TP"
        if ip in ipaddress.ip_network("192.168.201.0/24"):
            return "SSTP"
    except (ValueError, TypeError):
        pass
    return "UNKNOWN"


def is_vpn_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return any(ip in network for network in VPN_NETWORKS)
    except (ValueError, TypeError):
        return False


def read_log_events():
    events = []

    for path in sorted(glob.glob(os.path.join(LOG_DIR, "*.log"))):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    raw = line.rstrip("\n")
                    match = LINE_RE.match(raw)
                    if not match:
                        continue

                    timestamp, hostname, body = match.groups()

                    try:
                        event_at = datetime.fromisoformat(
                            timestamp.replace("Z", "+00:00")
                        )
                        if event_at.tzinfo:
                            event_at = event_at.astimezone().replace(tzinfo=None)
                    except ValueError:
                        continue

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

                    events.append(event)

        except OSError as exc:
            logger.warning("Gagal membaca %s: %s", path, exc)

    events.sort(key=lambda e: e["event_at"])
    return events


def sync_events(conn):
    events = read_log_events()
    imported = 0

    cur = conn.cursor()

    for event in events:
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
            continue

        imported += 1

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

            session_row = cur.fetchone()

            if session_row:
                session_id, login_at = session_row
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

    cur.close()
    conn.commit()
    logger.info("Log VPN: %s event baru dari %s event terbaca", imported, len(events))


def process_netflow_file(conn, path):
    stat = os.stat(path)
    filename = os.path.basename(path)

    cur = conn.cursor()

    cur.execute(
        "SELECT filename FROM netflow_file_checkpoints WHERE filename=%s",
        (filename,)
    )
    if cur.fetchone():
        cur.close()
        return False

    result = subprocess.run(
        ["/usr/bin/nfdump", "-r", path, "-o", "json"],
        capture_output=True,
        text=True,
        timeout=90,
        check=False
    )

    if result.returncode != 0:
        raise RuntimeError(
            "nfdump gagal untuk %s: %s" %
            (filename, result.stderr[-500:])
        )

    output = result.stdout.strip()

    # File NetFlow tanpa flow tetap dianggap valid.
    if "No matching flows" in output or not output:
        records = []
    else:
        try:
            records = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Output JSON tidak valid pada {filename}: {output[:300]}"
            ) from exc

    if not isinstance(records, list):
        raise RuntimeError("Format JSON tidak valid: " + filename)
    if not isinstance(records, list):
        raise RuntimeError("Format JSON tidak valid: " + filename)

    traffic = defaultdict(lambda: {
        "upload_bytes": 0, "download_bytes": 0,
        "upload_packets": 0, "download_packets": 0,
        "first": None, "last": None
    })

    destinations = {}

    for item in records:
        if item.get("type") != "FLOW":
            continue

        src = item.get("src4_addr") or item.get("src6_addr")
        dst = item.get("dst4_addr") or item.get("dst6_addr")
        src_xlt = item.get("src4_xlt_ip")
        dst_xlt = item.get("dst4_xlt_ip")

        # Upload: alamat sumber asli atau hasil translasi adalah IP VPN.
        if is_vpn_ip(src):
            vpn_ip = src
            remote_ip = dst_xlt or dst
            remote_port = item.get("dst_xlt_port") or item.get("dst_port")
            direction = "UPLOAD"

        elif is_vpn_ip(src_xlt):
            vpn_ip = src_xlt
            remote_ip = dst_xlt or dst
            remote_port = item.get("dst_xlt_port") or item.get("dst_port")
            direction = "UPLOAD"

        # Download: alamat tujuan asli atau hasil translasi adalah IP VPN.
        elif is_vpn_ip(dst_xlt):
            vpn_ip = dst_xlt
            remote_ip = src_xlt or src
            remote_port = item.get("src_xlt_port") or item.get("src_port")
            direction = "DOWNLOAD"

        elif is_vpn_ip(dst):
            vpn_ip = dst
            remote_ip = src_xlt or src
            remote_port = item.get("src_xlt_port") or item.get("src_port")
            direction = "DOWNLOAD"

        else:
            continue

        if not remote_ip:
            continue

        packets = int(item.get("in_packets") or 0)
        byte_count = int(item.get("in_bytes") or 0)
        proto_num = int(item.get("proto") or 0)
        protocol = PROTOCOLS.get(proto_num, str(proto_num))

        first = item.get("first")
        last = item.get("last")

        first_dt = to_mysql_datetime(first)
        last_dt = to_mysql_datetime(last)

        duration = 0
        if first_dt and last_dt:
            duration = max(0, (last_dt - first_dt).total_seconds())

        entry = traffic[vpn_ip]
        entry["upload_bytes" if direction == "UPLOAD" else "download_bytes"] += byte_count
        entry["upload_packets" if direction == "UPLOAD" else "download_packets"] += packets

        if first_dt and (entry["first"] is None or first_dt < entry["first"]):
            entry["first"] = first_dt
        if last_dt and (entry["last"] is None or last_dt > entry["last"]):
            entry["last"] = last_dt

        key = (vpn_ip, direction, remote_ip, str(remote_port or ""), protocol)

        if key not in destinations:
            destinations[key] = {
                "vpn_ip": vpn_ip,
                "direction": direction,
                "remote_ip": remote_ip,
                "remote_port": int(remote_port) if str(remote_port or "").isdigit() else None,
                "protocol": protocol,
                "packets": 0,
                "bytes": 0,
                "first_seen": first_dt,
                "last_seen": last_dt,
                "duration": 0
            }

        dest = destinations[key]
        dest["packets"] += packets
        dest["bytes"] += byte_count
        dest["duration"] += duration

        if first_dt and (dest["first_seen"] is None or first_dt < dest["first_seen"]):
            dest["first_seen"] = first_dt
        if last_dt and (dest["last_seen"] is None or last_dt > dest["last_seen"]):
            dest["last_seen"] = last_dt

    try:
        for vpn_ip, totals in traffic.items():
            cur.execute("""
                INSERT INTO traffic_history
                (vpn_ip, connection_type, period_start, period_end,
                 upload_bytes, download_bytes, upload_packets, download_packets)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                vpn_ip, connection_type(vpn_ip),
                totals["first"], totals["last"],
                totals["upload_bytes"], totals["download_bytes"],
                totals["upload_packets"], totals["download_packets"]
            ))

        for dest in destinations.values():
            cur.execute("""
                INSERT INTO netflow_destinations
                (vpn_ip, direction, remote_ip, remote_port, protocol,
                 packets, bytes, first_seen, last_seen, duration_seconds)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                dest["vpn_ip"], dest["direction"], dest["remote_ip"],
                dest["remote_port"], dest["protocol"], dest["packets"],
                dest["bytes"], dest["first_seen"], dest["last_seen"],
                dest["duration"]
            ))

        cur.execute("""
            INSERT INTO netflow_file_checkpoints
            (filename, file_size, file_mtime, flow_count)
            VALUES (%s,%s,%s,%s)
        """, (filename, stat.st_size, int(stat.st_mtime), len(records)))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        cur.close()

    logger.info(
        "NetFlow %s: %s flow, %s IP VPN, %s tujuan",
        filename, len(records), len(traffic), len(destinations)
    )
    return True


def sync_netflow(conn, max_files):
    paths = sorted(
        p for p in glob.glob(os.path.join(FLOW_DIR, "nfcapd.*"))
        if re.fullmatch(r"nfcapd\.\d{12}", os.path.basename(p))
        and os.path.isfile(p)
    )

    processed = 0

    for path in paths:
        if processed >= max_files:
            break

        try:
            if process_netflow_file(conn, path):
                processed += 1
        except Exception:
            conn.rollback()
            logger.exception("Gagal memproses %s", path)
            break

    logger.info("NetFlow: %s file baru diproses", processed)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-netflow-files", type=int, default=10)
    args = parser.parse_args()

    conn = db_connect()

    try:
        sync_events(conn)
        sync_netflow(conn, max(1, min(args.max_netflow_files, 100)))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
