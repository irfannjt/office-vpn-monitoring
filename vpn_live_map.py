#!/usr/bin/env python3

import json
import os
import sys
import mysql.connector

from router_manager import connect_router
from router_credentials import decrypt_secret


def db_connection():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "3306")),
        database=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        connection_timeout=5
    )


def clean(value):
    if value is None:
        return ""
    return str(value)


def collect():
    db = None
    routers_result = []
    sessions_result = []

    try:
        db = db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                r.id,
                r.name,
                r.host,
                r.port,
                r.connection_type,
                r.routeros_version,
                r.is_active,
                c.api_username,
                c.encrypted_password
            FROM managed_routers r
            LEFT JOIN router_credentials c
                ON c.router_id = r.id
            ORDER BY r.id
        """)

        routers = cursor.fetchall()
        cursor.close()

        for item in routers:
            router_info = {
                "id": item["id"],
                "name": item["name"],
                "host": item["host"],
                "connection_type": item["connection_type"],
                "status": "offline",
                "identity": "",
                "version": clean(item["routeros_version"]),
                "uptime": "",
                "session_count": 0,
                "error": ""
            }

            if not item["api_username"] or not item["encrypted_password"]:
                router_info["error"] = "Kredensial API belum tersedia."
                routers_result.append(router_info)
                continue

            router = None

            try:
                password = decrypt_secret(item["encrypted_password"])

                router = connect_router(
                    host=item["host"],
                    username=item["api_username"],
                    password=password,
                    port=item["port"],
                    timeout=5
                )

                identity_rows = list(
                    router.path("system", "identity")
                )
                resource_rows = list(
                    router.path("system", "resource")
                )

                if not identity_rows:
                    raise RuntimeError("Identitas router tidak ditemukan.")

                identity = identity_rows[0]
                resources = resource_rows[0] if resource_rows else {}

                router_info["status"] = "online"
                router_info["identity"] = clean(identity.get("name"))
                router_info["version"] = clean(
                    resources.get("version")
                ) or router_info["version"]
                router_info["uptime"] = clean(
                    resources.get("uptime")
                )

                active_rows = list(
                    router.path("ppp", "active")
                )

                for active in active_rows:
                    service = clean(active.get("service")).upper()

                    if service not in ("SSTP", "L2TP"):
                        continue

                    session = {
                        "router_id": item["id"],
                        "router_name": item["name"],
                        "service": service,
                        "user": clean(active.get("name")),
                        "vpn_ip": clean(active.get("address")),
                        "remote_ip": clean(active.get("caller-id")),
                        "uptime": clean(active.get("uptime")),
                        "status": "online"
                    }

                    sessions_result.append(session)
                    router_info["session_count"] += 1

            except Exception as exc:
                # Jangan pernah memasukkan password atau kredensial ke output.
                router_info["status"] = "offline"
                router_info["error"] = str(exc)[:250]

            finally:
                if router is not None:
                    try:
                        router.close()
                    except Exception:
                        pass

            routers_result.append(router_info)

    finally:
        if db is not None:
            db.close()

    return {
        "ok": True,
        "routers_total": len(routers_result),
        "routers_online": sum(
            1 for r in routers_result if r["status"] == "online"
        ),
        "routers_offline": sum(
            1 for r in routers_result if r["status"] != "online"
        ),
        "sessions_total": len(sessions_result),
        "routers": routers_result,
        "sessions": sessions_result
    }


if __name__ == "__main__":
    try:
        print(json.dumps(collect(), ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "error": str(exc)[:250]
        }, ensure_ascii=False))
        sys.exit(1)
