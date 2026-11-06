#!/opt/server-log-vpn-dashboard/venv/bin/python
import os
import json
from librouteros import connect

config = {}
with open("/etc/office-vpn-router.env") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            config[k.strip()] = v.strip().strip('"').strip("'")

router = connect(
    host=config["ROUTEROS_HOST"],
    username=config["ROUTEROS_USER"],
    password=config["ROUTEROS_PASSWORD"],
    port=int(config["ROUTEROS_PORT"]),
    timeout=8
)

try:
    active = {}
    for x in router.path("ppp", "active"):
        name = str(x.get("name", "-"))
        active[name] = {
            "user": name,
            "service": str(x.get("service", "-")).upper(),
            "vpn_ip": x.get("address", "-"),
            "remote_ip": x.get("caller-id", "-"),
            "uptime": x.get("uptime", "-"),
            "status": "ONLINE",
            "disabled": False
        }

    users = {}
    for x in router.path("ppp", "secret"):
        name = str(x.get("name", "-"))
        if name == "-":
            continue

        user = {
            "user": name,
            "service": str(x.get("service", "-")).upper(),
            "vpn_ip": x.get("remote-address", "-"),
            "remote_ip": "-",
            "uptime": "-",
            "status": "OFFLINE",
            "disabled": str(x.get("disabled", "false")).lower() == "true"
        }

        if name in active:
            user.update(active[name])

        users[name] = user

    # Tetap masukkan sesi aktif yang tidak ditemukan di PPP Secret.
    for name, user in active.items():
        users[name] = user

    sessions = sorted(
        users.values(),
        key=lambda x: (x["status"] != "ONLINE", str(x["user"]).lower())
    )

    print(json.dumps({
        "ok": True,
        "sessions": sessions,
        "online_count": sum(x["status"] == "ONLINE" for x in sessions),
        "offline_count": sum(x["status"] == "OFFLINE" for x in sessions)
    }))

finally:
    router.close()
