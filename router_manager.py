from librouteros import connect


def connect_router(host, username, password, port=8728, timeout=5):
    if not host or not username or not password:
        raise ValueError("Host, username, dan password wajib diisi.")

    return connect(
        host=host,
        username=username,
        password=password,
        port=int(port),
        timeout=int(timeout)
    )


def get_router_identity(router):
    result = list(router.path("system", "identity"))
    if not result:
        raise RuntimeError("Identitas router tidak ditemukan.")
    return result[0]


def get_router_resources(router):
    result = list(router.path("system", "resource"))
    if not result:
        raise RuntimeError("Informasi resource router tidak ditemukan.")
    return result[0]


def test_router_connection(host, username, password, port=8728, timeout=5):
    router = None
    try:
        router = connect_router(
            host, username, password, port, timeout
        )

        identity = get_router_identity(router)
        resources = get_router_resources(router)

        return {
            "ok": True,
            "identity": identity.get("name", "-"),
            "version": resources.get("version", "-"),
            "board": resources.get("board-name", "-"),
            "uptime": resources.get("uptime", "-")
        }
    finally:
        if router is not None:
            router.close()
