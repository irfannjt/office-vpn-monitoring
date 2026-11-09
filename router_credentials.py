from pathlib import Path
from cryptography.fernet import Fernet

KEY_FILE = Path("/etc/server-log-vpn-dashboard/router-fernet.key")


def load_cipher():
    if not KEY_FILE.is_file():
        raise RuntimeError("Kunci enkripsi router belum diinisialisasi.")

    if KEY_FILE.stat().st_mode & 0o077:
        raise PermissionError("Izin file kunci harus 600.")

    return Fernet(KEY_FILE.read_bytes().strip())


def initialize_key():
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    if KEY_FILE.exists():
        raise FileExistsError("Kunci sudah tersedia; tidak akan ditimpa.")

    KEY_FILE.write_bytes(Fernet.generate_key())
    KEY_FILE.chmod(0o600)


def encrypt_secret(value):
    if not isinstance(value, str) or not value:
        raise ValueError("Kredensial tidak boleh kosong.")
    return load_cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value):
    return load_cipher().decrypt(value.encode("ascii")).decode("utf-8")
