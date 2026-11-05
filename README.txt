SERVER LOG VPN RIM – Dashboard lokal
===================================

Paket awal dashboard untuk membaca file Rsyslog:
  /var/log/mikrotik-vpn/*.log

Dashboard:
  http://192.168.88.235:8080

Fitur awal:
- jumlah sesi VPN online (diturunkan dari event login/logout)
- jumlah login hari ini
- event gagal autentikasi yang cocok dengan pola umum
- aktivitas login/logout terbaru
- refresh otomatis 10 detik
- waktu ditampilkan dalam Asia/Jakarta

PENTING:
1. Angka online adalah estimasi dari event login/logout yang tersimpan. Jika log awal hilang,
   server restart tanpa event logout, atau format log berbeda, angka dapat tidak akurat.
2. Pengenalan gagal login menggunakan pola teks umum; perlu disesuaikan setelah melihat
   contoh log kegagalan autentikasi sebenarnya.
3. Dashboard ini melindungi halaman dengan HTTP Basic Auth. Jangan jalankan sebelum
   DASH_PASSWORD diisi dengan password yang kuat.
4. Batasi akses port 8080 untuk jaringan admin/LAN. Jangan port-forward ke internet.
5. Jangan mengubah atau menghapus file syslog asli.

Instalasi Ubuntu 24.04 LXC (jalankan sebagai root):
  apt update
  apt install -y python3-flask unzip
  mkdir -p /opt/server-log-vpn-dashboard
  unzip server-log-vpn-dashboard.zip -d /opt/server-log-vpn-dashboard
  cd /opt/server-log-vpn-dashboard

Buat password dashboard (ganti nilai contoh):
  export DASH_USER=admin
  export DASH_PASSWORD='GANTI_DENGAN_PASSWORD_KUAT'
  export VPN_LOG_DIR=/var/log/mikrotik-vpn
  python3 app.py

Buka dari komputer di LAN:
  http://192.168.88.235:8080

Untuk pemakaian permanen, buat systemd service dengan EnvironmentFile agar password
tidak ditulis di command history. Contoh file service ada di deploy/server-log-vpn-dashboard.service.
