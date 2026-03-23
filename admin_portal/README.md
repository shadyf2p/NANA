# Admin Portal

Trang quan tri local de:

- Tao key `7 ngay` / `30 ngay`
- Ban IP
- Ban HWID (machine_id)
- Theo doi su kien check key / dang nhap / thao tac admin

## Chay nhanh

```powershell
cd e:\MMO
py -3.13 admin_portal\server.py
```

Mo trinh duyet:

- <http://127.0.0.1:8787>

Mac dinh dang nhap:

- User: `admin`
- Pass: `admin123`

## Bien moi truong (nen doi truoc khi dung that)

```powershell
$env:ADMIN_USER="admin"
$env:ADMIN_PASS="doi_mat_khau_rat_manh"
$env:ADMIN_HOST="127.0.0.1"
$env:ADMIN_PORT="8787"
$env:ADMIN_LICENSE_SECRET="secret_trung_voi_License.py"
py -3.13 admin_portal\server.py
```

## Tich hop voi app check license

Trong `License.py`, URL check hien tai la `Apps Script`.
Neu muon app check vao portal moi nay, doi URL ve:

- `http://127.0.0.1:8787/api/check`

Luu y:

- `ADMIN_LICENSE_SECRET` ben admin portal phai trung voi `LICENSE_SECRET` trong `License.py`.
- Neu deploy server tu xa, nen dat sau reverse proxy (Nginx/Caddy) + HTTPS.

## Du lieu

DB SQLite mac dinh dung chung:

- `admin_portal/data/admin.db`

Desktop exe va web server deu tu dong tro ve file nay neu tim thay.

Neu muon chi dinh tuy chinh (ca 2 app dung cung 1 DB), dat:

```powershell
$env:ADMIN_DB_PATH="E:\MMO\admin_portal\data\admin.db"
```

Bang chinh:

- `licenses`
- `banned_ips`
- `banned_hwids`
- `events`
