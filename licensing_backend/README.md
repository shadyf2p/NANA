# MMO Licensing Backend (Node + Express + MySQL)

Backend production-ready cho hệ thống license tool MMO, tập trung chống crack theo hướng **server-authoritative**:

- Client không tự quyết định hợp lệ cục bộ.
- Mọi lần verify đi qua API server.
- Admin có thể revoke/ban key tức thì.
- Có log đầy đủ và chống brute-force/suspicious requests.

---

## 1) Kiến trúc thư mục

```txt
licensing_backend/
  src/
    config/
    controllers/
    middleware/
    models/
    routes/
    services/
    utils/
    validators/
    app.js
    server.js
  sql/schema.sql
  client_example/license_client.py
  .env.example
  package.json
```

---

## 2) Cài đặt và chạy

### Bước 1: Tạo DB schema

Chạy `sql/schema.sql` trên MySQL.

### Bước 2: Cấu hình môi trường

```bash
cp .env.example .env
```

Điền đúng `DB_*`, `JWT_SECRET`, `SEED_ADMIN_PASSWORD`.

### Bước 3: Cài dependency

```bash
npm install
```

### Bước 4: Chạy server

```bash
npm run dev
```

hoặc production:

```bash
npm start
```

Server mặc định: `http://127.0.0.1:8080`.

---

## 3) API bắt buộc

### POST `/api/login`

Admin login, trả JWT.

Body:

```json
{
  "username": "admin",
  "password": "ChangeThisStrongPassword!"
}
```

Response:

```json
{
  "token": "jwt_here",
  "expiresIn": "2h"
}
```

---

### POST `/api/key/create` (Admin JWT)

Body:

```json
{
  "expireAt": "2027-01-01T00:00:00.000Z",
  "prefix": "MMO"
}
```

Response:

```json
{
  "message": "License created",
  "data": {
    "key": "MMO-XXXX-XXXX-XXXX-XXXX",
    "expireAt": "2027-01-01T00:00:00.000Z",
    "status": "active"
  }
}
```

---

### POST `/api/key/verify` (Public for client)

Body:

```json
{
  "key": "MMO-....",
  "hwid": "client_hwid_hash"
}
```

Logic:

- Key không tồn tại -> reject
- `status=banned` -> reject
- `expire_at` quá hạn -> reject
- `hwid` null -> bind lần đầu
- `hwid` khác -> reject

Response:

```json
{
  "valid": true,
  "message": "License valid"
}
```

Hoặc:

```json
{
  "valid": false,
  "message": "HWID mismatch"
}
```

---

### POST `/api/key/ban` (Admin JWT)

Body:

```json
{
  "key": "MMO-...."
}
```

---

### GET `/api/key/list` (Admin JWT)

Query optional:

- `page` (default 1)
- `limit` (default 50, max 200)

---

## 4) API thêm cho vận hành

- POST `/api/key/delete` (Admin JWT)
- GET `/api/logs/list` (Admin JWT) - xem log verify (IP/HWID/key/reason)

---

## 5) Security notes (anti-crack)

- Không trust client input; mọi quyết định hợp lệ ở server.
- Password admin hash bằng `bcrypt` (cost 12).
- JWT bảo vệ route admin.
- Rate limit:
  - `/api/login`: chống brute-force mật khẩu.
  - `/api/key/verify`: chống spam verify.
- `verify_logs` lưu toàn bộ attempt: `ip`, `hwid`, `license_key`, `reason`.
- Chặn request nghi ngờ bằng ngưỡng fail lặp lại theo IP/HWID/KEY trong cửa sổ thời gian.
- Hỗ trợ revoke tức thì qua `/api/key/ban` (client lần revalidate kế tiếp sẽ fail ngay).

---

## 6) cURL mẫu

### Login

```bash
curl -X POST http://127.0.0.1:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ChangeThisStrongPassword!"}'
```

### Create key

```bash
curl -X POST http://127.0.0.1:8080/api/key/create \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"expireAt":"2027-01-01T00:00:00.000Z","prefix":"MMO"}'
```

### Verify key

```bash
curl -X POST http://127.0.0.1:8080/api/key/verify \
  -H "Content-Type: application/json" \
  -d '{"key":"MMO-...","hwid":"device_hwid_hash"}'
```

### Ban key

```bash
curl -X POST http://127.0.0.1:8080/api/key/ban \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"key":"MMO-..."}'
```

### List key

```bash
curl "http://127.0.0.1:8080/api/key/list?page=1&limit=50" \
  -H "Authorization: Bearer <JWT>"
```

---

## 7) Python client mẫu

Xem file:

- `client_example/license_client.py`

Nó gửi `key + hwid` tới `/api/key/verify`, và `exit(1)` nếu invalid.

> Khuyến nghị production: chạy verify theo chu kỳ (ví dụ mỗi 5-10 phút) + verify khi startup để hỗ trợ revoke gần real-time.

