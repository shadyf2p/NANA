# GOD MODE Licensing System (MMO Tool)

Backend + client mẫu cho mô hình license cứng hóa:

- **Client giả định bị compromise hoàn toàn**
- **Mọi quyết định hợp lệ đều do server**
- **Response trả execution instructions động**
- **Có anti-replay + encrypted envelope + risk scoring**
- **Có IP ban tự động + admin login anomaly log + logging intelligence**
- **Có encryption key rotation theo `kid` (AES/HMAC key-ring)**
- **Payment-ready: webhook auto issue key + customer dashboard token**

## 1) Thành phần hệ thống

1. Python Client (secure loader + periodic verify)
2. API Gateway/Service (Node.js + Express)
3. Core Licensing (MySQL)
4. Nonce/Rate/Fail counters (Redis)
5. Execution Control Service (policy theo plan + risk)
6. Admin API cho Vue admin panel

## 2) Cấu trúc thư mục

```txt
god_mode_backend/
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
  python_client/
    secure_client.py
    requirements.txt
  .env.example
  DEPLOYMENT.md
  SECURITY_LAYERS.md
```

## 3) Luồng verify bảo mật

Client gửi:

- `kid` (key id đang dùng)
- `encrypted_payload` (AES-256-GCM)
- `timestamp`
- `nonce`
- `signature` (HMAC-SHA256)

Server thực hiện:

1. Kiểm tra rate limit theo IP (Redis)
2. Verify HMAC chữ ký request
3. Check timestamp window chống replay
4. Consume nonce 1 lần qua Redis (`SET NX EX`)
5. Giải mã payload
6. Hash license key (SHA256)
7. Check license status/expire/hwid
8. Tính risk score + auto suspend nếu rủi ro quá cao
9. Auto-ban IP nếu fail patterns vượt ngưỡng
10. Ghi verify logs đầy đủ (IP/HWID/geo/request frequency/failure reason)
11. Trả response mã hóa + ký + execution instructions (kèm snippet rotate id)
12. Response có `kid` để client chọn key decrypt/verify tương ứng

## 4) API chính

### Auth

- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`

### Public verify

- `POST /api/key/verify`

### Public payment/dashboard

- `POST /api/public/payment/webhook`
- `GET /api/public/dashboard/licenses?token=...`

### Admin

- `POST /api/admin/key/create`
- `POST /api/admin/key/ban`
- `GET /api/admin/key/list`
- `GET /api/admin/logs/list`

## 5) Cài đặt nhanh

### B1. Database

Import file `sql/schema.sql`.

### B2. Config

```bash
cp .env.example .env
```

Bắt buộc set:

- `MYSQL_*`
- `REDIS_URL`
- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `COMM_AES_KEY_B64` (base64 của 32 bytes)
- `COMM_HMAC_SECRET`
- hoặc key-ring rotation:
  - `COMM_ACTIVE_KID`
  - `COMM_AES_KEYS_JSON`
  - `COMM_HMAC_KEYS_JSON`

### B3. Install + run

```bash
npm install
npm run dev
```

Health check:

```bash
curl http://127.0.0.1:8081/health
```

## 6) Ví dụ request

### Login admin

```bash
curl -X POST http://127.0.0.1:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ChangeMeStrong123!"}'
```

### Create key (admin)

```bash
curl -X POST http://127.0.0.1:8081/api/admin/key/create \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"licenseKeyPlain":"MMO-PROD-KEY-001-XYZ","expireAt":"2027-01-01T00:00:00.000Z","planCode":"pro"}'
```

### Ban key (admin)

```bash
curl -X POST http://127.0.0.1:8081/api/admin/key/ban \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"licenseKeyPlain":"MMO-PROD-KEY-001-XYZ"}'
```

### Payment webhook (auto issue key)

```bash
curl -X POST http://127.0.0.1:8081/api/public/payment/webhook \
  -H "Content-Type: application/json" \
  -H "x-webhook-signature: <HMAC_HEX>" \
  -d '{
    "event_id":"evt_1001",
    "provider":"stripe",
    "event_type":"payment.succeeded",
    "payment_ref":"pi_abc",
    "amount_cents":2999,
    "currency":"USD",
    "customer_email":"buyer@example.com",
    "customer_name":"Buyer",
    "plan_code":"pro",
    "duration_days":30
  }'
```

## 7) Python client mẫu

`python_client/secure_client.py` đã có:

- secure loader checks (delay + integrity + guard snapshot)
- anti-debug/timing/tool scan
- anti-memory patch loop (redundant state validation)
- anti-tamper (self hash + random integrity probes)
- runtime defense (hidden verify loop + randomized guard loop)
- encrypt request + hmac sign
- verify server signature
- periodic revalidation + hidden revalidation loop
- server-driven execution instructions

Chạy:

```bash
pip install -r python_client/requirements.txt
python python_client/secure_client.py
```

Set env:

- `LICENSE_KEY`
- `LICENSE_VERIFY_URL`
- `COMM_ACTIVE_KID`
- `COMM_AES_KEYS_JSON` (hoặc `COMM_AES_KEY_B64`)
- `COMM_HMAC_KEYS_JSON` (hoặc `COMM_HMAC_SECRET`)

Obfuscation:

- `python_client/OBFUSCATION.md`
- `python_client/build_obfuscated.ps1`

## 8) Lưu ý production

- Đặt backend sau Nginx + TLS bắt buộc
- Redis bật auth + private network
- Rotate `COMM_AES_KEY_B64` và `COMM_HMAC_SECRET` theo chu kỳ
- Log ship về SIEM/ELK để phân tích gian lận
- Chạy verify định kỳ trên client để revoke gần real-time

