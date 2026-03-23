# Deployment Guide (VPS + Domain + HTTPS)

## 1) Chuẩn bị VPS

- Ubuntu 22.04+
- Node.js 20+
- MySQL 8+
- Redis 7+
- Nginx
- PM2 (process manager)

## 2) Network hardening

- Chỉ mở public: `80`, `443`
- Chặn public vào MySQL/Redis
- MySQL/Redis chỉ bind private/internal

## 3) Triển khai app

```bash
git clone <repo>
cd god_mode_backend
npm install --omit=dev
cp .env.example .env
```

Điền `.env` production secrets thật mạnh.

Import schema:

```bash
mysql -u root -p < sql/schema.sql
```

Chạy bằng PM2:

```bash
pm2 start src/server.js --name god-mode-backend
pm2 save
pm2 startup
```

## 4) Nginx reverse proxy

Ví dụ:

```nginx
server {
    listen 80;
    server_name api.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 5) TLS certificate

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d api.yourdomain.com
```

## 6) Observability

- Bật PM2 logs + rotate
- Thu `verify_logs` về ELK/Grafana Loki
- Alert khi:
  - spike `bad_signature`
  - spike `nonce_replay_detected`
  - nhiều `hwid_mismatch` theo IP

## 7) Key rotation policy

- Rotation định kỳ `COMM_AES_KEY_B64` + `COMM_HMAC_SECRET`
- Hỗ trợ dual-key window khi rotate (thêm key cũ đọc tạm thời)
- Revoke toàn bộ refresh token sau sự cố bảo mật

