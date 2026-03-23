# Anti-Crack Layers (Design Summary)

## Layer 1: Server-authoritative license decision

- Client không tự xác nhận license.
- Mọi quyết định cho phép/chặn đều ở backend.

## Layer 2: Encrypted + signed transport envelope

- AES-256-GCM cho payload.
- HMAC-SHA256 cho integrity.
- Tách secrets khỏi binary pipeline khi build.

## Layer 3: Anti-replay

- Timestamp window.
- Nonce one-time-use qua Redis.

## Layer 4: Abuse controls

- Redis rate-limit theo IP.
- Failure counters theo IP/key/hwid.
- Auto reject khi vượt ngưỡng nghi ngờ.

## Layer 5: Risk scoring

- Cộng điểm theo hành vi bất thường:
  - đổi IP
  - hwid mismatch
  - tần suất fail cao
- Tự động suspend license khi risk vượt threshold.

## Layer 6: Execution control

- Server trả `instructions` để bật/tắt feature runtime.
- Khi risk tăng: degrade tính năng thay vì chỉ hard-block.

## Layer 7: Secure loader (client)

- Runtime checks trước khi chạy logic chính.
- Phát hiện debugger/tool cơ bản.
- Timing guard + integrity pin.
- Periodic re-verify để revoke gần real-time.

## Layer 8: Operational security

- TLS bắt buộc.
- Secret rotation theo chu kỳ.
- Audit logs + alerting.
- RBAC + refresh-token revocation.

---

Không có hệ nào "uncrackable". Mục tiêu thực tế là:

1. Tăng đáng kể chi phí bypass
2. Giảm thời gian tồn tại của bypass
3. Tối ưu khả năng phát hiện + phản ứng nhanh từ server

