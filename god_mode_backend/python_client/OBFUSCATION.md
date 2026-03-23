# Python Client Obfuscation Pipeline (PyArmor)

Tài liệu này giúp đạt mục tiêu mục (8): obfuscation + giảm static analysis.

## 1) Chuẩn bị

```bash
pip install pyarmor==9.0.7 pyinstaller==6.10.0
```

## 2) Obfuscate source

Từ thư mục `python_client`:

```bash
pyarmor gen --assert-call --mix-str --enable-jit --private secure_client.py
```

Output mặc định nằm trong `dist/secure_client`.

## 3) Build EXE từ bản đã obfuscate

```bash
pyinstaller --onefile --noconsole dist/secure_client/secure_client.py
```

## 4) Khuyến nghị hardening build

- Đưa secrets runtime qua env, không hardcode.
- Dùng `EXPECTED_SELF_SHA256` theo artifact thật sau đóng gói.
- Kết hợp rotate keys (`COMM_AES_KEY_B64`, `COMM_HMAC_SECRET`) phía server.
- Rebuild định kỳ với profile obfuscation khác nhau.

## 5) Code virtualization (khuyến nghị)

Python native khó đạt virtualization sâu như C/C++; hướng thực tế:

- Chuyển module cực nhạy sang native extension (Rust/C++).
- Thực thi logic động chủ yếu từ server instruction.
- Giảm logic cục bộ, ưu tiên server-authoritative.

