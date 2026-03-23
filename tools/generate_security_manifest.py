from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data_general" / "security_manifest.json"

# Các file nhạy cảm nên giữ nguyên ở bản release.
TARGETS = [
    "main.py",
    "License.py",
    "qt_ui/ui.py",
    "qt_ui/status_panel_clean.py",
    "core/client_security.py",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    files: dict[str, str] = {}
    for rel in TARGETS:
        p = ROOT / rel
        if p.exists() and p.is_file():
            files[rel] = sha256_file(p)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "generated_at": __import__("time").time(),
        "files": files,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[security_manifest] wrote {OUT}")


if __name__ == "__main__":
    main()

