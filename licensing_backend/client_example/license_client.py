import hashlib
import os
import platform
import sys
from typing import Tuple

import requests

API_VERIFY_URL = os.getenv("LICENSE_VERIFY_URL", "http://127.0.0.1:8080/api/key/verify")
LICENSE_KEY = os.getenv("LICENSE_KEY", "").strip()


def make_hwid() -> str:
    parts = [
        platform.system(),
        platform.machine(),
        platform.node(),
        os.getenv("PROCESSOR_IDENTIFIER", ""),
    ]
    raw = "|".join([p.strip().lower() for p in parts if p and p.strip()])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify_license(license_key: str, hwid: str) -> Tuple[bool, str]:
    payload = {"key": license_key, "hwid": hwid}
    try:
        response = requests.post(API_VERIFY_URL, json=payload, timeout=8)
        data = response.json() if response.content else {}
    except Exception as exc:
        return False, f"verify_api_error: {exc}"

    if response.status_code == 200 and bool(data.get("valid")):
        return True, str(data.get("message", "ok"))
    return False, str(data.get("message", f"http_{response.status_code}"))


def main() -> None:
    if not LICENSE_KEY:
        print("Missing LICENSE_KEY environment variable")
        sys.exit(1)

    hwid = make_hwid()
    valid, message = verify_license(LICENSE_KEY, hwid)

    if not valid:
        print(f"License invalid: {message}")
        sys.exit(1)

    print(f"License accepted: {message}")
    # App continues only when server says valid.


if __name__ == "__main__":
    main()

