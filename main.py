from qt_ui.ui import main as qt_main
from core.client_security import enforce_client_security


def main() -> None:
    if not enforce_client_security():
        # Chặn chạy nếu rủi ro cao (debugger/tamper/hook...) vượt ngưỡng.
        return
    qt_main()


if __name__ == "__main__":
    main()
  