from qt_ui.ui import main as qt_main
from core.client_security import evaluate_client_security


def main() -> None:
    report = evaluate_client_security(include_signature_check=True)
    qt_main(initial_security_report=report)


if __name__ == "__main__":
    main()
  