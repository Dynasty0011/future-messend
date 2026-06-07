from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from socket import socket

ROOT = Path(__file__).resolve().parent

REQUIRED = [
    "fastapi",
    "uvicorn",
    "python-multipart",
    "passlib[bcrypt]",
    "pyjwt",
    "email-validator",
    "aiofiles",
    "cryptography",
]


def has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def pip_install(package: str) -> None:
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


def ensure_deps() -> None:
    checks = [
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn[standard]"),
        ("multipart", "python-multipart"),
        ("passlib", "passlib[bcrypt]"),
        ("jwt", "pyjwt"),
        ("email_validator", "email-validator"),
        ("aiofiles", "aiofiles"),
        ("cryptography", "cryptography"),
    ]
    for module_name, package in checks:
        if not has_module(module_name):
            print(f"Installing missing dependency: {package}")
            pip_install(package)


def find_free_port(start: int = 8000, end: int = 8050) -> int:
    for port in range(start, end + 1):
        with socket() as s:
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free port found")


def open_browser_later(url: str, delay: float = 1.4) -> None:
    def _open() -> None:
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_open, daemon=True).start()


def main() -> None:
    os.chdir(ROOT)
    ensure_deps()

    from app.main import ensure_runtime

    ensure_runtime()

    port = int(os.environ.get("FUTURE_MESSENGER_PORT", find_free_port()))
    local_url = f"http://127.0.0.1:{port}"

    print()
    print("=" * 60)
    print("Future Messenger")
    print("=" * 60)
    print(f"Local access: {local_url}")
    print(f"Network access: http://YOUR_LOCAL_IP:{port}")
    print("=" * 60)
    print()

    open_browser_later(local_url)

    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=port, log_level="info", reload=False)


if __name__ == "__main__":
    main()
