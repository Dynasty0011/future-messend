from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ZIP_NAME = ROOT / "future_messenger_project.zip"


def should_skip(path: Path) -> bool:
    parts = set(path.parts)
    if "__pycache__" in parts:
        return True
    if path.name == ZIP_NAME.name:
        return True
    if path.suffix in {".pyc", ".pyo"}:
        return True
    return False


def main() -> None:
    if ZIP_NAME.exists():
        ZIP_NAME.unlink()
    with zipfile.ZipFile(ZIP_NAME, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in ROOT.rglob("*"):
            if path.is_file() and not should_skip(path):
                zf.write(path, path.relative_to(ROOT))
    print(f"Created: {ZIP_NAME}")


if __name__ == "__main__":
    main()
