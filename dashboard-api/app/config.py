import os
from pathlib import Path


def load_project_env() -> None:
    env_path = _find_project_env()
    if env_path is None:
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        os.environ[key] = _strip_quotes(value.strip())


def _find_project_env() -> Path | None:
    candidates = [
        Path.cwd() / ".env.project",
        Path.cwd().parent / ".env.project",
        Path("/workspace/.env.project"),
        Path("/repo/.env.project"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
