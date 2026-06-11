import argparse
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DIRS = [
    "issuer-service",
    "verifier-service",
    "device-agent",
    "fabric",
    "fabric-adapter",
    "scripts",
]

REQUIRED_FILES = [
    "docker-compose.yml",
    "docker-compose.fabric.yml",
    "docker-compose.perf.yml",
    "fabric/network.sh",
    "scripts/integration_test.py",
    "scripts/benchmark_pipeline.py",
    "scripts/fabric_smoke_test.py",
    "scripts/fabric_adapter_smoke_test.py",
]

IGNORED_PATHS = [
    "results/",
    "perf-out/",
    "data/",
    "__pycache__/",
    "fabric/chaincode/iam/vendor/",
]

PORTS = [
    (8000, "issuer"),
    (8001, "verifier"),
    (8010, "fabric adapter"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check local development environment.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 1 when warnings are present.",
    )
    args = parser.parse_args()

    rows = []
    add_python_check(rows)
    add_command_check(rows, "Docker installed", ["docker", "--version"], required=True)
    add_docker_daemon_check(rows)
    add_command_check(
        rows,
        "Docker compose works",
        ["docker", "compose", "version"],
        required=True,
    )
    add_command_check(rows, "Git installed", ["git", "--version"], required=True)
    add_git_bash_check(rows)
    add_project_paths_check(rows)
    add_fabric_orgs_check(rows)
    add_port_checks(rows)
    add_gitignore_checks(rows)

    print_table(rows)
    failed = any(row["status"] == "FAIL" for row in rows)
    warned = any(row["status"] == "WARN" for row in rows)
    return 1 if failed or (args.strict and warned) else 0


def add_python_check(rows: list[dict[str, str]]) -> None:
    version = sys.version_info
    detail = f"{version.major}.{version.minor}.{version.micro}"
    if version >= (3, 10):
        add_row(rows, "Python version", "PASS", detail)
    else:
        add_row(rows, "Python version", "FAIL", f"{detail}; Python 3.10+ recommended")


def add_command_check(
    rows: list[dict[str, str]], check: str, command: list[str], required: bool
) -> None:
    executable = shutil.which(command[0])
    if executable is None:
        add_row(rows, check, "FAIL" if required else "WARN", f"{command[0]} not found")
        return
    result = run(command)
    detail = first_output_line(result) or executable
    add_row(rows, check, "PASS" if result.returncode == 0 else "FAIL", detail)


def add_docker_daemon_check(rows: list[dict[str, str]]) -> None:
    if shutil.which("docker") is None:
        add_row(rows, "Docker daemon running", "FAIL", "docker not found")
        return
    result = run(["docker", "info"])
    detail = first_output_line(result) or "docker info returned no output"
    add_row(rows, "Docker daemon running", "PASS" if result.returncode == 0 else "FAIL", detail)


def add_git_bash_check(rows: list[dict[str, str]]) -> None:
    if os.name != "nt":
        add_row(rows, "Git Bash available", "PASS", "not required on non-Windows")
        return
    candidates = [
        Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe",
        Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/usr/bin/bash.exe",
        Path("C:/Program Files/Git/bin/bash.exe"),
    ]
    found = next((path for path in candidates if path.exists()), None)
    if found:
        add_row(rows, "Git Bash available", "PASS", str(found))
    elif shutil.which("bash"):
        add_row(rows, "Git Bash available", "PASS", shutil.which("bash") or "bash")
    else:
        add_row(rows, "Git Bash available", "WARN", "bash.exe not found")


def add_project_paths_check(rows: list[dict[str, str]]) -> None:
    for folder in REQUIRED_DIRS:
        path = REPO_ROOT / folder
        add_row(
            rows,
            f"Folder {folder}",
            "PASS" if path.is_dir() else "FAIL",
            str(path),
        )
    for filename in REQUIRED_FILES:
        path = REPO_ROOT / filename
        add_row(
            rows,
            f"File {filename}",
            "PASS" if path.is_file() else "FAIL",
            str(path),
        )


def add_fabric_orgs_check(rows: list[dict[str, str]]) -> None:
    value = os.getenv("FABRIC_SAMPLES_ORGS_HOST_PATH", "").strip()
    if not value:
        add_row(
            rows,
            "Fabric orgs path",
            "WARN",
            "FABRIC_SAMPLES_ORGS_HOST_PATH is not set",
        )
        return
    path = Path(value)
    add_row(
        rows,
        "Fabric orgs path",
        "PASS" if path.is_dir() else "FAIL",
        str(path),
    )


def add_port_checks(rows: list[dict[str, str]]) -> None:
    for port, label in PORTS:
        if is_port_open("127.0.0.1", port):
            add_row(rows, f"Port {port} {label}", "WARN", "already in use")
        else:
            add_row(rows, f"Port {port} {label}", "PASS", "available")


def add_gitignore_checks(rows: list[dict[str, str]]) -> None:
    if shutil.which("git") is None:
        add_row(rows, "Git ignore check", "WARN", "git not found")
        return
    for path in IGNORED_PATHS:
        result = run(["git", "check-ignore", path], cwd=REPO_ROOT)
        if result.returncode == 0:
            add_row(rows, f"Ignored {path}", "PASS", path)
        else:
            add_row(rows, f"Ignored {path}", "WARN", "not ignored or git unavailable")


def is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def run(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command,
            cwd=cwd or REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except Exception as exc:
        return subprocess.CompletedProcess(command, 1, "", str(exc))


def first_output_line(result: subprocess.CompletedProcess) -> str:
    output = (result.stdout or result.stderr or "").strip()
    return output.splitlines()[0] if output else ""


def add_row(rows: list[dict[str, str]], check: str, status: str, detail: str) -> None:
    rows.append({"check": check, "status": status, "detail": detail})


def print_table(rows: list[dict[str, str]]) -> None:
    headers = {"check": "CHECK", "status": "STATUS", "detail": "DETAIL"}
    widths = {
        key: max(len(headers[key]), *(len(row[key]) for row in rows))
        for key in headers
    }
    print(
        f"{headers['check'].ljust(widths['check'])}  "
        f"{headers['status'].ljust(widths['status'])}  "
        f"{headers['detail']}"
    )
    print(
        f"{'-' * widths['check']}  "
        f"{'-' * widths['status']}  "
        f"{'-' * widths['detail']}"
    )
    for row in rows:
        print(
            f"{row['check'].ljust(widths['check'])}  "
            f"{row['status'].ljust(widths['status'])}  "
            f"{row['detail']}"
        )


if __name__ == "__main__":
    sys.exit(main())
