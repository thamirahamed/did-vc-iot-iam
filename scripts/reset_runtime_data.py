import argparse
import shutil
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

ROOT_MARKERS = [
    "docker-compose.yml",
    "issuer-service",
    "verifier-service",
    "fabric",
]

GENERATED_DIRS = [
    "data",
    "results",
    "perf-out",
    "issuer-service/app/__pycache__",
    "verifier-service/app/__pycache__",
    "device-agent/app/__pycache__",
    "scripts/__pycache__",
    "fabric-adapter/app/__pycache__",
]

PROTECTED_NAMES = {".git", ".venv", "fabric-samples"}
PROTECTED_FILES = {
    "fabric/chaincode/iam/go.mod",
    "fabric/chaincode/iam/go.sum",
    "fabric/chaincode/iam/iam.go",
    "docker-compose.yml",
    "docker-compose.fabric.yml",
    "docker-compose.perf.yml",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Remove generated runtime data safely.")
    parser.add_argument("--apply", action="store_true", help="Actually remove files.")
    args = parser.parse_args()

    if not looks_like_repo_root(REPO_ROOT):
        print(f"Refusing to run: {REPO_ROOT} does not look like the repository root.")
        return 1

    targets = collect_targets()
    action = "Removing" if args.apply else "Would remove"
    for target in targets:
        print(f"{action}: {target.relative_to(REPO_ROOT)}")

    removed = 0
    if args.apply:
        for target in targets:
            remove_target(target)
            removed += 1

    print_summary(args.apply, len(targets), removed)
    return 0


def looks_like_repo_root(root: Path) -> bool:
    return all((root / marker).exists() for marker in ROOT_MARKERS)


def collect_targets() -> list[Path]:
    targets: set[Path] = set()
    for relative in GENERATED_DIRS:
        add_if_safe(targets, REPO_ROOT / relative)

    for path in REPO_ROOT.rglob("__pycache__"):
        add_if_safe(targets, path)
    for path in REPO_ROOT.rglob("*.pyc"):
        add_if_safe(targets, path)

    return sorted(targets, key=lambda item: str(item).lower())


def add_if_safe(targets: set[Path], path: Path) -> None:
    try:
        resolved = path.resolve()
        resolved.relative_to(REPO_ROOT.resolve())
    except ValueError:
        return
    relative = resolved.relative_to(REPO_ROOT.resolve()).as_posix()
    if not path.exists():
        return
    if any(part in PROTECTED_NAMES for part in resolved.parts):
        return
    if relative in PROTECTED_FILES:
        return
    if any(is_relative_to(resolved, existing) for existing in targets if existing.is_dir()):
        return
    if resolved.is_dir():
        for existing in list(targets):
            if is_relative_to(existing, resolved):
                targets.remove(existing)
    targets.add(resolved)


def remove_target(target: Path) -> None:
    if target.is_dir():
        shutil.rmtree(target)
    elif target.exists():
        target.unlink()


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def print_summary(apply: bool, target_count: int, removed: int) -> None:
    mode = "apply" if apply else "dry run"
    print(f"Mode: {mode}")
    print(f"Targets found: {target_count}")
    if apply:
        print(f"Targets removed: {removed}")
    else:
        print("No files were removed. Re-run with --apply to clean.")


if __name__ == "__main__":
    sys.exit(main())
