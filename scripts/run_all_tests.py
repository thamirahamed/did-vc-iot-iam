import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
COMPILE_TARGETS = [
    "issuer-service\\app",
    "verifier-service\\app",
    "device-agent\\app",
    "scripts",
    "fabric-adapter\\app",
]


class Step:
    def __init__(
        self,
        name: str,
        command: list[str],
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        wait_url: str = "",
    ) -> None:
        self.name = name
        self.command = command
        self.cwd = cwd or REPO_ROOT
        self.env = env or {}
        self.wait_url = wait_url


def main() -> int:
    parser = argparse.ArgumentParser(description="Run common repository validation flows.")
    parser.add_argument("--mode", choices=["local", "fabric", "perf", "all"], default="local")
    parser.add_argument("--redeploy-chaincode", action="store_true")
    parser.add_argument("--skip-demo", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=0)
    parser.add_argument("--label", default="perf-smoke")
    args = parser.parse_args()

    start = time.perf_counter()
    modes = ["local", "fabric", "perf"] if args.mode == "all" else [args.mode]
    passed: list[str] = []
    failed_step = ""

    if args.redeploy_chaincode and any(mode in ("fabric", "perf") for mode in modes):
        for step in chaincode_steps():
            if not run_step("chaincode", step):
                failed_step = f"chaincode: {step.name}"
                break
            passed.append(f"chaincode: {step.name}")

    for mode in modes:
        if failed_step:
            break
        steps = build_steps(mode, args)
        if mode in ("fabric", "perf") and not fabric_orgs_ready():
            failed_step = f"{mode}: FABRIC_SAMPLES_ORGS_HOST_PATH missing or invalid"
            print(f"FAIL {failed_step}")
            break

        for step in steps:
            if not run_step(mode, step):
                failed_step = f"{mode}: {step.name}"
                break
            passed.append(f"{mode}: {step.name}")
        if failed_step:
            break

    duration = time.perf_counter() - start
    print_summary(args.mode, passed, failed_step, duration)
    return 1 if failed_step else 0


def build_steps(mode: str, args: argparse.Namespace) -> list[Step]:
    steps: list[Step] = []
    if mode == "local":
        steps.append(compile_step())
        if not args.skip_build:
            steps.append(Step("docker compose up", ["docker", "compose", "up", "-d", "--build"]))
        steps.append(Step("wait issuer health", [], wait_url="http://localhost:8000/health"))
        steps.append(Step("wait verifier health", [], wait_url="http://localhost:8001/health"))
        steps.append(Step("integration test", [sys.executable, "scripts/integration_test.py"]))
        if not args.skip_demo:
            steps.append(
                Step(
                    "demo walkthrough",
                    [sys.executable, "scripts/demo_walkthrough.py"],
                    env={"PAUSE": "0"},
                )
            )
    elif mode == "fabric":
        steps.append(compile_step())
        if not args.skip_build:
            steps.append(
                Step(
                    "fabric compose up",
                    [
                        "docker",
                        "compose",
                        "-f",
                        "docker-compose.yml",
                        "-f",
                        "docker-compose.fabric.yml",
                        "up",
                        "-d",
                        "--build",
                    ],
                )
            )
        steps.append(Step("wait issuer health", [], wait_url="http://localhost:8000/health"))
        steps.append(Step("wait verifier health", [], wait_url="http://localhost:8001/health"))
        steps.append(
            Step("wait fabric adapter health", [], wait_url="http://localhost:8010/health")
        )
        steps.append(
            Step("fabric adapter smoke", [sys.executable, "scripts/fabric_adapter_smoke_test.py"])
        )
        steps.append(Step("integration test", [sys.executable, "scripts/integration_test.py"]))
    elif mode == "perf":
        if not args.skip_build:
            steps.append(
                Step(
                    "perf compose up",
                    [
                        "docker",
                        "compose",
                        "-f",
                        "docker-compose.yml",
                        "-f",
                        "docker-compose.fabric.yml",
                        "-f",
                        "docker-compose.perf.yml",
                        "up",
                        "-d",
                        "--build",
                    ],
                )
            )
        steps.append(Step("wait issuer health", [], wait_url="http://localhost:8000/health"))
        steps.append(Step("wait verifier health", [], wait_url="http://localhost:8001/health"))
        steps.append(
            Step("wait fabric adapter health", [], wait_url="http://localhost:8010/health")
        )
        steps.append(
            Step(
                "fabric accumulator perf benchmark",
                [sys.executable, "scripts/benchmark_pipeline.py"],
                env={
                    "BENCHMARK_PROFILE": "fabric_accumulator_perf",
                    "BENCHMARK_RUNS": str(args.runs),
                    "BENCHMARK_WARMUP_RUNS": str(args.warmup),
                    "BENCHMARK_LABEL": args.label,
                    "REVOCATION_MODE": "accumulator",
                    "AUDIT_MODE": "async",
                    "FABRIC_CLIENT_MODE": "adapter",
                },
            )
        )
    return steps


def compile_step() -> Step:
    return Step("compileall", [sys.executable, "-m", "compileall", *COMPILE_TARGETS])


def chaincode_steps() -> list[Step]:
    bash = find_bash()
    if not bash:
        return [
            Step(
                "bash unavailable",
                [sys.executable, "-c", "import sys; print('bash not found'); sys.exit(1)"],
            )
        ]
    return [
        Step("chaincode test", [bash, "./network.sh", "cc-test"], cwd=REPO_ROOT / "fabric"),
        Step("chaincode build", [bash, "./network.sh", "cc-build"], cwd=REPO_ROOT / "fabric"),
        Step("fabric network down", [bash, "./network.sh", "down"], cwd=REPO_ROOT / "fabric"),
        Step("fabric network up", [bash, "./network.sh", "up"], cwd=REPO_ROOT / "fabric"),
        Step(
            "deploy chaincode",
            [bash, "./network.sh", "deployCC-docker"],
            cwd=REPO_ROOT / "fabric",
        ),
        Step("chaincode ping", [bash, "./network.sh", "ping"], cwd=REPO_ROOT / "fabric"),
    ]


def run_step(mode: str, step: Step) -> bool:
    if step.wait_url:
        print(f"\n[{mode}] WAIT {step.wait_url}")
        if wait_for_url(step.wait_url):
            print(f"[{mode}] PASS {step.name}")
            return True
        print(f"[{mode}] FAIL {step.name} (timeout)")
        return False

    print(f"\n[{mode}] RUN {format_command(step.command)}")
    env = os.environ.copy()
    env.update(step.env)
    result = subprocess.run(step.command, cwd=step.cwd, env=env, check=False)
    if result.returncode == 0:
        print(f"[{mode}] PASS {step.name}")
        return True
    print(f"[{mode}] FAIL {step.name} (exit {result.returncode})")
    return False


def wait_for_url(url: str, timeout_seconds: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=3) as response:
                if 200 <= response.status < 300:
                    return True
        except (OSError, URLError) as exc:
            last_error = str(exc)
        time.sleep(1)
    if last_error:
        print(f"Last health error: {last_error}")
    return False


def fabric_orgs_ready() -> bool:
    value = os.getenv("FABRIC_SAMPLES_ORGS_HOST_PATH", "").strip()
    return bool(value) and Path(value).is_dir()


def find_bash() -> str:
    found = shutil.which("bash")
    if found:
        return found
    if os.name == "nt":
        candidate = Path("C:/Program Files/Git/bin/bash.exe")
        if candidate.exists():
            return str(candidate)
    return ""


def format_command(command: list[str]) -> str:
    return " ".join(quote_arg(part) for part in command)


def quote_arg(value: str) -> str:
    if " " in value or "\t" in value:
        return f'"{value}"'
    return value


def print_summary(
    mode: str,
    passed: list[str],
    failed_step: str,
    duration: float,
) -> None:
    print("\nSummary")
    print(f"mode: {mode}")
    print(f"passed steps: {len(passed)}")
    for step in passed:
        print(f"  PASS {step}")
    if failed_step:
        print(f"failed step: {failed_step}")
    else:
        print("failed step: none")
    print(f"duration seconds: {duration:.1f}")


if __name__ == "__main__":
    sys.exit(main())
