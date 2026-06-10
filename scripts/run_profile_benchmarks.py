import argparse


PROFILES = [
    ("full sync audit", "sync", "true", "full"),
    ("async audit", "async", "true", "async_audit"),
    ("disabled audit", "disabled", "false", "no_audit"),
]


def main() -> None:
    args = parse_args()
    print("Profile benchmark command plan")
    print("Services must be restarted for each audit mode so container env changes apply.")
    for title, audit_mode, audit_enabled, profile in PROFILES:
        label = f"{args.label_prefix}-{profile}"
        print()
        print(f"[{title}]")
        print(f"$env:AUDIT_MODE=\"{audit_mode}\"")
        print(f"$env:AUDIT_ENABLED=\"{audit_enabled}\"")
        print(f"$env:BENCHMARK_PROFILE=\"{profile}\"")
        print(f"$env:BENCHMARK_LABEL=\"{label}\"")
        print(f"$env:BENCHMARK_RUNS=\"{args.runs}\"")
        print(f"$env:BENCHMARK_WARMUP_RUNS=\"{args.warmup}\"")
        if args.fabric:
            print(
                "$env:FABRIC_SAMPLES_ORGS_HOST_PATH="
                "\"C:/Users/kebab/Documents/CodingProjects/fabric-samples/test-network/organizations\""
            )
            print("docker compose -f docker-compose.yml -f docker-compose.fabric.yml up -d --build")
        else:
            print("docker compose up -d --build")
        print("python scripts/benchmark_pipeline.py")

    print()
    print("Compare summaries after the runs, for example:")
    print(
        "python scripts/compare_benchmarks.py "
        "results\\benchmark_summary_sync.csv results\\benchmark_summary_async.csv "
        "--left-label sync --right-label async"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Print benchmark commands for audit profile experiments."
    )
    parser.add_argument("--label-prefix", default="profile")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--fabric", action="store_true", help="print Fabric compose commands")
    return parser.parse_args()


if __name__ == "__main__":
    main()
