import json

from network_faults import setup_proxies


def main() -> None:
    result = setup_proxies()
    print(json.dumps({"ok": True, "proxies": result}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
